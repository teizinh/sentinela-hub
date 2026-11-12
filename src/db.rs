use crate::models::{AgentNode, HubIncident};
use rusqlite::{params, Connection, Result};
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;

             CREATE TABLE IF NOT EXISTS nodes (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 ip TEXT NOT NULL,
                 version TEXT NOT NULL,
                 last_seen TEXT NOT NULL,
                 incident_count INTEGER NOT NULL DEFAULT 0,
                 online INTEGER NOT NULL DEFAULT 1
             );

             CREATE TABLE IF NOT EXISTS incidents (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 node_id TEXT NOT NULL,
                 timestamp TEXT NOT NULL,
                 ip TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 service TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 country TEXT NOT NULL,
                 city TEXT NOT NULL,
                 isp TEXT NOT NULL,
                 rdns TEXT,
                 payload TEXT,
                 threat_score INTEGER NOT NULL,
                 hit_count INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
             CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(ip);
             CREATE INDEX IF NOT EXISTS idx_incidents_node_id ON incidents(node_id);
            ",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS nodes (
                 id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 ip TEXT NOT NULL,
                 version TEXT NOT NULL,
                 last_seen TEXT NOT NULL,
                 incident_count INTEGER NOT NULL DEFAULT 0,
                 online INTEGER NOT NULL DEFAULT 1
             );

             CREATE TABLE IF NOT EXISTS incidents (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 node_id TEXT NOT NULL,
                 timestamp TEXT NOT NULL,
                 ip TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 service TEXT NOT NULL,
                 severity TEXT NOT NULL,
                 country TEXT NOT NULL,
                 city TEXT NOT NULL,
                 isp TEXT NOT NULL,
                 rdns TEXT,
                 payload TEXT,
                 threat_score INTEGER NOT NULL,
                 hit_count INTEGER NOT NULL
             );

             CREATE INDEX IF NOT EXISTS idx_incidents_timestamp ON incidents(timestamp DESC);
             CREATE INDEX IF NOT EXISTS idx_incidents_ip ON incidents(ip);
             CREATE INDEX IF NOT EXISTS idx_incidents_node_id ON incidents(node_id);
            ",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn register_or_update_node(&self, node: &AgentNode) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO nodes (id, name, ip, version, last_seen, incident_count, online)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 ip = excluded.ip,
                 version = excluded.version,
                 last_seen = excluded.last_seen,
                 online = excluded.online",
            params![
                node.id,
                node.name,
                node.ip,
                node.version,
                node.last_seen,
                node.incident_count as i64,
                if node.online { 1 } else { 0 },
            ],
        )?;
        Ok(())
    }

    pub fn insert_incident(&self, inc: &HubIncident) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO incidents (node_id, timestamp, ip, port, service, severity, country, city, isp, rdns, payload, threat_score, hit_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                inc.node_id,
                inc.timestamp,
                inc.ip,
                inc.port,
                inc.service,
                inc.severity,
                inc.country,
                inc.city,
                inc.isp,
                inc.rdns,
                inc.payload,
                inc.threat_score,
                inc.hit_count as i64,
            ],
        )?;
        let id = conn.last_insert_rowid();

        let _ = conn.execute(
            "UPDATE nodes SET incident_count = incident_count + 1, last_seen = ?2, online = 1 WHERE id = ?1",
            params![inc.node_id, inc.timestamp],
        );

        Ok(id)
    }

    pub fn get_recent_incidents(&self, limit: usize) -> Result<Vec<HubIncident>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, node_id, timestamp, ip, port, service, severity, country, city, isp, rdns, payload, threat_score, hit_count
             FROM incidents ORDER BY id DESC LIMIT ?1",
        )?;

        let iter = stmt.query_map(params![limit as i64], |row| {
            Ok(HubIncident {
                id: Some(row.get(0)?),
                node_id: row.get(1)?,
                timestamp: row.get(2)?,
                ip: row.get(3)?,
                port: row.get(4)?,
                service: row.get(5)?,
                severity: row.get(6)?,
                country: row.get(7)?,
                city: row.get(8)?,
                isp: row.get(9)?,
                rdns: row.get(10)?,
                payload: row.get(11)?,
                threat_score: row.get(12)?,
                hit_count: row.get::<_, i64>(13)? as usize,
            })
        })?;

        let mut result = Vec::new();
        for item in iter {
            result.push(item?);
        }
        Ok(result)
    }

    pub fn get_nodes(&self) -> Result<Vec<AgentNode>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, ip, version, last_seen, incident_count, online FROM nodes ORDER BY name ASC",
        )?;

        let iter = stmt.query_map([], |row| {
            Ok(AgentNode {
                id: row.get(0)?,
                name: row.get(1)?,
                ip: row.get(2)?,
                version: row.get(3)?,
                last_seen: row.get(4)?,
                incident_count: row.get::<_, i64>(5)? as usize,
                online: row.get::<_, i64>(6)? != 0,
            })
        })?;

        let mut result = Vec::new();
        for item in iter {
            result.push(item?);
        }
        Ok(result)
    }

    pub fn get_top_attackers(&self, limit: usize) -> Result<Vec<(String, usize, u8, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT ip, SUM(hit_count) as total_hits, MAX(threat_score) as max_score, MAX(country) as country
             FROM incidents GROUP BY ip ORDER BY total_hits DESC LIMIT ?1",
        )?;

        let iter = stmt.query_map(params![limit as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, u8>(2)?,
                row.get::<_, String>(3).unwrap_or_default(),
            ))
        })?;

        let mut result = Vec::new();
        for item in iter {
            result.push(item?);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqlite_in_memory_crud() {
        let db = Database::open_in_memory().unwrap();

        // Regista nó
        let node = AgentNode {
            id: "node-1".to_string(),
            name: "salvador-laptop".to_string(),
            ip: "172.20.200.201".to_string(),
            version: "0.4.0".to_string(),
            last_seen: "2026-11-12 18:00:00".to_string(),
            incident_count: 0,
            online: true,
        };
        db.register_or_update_node(&node).unwrap();

        let nodes = db.get_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "salvador-laptop");

        // Insere incidente
        let inc = HubIncident {
            id: None,
            node_id: "node-1".to_string(),
            timestamp: "2026-11-12 18:01:00".to_string(),
            ip: "198.51.100.42".to_string(),
            port: 2222,
            service: "SSH".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "US".to_string(),
            city: "NYC".to_string(),
            isp: "DigitalOcean".to_string(),
            rdns: None,
            payload: Some("SSH-2.0-Exploit".to_string()),
            threat_score: 90,
            hit_count: 5,
        };
        let inc_id = db.insert_incident(&inc).unwrap();
        assert!(inc_id > 0);

        let incidents = db.get_recent_incidents(10).unwrap();
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].ip, "198.51.100.42");
        assert_eq!(incidents[0].service, "SSH");

        // Verifica que o incident_count do nó foi incrementado
        let nodes_after = db.get_nodes().unwrap();
        assert_eq!(nodes_after[0].incident_count, 1);

        // Verifica top attackers
        let top = db.get_top_attackers(5).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "198.51.100.42");
        assert_eq!(top[0].1, 5);
        assert_eq!(top[0].2, 90);
        assert_eq!(top[0].3, "US");
    }
}
