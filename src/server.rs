use crate::db::Database;
use crate::models::{AgentNode, HubIncident};
use std::sync::mpsc::Sender;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub enum HubEvent {
    NewIncident(HubIncident),
    NodeHeartbeat(AgentNode),
}

pub struct IngestionServer {
    db: Database,
    event_tx: Sender<HubEvent>,
    bind_addr: String,
}

impl IngestionServer {
    pub fn new(db: Database, event_tx: Sender<HubEvent>, bind_addr: String) -> Self {
        Self {
            db,
            event_tx,
            bind_addr,
        }
    }

    pub async fn run(self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        eprintln!("[*] Sentinela Hub Ingestion Server a escutar em {}", self.bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let db = self.db.clone();
                    let tx = self.event_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, db, tx).await {
                            eprintln!("[!] Erro ao processar conexão: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[!] Erro no listener: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    db: Database,
    tx: Sender<HubEvent>,
) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(4096);
    let mut temp = [0u8; 1024];

    // Read initial headers
    let mut content_length: Option<usize> = None;
    let mut header_end_pos: Option<usize> = None;

    loop {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..n]);

        if header_end_pos.is_none() {
            if let Some(pos) = find_header_end(&buffer) {
                header_end_pos = Some(pos);
                let header_str = String::from_utf8_lossy(&buffer[..pos]);
                for line in header_str.lines() {
                    let lower = line.to_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some(val) = line.split(':').nth(1) {
                            content_length = val.trim().parse::<usize>().ok();
                        }
                    }
                }
            }
        }

        if let Some(pos) = header_end_pos {
            let body_len = buffer.len() - pos;
            let target_len = content_length.unwrap_or(0);
            if body_len >= target_len {
                break;
            }
        }

        if buffer.len() > 1024 * 1024 {
            // 1MB protection limit
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Payload too large",
            ));
        }
    }

    let pos = match header_end_pos {
        Some(p) => p,
        None => {
            return send_response(
                &mut stream,
                400,
                "Bad Request",
                r#"{"error":"malformed http headers"}"#,
            )
            .await;
        }
    };

    let header_part = String::from_utf8_lossy(&buffer[..pos]);
    let mut lines = header_part.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    let body_bytes = &buffer[pos..];

    match (method, path) {
        ("GET", "/api/v1/health") => {
            send_response(&mut stream, 200, "OK", r#"{"status":"healthy","version":"0.1.0"}"#).await
        }
        ("POST", "/api/v1/incident") => {
            match serde_json::from_slice::<HubIncident>(body_bytes) {
                Ok(incident) => {
                    let _ = db.insert_incident(&incident);
                    let _ = tx.send(HubEvent::NewIncident(incident.clone()));
                    send_response(&mut stream, 200, "OK", r#"{"status":"incident recorded"}"#).await
                }
                Err(err) => {
                    // Try parsing wrapped format: { "node_id": "...", "incident": { ... } }
                    #[derive(serde::Deserialize)]
                    struct WrappedPayload {
                        node_id: String,
                        incident: serde_json::Value,
                    }
                    if let Ok(wrapped) = serde_json::from_slice::<WrappedPayload>(body_bytes) {
                        let mut inc: HubIncident = serde_json::from_value(wrapped.incident).map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        inc.node_id = wrapped.node_id;
                        let _ = db.insert_incident(&inc);
                        let _ = tx.send(HubEvent::NewIncident(inc));
                        send_response(&mut stream, 200, "OK", r#"{"status":"incident recorded"}"#).await
                    } else {
                        let err_msg = format!(r#"{{"error":"invalid incident json: {}"}}"#, err);
                        send_response(&mut stream, 400, "Bad Request", &err_msg).await
                    }
                }
            }
        }
        ("POST", "/api/v1/heartbeat") | ("POST", "/api/v1/register") => {
            match serde_json::from_slice::<AgentNode>(body_bytes) {
                Ok(node) => {
                    let _ = db.register_or_update_node(&node);
                    let _ = tx.send(HubEvent::NodeHeartbeat(node));
                    send_response(&mut stream, 200, "OK", r#"{"status":"node updated"}"#).await
                }
                Err(e) => {
                    let err_msg = format!(r#"{{"error":"invalid node json: {}"}}"#, e);
                    send_response(&mut stream, 400, "Bad Request", &err_msg).await
                }
            }
        }
        _ => send_response(&mut stream, 404, "Not Found", r#"{"error":"route not found"}"#).await,
    }
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    for i in 0..data.len().saturating_sub(1) {
        if &data[i..i + 2] == b"\n\n" {
            return Some(i + 2);
        }
    }
    None
}

async fn send_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
         \r\n\
         {}",
        status_code,
        status_text,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    #[tokio::test]
    async fn test_ingestion_health_and_incident() {
        let db = Database::open_in_memory().unwrap();
        let (tx, rx) = channel();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn test server
        let db_clone = db.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let d = db_clone.clone();
                    let t = tx.clone();
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, d, t).await;
                    });
                }
            }
        });

        // 1. Test GET /api/v1/health
        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        client
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("\"status\":\"healthy\""));

        // 2. Test POST /api/v1/incident
        let incident_json = r#"{
            "node_id": "laptop-fedora",
            "timestamp": "2026-11-12 18:10:00",
            "ip": "172.20.200.174",
            "port": 2222,
            "service": "SSH",
            "severity": "CRÍTICO",
            "country": "Portugal",
            "city": "Porto",
            "isp": "Wi-Fi",
            "rdns": null,
            "payload": "SSH-2.0-OpenSSH_9.6",
            "threat_score": 85,
            "hit_count": 1
        }"#;

        let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .unwrap();
        let req = format!(
            "POST /api/v1/incident HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{}",
            incident_json.len(),
            incident_json
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));

        // Check channel received event
        let event = rx.recv().expect("Event should arrive on mpsc channel");
        match event {
            HubEvent::NewIncident(inc) => {
                assert_eq!(inc.node_id, "laptop-fedora");
                assert_eq!(inc.ip, "172.20.200.174");
                assert_eq!(inc.port, 2222);
            }
            _ => panic!("Expected NewIncident event"),
        }

        // Check DB has the incident
        let recent = db.get_recent_incidents(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].node_id, "laptop-fedora");
        assert_eq!(recent[0].ip, "172.20.200.174");
    }
}
