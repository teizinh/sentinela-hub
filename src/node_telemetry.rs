use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

pub const DEFAULT_HISTORY_CAPACITY: usize = 60;
pub const STATUS_ONLINE: &str = "online";
pub const STATUS_DEGRADED: &str = "degraded";
pub const STATUS_OFFLINE: &str = "offline";

/// Health evaluation snapshot for a sensor node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeHealth {
    pub is_online: bool,
    pub latency_ms: u64,
    pub packet_rate_pps: usize,
    pub missed_heartbeats: usize,
    pub status_label: String,
}

impl NodeHealth {
    pub fn new(
        is_online: bool,
        latency_ms: u64,
        packet_rate_pps: usize,
        missed_heartbeats: usize,
        status_label: impl Into<String>,
    ) -> Self {
        Self {
            is_online,
            latency_ms,
            packet_rate_pps,
            missed_heartbeats,
            status_label: status_label.into(),
        }
    }

    pub fn is_degraded(&self) -> bool {
        self.status_label == STATUS_DEGRADED || self.missed_heartbeats == 2
    }

    pub fn is_offline(&self) -> bool {
        !self.is_online || self.status_label == STATUS_OFFLINE || self.missed_heartbeats >= 3
    }

    pub fn is_healthy(&self) -> bool {
        self.is_online && self.status_label == STATUS_ONLINE && self.missed_heartbeats < 2
    }
}

/// A single recorded telemetry heartbeat event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatReading {
    pub timestamp: u64,
    pub packet_rate_pps: usize,
    pub latency_ms: u64,
}

/// Circular buffer storing the last N (default 60) heartbeat telemetry readings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMetricsHistory {
    pub readings: VecDeque<HeartbeatReading>,
    pub capacity: usize,
}

impl Default for NodeMetricsHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeMetricsHistory {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_HISTORY_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            readings: VecDeque::with_capacity(capacity),
            capacity: capacity.max(1),
        }
    }

    pub fn push(&mut self, reading: HeartbeatReading) {
        if self.readings.len() >= self.capacity {
            self.readings.pop_front();
        }
        self.readings.push_back(reading);
    }

    pub fn record(&mut self, timestamp: u64, packet_rate_pps: usize, latency_ms: u64) {
        self.push(HeartbeatReading {
            timestamp,
            packet_rate_pps,
            latency_ms,
        });
    }

    pub fn len(&self) -> usize {
        self.readings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.readings.is_empty()
    }

    pub fn latest(&self) -> Option<&HeartbeatReading> {
        self.readings.back()
    }

    pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, HeartbeatReading> {
        self.readings.iter()
    }

    pub fn avg_latency_ms(&self) -> f64 {
        if self.readings.is_empty() {
            0.0
        } else {
            let sum: u64 = self.readings.iter().map(|r| r.latency_ms).sum();
            sum as f64 / self.readings.len() as f64
        }
    }

    pub fn avg_pps(&self) -> f64 {
        if self.readings.is_empty() {
            0.0
        } else {
            let sum: usize = self.readings.iter().map(|r| r.packet_rate_pps).sum();
            sum as f64 / self.readings.len() as f64
        }
    }

    pub fn max_pps(&self) -> usize {
        self.readings.iter().map(|r| r.packet_rate_pps).max().unwrap_or(0)
    }

    pub fn min_latency_ms(&self) -> u64 {
        self.readings.iter().map(|r| r.latency_ms).min().unwrap_or(0)
    }

    pub fn max_latency_ms(&self) -> u64 {
        self.readings.iter().map(|r| r.latency_ms).max().unwrap_or(0)
    }
}

/// Internal per-node telemetry tracking state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeTelemetryRecord {
    pub node_id: String,
    pub last_seen_ts: u64,
    pub health: NodeHealth,
    pub history: NodeMetricsHistory,
}

/// Manages real-time sensor fleet telemetry, rolling metrics, and health evaluation.
#[derive(Clone, Debug)]
pub struct FleetTelemetryManager {
    pub heartbeat_timeout_secs: u64,
    nodes: BTreeMap<String, NodeTelemetryRecord>,
}

impl FleetTelemetryManager {
    pub fn new(heartbeat_timeout_secs: u64) -> Self {
        Self {
            heartbeat_timeout_secs,
            nodes: BTreeMap::new(),
        }
    }

    /// Record an incoming heartbeat from a sensor node.
    pub fn record_heartbeat(&mut self, node_id: &str, pps: usize, latency_ms: u64, now_ts: u64) {
        let record = self
            .nodes
            .entry(node_id.to_string())
            .or_insert_with(|| NodeTelemetryRecord {
                node_id: node_id.to_string(),
                last_seen_ts: now_ts,
                health: NodeHealth {
                    is_online: true,
                    latency_ms,
                    packet_rate_pps: pps,
                    missed_heartbeats: 0,
                    status_label: STATUS_ONLINE.to_string(),
                },
                history: NodeMetricsHistory::new(),
            });

        record.last_seen_ts = now_ts;
        record.health.is_online = true;
        record.health.latency_ms = latency_ms;
        record.health.packet_rate_pps = pps;
        record.health.missed_heartbeats = 0;
        record.health.status_label = STATUS_ONLINE.to_string();

        record.history.record(now_ts, pps, latency_ms);
    }

    /// Evaluate current health across all managed nodes relative to `now_ts`.
    /// - Marks node degraded if missed 2 heartbeats.
    /// - Marks node offline if missed 3+ heartbeats.
    pub fn evaluate_fleet_health(&mut self, now_ts: u64) -> Vec<(String, NodeHealth)> {
        let timeout = self.heartbeat_timeout_secs;
        let mut results = Vec::with_capacity(self.nodes.len());

        for (node_id, record) in self.nodes.iter_mut() {
            let elapsed = now_ts.saturating_sub(record.last_seen_ts);
            let missed = elapsed.checked_div(timeout).unwrap_or(0) as usize;

            record.health.missed_heartbeats = missed;

            if missed >= 3 {
                record.health.is_online = false;
                record.health.status_label = STATUS_OFFLINE.to_string();
            } else if missed == 2 {
                record.health.is_online = true;
                record.health.status_label = STATUS_DEGRADED.to_string();
            } else {
                record.health.is_online = true;
                record.health.status_label = STATUS_ONLINE.to_string();
            }

            results.push((node_id.clone(), record.health.clone()));
        }

        results
    }

    /// Return fleet health counts: (online_count, degraded_count, offline_count).
    pub fn fleet_summary(&self) -> (usize, usize, usize) {
        let mut online = 0;
        let mut degraded = 0;
        let mut offline = 0;

        for record in self.nodes.values() {
            match record.health.status_label.as_str() {
                STATUS_ONLINE => online += 1,
                STATUS_DEGRADED => degraded += 1,
                STATUS_OFFLINE => offline += 1,
                _ => {
                    if record.health.missed_heartbeats >= 3 || !record.health.is_online {
                        offline += 1;
                    } else if record.health.missed_heartbeats == 2 {
                        degraded += 1;
                    } else {
                        online += 1;
                    }
                }
            }
        }

        (online, degraded, offline)
    }

    pub fn get_node_health(&self, node_id: &str) -> Option<&NodeHealth> {
        self.nodes.get(node_id).map(|r| &r.health)
    }

    pub fn get_node_history(&self, node_id: &str) -> Option<&NodeMetricsHistory> {
        self.nodes.get(node_id).map(|r| &r.history)
    }

    pub fn get_node_record(&self, node_id: &str) -> Option<&NodeTelemetryRecord> {
        self.nodes.get(node_id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn node_ids(&self) -> Vec<String> {
        self.nodes.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbeat_updates_online_status() {
        let mut manager = FleetTelemetryManager::new(5);
        let node_id = "node-alpha-01";

        assert_eq!(manager.node_count(), 0);
        assert!(manager.get_node_health(node_id).is_none());

        manager.record_heartbeat(node_id, 1200, 18, 1000);

        assert_eq!(manager.node_count(), 1);
        let health = manager
            .get_node_health(node_id)
            .expect("Node health must be present after heartbeat");

        assert!(health.is_online);
        assert_eq!(health.latency_ms, 18);
        assert_eq!(health.packet_rate_pps, 1200);
        assert_eq!(health.missed_heartbeats, 0);
        assert_eq!(health.status_label, STATUS_ONLINE);

        // Check history updated
        let history = manager
            .get_node_history(node_id)
            .expect("History must be recorded");
        assert_eq!(history.len(), 1);
        assert_eq!(history.latest().unwrap().packet_rate_pps, 1200);
        assert_eq!(history.latest().unwrap().latency_ms, 18);
        assert_eq!(history.latest().unwrap().timestamp, 1000);
    }

    #[test]
    fn test_missed_heartbeats_transition_to_degraded_and_offline() {
        let timeout_secs = 10;
        let mut manager = FleetTelemetryManager::new(timeout_secs);
        let node_id = "sensor-perimeter-42";
        let start_ts = 1000;

        manager.record_heartbeat(node_id, 850, 25, start_ts);

        // Within first interval (< 10s): 0 missed heartbeats -> online
        let fleet = manager.evaluate_fleet_health(start_ts + 5);
        assert_eq!(fleet.len(), 1);
        assert_eq!(fleet[0].1.missed_heartbeats, 0);
        assert!(fleet[0].1.is_online);
        assert_eq!(fleet[0].1.status_label, STATUS_ONLINE);

        // 1 missed heartbeat (10s <= elapsed < 20s): still online
        let fleet = manager.evaluate_fleet_health(start_ts + 10);
        assert_eq!(fleet[0].1.missed_heartbeats, 1);
        assert!(fleet[0].1.is_online);
        assert_eq!(fleet[0].1.status_label, STATUS_ONLINE);

        // 2 missed heartbeats (20s <= elapsed < 30s): marks node degraded
        let fleet = manager.evaluate_fleet_health(start_ts + 20);
        assert_eq!(fleet[0].1.missed_heartbeats, 2);
        assert!(fleet[0].1.is_online);
        assert_eq!(fleet[0].1.status_label, STATUS_DEGRADED);
        assert!(fleet[0].1.is_degraded());

        // 3 missed heartbeats (30s <= elapsed < 40s): marks node offline
        let fleet = manager.evaluate_fleet_health(start_ts + 30);
        assert_eq!(fleet[0].1.missed_heartbeats, 3);
        assert!(!fleet[0].1.is_online);
        assert_eq!(fleet[0].1.status_label, STATUS_OFFLINE);
        assert!(fleet[0].1.is_offline());

        // 4+ missed heartbeats: remains offline
        let fleet = manager.evaluate_fleet_health(start_ts + 50);
        assert_eq!(fleet[0].1.missed_heartbeats, 5);
        assert!(!fleet[0].1.is_online);
        assert_eq!(fleet[0].1.status_label, STATUS_OFFLINE);

        // Node recovers after receiving a new heartbeat
        manager.record_heartbeat(node_id, 920, 15, start_ts + 60);
        let health = manager.get_node_health(node_id).unwrap();
        assert!(health.is_online);
        assert_eq!(health.missed_heartbeats, 0);
        assert_eq!(health.status_label, STATUS_ONLINE);
        assert_eq!(health.packet_rate_pps, 920);
        assert_eq!(health.latency_ms, 15);
    }

    #[test]
    fn test_fleet_summary_counts() {
        let timeout = 10;
        let mut manager = FleetTelemetryManager::new(timeout);
        let now_ts = 1000;

        // node1: recent heartbeat at 1000 (0 missed -> online)
        manager.record_heartbeat("node-1", 500, 10, now_ts);

        // node2: heartbeat at 980 (elapsed = 20 -> 2 missed -> degraded)
        manager.record_heartbeat("node-2", 400, 30, now_ts - 20);

        // node3: heartbeat at 960 (elapsed = 40 -> 4 missed -> offline)
        manager.record_heartbeat("node-3", 300, 50, now_ts - 40);

        // node4: another online node at 995 (elapsed = 5 -> 0 missed -> online)
        manager.record_heartbeat("node-4", 600, 12, now_ts - 5);

        // node5: heartbeat at 970 (elapsed = 30 -> 3 missed -> offline)
        manager.record_heartbeat("node-5", 100, 80, now_ts - 30);

        let results = manager.evaluate_fleet_health(now_ts);
        assert_eq!(results.len(), 5);

        // Online: node-1, node-4 = 2
        // Degraded: node-2 = 1
        // Offline: node-3, node-5 = 2
        let (online, degraded, offline) = manager.fleet_summary();
        assert_eq!(online, 2);
        assert_eq!(degraded, 1);
        assert_eq!(offline, 2);
    }

    #[test]
    fn test_circular_buffer_capacity_limit() {
        let mut history = NodeMetricsHistory::with_capacity(3);
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);

        history.record(100, 10, 5);
        history.record(101, 20, 10);
        history.record(102, 30, 15);
        assert_eq!(history.len(), 3);
        assert_eq!(history.latest().unwrap().timestamp, 102);

        // Adding 4th reading should push out timestamp 100
        history.record(103, 40, 20);
        assert_eq!(history.len(), 3);
        assert_eq!(history.readings.front().unwrap().timestamp, 101);
        assert_eq!(history.latest().unwrap().timestamp, 103);

        // Default capacity is 60
        let default_history = NodeMetricsHistory::new();
        assert_eq!(default_history.capacity, 60);

        let mut mgr = FleetTelemetryManager::new(5);
        for i in 0..75 {
            mgr.record_heartbeat("node-buff", i, (i * 2) as u64, i as u64);
        }
        let buff_hist = mgr.get_node_history("node-buff").unwrap();
        assert_eq!(buff_hist.len(), 60);
        assert_eq!(buff_hist.readings.front().unwrap().timestamp, 15);
        assert_eq!(buff_hist.latest().unwrap().timestamp, 74);
    }

    #[test]
    fn test_metrics_averages_and_extremes() {
        let mut history = NodeMetricsHistory::new();
        assert_eq!(history.avg_latency_ms(), 0.0);
        assert_eq!(history.avg_pps(), 0.0);
        assert_eq!(history.min_latency_ms(), 0);
        assert_eq!(history.max_latency_ms(), 0);
        assert_eq!(history.max_pps(), 0);

        history.record(1, 100, 20);
        history.record(2, 200, 40);
        history.record(3, 300, 60);

        assert_eq!(history.avg_latency_ms(), 40.0);
        assert_eq!(history.avg_pps(), 200.0);
        assert_eq!(history.min_latency_ms(), 20);
        assert_eq!(history.max_latency_ms(), 60);
        assert_eq!(history.max_pps(), 300);
    }

    #[test]
    fn test_serde_node_health() {
        let health = NodeHealth::new(true, 42, 1500, 0, STATUS_ONLINE);
        let serialized = serde_json::to_string(&health).expect("Serialize NodeHealth");
        let deserialized: NodeHealth =
            serde_json::from_str(&serialized).expect("Deserialize NodeHealth");
        assert_eq!(health, deserialized);
    }
}
