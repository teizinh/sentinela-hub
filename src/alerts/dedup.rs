use crate::models::HubIncident;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An alert coalesced by the deduplication engine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoalescedAlert {
    pub incident: HubIncident,
    pub first_seen: u64,
    pub last_seen: u64,
    pub hit_count: usize,
    pub should_emit_immediate: bool,
}

/// Alert deduplication and coalescing engine designed to prevent alert storms
/// from flooding outbound webhooks (Discord, Slack, Telegram).
#[derive(Clone, Debug)]
pub struct AlertDeduplicator {
    coalesce_window_secs: u64,
    entries: HashMap<(String, String), CoalescedAlert>,
}

impl Default for AlertDeduplicator {
    fn default() -> Self {
        Self::new(60)
    }
}

impl AlertDeduplicator {
    /// Creates a new `AlertDeduplicator` with the specified coalesce window in seconds.
    pub fn new(coalesce_window_secs: u64) -> Self {
        Self {
            coalesce_window_secs,
            entries: HashMap::new(),
        }
    }

    /// Returns the configured coalesce window duration in seconds.
    pub fn coalesce_window_secs(&self) -> u64 {
        self.coalesce_window_secs
    }

    /// Filters and coalesces incoming incidents.
    ///
    /// - If it is the first time seen for `(attacker_ip, service)`:
    ///   returns `Some(CoalescedAlert)` immediately with `hit_count = 1` and `should_emit_immediate = true`.
    /// - If repeated within `coalesce_window_secs`:
    ///   increments `hit_count`, updates `last_seen`, and returns `None` (suppressing spam).
    /// - When the window expires:
    ///   purges expired state so subsequent attacks trigger a new alert.
    pub fn filter_and_coalesce(
        &mut self,
        inc: &HubIncident,
        now_ts: u64,
    ) -> Option<CoalescedAlert> {
        let key = (inc.ip.clone(), inc.service.clone());

        // Purge expired entries globally to keep memory footprint bounded
        self.purge_expired(now_ts);

        if let Some(entry) = self.entries.get_mut(&key) {
            let elapsed = now_ts.saturating_sub(entry.first_seen);
            if self.coalesce_window_secs > 0 && elapsed <= self.coalesce_window_secs {
                entry.hit_count += 1;
                entry.last_seen = now_ts;
                entry.incident = inc.clone();
                return None;
            }
        }

        // Fresh alert for this (ip, service)
        let alert = CoalescedAlert {
            incident: inc.clone(),
            first_seen: now_ts,
            last_seen: now_ts,
            hit_count: 1,
            should_emit_immediate: true,
        };

        if self.coalesce_window_secs > 0 {
            self.entries.insert(key, alert.clone());
        }

        Some(alert)
    }

    /// Purges all entries whose coalesce window has expired relative to `now_ts`.
    pub fn purge_expired(&mut self, now_ts: u64) {
        if self.coalesce_window_secs == 0 {
            self.entries.clear();
            return;
        }
        let window = self.coalesce_window_secs;
        self.entries.retain(|_, entry| {
            now_ts.saturating_sub(entry.first_seen) <= window
        });
    }

    /// Returns the number of active alert suppressions currently tracked.
    pub fn active_suppressions(&self) -> usize {
        self.entries.len()
    }

    /// Retrieves an active coalesced entry by IP and service, if present.
    pub fn get(&self, ip: &str, service: &str) -> Option<&CoalescedAlert> {
        self.entries.get(&(ip.to_string(), service.to_string()))
    }

    /// Clears all suppression state.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_incident(ip: &str, service: &str) -> HubIncident {
        HubIncident {
            id: None,
            node_id: "node-soc-01".to_string(),
            timestamp: "2026-11-13 10:00:00".to_string(),
            ip: ip.to_string(),
            port: 22,
            service: service.to_string(),
            severity: "ALTO".to_string(),
            country: "Portugal".to_string(),
            city: "Lisboa".to_string(),
            isp: "MEO".to_string(),
            rdns: None,
            payload: Some("malicious scan probe".to_string()),
            threat_score: 85,
            hit_count: 1,
        }
    }

    #[test]
    fn test_first_incident_emits_immediate() {
        let mut dedup = AlertDeduplicator::new(60);
        let inc = dummy_incident("192.168.1.50", "SSH");

        let result = dedup.filter_and_coalesce(&inc, 1000);
        assert!(result.is_some(), "First incident must emit immediately");

        let alert = result.unwrap();
        assert_eq!(alert.incident.ip, "192.168.1.50");
        assert_eq!(alert.incident.service, "SSH");
        assert_eq!(alert.first_seen, 1000);
        assert_eq!(alert.last_seen, 1000);
        assert_eq!(alert.hit_count, 1);
        assert!(alert.should_emit_immediate);
        assert_eq!(dedup.active_suppressions(), 1);
    }

    #[test]
    fn test_burst_suppressed() {
        let mut dedup = AlertDeduplicator::new(60);
        let inc = dummy_incident("10.0.0.99", "HTTP");

        // First event emits
        let first = dedup.filter_and_coalesce(&inc, 1000);
        assert!(first.is_some());

        // Burst of repeated attacks within the 60s coalesce window
        for ts in [1001, 1005, 1015, 1030, 1059, 1060] {
            let res = dedup.filter_and_coalesce(&inc, ts);
            assert!(
                res.is_none(),
                "Burst attack at ts={} should have been suppressed",
                ts
            );
        }

        assert_eq!(dedup.active_suppressions(), 1);

        let cached = dedup
            .get("10.0.0.99", "HTTP")
            .expect("Suppressed alert should be tracked");
        assert_eq!(cached.first_seen, 1000);
        assert_eq!(cached.last_seen, 1060);
        assert_eq!(cached.hit_count, 7); // 1 initial + 6 burst hits
    }

    #[test]
    fn test_window_expiration_allows_new_alert() {
        let mut dedup = AlertDeduplicator::new(60);
        let inc = dummy_incident("172.16.0.42", "RDP");

        // First attack at t=1000 -> emits
        let first = dedup.filter_and_coalesce(&inc, 1000);
        assert!(first.is_some());
        assert_eq!(first.unwrap().hit_count, 1);

        // Burst at t=1020 -> suppressed
        let suppressed = dedup.filter_and_coalesce(&inc, 1020);
        assert!(suppressed.is_none());

        // Attack after window expires (1000 + 60 = 1060, so t=1061 is expired)
        let renewed = dedup.filter_and_coalesce(&inc, 1061);
        assert!(
            renewed.is_some(),
            "Attack after window expiration must emit a new alert"
        );

        let renewed_alert = renewed.unwrap();
        assert_eq!(renewed_alert.first_seen, 1061);
        assert_eq!(renewed_alert.last_seen, 1061);
        assert_eq!(renewed_alert.hit_count, 1);
        assert!(renewed_alert.should_emit_immediate);
        assert_eq!(dedup.active_suppressions(), 1);
    }

    #[test]
    fn test_different_ip_not_suppressed() {
        let mut dedup = AlertDeduplicator::new(60);
        let inc1 = dummy_incident("198.51.100.1", "SSH");
        let inc2 = dummy_incident("198.51.100.2", "SSH");

        let res1 = dedup.filter_and_coalesce(&inc1, 1000);
        let res2 = dedup.filter_and_coalesce(&inc2, 1000);

        assert!(res1.is_some(), "IP 1 must emit alert");
        assert!(res2.is_some(), "IP 2 must emit alert independently");
        assert_eq!(dedup.active_suppressions(), 2);
    }

    #[test]
    fn test_different_service_not_suppressed() {
        let mut dedup = AlertDeduplicator::new(60);
        let inc_ssh = dummy_incident("192.168.1.100", "SSH");
        let inc_http = dummy_incident("192.168.1.100", "HTTP");

        let res1 = dedup.filter_and_coalesce(&inc_ssh, 1000);
        let res2 = dedup.filter_and_coalesce(&inc_http, 1000);

        assert!(res1.is_some(), "SSH service must emit alert");
        assert!(
            res2.is_some(),
            "HTTP service for same IP must emit distinct alert"
        );
        assert_eq!(dedup.active_suppressions(), 2);
    }

    #[test]
    fn test_zero_window_disables_coalescing() {
        let mut dedup = AlertDeduplicator::new(0);
        let inc = dummy_incident("10.10.10.10", "SSH");

        let res1 = dedup.filter_and_coalesce(&inc, 1000);
        let res2 = dedup.filter_and_coalesce(&inc, 1000);

        assert!(res1.is_some());
        assert!(res2.is_some());
        assert_eq!(dedup.active_suppressions(), 0);
    }
}
