use crate::models::{CorrelationAlert, HubIncident};
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
struct TrackedIncident {
    pub incident: HubIncident,
    pub received_at: Instant,
}

#[derive(Debug)]
pub struct CorrelationEngine {
    window_duration: Duration,
    tracked: Vec<TrackedIncident>,
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(Duration::from_secs(600)) // 10 minutes
    }
}

impl CorrelationEngine {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            window_duration,
            tracked: Vec::new(),
        }
    }

    /// Cleans up incidents outside the sliding time window.
    pub fn prune(&mut self, now: Instant) {
        let cutoff = self.window_duration;
        self.tracked.retain(|item| now.duration_since(item.received_at) <= cutoff);
    }

    /// Ingests a new incident, prunes expired incidents, and checks if it triggers a multi-host correlation.
    pub fn process_incident(&mut self, incident: &HubIncident) -> Option<CorrelationAlert> {
        let now = Instant::now();
        self.prune(now);

        self.tracked.push(TrackedIncident {
            incident: incident.clone(),
            received_at: now,
        });

        self.correlate_ip(&incident.ip)
    }

    /// Evaluates if an attacker IP has targeted 2 or more distinct nodes.
    pub fn correlate_ip(&self, ip: &str) -> Option<CorrelationAlert> {
        let relevant: Vec<&HubIncident> = self
            .tracked
            .iter()
            .map(|t| &t.incident)
            .filter(|inc| inc.ip == ip)
            .collect();

        if relevant.is_empty() {
            return None;
        }

        let mut distinct_nodes: HashSet<String> = HashSet::new();
        let mut services: HashSet<String> = HashSet::new();
        let mut total_hits: usize = 0;
        let mut max_threat: u8 = 0;
        let mut first_seen = &relevant[0].timestamp;
        let mut last_seen = &relevant[0].timestamp;

        for inc in &relevant {
            distinct_nodes.insert(inc.node_id.clone());
            if !inc.service.is_empty() {
                services.insert(inc.service.clone());
            }
            total_hits += inc.hit_count.max(1);
            if inc.threat_score > max_threat {
                max_threat = inc.threat_score;
            }
            if inc.timestamp < *first_seen {
                first_seen = &inc.timestamp;
            }
            if inc.timestamp > *last_seen {
                last_seen = &inc.timestamp;
            }
        }

        if distinct_nodes.len() >= 2 {
            let mut nodes_vec: Vec<String> = distinct_nodes.into_iter().collect();
            nodes_vec.sort();

            let mut services_vec: Vec<String> = services.into_iter().collect();
            services_vec.sort();

            // Multi-host attack multiplier: +15 threat points for coordinated scanning
            let boosted_threat = (max_threat as u16 + 15).min(100) as u8;

            Some(CorrelationAlert {
                id: None,
                attacker_ip: ip.to_string(),
                nodes_targeted: nodes_vec,
                first_seen: first_seen.clone(),
                last_seen: last_seen.clone(),
                total_hits,
                threat_score: boosted_threat,
                targeted_services: services_vec,
            })
        } else {
            None
        }
    }

    /// Returns all current active multi-host correlation alerts in the time window.
    pub fn get_active_correlations(&self) -> Vec<CorrelationAlert> {
        let mut ip_set: HashSet<String> = HashSet::new();
        for item in &self.tracked {
            ip_set.insert(item.incident.ip.clone());
        }

        let mut alerts = Vec::new();
        for ip in ip_set {
            if let Some(alert) = self.correlate_ip(&ip) {
                alerts.push(alert);
            }
        }

        alerts.sort_by(|a, b| b.threat_score.cmp(&a.threat_score).then_with(|| b.total_hits.cmp(&a.total_hits)));
        alerts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_incident(node: &str, ip: &str, service: &str, threat: u8) -> HubIncident {
        HubIncident {
            id: None,
            node_id: node.to_string(),
            timestamp: "2026-11-12 18:00:00".to_string(),
            ip: ip.to_string(),
            port: 2222,
            service: service.to_string(),
            severity: "ALTO".to_string(),
            country: "Portugal".to_string(),
            city: "Porto".to_string(),
            isp: "Vodafone".to_string(),
            rdns: None,
            payload: None,
            threat_score: threat,
            hit_count: 1,
        }
    }

    #[test]
    fn test_single_node_no_correlation() {
        let mut engine = CorrelationEngine::new(Duration::from_secs(60));
        let inc1 = dummy_incident("laptop-01", "192.168.1.100", "SSH", 50);
        let inc2 = dummy_incident("laptop-01", "192.168.1.100", "HTTP", 60);

        assert!(engine.process_incident(&inc1).is_none());
        assert!(engine.process_incident(&inc2).is_none());
        assert_eq!(engine.get_active_correlations().len(), 0);
    }

    #[test]
    fn test_multi_node_triggers_correlation() {
        let mut engine = CorrelationEngine::new(Duration::from_secs(60));
        let inc1 = dummy_incident("laptop-01", "192.168.1.100", "SSH", 50);
        let inc2 = dummy_incident("server-vps", "192.168.1.100", "HTTP", 70);

        assert!(engine.process_incident(&inc1).is_none());
        let alert = engine.process_incident(&inc2).expect("Must trigger correlation on 2nd node");

        assert_eq!(alert.attacker_ip, "192.168.1.100");
        assert_eq!(alert.nodes_targeted, vec!["laptop-01", "server-vps"]);
        assert_eq!(alert.targeted_services, vec!["HTTP", "SSH"]);
        assert_eq!(alert.threat_score, 85); // 70 + 15
        assert_eq!(alert.total_hits, 2);

        let active = engine.get_active_correlations();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].attacker_ip, "192.168.1.100");
    }

    #[test]
    fn test_window_expiration() {
        let mut engine = CorrelationEngine::new(Duration::from_millis(50));
        let inc1 = dummy_incident("laptop-01", "10.0.0.99", "SSH", 40);
        engine.process_incident(&inc1);

        // Sleep to let inc1 expire
        std::thread::sleep(Duration::from_millis(60));

        let inc2 = dummy_incident("server-vps", "10.0.0.99", "HTTP", 40);
        // After expiration, inc1 is gone, so inc2 is only 1 node in the window
        let alert = engine.process_incident(&inc2);
        assert!(alert.is_none());
    }
}
