use crate::models::HubIncident;
use crate::ui::modal::map_to_mitre;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Represents a detected coordinated attack campaign targeting multiple sensor nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackCampaign {
    pub id: String,
    pub name: String,
    pub attacking_subnets: Vec<String>,
    pub targeted_nodes: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub incident_count: usize,
    pub severity: String,
}

/// Internal tracked incident with parsed metadata for temporal clustering.
#[derive(Clone, Debug)]
struct TrackedIncident {
    pub incident: HubIncident,
    pub timestamp_secs: u64,
    pub received_at: Instant,
    pub subnet: String,
    pub mitre_tech_id: String,
    pub service: String,
}

/// Coordinated multi-sensor attack campaign detection engine.
#[derive(Debug)]
pub struct CampaignClusterer {
    window_secs: u64,
    min_nodes: usize,
    tracked: Vec<TrackedIncident>,
    active_campaigns_cache: Vec<AttackCampaign>,
}

impl Default for CampaignClusterer {
    fn default() -> Self {
        Self::new(600, 2)
    }
}

/// Parses standard timestamp formats or epoch seconds to unix timestamp in seconds.
pub fn parse_timestamp_secs(ts: &str) -> u64 {
    let clean = ts.trim();
    if let Ok(val) = clean.parse::<u64>() {
        return val;
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(clean) {
        return dt.timestamp().max(0) as u64;
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(clean, "%Y-%m-%d %H:%M:%S") {
        return dt.and_utc().timestamp().max(0) as u64;
    }
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(clean, "%Y-%m-%dT%H:%M:%S") {
        return dt.and_utc().timestamp().max(0) as u64;
    }
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extracts /24 IPv4 subnet (e.g. "192.168.1.0/24") or /48 IPv6 prefix.
pub fn extract_subnet_24(ip_str: &str) -> String {
    let clean = ip_str.trim();
    let host = if clean.contains(':') && !clean.contains("::") {
        clean.split(':').next().unwrap_or(clean)
    } else {
        clean
    };

    if let Ok(ipv4) = host.parse::<Ipv4Addr>() {
        let octets = ipv4.octets();
        format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
    } else if let Ok(ipv6) = host.parse::<Ipv6Addr>() {
        let segs = ipv6.segments();
        format!("{:x}:{:x}:{:x}::/48", segs[0], segs[1], segs[2])
    } else {
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 3 {
            format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
        } else {
            format!("{}/24", host)
        }
    }
}

impl CampaignClusterer {
    pub fn new(window_secs: u64, min_nodes: usize) -> Self {
        Self {
            window_secs,
            min_nodes,
            tracked: Vec::new(),
            active_campaigns_cache: Vec::new(),
        }
    }

    /// Prunes expired incidents based on the temporal window.
    pub fn cleanup(&mut self) {
        let now_instant = Instant::now();
        let window_ms = (self.window_secs as u128) * 1000;
        self.tracked.retain(|item| {
            if self.window_secs == 0 {
                return false;
            }
            let elapsed_ms = now_instant.duration_since(item.received_at).as_millis();
            elapsed_ms < window_ms
        });
        self.recluster();
    }

    /// Prunes incidents older than the given reference timestamp.
    pub fn prune_older_than(&mut self, current_ts: u64) {
        let cutoff = current_ts.saturating_sub(self.window_secs);
        self.tracked.retain(|item| item.timestamp_secs >= cutoff);
        self.recluster();
    }

    /// Ingests a new incident, groups incidents hitting >= min_nodes, and returns the triggered/updated campaign if any.
    pub fn ingest_incident(&mut self, inc: &HubIncident) -> Option<AttackCampaign> {
        let now_instant = Instant::now();
        let ts_secs = parse_timestamp_secs(&inc.timestamp);
        let subnet = extract_subnet_24(&inc.ip);
        let (tech_id, _) = map_to_mitre(
            &inc.service,
            inc.port,
            &inc.severity,
            inc.payload.as_deref(),
        );
        let service = inc.service.trim().to_uppercase();

        // 1. Sliding window cleanup
        let window_ms = (self.window_secs as u128) * 1000;
        self.tracked.retain(|item| {
            let real_expired = self.window_secs > 0
                && now_instant.duration_since(item.received_at).as_millis() >= window_ms;
            let ts_expired = self.window_secs > 0
                && ts_secs > item.timestamp_secs
                && (ts_secs - item.timestamp_secs) > self.window_secs;
            !real_expired && !ts_expired
        });

        // 2. Add incoming incident
        let new_item = TrackedIncident {
            incident: inc.clone(),
            timestamp_secs: ts_secs,
            received_at: now_instant,
            subnet: subnet.clone(),
            mitre_tech_id: tech_id.to_string(),
            service: service.clone(),
        };
        self.tracked.push(new_item);

        // 3. Recompute all clusters and locate the campaign containing the newly ingested incident
        let (campaigns, incoming_cluster_campaign) = self.compute_clusters(self.tracked.len() - 1);
        self.active_campaigns_cache = campaigns;

        incoming_cluster_campaign
    }

    /// Returns a list of all currently active campaigns.
    pub fn active_campaigns(&self) -> Vec<&AttackCampaign> {
        self.active_campaigns_cache.iter().collect()
    }

    /// Re-evaluates clusters and updates `active_campaigns_cache`.
    fn recluster(&mut self) {
        let (campaigns, _) = self.compute_clusters(usize::MAX);
        self.active_campaigns_cache = campaigns;
    }

    /// Computes clusters and identifies the campaign for `target_idx` (if valid and meets min_nodes).
    fn compute_clusters(&self, target_idx: usize) -> (Vec<AttackCampaign>, Option<AttackCampaign>) {
        if self.tracked.is_empty() {
            return (Vec::new(), None);
        }

        let n = self.tracked.len();
        let mut parent: Vec<usize> = (0..n).collect();

        fn find(parent: &mut [usize], i: usize) -> usize {
            if parent[i] != i {
                let p = parent[i];
                parent[i] = find(parent, p);
            }
            parent[i]
        }

        fn union(parent: &mut [usize], i: usize, j: usize) {
            let root_i = find(parent, i);
            let root_j = find(parent, j);
            if root_i != root_j {
                parent[root_i] = root_j;
            }
        }

        // Connect incidents if they share:
        // a) same /24 IP subnet, OR
        // b) same MITRE ATT&CK technique + same target service
        for i in 0..n {
            for j in (i + 1)..n {
                let same_subnet = self.tracked[i].subnet == self.tracked[j].subnet;
                let same_mitre = self.tracked[i].mitre_tech_id == self.tracked[j].mitre_tech_id;
                let same_service = !self.tracked[i].service.is_empty()
                    && self.tracked[i].service == self.tracked[j].service;

                if same_subnet || (same_mitre && same_service) {
                    union(&mut parent, i, j);
                }
            }
        }

        // Group indices by cluster root
        let mut clusters: HashMap<usize, Vec<usize>> = HashMap::new();
        for i in 0..n {
            let root = find(&mut parent, i);
            clusters.entry(root).or_default().push(i);
        }

        let target_root = if target_idx < n {
            Some(find(&mut parent, target_idx))
        } else {
            None
        };

        let mut campaigns = Vec::new();
        let mut target_campaign = None;

        for (root, indices) in clusters {
            let mut distinct_nodes: HashSet<String> = HashSet::new();
            let mut subnets_set: HashSet<String> = HashSet::new();
            let mut mitre_set: HashSet<String> = HashSet::new();
            let mut services_set: HashSet<String> = HashSet::new();
            let mut first_seen = u64::MAX;
            let mut last_seen = 0u64;
            let mut incident_count = 0usize;
            let mut max_threat_score = 0u8;
            let mut has_critical_severity = false;
            let mut has_high_severity = false;

            for &idx in &indices {
                let item = &self.tracked[idx];
                distinct_nodes.insert(item.incident.node_id.clone());
                subnets_set.insert(item.subnet.clone());
                mitre_set.insert(item.mitre_tech_id.clone());
                if !item.service.is_empty() {
                    services_set.insert(item.service.clone());
                }

                first_seen = first_seen.min(item.timestamp_secs);
                last_seen = last_seen.max(item.timestamp_secs);
                incident_count += item.incident.hit_count.max(1);
                max_threat_score = max_threat_score.max(item.incident.threat_score);

                let sev_upper = item.incident.severity.to_uppercase();
                if sev_upper.contains("CRÍT") || sev_upper.contains("CRIT") {
                    has_critical_severity = true;
                } else if sev_upper.contains("ALT") || sev_upper.contains("HIGH") {
                    has_high_severity = true;
                }
            }

            // Group incidents hitting >= min_nodes
            if distinct_nodes.len() >= self.min_nodes {
                let mut attacking_subnets: Vec<String> = subnets_set.into_iter().collect();
                attacking_subnets.sort();

                let mut targeted_nodes: Vec<String> = distinct_nodes.into_iter().collect();
                targeted_nodes.sort();

                let mut mitre_techniques: Vec<String> = mitre_set.into_iter().collect();
                mitre_techniques.sort();

                let mut services: Vec<String> = services_set.into_iter().collect();
                services.sort();

                let severity = if has_critical_severity || max_threat_score >= 80 || targeted_nodes.len() >= 3 {
                    "CRÍTICO".to_string()
                } else if has_high_severity || max_threat_score >= 50 {
                    "ALTO".to_string()
                } else {
                    "MÉDIO".to_string()
                };

                let primary_subnet = attacking_subnets.first().cloned().unwrap_or_default();
                let primary_mitre = mitre_techniques.first().cloned().unwrap_or_default();
                let primary_service = services.first().cloned().unwrap_or_default();

                let (id, name) = if attacking_subnets.len() == 1 {
                    (
                        format!("cmp-sub-{}", primary_subnet.replace('/', "-")),
                        format!("Campanha Coordenada: Sub-rede {}", primary_subnet),
                    )
                } else {
                    (
                        format!(
                            "cmp-mitre-{}-{}",
                            primary_mitre.to_lowercase().replace('.', "-"),
                            primary_service.to_lowercase()
                        ),
                        format!(
                            "Campanha Distribuída: {} em {}",
                            primary_mitre, primary_service
                        ),
                    )
                };

                let campaign = AttackCampaign {
                    id,
                    name,
                    attacking_subnets,
                    targeted_nodes,
                    mitre_techniques,
                    first_seen: if first_seen == u64::MAX { 0 } else { first_seen },
                    last_seen,
                    incident_count,
                    severity,
                };

                if Some(root) == target_root {
                    target_campaign = Some(campaign.clone());
                }

                campaigns.push(campaign);
            }
        }

        campaigns.sort_by(|a, b| {
            b.incident_count
                .cmp(&a.incident_count)
                .then_with(|| b.last_seen.cmp(&a.last_seen))
        });

        (campaigns, target_campaign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_incident(node: &str, ip: &str, service: &str, threat: u8) -> HubIncident {
        HubIncident {
            id: None,
            node_id: node.to_string(),
            timestamp: "2026-11-13 10:00:00".to_string(),
            ip: ip.to_string(),
            port: match service {
                "SSH" => 22,
                "HTTP" => 80,
                "DNS" => 53,
                "SMB" => 445,
                _ => 8080,
            },
            service: service.to_string(),
            severity: "ALTO".to_string(),
            country: "Portugal".to_string(),
            city: "Lisbon".to_string(),
            isp: "Vodafone".to_string(),
            rdns: None,
            payload: None,
            threat_score: threat,
            hit_count: 1,
        }
    }

    #[test]
    fn test_single_node_no_campaign() {
        let mut clusterer = CampaignClusterer::new(60, 2);
        let inc1 = dummy_incident("node-1", "192.168.1.10", "SSH", 50);
        let inc2 = dummy_incident("node-1", "192.168.1.20", "SSH", 60);

        assert!(clusterer.ingest_incident(&inc1).is_none());
        assert!(clusterer.ingest_incident(&inc2).is_none());
        assert_eq!(clusterer.active_campaigns().len(), 0);
    }

    #[test]
    fn test_multi_node_same_subnet_triggers_campaign() {
        let mut clusterer = CampaignClusterer::new(60, 2);
        let inc1 = dummy_incident("node-1", "192.168.1.10", "SSH", 50);
        let inc2 = dummy_incident("node-2", "192.168.1.25", "HTTP", 70);

        assert!(clusterer.ingest_incident(&inc1).is_none());
        let campaign = clusterer
            .ingest_incident(&inc2)
            .expect("Campaign must be triggered on 2nd node hitting same /24 subnet");

        assert!(campaign.attacking_subnets.contains(&"192.168.1.0/24".to_string()));
        assert_eq!(campaign.targeted_nodes.len(), 2);
        assert!(campaign.targeted_nodes.contains(&"node-1".to_string()));
        assert!(campaign.targeted_nodes.contains(&"node-2".to_string()));
        assert_eq!(campaign.incident_count, 2);
        assert!(!campaign.severity.is_empty());
        assert_eq!(clusterer.active_campaigns().len(), 1);
    }

    #[test]
    fn test_multi_node_mitre_campaign() {
        let mut clusterer = CampaignClusterer::new(60, 2);
        // Incidents from completely different /24 subnets, but both targeting SSH (MITRE T1110.001)
        let inc1 = dummy_incident("node-1", "10.0.1.5", "SSH", 55);
        let inc2 = dummy_incident("node-2", "192.168.2.99", "SSH", 65);

        assert!(clusterer.ingest_incident(&inc1).is_none());
        let campaign = clusterer
            .ingest_incident(&inc2)
            .expect("Campaign must be triggered on shared MITRE technique and service");

        assert!(campaign.mitre_techniques.contains(&"T1110.001".to_string()));
        assert_eq!(campaign.targeted_nodes.len(), 2);
        assert!(campaign.targeted_nodes.contains(&"node-1".to_string()));
        assert!(campaign.targeted_nodes.contains(&"node-2".to_string()));
        assert!(campaign.attacking_subnets.contains(&"10.0.1.0/24".to_string()));
        assert!(campaign.attacking_subnets.contains(&"192.168.2.0/24".to_string()));
        assert_eq!(clusterer.active_campaigns().len(), 1);
    }

    #[test]
    fn test_window_cleanup() {
        // 1. Wall-clock temporal window expiration test
        let mut clusterer = CampaignClusterer::new(1, 2); // 1-second window
        let inc1 = dummy_incident("node-1", "192.168.1.10", "SSH", 50);
        assert!(clusterer.ingest_incident(&inc1).is_none());

        // Sleep to let inc1 expire
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Ingest incident on node-2 after inc1 expired
        let inc2 = dummy_incident("node-2", "192.168.1.20", "SSH", 50);
        let campaign = clusterer.ingest_incident(&inc2);
        assert!(campaign.is_none());
        assert_eq!(clusterer.active_campaigns().len(), 0);

        // 2. Timestamp distance temporal window expiration test
        let mut clusterer_ts = CampaignClusterer::new(60, 2); // 60-second window
        let mut inc_ts1 = dummy_incident("node-1", "10.0.0.1", "SSH", 50);
        inc_ts1.timestamp = "2026-11-13 10:00:00".to_string();
        assert!(clusterer_ts.ingest_incident(&inc_ts1).is_none());

        let mut inc_ts2 = dummy_incident("node-2", "10.0.0.2", "SSH", 50);
        inc_ts2.timestamp = "2026-11-13 10:05:00".to_string(); // 300 seconds later (> 60s)
        let camp_ts = clusterer_ts.ingest_incident(&inc_ts2);
        assert!(camp_ts.is_none());
        assert_eq!(clusterer_ts.active_campaigns().len(), 0);
    }

    #[test]
    fn test_attack_campaign_serde() {
        let campaign = AttackCampaign {
            id: "cmp-sub-192.168.1.0-24".to_string(),
            name: "Campanha Coordenada: Sub-rede 192.168.1.0/24".to_string(),
            attacking_subnets: vec!["192.168.1.0/24".to_string()],
            targeted_nodes: vec!["node-1".to_string(), "node-2".to_string()],
            mitre_techniques: vec!["T1110.001".to_string()],
            first_seen: 1700000000,
            last_seen: 1700000060,
            incident_count: 5,
            severity: "ALTO".to_string(),
        };

        let json = serde_json::to_string(&campaign).unwrap();
        let decoded: AttackCampaign = serde_json::from_str(&json).unwrap();
        assert_eq!(campaign, decoded);
    }

    #[test]
    fn test_extract_subnet_and_timestamp_parser() {
        assert_eq!(extract_subnet_24("192.168.1.42"), "192.168.1.0/24");
        assert_eq!(extract_subnet_24("10.200.5.1:8080"), "10.200.5.0/24");
        assert_eq!(extract_subnet_24("2001:db8:85a3::8a2e:370:7334"), "2001:db8:85a3::/48");

        assert_eq!(parse_timestamp_secs("1700000000"), 1700000000);
        assert!(parse_timestamp_secs("2026-11-13 10:00:00") > 0);
    }

    #[test]
    fn test_severity_escalation_to_critical() {
        let mut clusterer = CampaignClusterer::new(60, 2);
        let mut inc1 = dummy_incident("node-1", "192.168.1.10", "SSH", 50);
        inc1.severity = "ALTO".to_string();
        let mut inc2 = dummy_incident("node-2", "192.168.1.20", "SSH", 90);
        inc2.severity = "CRÍTICO".to_string();

        clusterer.ingest_incident(&inc1);
        let camp = clusterer.ingest_incident(&inc2).unwrap();
        assert_eq!(camp.severity, "CRÍTICO");
    }

    #[test]
    fn test_prune_older_than_and_cleanup() {
        let mut clusterer = CampaignClusterer::new(100, 2);
        let mut inc1 = dummy_incident("node-1", "192.168.1.10", "SSH", 50);
        inc1.timestamp = "1000".to_string();
        let mut inc2 = dummy_incident("node-2", "192.168.1.20", "SSH", 50);
        inc2.timestamp = "1050".to_string();

        clusterer.ingest_incident(&inc1);
        let camp = clusterer.ingest_incident(&inc2);
        assert!(camp.is_some());
        assert_eq!(clusterer.active_campaigns().len(), 1);

        clusterer.prune_older_than(1200);
        assert_eq!(clusterer.active_campaigns().len(), 0);
    }
}
