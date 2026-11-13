use crate::models::HubIncident;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    TorExitNode,
    C2Server,
    KnownScanner,
    Botnet,
    Clean,
}

impl ThreatCategory {
    pub fn tag(&self) -> &'static str {
        match self {
            ThreatCategory::TorExitNode => "[TOR]",
            ThreatCategory::C2Server => "[C2]",
            ThreatCategory::KnownScanner => "[SCANNER]",
            ThreatCategory::Botnet => "[BOTNET]",
            ThreatCategory::Clean => "",
        }
    }

    pub fn score_bonus(&self) -> u8 {
        match self {
            ThreatCategory::TorExitNode => 25,
            ThreatCategory::C2Server => 30,
            ThreatCategory::KnownScanner => 15,
            ThreatCategory::Botnet => 25,
            ThreatCategory::Clean => 0,
        }
    }
}

impl std::fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatCategory::TorExitNode => write!(f, "Tor Exit Node"),
            ThreatCategory::C2Server => write!(f, "C2 Server"),
            ThreatCategory::KnownScanner => write!(f, "Known Scanner"),
            ThreatCategory::Botnet => write!(f, "Botnet"),
            ThreatCategory::Clean => write!(f, "Clean"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ThreatIntelFeed {
    prefixes: Vec<(String, ThreatCategory)>,
}

impl Default for ThreatIntelFeed {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelFeed {
    pub fn new() -> Self {
        let mut feed = Self {
            prefixes: Vec::new(),
        };

        // Tor Exit Nodes
        feed.add_prefix("185.220.101.", ThreatCategory::TorExitNode);
        feed.add_prefix("185.220.100.", ThreatCategory::TorExitNode);
        feed.add_prefix("198.51.100.", ThreatCategory::TorExitNode);
        feed.add_prefix("109.70.100.", ThreatCategory::TorExitNode);
        feed.add_prefix("171.25.193.", ThreatCategory::TorExitNode);
        feed.add_prefix("51.15.", ThreatCategory::TorExitNode);
        feed.add_prefix("162.247.74.", ThreatCategory::TorExitNode);

        // C2 Servers
        feed.add_prefix("185.156.73.", ThreatCategory::C2Server);
        feed.add_prefix("194.26.29.", ThreatCategory::C2Server);
        feed.add_prefix("45.154.255.", ThreatCategory::C2Server);
        feed.add_prefix("91.240.118.", ThreatCategory::C2Server);
        feed.add_prefix("193.142.59.", ThreatCategory::C2Server);

        // Known Public Scanners (Shodan, Censys, Shadowserver)
        // Shodan ranges
        feed.add_prefix("198.20.99.", ThreatCategory::KnownScanner);
        feed.add_prefix("198.20.87.", ThreatCategory::KnownScanner);
        feed.add_prefix("71.6.135.", ThreatCategory::KnownScanner);
        feed.add_prefix("71.6.165.", ThreatCategory::KnownScanner);
        feed.add_prefix("71.6.167.", ThreatCategory::KnownScanner);
        feed.add_prefix("66.240.205.", ThreatCategory::KnownScanner);
        // Censys ranges
        feed.add_prefix("162.142.125.", ThreatCategory::KnownScanner);
        feed.add_prefix("167.94.138.", ThreatCategory::KnownScanner);
        feed.add_prefix("167.94.145.", ThreatCategory::KnownScanner);
        feed.add_prefix("167.94.146.", ThreatCategory::KnownScanner);
        feed.add_prefix("167.248.133.", ThreatCategory::KnownScanner);
        // Shadowserver ranges
        feed.add_prefix("184.105.139.", ThreatCategory::KnownScanner);
        feed.add_prefix("184.105.247.", ThreatCategory::KnownScanner);

        // Botnets
        feed.add_prefix("45.148.10.", ThreatCategory::Botnet);
        feed.add_prefix("103.145.13.", ThreatCategory::Botnet);
        feed.add_prefix("185.244.25.", ThreatCategory::Botnet);
        feed.add_prefix("194.180.48.", ThreatCategory::Botnet);

        feed
    }

    pub fn add_prefix(&mut self, prefix: impl Into<String>, category: ThreatCategory) {
        self.prefixes.push((prefix.into(), category));
    }

    pub fn lookup(&self, ip: &str) -> ThreatCategory {
        let clean_ip = ip.trim();
        let target_ip = if clean_ip.contains(':') && !clean_ip.contains("::") {
            clean_ip.split(':').next().unwrap_or(clean_ip)
        } else {
            clean_ip
        };

        for (prefix, category) in &self.prefixes {
            if target_ip.starts_with(prefix)
                || (prefix.ends_with('.') && target_ip == prefix.trim_end_matches('.'))
            {
                return *category;
            }
        }

        ThreatCategory::Clean
    }

    pub fn enrich_incident(&self, incident: &mut HubIncident) {
        let category = self.lookup(&incident.ip);
        if category != ThreatCategory::Clean {
            let tag = category.tag();
            if !incident.isp.starts_with(tag) {
                if incident.isp.is_empty() {
                    incident.isp = tag.to_string();
                } else {
                    incident.isp = format!("{tag} {}", incident.isp);
                }
            }
            incident.threat_score = incident
                .threat_score
                .saturating_add(category.score_bonus())
                .min(100);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HubIncident;

    fn mock_incident(ip: &str, isp: &str, threat_score: u8) -> HubIncident {
        HubIncident {
            id: Some(1),
            node_id: "test-node".to_string(),
            timestamp: "2026-11-13 10:00:00".to_string(),
            ip: ip.to_string(),
            port: 22,
            service: "SSH".to_string(),
            severity: "ALTO".to_string(),
            country: "Portugal".to_string(),
            city: "Lisbon".to_string(),
            isp: isp.to_string(),
            rdns: None,
            payload: None,
            threat_score,
            hit_count: 1,
        }
    }

    #[test]
    fn test_threat_intel_tor_lookup() {
        let feed = ThreatIntelFeed::new();
        assert_eq!(feed.lookup("185.220.101.5"), ThreatCategory::TorExitNode);
        assert_eq!(feed.lookup("198.51.100.23"), ThreatCategory::TorExitNode);
        assert_eq!(feed.lookup("185.220.101."), ThreatCategory::TorExitNode);
        assert_eq!(feed.lookup("109.70.100.4"), ThreatCategory::TorExitNode);
    }

    #[test]
    fn test_threat_intel_clean_ip() {
        let feed = ThreatIntelFeed::new();
        assert_eq!(feed.lookup("192.168.1.1"), ThreatCategory::Clean);
        assert_eq!(feed.lookup("10.0.0.1"), ThreatCategory::Clean);
        assert_eq!(feed.lookup("172.16.0.5"), ThreatCategory::Clean);
        assert_eq!(feed.lookup("8.8.8.8"), ThreatCategory::Clean);
        assert_eq!(feed.lookup("127.0.0.1"), ThreatCategory::Clean);
    }

    #[test]
    fn test_enrich_incident_threat_score() {
        let feed = ThreatIntelFeed::new();
        let mut incident = mock_incident("185.220.101.42", "Tor Exit Node", 50);
        feed.enrich_incident(&mut incident);
        assert_eq!(incident.isp, "[TOR] Tor Exit Node");
        assert_eq!(incident.threat_score, 75);
    }

    #[test]
    fn test_threat_intel_c2_and_scanners_and_botnets() {
        let feed = ThreatIntelFeed::new();
        assert_eq!(feed.lookup("185.156.73.10"), ThreatCategory::C2Server);
        assert_eq!(feed.lookup("198.20.99.1"), ThreatCategory::KnownScanner);
        assert_eq!(feed.lookup("162.142.125.40"), ThreatCategory::KnownScanner);
        assert_eq!(feed.lookup("45.148.10.99"), ThreatCategory::Botnet);
    }

    #[test]
    fn test_enrich_incident_threat_score_capping() {
        let feed = ThreatIntelFeed::new();
        let mut incident = mock_incident("185.156.73.5", "Malicious Hosting", 85);
        feed.enrich_incident(&mut incident);
        assert_eq!(incident.isp, "[C2] Malicious Hosting");
        assert_eq!(incident.threat_score, 100);
    }

    #[test]
    fn test_enrich_incident_clean_ip_untouched() {
        let feed = ThreatIntelFeed::new();
        let mut incident = mock_incident("192.168.1.50", "Local LAN", 40);
        feed.enrich_incident(&mut incident);
        assert_eq!(incident.isp, "Local LAN");
        assert_eq!(incident.threat_score, 40);
    }

    #[test]
    fn test_threat_category_properties() {
        assert_eq!(ThreatCategory::TorExitNode.tag(), "[TOR]");
        assert_eq!(ThreatCategory::TorExitNode.score_bonus(), 25);
        assert_eq!(ThreatCategory::C2Server.tag(), "[C2]");
        assert_eq!(ThreatCategory::C2Server.score_bonus(), 30);
        assert_eq!(ThreatCategory::KnownScanner.tag(), "[SCANNER]");
        assert_eq!(ThreatCategory::KnownScanner.score_bonus(), 15);
        assert_eq!(ThreatCategory::Botnet.tag(), "[BOTNET]");
        assert_eq!(ThreatCategory::Botnet.score_bonus(), 25);
        assert_eq!(ThreatCategory::Clean.tag(), "");
        assert_eq!(ThreatCategory::Clean.score_bonus(), 0);
    }
}
