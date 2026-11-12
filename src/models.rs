use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentNode {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub version: String,
    pub last_seen: String,
    pub incident_count: usize,
    pub online: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubIncident {
    pub id: Option<i64>,
    pub node_id: String,
    pub timestamp: String,
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub severity: String,
    pub country: String,
    pub city: String,
    pub isp: String,
    pub rdns: Option<String>,
    pub payload: Option<String>,
    pub threat_score: u8,
    pub hit_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrelationAlert {
    pub id: Option<i64>,
    pub attacker_ip: String,
    pub nodes_targeted: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub total_hits: usize,
    pub threat_score: u8,
    pub targeted_services: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hub_incident_serde() {
        let incident = HubIncident {
            id: Some(1),
            node_id: "laptop-01".to_string(),
            timestamp: "2026-11-12 18:00:00".to_string(),
            ip: "172.20.200.174".to_string(),
            port: 2222,
            service: "SSH".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "Rede Local (Wi-Fi)".to_string(),
            city: "Sub-rede wlo1".to_string(),
            isp: "Dispositivo na mesma rede Wi-Fi".to_string(),
            rdns: Some("telemovel.local".to_string()),
            payload: Some("SSH-2.0-OpenSSH".to_string()),
            threat_score: 85,
            hit_count: 3,
        };

        let json = serde_json::to_string(&incident).unwrap();
        let decoded: HubIncident = serde_json::from_str(&json).unwrap();
        assert_eq!(incident, decoded);
    }

    #[test]
    fn test_correlation_alert_serde() {
        let alert = CorrelationAlert {
            id: Some(42),
            attacker_ip: "198.51.100.42".to_string(),
            nodes_targeted: vec!["laptop-01".to_string(), "vps-oracle".to_string()],
            first_seen: "2026-11-12 18:00:00".to_string(),
            last_seen: "2026-11-12 18:05:00".to_string(),
            total_hits: 15,
            threat_score: 95,
            targeted_services: vec!["SSH".to_string(), "HTTP".to_string()],
        };

        let json = serde_json::to_string(&alert).unwrap();
        let decoded: CorrelationAlert = serde_json::from_str(&json).unwrap();
        assert_eq!(alert, decoded);
    }
}
