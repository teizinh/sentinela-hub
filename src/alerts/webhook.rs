use crate::models::HubIncident;
use crate::ui::modal::map_to_mitre;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const DISCORD_COLOR_RED: u32 = 15158332;   // #E74C3C
pub const DISCORD_COLOR_AMBER: u32 = 15967250; // #F39C12

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebhookProvider {
    Discord,
    Slack,
    Telegram,
    Generic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub provider: WebhookProvider,
    pub min_severity: String,
}

impl WebhookConfig {
    pub fn new(url: impl Into<String>, provider: WebhookProvider, min_severity: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            provider,
            min_severity: min_severity.into(),
        }
    }

    pub fn should_dispatch(&self, severity: &str) -> bool {
        severity_rank(severity) >= severity_rank(&self.min_severity)
    }

    pub fn format_payload(&self, incident: &HubIncident) -> String {
        format_webhook_payload(self.provider, incident)
    }
}

pub fn severity_rank(sev: &str) -> u8 {
    match sev.trim().to_uppercase().as_str() {
        "CRÍTICO" | "CRITICO" => 4,
        "ALTO" => 3,
        "MÉDIO" | "MEDIO" | "ALERTA" => 2,
        "BAIXO" | "INFO" | "SWEEP" | "SCAN" => 1,
        _ => 0,
    }
}

pub fn get_discord_color(incident: &HubIncident) -> u32 {
    let sev = incident.severity.to_uppercase();
    if sev.contains("CRIT") || sev.contains("ALTO") || incident.threat_score >= 70 {
        DISCORD_COLOR_RED
    } else {
        DISCORD_COLOR_AMBER
    }
}

pub fn format_webhook_payload(provider: WebhookProvider, incident: &HubIncident) -> String {
    let (tech_id, tech_name) = map_to_mitre(
        &incident.service,
        incident.port,
        &incident.severity,
        incident.payload.as_deref(),
    );

    match provider {
        WebhookProvider::Discord => {
            let color = get_discord_color(incident);
            let description = format!(
                "Incidente de segurança detetado no nó '{}' [{}]",
                incident.node_id, incident.severity
            );

            let payload = json!({
                "embeds": [
                    {
                        "title": "🚨 Alerta Sentinela SOC",
                        "description": description,
                        "color": color,
                        "fields": [
                            {
                                "name": "IP",
                                "value": incident.ip,
                                "inline": true
                            },
                            {
                                "name": "Port/Service",
                                "value": format!("{}/{}", incident.port, incident.service),
                                "inline": true
                            },
                            {
                                "name": "Threat Score",
                                "value": format!("{}/100", incident.threat_score),
                                "inline": true
                            },
                            {
                                "name": "MITRE ATT&CK",
                                "value": format!("{} - {}", tech_id, tech_name),
                                "inline": false
                            }
                        ],
                        "footer": {
                            "text": "Sentinela SOC • SIEM Telemetry"
                        },
                        "timestamp": incident.timestamp
                    }
                ]
            });
            serde_json::to_string(&payload).unwrap_or_default()
        }
        WebhookProvider::Slack => {
            let payload = json!({
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🚨 Alerta Sentinela SOC",
                            "emoji": true
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": format!("*IP:*\n{}", incident.ip)
                            },
                            {
                                "type": "mrkdwn",
                                "text": format!("*Port/Service:*\n{}/{}", incident.port, incident.service)
                            },
                            {
                                "type": "mrkdwn",
                                "text": format!("*Threat Score:*\n{}/100", incident.threat_score)
                            },
                            {
                                "type": "mrkdwn",
                                "text": format!("*MITRE ATT&CK:*\n{} - {}", tech_id, tech_name)
                            }
                        ]
                    }
                ]
            });
            serde_json::to_string(&payload).unwrap_or_default()
        }
        WebhookProvider::Telegram => {
            let text = format!(
                "🚨 *Alerta Sentinela SOC*\n\n\
                 • *Nó:* {}\n\
                 • *IP:* {}\n\
                 • *Port/Service:* {}/{}\n\
                 • *Severidade:* {}\n\
                 • *Threat Score:* {}/100\n\
                 • *MITRE ATT&CK:* {} - {}\n\
                 • *Timestamp:* {}",
                incident.node_id,
                incident.ip,
                incident.port,
                incident.service,
                incident.severity,
                incident.threat_score,
                tech_id,
                tech_name,
                incident.timestamp
            );
            let payload = json!({
                "text": text,
                "parse_mode": "Markdown"
            });
            serde_json::to_string(&payload).unwrap_or_default()
        }
        WebhookProvider::Generic => {
            let payload = json!({
                "title": "🚨 Alerta Sentinela SOC",
                "provider": "Generic",
                "ip": incident.ip,
                "port": incident.port,
                "service": incident.service,
                "severity": incident.severity,
                "threat_score": incident.threat_score,
                "node_id": incident.node_id,
                "timestamp": incident.timestamp,
                "country": incident.country,
                "city": incident.city,
                "isp": incident.isp,
                "rdns": incident.rdns,
                "payload": incident.payload,
                "hit_count": incident.hit_count,
                "mitre_technique_id": tech_id,
                "mitre_technique_name": tech_name,
                "incident": incident
            });
            serde_json::to_string(&payload).unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_incident() -> HubIncident {
        HubIncident {
            id: Some(1),
            node_id: "laptop-01".to_string(),
            timestamp: "2026-11-13 10:00:00".to_string(),
            ip: "198.51.100.42".to_string(),
            port: 22,
            service: "SSH".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "Portugal".to_string(),
            city: "Lisbon".to_string(),
            isp: "Example ISP".to_string(),
            rdns: Some("attacker.evil.com".to_string()),
            payload: Some("SSH-2.0-OpenSSH".to_string()),
            threat_score: 95,
            hit_count: 5,
        }
    }

    #[test]
    fn test_format_discord_embed_payload() {
        let incident = make_test_incident();
        let payload_str = format_webhook_payload(WebhookProvider::Discord, &incident);
        let v: serde_json::Value = serde_json::from_str(&payload_str).expect("Valid JSON");

        let embeds = v.get("embeds").and_then(|e| e.as_array()).expect("embeds array");
        assert_eq!(embeds.len(), 1);
        let embed = &embeds[0];

        assert_eq!(embed["title"], "🚨 Alerta Sentinela SOC");
        assert!(embed["description"].as_str().unwrap().contains("laptop-01"));
        assert_eq!(embed["color"], DISCORD_COLOR_RED);

        let fields = embed["fields"].as_array().expect("fields array");
        assert_eq!(fields.len(), 4);

        let ip_field = fields.iter().find(|f| f["name"] == "IP").expect("IP field");
        assert_eq!(ip_field["value"], "198.51.100.42");

        let port_field = fields.iter().find(|f| f["name"] == "Port/Service").expect("Port/Service field");
        assert_eq!(port_field["value"], "22/SSH");

        let threat_field = fields.iter().find(|f| f["name"] == "Threat Score").expect("Threat Score field");
        assert_eq!(threat_field["value"], "95/100");

        let mitre_field = fields.iter().find(|f| f["name"] == "MITRE ATT&CK").expect("MITRE ATT&CK field");
        assert!(mitre_field["value"].as_str().unwrap().contains("T1110.001"));

        // Amber test for lower severity
        let mut medium_incident = incident.clone();
        medium_incident.severity = "MÉDIO".to_string();
        medium_incident.threat_score = 40;
        let medium_str = format_webhook_payload(WebhookProvider::Discord, &medium_incident);
        let v_med: serde_json::Value = serde_json::from_str(&medium_str).unwrap();
        assert_eq!(v_med["embeds"][0]["color"], DISCORD_COLOR_AMBER);
    }

    #[test]
    fn test_format_slack_payload() {
        let incident = make_test_incident();
        let payload_str = format_webhook_payload(WebhookProvider::Slack, &incident);
        let v: serde_json::Value = serde_json::from_str(&payload_str).expect("Valid JSON");

        let blocks = v.get("blocks").and_then(|b| b.as_array()).expect("blocks array");
        assert_eq!(blocks.len(), 2);

        assert_eq!(blocks[0]["type"], "header");
        assert_eq!(blocks[0]["text"]["text"], "🚨 Alerta Sentinela SOC");

        assert_eq!(blocks[1]["type"], "section");
        let fields = blocks[1]["fields"].as_array().expect("section fields");
        assert_eq!(fields.len(), 4);

        let fields_str = serde_json::to_string(fields).unwrap();
        assert!(fields_str.contains("198.51.100.42"));
        assert!(fields_str.contains("22/SSH"));
        assert!(fields_str.contains("95/100"));
        assert!(fields_str.contains("T1110.001"));
    }

    #[test]
    fn test_format_telegram_payload() {
        let incident = make_test_incident();
        let payload_str = format_webhook_payload(WebhookProvider::Telegram, &incident);
        let v: serde_json::Value = serde_json::from_str(&payload_str).expect("Valid JSON");

        let text = v.get("text").and_then(|t| t.as_str()).expect("text field");
        assert!(text.contains("🚨 *Alerta Sentinela SOC*"));
        assert!(text.contains("laptop-01"));
        assert!(text.contains("198.51.100.42"));
        assert!(text.contains("22/SSH"));
        assert!(text.contains("95/100"));
        assert!(text.contains("T1110.001"));

        assert_eq!(v["parse_mode"], "Markdown");
    }

    #[test]
    fn test_format_generic_payload() {
        let incident = make_test_incident();
        let payload_str = format_webhook_payload(WebhookProvider::Generic, &incident);
        let v: serde_json::Value = serde_json::from_str(&payload_str).expect("Valid JSON");

        assert_eq!(v["ip"], "198.51.100.42");
        assert_eq!(v["port"], 22);
        assert_eq!(v["service"], "SSH");
        assert_eq!(v["severity"], "CRÍTICO");
        assert_eq!(v["threat_score"], 95);
        assert_eq!(v["incident"]["node_id"], "laptop-01");
        assert!(v["mitre_technique_id"].as_str().unwrap().contains("T1110.001"));
    }

    #[test]
    fn test_webhook_config_dispatch_filter() {
        let config = WebhookConfig::new("https://discord.com/api/webhooks/test", WebhookProvider::Discord, "CRÍTICO");
        assert_eq!(config.provider, WebhookProvider::Discord);
        assert!(config.should_dispatch("CRÍTICO"));
        assert!(!config.should_dispatch("ALTO"));
        assert!(!config.should_dispatch("MÉDIO"));

        let config_slack = WebhookConfig::new("https://hooks.slack.com/test", WebhookProvider::Slack, "MÉDIO");
        assert!(config_slack.should_dispatch("CRÍTICO"));
        assert!(config_slack.should_dispatch("ALTO"));
        assert!(config_slack.should_dispatch("MÉDIO"));
        assert!(!config_slack.should_dispatch("BAIXO"));
    }
}
