use crate::models::HubIncident;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// SplitMix64 PRNG for mixing bits into RFC 4122 UUID fields.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

/// Generates a valid RFC 4122 version 4 UUID string.
pub fn generate_uuid_v4() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);

    let mut bytes = [0u8; 16];
    let h1 = splitmix64(now as u64 ^ (count << 32));
    let h2 = splitmix64((now >> 64) as u64 ^ count.wrapping_mul(31) ^ 0x9e3779b97f4a7c15);
    bytes[0..8].copy_from_slice(&h1.to_be_bytes());
    bytes[8..16].copy_from_slice(&h2.to_be_bytes());

    // Version 4 (0100)
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    // RFC 4122 Variant (10xx)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Generates a deterministic RFC 4122 version 5 UUID from namespace and name.
pub fn deterministic_uuid_v5(namespace: &str, name: &str) -> String {
    let mut h1 = 0xcbf29ce484222325u64;
    for b in namespace.as_bytes() {
        h1 ^= *b as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
    }
    for b in name.as_bytes() {
        h1 ^= *b as u64;
        h1 = h1.wrapping_mul(0x100000001b3);
    }

    let h2 = splitmix64(h1);
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&h1.to_be_bytes());
    bytes[8..16].copy_from_slice(&h2.to_be_bytes());

    // Version 5 (0101)
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    // RFC 4122 Variant (10xx)
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// STIX 2.1 Cyber Threat Intelligence (CTI) Bundle Container.
#[derive(Debug, Clone, PartialEq)]
pub struct StixBundle {
    pub id: String,
    pub spec_version: String,
    pub objects: Vec<serde_json::Value>,
}

impl StixBundle {
    pub fn new(objects: Vec<serde_json::Value>) -> Self {
        Self {
            id: format!("bundle--{}", generate_uuid_v4()),
            spec_version: "2.1".to_string(),
            objects,
        }
    }
}

impl Serialize for StixBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = serializer.serialize_struct("StixBundle", 4)?;
        s.serialize_field("type", "bundle")?;
        s.serialize_field("id", &self.id)?;
        s.serialize_field("spec_version", &self.spec_version)?;
        s.serialize_field("objects", &self.objects)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for StixBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            id: String,
            #[serde(default = "default_spec_version")]
            spec_version: String,
            #[serde(default)]
            objects: Vec<serde_json::Value>,
        }
        fn default_spec_version() -> String {
            "2.1".to_string()
        }

        let helper = Helper::deserialize(deserializer)?;
        Ok(StixBundle {
            id: helper.id,
            spec_version: helper.spec_version,
            objects: helper.objects,
        })
    }
}

/// Formats a timestamp into standard STIX 2.1 ISO 8601 (RFC 3339) UTC format.
fn format_stix_timestamp(ts: &str) -> String {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return dt
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
        return chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive, chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    }
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Converts a slice of HubIncident records into a standard STIX 2.1 Bundle.
///
/// Produces:
/// - STIX 2.1 `indicator` objects with pattern `[ipv4-addr:value = '<ip>']`
/// - STIX 2.1 `attack-pattern` objects linking MITRE ATT&CK techniques
/// - STIX 2.1 `relationship` objects (`indicates`, `uses`)
pub fn incidents_to_stix_bundle(incidents: &[HubIncident]) -> StixBundle {
    let mut objects = Vec::new();
    let now_ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let mut seen_techniques: HashMap<String, String> = HashMap::new();

    for incident in incidents {
        let incident_ts = format_stix_timestamp(&incident.timestamp);
        let (tech_id, tech_name) = crate::ui::modal::map_to_mitre(
            &incident.service,
            incident.port,
            &incident.severity,
            incident.payload.as_deref(),
        );

        // 1. Attack Pattern object (deduplicated by technique ID)
        let attack_pattern_id = if let Some(existing_id) = seen_techniques.get(tech_id) {
            existing_id.clone()
        } else {
            let ap_uuid = deterministic_uuid_v5("attack-pattern", tech_id);
            let ap_id = format!("attack-pattern--{}", ap_uuid);
            let ap_obj = serde_json::json!({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": now_ts,
                "modified": now_ts,
                "name": tech_name,
                "description": format!("MITRE ATT&CK technique {} ({})", tech_id, tech_name),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": format!("https://attack.mitre.org/techniques/{}", tech_id.replace('.', "/"))
                    }
                ]
            });
            objects.push(ap_obj);
            seen_techniques.insert(tech_id.to_string(), ap_id.clone());
            ap_id
        };

        // 2. Indicator object
        let ind_uuid = generate_uuid_v4();
        let indicator_id = format!("indicator--{}", ind_uuid);
        let pattern = if incident.ip.contains(':') && !incident.ip.contains('.') {
            format!("[ipv6-addr:value = '{}']", incident.ip)
        } else {
            format!("[ipv4-addr:value = '{}']", incident.ip)
        };

        let ind_obj = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": incident_ts,
            "modified": incident_ts,
            "name": format!("Malicious IPv4 Indicator: {}", incident.ip),
            "description": format!("Traffic detected from {} on port {} ({})", incident.ip, incident.port, incident.service),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": incident_ts,
            "confidence": incident.threat_score
        });
        objects.push(ind_obj);

        // 3. Relationship object: 'indicates'
        let rel_ind_uuid = generate_uuid_v4();
        let rel_indicates = serde_json::json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": format!("relationship--{}", rel_ind_uuid),
            "created": incident_ts,
            "modified": incident_ts,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": attack_pattern_id
        });
        objects.push(rel_indicates);

        // 4. Relationship object: 'uses'
        let rel_uses_uuid = generate_uuid_v4();
        let rel_uses = serde_json::json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": format!("relationship--{}", rel_uses_uuid),
            "created": incident_ts,
            "modified": incident_ts,
            "relationship_type": "uses",
            "source_ref": indicator_id,
            "target_ref": attack_pattern_id
        });
        objects.push(rel_uses);
    }

    StixBundle {
        id: format!("bundle--{}", generate_uuid_v4()),
        spec_version: "2.1".to_string(),
        objects,
    }
}

/// Formats a slice of HubIncident records into a standard MISP Event JSON string.
///
/// Formats an event object with attributes `ip-src`, `port`, and `comment`.
pub fn export_misp_json(incidents: &[HubIncident]) -> String {
    let now = chrono::Utc::now();
    let event_uuid = generate_uuid_v4();
    let date_str = now.format("%Y-%m-%d").to_string();

    let mut attributes = Vec::new();

    for incident in incidents {
        let (tech_id, tech_name) = crate::ui::modal::map_to_mitre(
            &incident.service,
            incident.port,
            &incident.severity,
            incident.payload.as_deref(),
        );

        // Attribute: ip-src
        attributes.push(serde_json::json!({
            "uuid": generate_uuid_v4(),
            "type": "ip-src",
            "category": "Network activity",
            "to_ids": true,
            "value": incident.ip,
            "comment": format!("Attacker IP on node {} (service: {})", incident.node_id, incident.service)
        }));

        // Attribute: port
        attributes.push(serde_json::json!({
            "uuid": generate_uuid_v4(),
            "type": "port",
            "category": "Network activity",
            "to_ids": false,
            "value": incident.port.to_string(),
            "comment": format!("Target port {} ({})", incident.port, incident.service)
        }));

        // Attribute: comment
        let comment_detail = format!(
            "Node: {}, Service: {}, Severity: {}, Score: {}, MITRE: {} ({}), Hits: {}, Payload: {}",
            incident.node_id,
            incident.service,
            incident.severity,
            incident.threat_score,
            tech_id,
            tech_name,
            incident.hit_count,
            incident.payload.as_deref().unwrap_or("None")
        );

        attributes.push(serde_json::json!({
            "uuid": generate_uuid_v4(),
            "type": "comment",
            "category": "Internal reference",
            "to_ids": false,
            "value": comment_detail,
            "comment": format!("Sentinela Hub incident forensic details for {}", incident.ip)
        }));
    }

    let misp_obj = serde_json::json!({
        "Event": {
            "uuid": event_uuid,
            "info": "Sentinela Hub Cyber Threat Intelligence Export",
            "date": date_str,
            "threat_level_id": "2",
            "analysis": "2",
            "distribution": "0",
            "published": false,
            "Attribute": attributes
        }
    });

    serde_json::to_string_pretty(&misp_obj).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::HubIncident;

    fn sample_ssh_incident() -> HubIncident {
        HubIncident {
            id: Some(101),
            node_id: "edge-gateway-01".to_string(),
            timestamp: "2026-11-13 10:15:30".to_string(),
            ip: "198.51.100.42".to_string(),
            port: 2222,
            service: "SSH".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "Germany".to_string(),
            city: "Frankfurt".to_string(),
            isp: "Host Europe GmbH".to_string(),
            rdns: Some("scanner.example.com".to_string()),
            payload: Some("SSH-2.0-libssh".to_string()),
            threat_score: 95,
            hit_count: 7,
        }
    }

    fn sample_dns_incident() -> HubIncident {
        HubIncident {
            id: Some(102),
            node_id: "dns-auth-02".to_string(),
            timestamp: "2026-11-13 10:16:00".to_string(),
            ip: "203.0.113.88".to_string(),
            port: 53,
            service: "DNS".to_string(),
            severity: "MÉDIO".to_string(),
            country: "United States".to_string(),
            city: "Dallas".to_string(),
            isp: "Cloudflare Inc".to_string(),
            rdns: None,
            payload: Some("ANY example.com".to_string()),
            threat_score: 60,
            hit_count: 2,
        }
    }

    #[test]
    fn test_stix_bundle_valid_json() {
        let incidents = vec![sample_ssh_incident(), sample_dns_incident()];
        let bundle = incidents_to_stix_bundle(&incidents);

        assert_eq!(bundle.spec_version, "2.1");
        assert!(bundle.id.starts_with("bundle--"));
        assert!(!bundle.objects.is_empty());

        let json_str = serde_json::to_string(&bundle).expect("Serialization to JSON failed");
        let val: serde_json::Value =
            serde_json::from_str(&json_str).expect("Parsing serialized JSON failed");

        // Verify top-level STIX 2.1 Bundle fields
        assert_eq!(val["type"], "bundle");
        assert_eq!(val["spec_version"], "2.1");
        assert!(val["id"].as_str().unwrap().starts_with("bundle--"));
        assert!(val["objects"].is_array());

        // Verify deserialization back to StixBundle struct
        let deserialized: StixBundle =
            serde_json::from_str(&json_str).expect("Deserialization back to StixBundle failed");
        assert_eq!(deserialized.spec_version, "2.1");
        assert_eq!(deserialized.id, bundle.id);
        assert_eq!(deserialized.objects.len(), bundle.objects.len());
    }

    #[test]
    fn test_stix_indicator_pattern_syntax() {
        let incident = sample_ssh_incident();
        let bundle = incidents_to_stix_bundle(&[incident]);

        let indicator = bundle
            .objects
            .iter()
            .find(|obj| obj["type"] == "indicator")
            .expect("Expected at least one indicator in STIX bundle");

        assert_eq!(indicator["type"], "indicator");
        assert_eq!(indicator["spec_version"], "2.1");
        assert_eq!(indicator["pattern_type"], "stix");
        assert_eq!(indicator["pattern_version"], "2.1");

        let pattern = indicator["pattern"].as_str().expect("Pattern must be a string");
        assert_eq!(pattern, "[ipv4-addr:value = '198.51.100.42']");
        assert!(pattern.starts_with('[') && pattern.ends_with(']'));
        assert!(pattern.contains("ipv4-addr:value = '198.51.100.42'"));
    }

    #[test]
    fn test_misp_export_structure() {
        let incidents = vec![sample_ssh_incident()];
        let misp_json = export_misp_json(&incidents);

        let parsed: serde_json::Value =
            serde_json::from_str(&misp_json).expect("MISP export must be valid JSON");

        // Root must contain standard MISP 'Event' container
        let event = parsed.get("Event").expect("MISP JSON must contain top-level 'Event'");
        assert!(event.get("uuid").is_some());
        assert!(event.get("info").is_some());
        assert!(event.get("date").is_some());

        // Attributes array
        let attributes = event
            .get("Attribute")
            .and_then(|a| a.as_array())
            .expect("Event must contain 'Attribute' array");

        // Verify ip-src attribute
        let ip_attr = attributes
            .iter()
            .find(|a| a["type"] == "ip-src")
            .expect("Must have an attribute of type 'ip-src'");
        assert_eq!(ip_attr["value"], "198.51.100.42");
        assert_eq!(ip_attr["to_ids"], true);
        assert!(!ip_attr["comment"].as_str().unwrap().is_empty());

        // Verify port attribute
        let port_attr = attributes
            .iter()
            .find(|a| a["type"] == "port")
            .expect("Must have an attribute of type 'port'");
        assert_eq!(port_attr["value"], "2222");
        assert_eq!(port_attr["to_ids"], false);
        assert!(!port_attr["comment"].as_str().unwrap().is_empty());

        // Verify comment attribute
        let comment_attr = attributes
            .iter()
            .find(|a| a["type"] == "comment")
            .expect("Must have an attribute of type 'comment'");
        assert!(!comment_attr["value"].as_str().unwrap().is_empty());
        assert!(!comment_attr["comment"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_stix_relationships_and_attack_patterns() {
        let incidents = vec![sample_ssh_incident()];
        let bundle = incidents_to_stix_bundle(&incidents);

        let indicator = bundle.objects.iter().find(|o| o["type"] == "indicator").unwrap();
        let attack_pattern = bundle.objects.iter().find(|o| o["type"] == "attack-pattern").unwrap();

        let indicator_id = indicator["id"].as_str().unwrap();
        let ap_id = attack_pattern["id"].as_str().unwrap();

        let rels: Vec<_> = bundle
            .objects
            .iter()
            .filter(|o| o["type"] == "relationship")
            .collect();
        assert_eq!(rels.len(), 2);

        let indicates = rels
            .iter()
            .find(|r| r["relationship_type"] == "indicates")
            .expect("indicates rel");
        assert_eq!(indicates["source_ref"], indicator_id);
        assert_eq!(indicates["target_ref"], ap_id);

        let uses = rels
            .iter()
            .find(|r| r["relationship_type"] == "uses")
            .expect("uses rel");
        assert_eq!(uses["source_ref"], indicator_id);
        assert_eq!(uses["target_ref"], ap_id);
    }

    #[test]
    fn test_empty_incidents() {
        let bundle = incidents_to_stix_bundle(&[]);
        assert_eq!(bundle.spec_version, "2.1");
        assert!(bundle.objects.is_empty());

        let misp_json = export_misp_json(&[]);
        let parsed: serde_json::Value = serde_json::from_str(&misp_json).unwrap();
        let attrs = parsed["Event"]["Attribute"].as_array().unwrap();
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_uuid_rfc4122_compliance() {
        let u = generate_uuid_v4();
        assert_eq!(u.len(), 36);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0].len(), 8);
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
        assert_eq!(parts[3].len(), 4);
        assert_eq!(parts[4].len(), 12);
        // Version 4 check
        assert!(parts[2].starts_with('4'));
        // Variant check (8, 9, a, or b)
        let variant_char = parts[3].chars().next().unwrap();
        assert!(matches!(variant_char, '8' | '9' | 'a' | 'b'));
    }
}
