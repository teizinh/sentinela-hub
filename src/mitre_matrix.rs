use crate::models::HubIncident;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Summary of hits and attacker footprint for a single ATT&CK technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TechniqueSummary {
    pub id: String,
    pub name: String,
    pub count: usize,
    pub distinct_attackers: usize,
}

/// A tactic column in the ATT&CK Enterprise Matrix containing its techniques.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TacticColumn {
    pub tactic: String,
    pub techniques: Vec<TechniqueSummary>,
}

/// MITRE ATT&CK Enterprise Matrix compiler and heatmap intensity calculator for the SOC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitreEnterpriseMatrix {
    pub columns: Vec<TacticColumn>,
}

const TACTIC_DEFINITIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "Reconnaissance",
        &[
            ("T1595", "Active Scanning"),
            ("T1046", "Network Service Discovery"),
        ],
    ),
    (
        "InitialAccess",
        &[
            ("T1190", "Exploit Public-Facing App"),
            ("T1078", "Valid Accounts"),
        ],
    ),
    (
        "Execution",
        &[("T1059", "Command & Scripting Interpreter")],
    ),
    (
        "CredentialAccess",
        &[
            ("T1110", "Brute Force"),
            ("T1552", "Unsecured Credentials"),
        ],
    ),
    (
        "CommandAndControl",
        &[
            ("T1071", "App Layer Protocol"),
            ("T1095", "Non-Application Standard Protocol"),
        ],
    ),
    (
        "Exfiltration",
        &[("T1048", "Exfiltration Over Alternative Protocol")],
    ),
];

impl MitreEnterpriseMatrix {
    /// Compiles an ATT&CK Enterprise Matrix from a collection of SOC incidents.
    pub fn build_from_incidents(incidents: &[HubIncident]) -> Self {
        let mut tech_counts: HashMap<&'static str, usize> = HashMap::new();
        let mut tech_attackers: HashMap<&'static str, HashSet<String>> = HashMap::new();

        for inc in incidents {
            let tech_id = classify_incident(inc);
            let hits = inc.hit_count.max(1);

            *tech_counts.entry(tech_id).or_insert(0) += hits;
            tech_attackers
                .entry(tech_id)
                .or_default()
                .insert(inc.ip.clone());
        }

        let mut columns = Vec::with_capacity(TACTIC_DEFINITIONS.len());
        for (tactic, techniques) in TACTIC_DEFINITIONS {
            let mut summary_list = Vec::with_capacity(techniques.len());
            for (id, name) in *techniques {
                let count = tech_counts.get(id).copied().unwrap_or(0);
                let distinct_attackers = tech_attackers
                    .get(id)
                    .map(|set| set.len())
                    .unwrap_or(0);

                summary_list.push(TechniqueSummary {
                    id: (*id).to_string(),
                    name: (*name).to_string(),
                    count,
                    distinct_attackers,
                });
            }

            columns.push(TacticColumn {
                tactic: (*tactic).to_string(),
                techniques: summary_list,
            });
        }

        Self { columns }
    }

    /// Accessor for the tactic columns.
    pub fn columns(&self) -> &[TacticColumn] {
        &self.columns
    }

    /// Accessor alias for tactic columns.
    pub fn tactic_columns(&self) -> &[TacticColumn] {
        &self.columns
    }

    /// Finds a tactic column by name (case-insensitive).
    pub fn get_column(&self, tactic: &str) -> Option<&TacticColumn> {
        self.columns
            .iter()
            .find(|c| c.tactic.eq_ignore_ascii_case(tactic))
    }

    /// Finds a technique summary by its ATT&CK ID (case-insensitive).
    pub fn get_technique(&self, id: &str) -> Option<&TechniqueSummary> {
        self.columns
            .iter()
            .flat_map(|col| &col.techniques)
            .find(|t| t.id.eq_ignore_ascii_case(id))
    }

    /// Returns the sum of all technique hits in the matrix.
    pub fn total_technique_hits(&self) -> usize {
        self.columns
            .iter()
            .flat_map(|col| &col.techniques)
            .map(|t| t.count)
            .sum()
    }

    /// Returns the maximum hit count across all techniques in the matrix.
    pub fn max_technique_count(&self) -> usize {
        self.columns
            .iter()
            .flat_map(|col| &col.techniques)
            .map(|t| t.count)
            .max()
            .unwrap_or(0)
    }

    /// Returns the top observed techniques ordered by count descending.
    /// Only techniques with count > 0 are considered.
    pub fn top_techniques(&self, limit: usize) -> Vec<TechniqueSummary> {
        let mut all: Vec<TechniqueSummary> = self
            .columns
            .iter()
            .flat_map(|col| col.techniques.clone())
            .filter(|t| t.count > 0)
            .collect();

        all.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| b.distinct_attackers.cmp(&a.distinct_attackers))
                .then_with(|| a.id.cmp(&b.id))
        });

        all.truncate(limit);
        all
    }

    /// Calculates a normalized warmth intensity between 0.0 and 1.0 for UI heatmap visualization.
    pub fn calculate_cell_intensity(&self, count: usize) -> f32 {
        let max = self.max_technique_count();
        if max == 0 {
            0.0
        } else {
            (count as f32 / max as f32).clamp(0.0, 1.0)
        }
    }
}

/// Classifies an incident into one of the 10 ATT&CK Enterprise Matrix techniques.
fn classify_incident(inc: &HubIncident) -> &'static str {
    let s_upper = inc.service.to_uppercase();
    let sev_upper = inc.severity.to_uppercase();
    let pay = inc.payload.as_deref().unwrap_or("");
    let pay_upper = pay.to_uppercase();

    // 1. Direct ATT&CK ID or name matching in service / severity / payload
    if s_upper.contains("T1595") || sev_upper.contains("T1595") || pay_upper.contains("T1595")
        || s_upper.contains("ACTIVE SCANNING")
        || sev_upper.contains("ACTIVE SCANNING")
    {
        return "T1595";
    }

    if s_upper.contains("T1046") || sev_upper.contains("T1046") || pay_upper.contains("T1046")
        || s_upper.contains("NETWORK SERVICE DISCOVERY")
        || sev_upper.contains("NETWORK SERVICE DISCOVERY")
    {
        return "T1046";
    }

    if s_upper.contains("T1190") || sev_upper.contains("T1190") || pay_upper.contains("T1190")
        || s_upper.contains("EXPLOIT PUBLIC-FACING")
        || sev_upper.contains("EXPLOIT PUBLIC-FACING")
    {
        return "T1190";
    }

    if s_upper.contains("T1078") || sev_upper.contains("T1078") || pay_upper.contains("T1078")
        || s_upper.contains("VALID ACCOUNTS")
        || sev_upper.contains("VALID ACCOUNTS")
    {
        return "T1078";
    }

    if s_upper.contains("T1059") || sev_upper.contains("T1059") || pay_upper.contains("T1059")
        || s_upper.contains("COMMAND & SCRIPTING")
        || s_upper.contains("COMMAND AND SCRIPTING")
        || sev_upper.contains("COMMAND & SCRIPTING")
        || sev_upper.contains("COMMAND AND SCRIPTING")
    {
        return "T1059";
    }

    if s_upper.contains("T1110") || sev_upper.contains("T1110") || pay_upper.contains("T1110")
        || s_upper.contains("BRUTE FORCE")
        || sev_upper.contains("BRUTE FORCE")
    {
        return "T1110";
    }

    if s_upper.contains("T1552") || sev_upper.contains("T1552") || pay_upper.contains("T1552")
        || s_upper.contains("UNSECURED CREDENTIALS")
        || sev_upper.contains("UNSECURED CREDENTIALS")
    {
        return "T1552";
    }

    if s_upper.contains("T1071") || sev_upper.contains("T1071") || pay_upper.contains("T1071")
        || s_upper.contains("APP LAYER PROTOCOL")
        || s_upper.contains("APPLICATION LAYER PROTOCOL")
        || sev_upper.contains("APP LAYER PROTOCOL")
        || sev_upper.contains("APPLICATION LAYER PROTOCOL")
    {
        return "T1071";
    }

    if s_upper.contains("T1095") || sev_upper.contains("T1095") || pay_upper.contains("T1095")
        || s_upper.contains("NON-APPLICATION STANDARD")
        || sev_upper.contains("NON-APPLICATION STANDARD")
    {
        return "T1095";
    }

    if s_upper.contains("T1048") || sev_upper.contains("T1048") || pay_upper.contains("T1048")
        || s_upper.contains("EXFILTRATION OVER ALTERNATIVE")
        || sev_upper.contains("EXFILTRATION OVER ALTERNATIVE")
    {
        return "T1048";
    }

    // 2. Sweeps / Scans / Reconnaissance Specific Indicators
    if s_upper.contains("SWEEP")
        || sev_upper.contains("SWEEP")
        || s_upper.contains("PROBE")
        || sev_upper.contains("PROBE")
        || s_upper.contains("VULN")
        || inc.port == 25
    {
        return "T1595";
    }

    if s_upper.contains("PORT_SCAN")
        || s_upper.contains("DISCOVERY")
        || sev_upper.contains("DISCOVERY")
        || (s_upper.contains("SCAN") && !s_upper.contains("ACTIVE"))
        || (sev_upper.contains("SCAN") && !sev_upper.contains("ACTIVE"))
    {
        return "T1046";
    }

    // 3. Payload Inspection
    if !pay.is_empty() {
        let p_lower = pay.to_lowercase();
        // Execution
        if p_lower.contains("/bin/sh")
            || p_lower.contains("/bin/bash")
            || p_lower.contains("bash -c")
            || p_lower.contains("sh -c")
            || p_lower.contains("cmd.exe")
            || p_lower.contains("powershell")
            || p_lower.contains("eval(")
            || p_lower.contains("exec(")
            || p_lower.contains("whoami")
        {
            return "T1059";
        }

        // Credential Access: Unsecured Credentials
        if p_lower.contains("id_rsa")
            || p_lower.contains("shadow")
            || p_lower.contains("begin rsa private key")
            || p_lower.contains("begin private key")
            || p_lower.contains(".env")
            || p_lower.contains("wp-config")
            || p_lower.contains("password=")
            || p_lower.contains("/etc/passwd")
        {
            return "T1552";
        }

        // Exfiltration
        if p_lower.contains("exfil")
            || p_lower.contains("data_dump")
            || p_lower.contains("upload_archive")
        {
            return "T1048";
        }

        // Exploitation of Web Services
        if p_lower.contains("cve-")
            || p_lower.contains("union select")
            || p_lower.contains("<?php")
            || p_lower.contains("<script>")
            || p_lower.contains("../")
        {
            return "T1190";
        }
    }

    // 4. Service, Port, and Protocol Specific Heuristics
    // Credential Access: Brute Force (SSH)
    if s_upper.contains("SSH") || inc.port == 22 || inc.port == 2222 {
        return "T1110";
    }

    // Exfiltration (FTP / Exfiltration services)
    if s_upper.contains("FTP") || inc.port == 21 || inc.port == 20 || s_upper.contains("EXFIL") {
        return "T1048";
    }

    // Command & Control: App Layer Protocol (DNS)
    if s_upper.contains("DNS") || inc.port == 53 || s_upper.contains("C2-APP") {
        return "T1071";
    }

    // Initial Access: Valid Accounts (Default / DB Accounts)
    if inc.port == 3306
        || inc.port == 5432
        || inc.port == 1433
        || inc.port == 27017
        || s_upper.contains("MYSQL")
        || s_upper.contains("POSTGRES")
        || s_upper.contains("MONGO")
        || s_upper.contains("DATABASE")
        || s_upper.contains("AUTH")
    {
        return "T1078";
    }

    // Command & Control: Non-Application Standard Protocol (ICMP / Raw sockets / Tunnels)
    if s_upper.contains("ICMP")
        || inc.port == 4444
        || s_upper.contains("RAW")
        || s_upper.contains("TUNNEL")
        || s_upper.contains("NON-APP")
        || inc.port == 0
    {
        return "T1095";
    }

    // Initial Access: Exploit Public-Facing App (HTTP / Web / Critical Web alerts)
    if s_upper.contains("HTTP")
        || s_upper.contains("WEB")
        || s_upper.contains("NGINX")
        || s_upper.contains("APACHE")
        || inc.port == 80
        || inc.port == 443
        || inc.port == 8080
        || inc.port == 8443
        || sev_upper.contains("CRIT")
    {
        return "T1190";
    }

    // Reconnaissance: Network Service Discovery (Default fallback)
    "T1046"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_incident(
        ip: &str,
        service: &str,
        port: u16,
        severity: &str,
        payload: Option<&str>,
        hit_count: usize,
    ) -> HubIncident {
        HubIncident {
            id: None,
            node_id: "node-soc-01".to_string(),
            timestamp: "2026-11-13 10:00:00".to_string(),
            ip: ip.to_string(),
            port,
            service: service.to_string(),
            severity: severity.to_string(),
            country: "Portugal".to_string(),
            city: "Lisbon".to_string(),
            isp: "Enterprise ISP".to_string(),
            rdns: None,
            payload: payload.map(|p| p.to_string()),
            threat_score: 80,
            hit_count,
        }
    }

    #[test]
    fn test_matrix_empty_incidents() {
        let matrix = MitreEnterpriseMatrix::build_from_incidents(&[]);

        // 6 Enterprise columns must be present
        assert_eq!(matrix.columns.len(), 6);
        assert_eq!(matrix.total_technique_hits(), 0);
        assert_eq!(matrix.max_technique_count(), 0);
        assert!(matrix.top_techniques(5).is_empty());
        assert_eq!(matrix.calculate_cell_intensity(0), 0.0);

        let tactics: Vec<&str> = matrix.columns.iter().map(|c| c.tactic.as_str()).collect();
        assert_eq!(
            tactics,
            vec![
                "Reconnaissance",
                "InitialAccess",
                "Execution",
                "CredentialAccess",
                "CommandAndControl",
                "Exfiltration",
            ]
        );

        // All techniques must have 0 counts and 0 distinct attackers
        for col in &matrix.columns {
            for tech in &col.techniques {
                assert_eq!(tech.count, 0);
                assert_eq!(tech.distinct_attackers, 0);
            }
        }
    }

    #[test]
    fn test_matrix_technique_categorization() {
        let incidents = vec![
            // Reconnaissance: T1595 Active Scanning
            create_incident("10.0.0.1", "SWEEP", 0, "SWEEP", None, 5),
            // Reconnaissance: T1046 Network Service Discovery
            create_incident("10.0.0.2", "SCAN", 8888, "SCAN", None, 3),
            // InitialAccess: T1190 Exploit Public-Facing App
            create_incident("10.0.0.3", "HTTP", 80, "CRÍTICO", Some("GET /admin.php"), 4),
            // InitialAccess: T1078 Valid Accounts
            create_incident("10.0.0.4", "MYSQL", 3306, "ALTO", None, 2),
            // Execution: T1059 Command & Scripting Interpreter
            create_incident("10.0.0.5", "HTTP", 8080, "ALTO", Some("/bin/bash -c id"), 6),
            // CredentialAccess: T1110 Brute Force
            create_incident("10.0.0.6", "SSH", 22, "ALTO", None, 8),
            // CredentialAccess: T1552 Unsecured Credentials
            create_incident("10.0.0.7", "WEB", 443, "ALTO", Some("cat /etc/shadow"), 1),
            // CommandAndControl: T1071 App Layer Protocol
            create_incident("10.0.0.8", "DNS", 53, "MÉDIO", None, 7),
            // CommandAndControl: T1095 Non-Application Standard Protocol
            create_incident("10.0.0.9", "ICMP", 0, "ALERTA", None, 2),
            // Exfiltration: T1048 Exfiltration Over Alternative Protocol
            create_incident("10.0.0.10", "FTP", 21, "ALTO", None, 9),
        ];

        let matrix = MitreEnterpriseMatrix::build_from_incidents(&incidents);

        assert_eq!(matrix.get_technique("T1595").unwrap().count, 5);
        assert_eq!(matrix.get_technique("T1595").unwrap().name, "Active Scanning");

        assert_eq!(matrix.get_technique("T1046").unwrap().count, 3);
        assert_eq!(matrix.get_technique("T1046").unwrap().name, "Network Service Discovery");

        assert_eq!(matrix.get_technique("T1190").unwrap().count, 4);
        assert_eq!(matrix.get_technique("T1190").unwrap().name, "Exploit Public-Facing App");

        assert_eq!(matrix.get_technique("T1078").unwrap().count, 2);
        assert_eq!(matrix.get_technique("T1078").unwrap().name, "Valid Accounts");

        assert_eq!(matrix.get_technique("T1059").unwrap().count, 6);
        assert_eq!(matrix.get_technique("T1059").unwrap().name, "Command & Scripting Interpreter");

        assert_eq!(matrix.get_technique("T1110").unwrap().count, 8);
        assert_eq!(matrix.get_technique("T1110").unwrap().name, "Brute Force");

        assert_eq!(matrix.get_technique("T1552").unwrap().count, 1);
        assert_eq!(matrix.get_technique("T1552").unwrap().name, "Unsecured Credentials");

        assert_eq!(matrix.get_technique("T1071").unwrap().count, 7);
        assert_eq!(matrix.get_technique("T1071").unwrap().name, "App Layer Protocol");

        assert_eq!(matrix.get_technique("T1095").unwrap().count, 2);
        assert_eq!(matrix.get_technique("T1095").unwrap().name, "Non-Application Standard Protocol");

        assert_eq!(matrix.get_technique("T1048").unwrap().count, 9);
        assert_eq!(matrix.get_technique("T1048").unwrap().name, "Exfiltration Over Alternative Protocol");

        // Verify total hits
        assert_eq!(matrix.total_technique_hits(), 5 + 3 + 4 + 2 + 6 + 8 + 1 + 7 + 2 + 9);
    }

    #[test]
    fn test_top_techniques_ordering() {
        let incidents = vec![
            create_incident("192.168.1.10", "SSH", 22, "ALTO", None, 50),
            create_incident("192.168.1.11", "FTP", 21, "ALTO", None, 30),
            create_incident("192.168.1.12", "DNS", 53, "MÉDIO", None, 20),
            create_incident("192.168.1.13", "SWEEP", 0, "SWEEP", None, 10),
            create_incident("192.168.1.14", "SCAN", 80, "SCAN", None, 5),
        ];

        let matrix = MitreEnterpriseMatrix::build_from_incidents(&incidents);
        let top3 = matrix.top_techniques(3);

        assert_eq!(top3.len(), 3);
        assert_eq!(top3[0].id, "T1110");
        assert_eq!(top3[0].count, 50);

        assert_eq!(top3[1].id, "T1048");
        assert_eq!(top3[1].count, 30);

        assert_eq!(top3[2].id, "T1071");
        assert_eq!(top3[2].count, 20);

        // Asking for top 10 when 5 techniques have hits returns 5
        let top10 = matrix.top_techniques(10);
        assert_eq!(top10.len(), 5);
        assert_eq!(top10[3].id, "T1595");
        assert_eq!(top10[3].count, 10);
        assert_eq!(top10[4].id, "T1046");
        assert_eq!(top10[4].count, 5);
    }

    #[test]
    fn test_heat_intensity_normalization() {
        let incidents = vec![
            create_incident("10.0.0.1", "SSH", 22, "ALTO", None, 100),
            create_incident("10.0.0.2", "FTP", 21, "ALTO", None, 50),
            create_incident("10.0.0.3", "DNS", 53, "MÉDIO", None, 25),
        ];

        let matrix = MitreEnterpriseMatrix::build_from_incidents(&incidents);
        assert_eq!(matrix.max_technique_count(), 100);

        // Maximum heat cell
        assert_eq!(matrix.calculate_cell_intensity(100), 1.0);
        // Half heat cell
        assert_eq!(matrix.calculate_cell_intensity(50), 0.5);
        // Quarter heat cell
        assert_eq!(matrix.calculate_cell_intensity(25), 0.25);
        // Cold / no-hit cell
        assert_eq!(matrix.calculate_cell_intensity(0), 0.0);
        // Value exceeding max is clamped to 1.0
        assert_eq!(matrix.calculate_cell_intensity(150), 1.0);
    }

    #[test]
    fn test_distinct_attackers_tracking() {
        let incidents = vec![
            create_incident("10.0.0.1", "SSH", 22, "ALTO", None, 5),
            create_incident("10.0.0.1", "SSH", 22, "ALTO", None, 3),
            create_incident("10.0.0.2", "SSH", 22, "ALTO", None, 2),
            create_incident("10.0.0.3", "SSH", 22, "ALTO", None, 10),
        ];

        let matrix = MitreEnterpriseMatrix::build_from_incidents(&incidents);
        let ssh_tech = matrix.get_technique("T1110").expect("T1110 technique exists");

        // 5 + 3 + 2 + 10 = 20 hits
        assert_eq!(ssh_tech.count, 20);
        // 3 unique IPs: 10.0.0.1, 10.0.0.2, 10.0.0.3
        assert_eq!(ssh_tech.distinct_attackers, 3);
    }

    #[test]
    fn test_direct_technique_id_and_subtechnique_matching() {
        let incidents = vec![
            create_incident("192.168.1.1", "T1595.002", 80, "ALTO", None, 4),
            create_incident("192.168.1.2", "CustomService", 9999, "ALTO", Some("T1059.001 script"), 2),
            create_incident("192.168.1.3", "T1078.001", 3306, "MÉDIO", None, 3),
        ];

        let matrix = MitreEnterpriseMatrix::build_from_incidents(&incidents);
        assert_eq!(matrix.get_technique("T1595").unwrap().count, 4);
        assert_eq!(matrix.get_technique("T1059").unwrap().count, 2);
        assert_eq!(matrix.get_technique("T1078").unwrap().count, 3);
    }
}
