use crate::models::{CorrelationAlert, HubIncident};
use crate::ui::modal::map_to_mitre;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

/// Generates a formatted executive Markdown threat intelligence report.
pub fn export_executive_report(
    incidents: &[HubIncident],
    correlations: &[CorrelationAlert],
) -> String {
    let now_str = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    let mut report = String::new();

    // 1. Header & Summary
    report.push_str("# Relatório Executivo de Inteligência de Ameaças - Sentinela SOC\n\n");
    report.push_str(&format!("**Data de Emissão:** {}\n", now_str));
    report.push_str(&format!("**Total de Incidentes:** {}\n", incidents.len()));
    report.push_str(&format!(
        "**Ataques Distribuídos (Correlacionados):** {}\n",
        correlations.len()
    ));

    let distinct_nodes: HashSet<_> = incidents.iter().map(|i| &i.node_id).collect();
    let critical_count = incidents
        .iter()
        .filter(|i| {
            let s = i.severity.to_uppercase();
            s == "CRÍTICO" || s == "CRITICO"
        })
        .count();
    report.push_str(&format!(
        "**Sensores/Nós Impactados:** {}\n",
        distinct_nodes.len()
    ));
    report.push_str(&format!(
        "**Incidentes Críticos:** {}\n\n",
        critical_count
    ));

    report.push_str("---\n\n");

    // 2. Section: Top Malicious IPs
    report.push_str("## Top Endereços IP Maliciosos (Top Malicious IPs)\n\n");
    if incidents.is_empty() {
        report.push_str("*Nenhum endereço IP malicioso registado no período de análise.*\n\n");
    } else {
        struct IpStats<'a> {
            ip: &'a str,
            total_hits: usize,
            max_threat_score: u8,
            services: HashSet<&'a str>,
            country: &'a str,
            city: &'a str,
            isp: &'a str,
            _rdns: Option<&'a str>,
        }

        let mut ip_map: HashMap<&str, IpStats> = HashMap::new();
        for inc in incidents {
            let entry = ip_map.entry(&inc.ip).or_insert_with(|| IpStats {
                ip: &inc.ip,
                total_hits: 0,
                max_threat_score: inc.threat_score,
                services: HashSet::new(),
                country: &inc.country,
                city: &inc.city,
                isp: &inc.isp,
                _rdns: inc.rdns.as_deref(),
            });
            entry.total_hits += inc.hit_count.max(1);
            entry.max_threat_score = entry.max_threat_score.max(inc.threat_score);
            entry.services.insert(&inc.service);
        }

        let mut ranked_ips: Vec<_> = ip_map.into_values().collect();
        ranked_ips.sort_by(|a, b| {
            b.total_hits
                .cmp(&a.total_hits)
                .then_with(|| b.max_threat_score.cmp(&a.max_threat_score))
        });

        report.push_str("| IP de Origem | Ocorrências (Hits) | Threat Score | Serviços Alvo | Localização (País/Cidade) | Operador / ISP |\n");
        report.push_str("|---|---|---|---|---|---|\n");
        for ip_stat in &ranked_ips {
            let mut services_vec: Vec<_> = ip_stat.services.iter().copied().collect();
            services_vec.sort();
            let services_str = if services_vec.is_empty() {
                "-".to_string()
            } else {
                services_vec.join(", ")
            };
            let loc_str = if ip_stat.city.is_empty() || ip_stat.city == "-" {
                ip_stat.country.to_string()
            } else {
                format!("{}, {}", ip_stat.country, ip_stat.city)
            };
            report.push_str(&format!(
                "| `{}` | {} | {}/100 | {} | {} | {} |\n",
                ip_stat.ip,
                ip_stat.total_hits,
                ip_stat.max_threat_score,
                services_str,
                loc_str,
                ip_stat.isp
            ));
        }
        report.push('\n');
    }

    // 3. Section: MITRE ATT&CK Techniques Observed
    report.push_str("## Técnicas MITRE ATT&CK® Observadas\n\n");
    let mut mitre_map: HashMap<(&'static str, &'static str), usize> = HashMap::new();
    for inc in incidents {
        let (tech_id, tech_name) = map_to_mitre(
            &inc.service,
            inc.port,
            &inc.severity,
            inc.payload.as_deref(),
        );
        let hits = inc.hit_count.max(1);
        *mitre_map.entry((tech_id, tech_name)).or_insert(0) += hits;
    }

    for corr in correlations {
        let hits = corr.total_hits.max(1);
        *mitre_map
            .entry(("T1046", "Network Service Scanning"))
            .or_insert(0) += hits;
    }

    if mitre_map.is_empty() {
        report.push_str("*Nenhuma técnica MITRE ATT&CK® identificada no período.*\n\n");
    } else {
        let mut mitre_list: Vec<_> = mitre_map.into_iter().collect();
        mitre_list.sort_by_key(|a| std::cmp::Reverse(a.1));

        report.push_str("| ID Técnica | Nome da Técnica MITRE | Tentativas Observadas | Nível de Risco SOC |\n");
        report.push_str("|---|---|---|---|\n");
        for ((tech_id, tech_name), count) in mitre_list {
            let risk_level = match tech_id {
                "T1059" | "T1486" | "T1190" => "Crítico",
                "T1110" | "T1110.001" | "T1021.001" | "T1021.002" => "Alto",
                _ => "Médio",
            };
            report.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                tech_id, tech_name, count, risk_level
            ));
        }
        report.push('\n');
    }

    // 4. Section: Targeted Services & Port Vulnerability Assessment
    report.push_str(
        "## Avaliação de Vulnerabilidade de Serviços e Portas Alvo (Targeted Services)\n\n",
    );
    if incidents.is_empty() {
        report.push_str("*Nenhum serviço ou porta alvo registado no período.*\n\n");
    } else {
        struct ServiceStats<'a> {
            service: &'a str,
            port: u16,
            total_hits: usize,
            max_threat_score: u8,
        }

        let mut svc_map: HashMap<(&str, u16), ServiceStats> = HashMap::new();
        for inc in incidents {
            let entry = svc_map
                .entry((&inc.service, inc.port))
                .or_insert_with(|| ServiceStats {
                    service: &inc.service,
                    port: inc.port,
                    total_hits: 0,
                    max_threat_score: inc.threat_score,
                });
            entry.total_hits += inc.hit_count.max(1);
            entry.max_threat_score = entry.max_threat_score.max(inc.threat_score);
        }

        let mut svc_list: Vec<_> = svc_map.into_values().collect();
        svc_list.sort_by(|a, b| {
            b.total_hits
                .cmp(&a.total_hits)
                .then_with(|| b.max_threat_score.cmp(&a.max_threat_score))
        });

        report.push_str("| Serviço Alvo | Porta | Ocorrências (Hits) | Threat Score | Avaliação de Risco & Vetor de Ataque |\n");
        report.push_str("|---|---|---|---|---|\n");
        for svc in svc_list {
            let s_up = svc.service.to_uppercase();
            let assessment = if s_up.contains("SSH") || svc.port == 22 || svc.port == 2222 {
                "Ataques de força bruta e tentativa de exaustão de credenciais de acesso shell administrativo."
            } else if s_up.contains("HTTP")
                || svc.port == 80
                || svc.port == 443
                || svc.port == 8080
            {
                "Sondagem e exploração de vulnerabilidades web (RCE, SQLi, web shells ou path traversal)."
            } else if s_up.contains("SMB") || svc.port == 445 || svc.port == 139 {
                "Mapeamento de partilhas de rede e exploração potencial de vulnerabilidades de execução remota (ex: EternalBlue)."
            } else if s_up.contains("RDP") || svc.port == 3389 {
                "Tentativa de login interativo forçado em desktop remoto e acesso gráfico ao host."
            } else if s_up.contains("TELNET") || svc.port == 23 {
                "Protocolo em texto claro; propício a botnets IoT e injeção de comandos legados."
            } else if s_up.contains("DNS") || svc.port == 53 {
                "Tentativa de tunelamento DNS, poisoning ou amplificação de tráfego de negação de serviço."
            } else if s_up.contains("FTP") || svc.port == 21 {
                "Tentativas de autenticação anónima ou exploração de credenciais para exfiltração de ficheiros."
            } else {
                "Sondagem ativa de porta para descoberta de serviços em execução e fingerprinting de SO."
            };

            report.push_str(&format!(
                "| `{}` | `{}` | {} | {}/100 | {} |\n",
                svc.service, svc.port, svc.total_hits, svc.max_threat_score, assessment
            ));
        }
        report.push('\n');
    }

    // 5. Section: Recommended Remediation Actions
    report.push_str("## Ações de Remediação Recomendadas (Remediation Actions)\n\n");

    // iptables rules
    report.push_str("### 1. Bloqueio Imediato via Firewall (iptables / UFW)\n\n");
    report.push_str("Comandos recomendados para aplicação imediata nos nós de perímetro e gateways:\n\n");
    report.push_str("```bash\n");
    report.push_str("# Bloqueio de pacotes de entrada dos Top IPs maliciosos identificados:\n");

    let mut seen_ips = HashSet::new();
    let mut ip_count = 0;
    for inc in incidents {
        if seen_ips.insert(&inc.ip) {
            report.push_str(&format!("iptables -A INPUT -s {} -j DROP\n", inc.ip));
            ip_count += 1;
            if ip_count >= 10 {
                break;
            }
        }
    }
    if ip_count == 0 {
        report.push_str("# Exemplo de regra preventiva:\n");
        report.push_str("iptables -A INPUT -s <IP_ATACANTE> -j DROP\n");
    }

    report.push_str("\n# Equivalente via UFW (Uncomplicated Firewall):\n");
    let mut seen_ufw = HashSet::new();
    let mut ufw_count = 0;
    for inc in incidents {
        if seen_ufw.insert(&inc.ip) {
            report.push_str(&format!("ufw insert 1 deny from {} to any\n", inc.ip));
            ufw_count += 1;
            if ufw_count >= 5 {
                break;
            }
        }
    }
    if ufw_count == 0 {
        report.push_str("ufw insert 1 deny from <IP_ATACANTE> to any\n");
    }
    report.push_str("```\n\n");

    // Hardening Recommendations
    report.push_str("### 2. Hardening de Infraestrutura e Mitigação Proativa\n\n");
    report.push_str("- **Hardening SSH:** Desativar login de `root` (`PermitRootLogin no`) e autenticação por senha (`PasswordAuthentication no`). Utilizar apenas chaves criptográficas (Ed25519) e mover serviços para portas não padronizadas.\n");
    report.push_str("- **Deteção Automática com Sentinela / Fail2ban:** Configurar jails dinâmicas com limites de 3 a 5 tentativas falhadas para bloqueio automático por IP na camada do kernel.\n");
    report.push_str("- **Isolamento de Redes e Zero Trust:** Isolar segmentos de rede expostos à internet em DMZs dedicadas, restringindo o tráfego este-oeste para evitar movimentação lateral.\n");
    report.push_str("- **Monitorização de Ataques Distribuídos:** Manter atenção redobrada aos alertas de correlação multi-nó gerados pelo Sentinela Hub, que indicam campanhas coordenadas de adversários.\n\n");

    report
}

#[derive(Serialize)]
pub struct ExecutiveReportJson<'a> {
    pub title: &'static str,
    pub generated_at: String,
    pub total_incidents: usize,
    pub total_correlations: usize,
    pub incidents: &'a [HubIncident],
    pub correlations: &'a [CorrelationAlert],
}

/// Generates a structured JSON threat intelligence report.
pub fn export_executive_report_json(
    incidents: &[HubIncident],
    correlations: &[CorrelationAlert],
) -> Result<String, serde_json::Error> {
    let report_data = ExecutiveReportJson {
        title: "Relatório Executivo de Inteligência de Ameaças - Sentinela SOC",
        generated_at: chrono::Utc::now().to_rfc3339(),
        total_incidents: incidents.len(),
        total_correlations: correlations.len(),
        incidents,
        correlations,
    };
    serde_json::to_string_pretty(&report_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_executive_report_structure() {
        let incidents = vec![
            HubIncident {
                id: Some(1),
                node_id: "edge-01".to_string(),
                timestamp: "2026-11-12 18:00:00".to_string(),
                ip: "192.0.2.10".to_string(),
                port: 22,
                service: "SSH".to_string(),
                severity: "CRÍTICO".to_string(),
                country: "US".to_string(),
                city: "Ashburn".to_string(),
                isp: "Hosting Provider".to_string(),
                rdns: Some("bad-scanner.net".to_string()),
                payload: Some("SSH-2.0-libssh".to_string()),
                threat_score: 95,
                hit_count: 50,
            },
            HubIncident {
                id: Some(2),
                node_id: "edge-02".to_string(),
                timestamp: "2026-11-12 18:05:00".to_string(),
                ip: "198.51.100.25".to_string(),
                port: 80,
                service: "HTTP".to_string(),
                severity: "MÉDIO".to_string(),
                country: "DE".to_string(),
                city: "Frankfurt".to_string(),
                isp: "Cloud Corp".to_string(),
                rdns: None,
                payload: Some("GET /shell.php".to_string()),
                threat_score: 60,
                hit_count: 10,
            },
        ];

        let correlations = vec![CorrelationAlert {
            id: Some(101),
            attacker_ip: "192.0.2.10".to_string(),
            nodes_targeted: vec!["edge-01".to_string(), "edge-02".to_string()],
            first_seen: "2026-11-12 18:00:00".to_string(),
            last_seen: "2026-11-12 18:05:00".to_string(),
            total_hits: 50,
            threat_score: 95,
            targeted_services: vec!["SSH".to_string()],
        }];

        let report = export_executive_report(&incidents, &correlations);

        // Header check
        assert!(report.contains("# Relatório Executivo de Inteligência de Ameaças - Sentinela SOC"));

        // Summary and Date
        assert!(report.contains("Total de Incidentes"));
        assert!(report.contains("Ataques Distribuídos"));

        // Sections
        assert!(report.contains("Top Endereços IP Maliciosos") || report.contains("Top Malicious IPs"));
        assert!(report.contains("MITRE ATT&CK"));
        assert!(report.contains("Serviços e Portas Alvo") || report.contains("Targeted Services"));
        assert!(report.contains("Ações de Remediação Recomendadas") || report.contains("Remediation"));
        assert!(report.contains("iptables"));

        // Content check: Top IPs
        assert!(report.contains("192.0.2.10"));
        assert!(report.contains("198.51.100.25"));
    }

    #[test]
    fn test_export_executive_report_empty() {
        let report = export_executive_report(&[], &[]);
        assert!(report.contains("# Relatório Executivo de Inteligência de Ameaças - Sentinela SOC"));
        assert!(report.contains("**Total de Incidentes:** 0"));
        assert!(report.contains("**Ataques Distribuídos (Correlacionados):** 0"));
        assert!(report.contains("iptables -A INPUT -s <IP_ATACANTE> -j DROP"));
    }

    #[test]
    fn test_export_executive_report_json() {
        let incidents = vec![HubIncident {
            id: Some(1),
            node_id: "node-1".to_string(),
            timestamp: "2026-11-12 12:00:00".to_string(),
            ip: "203.0.113.1".to_string(),
            port: 22,
            service: "SSH".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "PT".to_string(),
            city: "Lisboa".to_string(),
            isp: "Vodafone".to_string(),
            rdns: None,
            payload: None,
            threat_score: 90,
            hit_count: 5,
        }];
        let json_str = export_executive_report_json(&incidents, &[]).unwrap();
        assert!(json_str.contains("203.0.113.1"));
        assert!(json_str.contains("Relatório Executivo de Inteligência de Ameaças - Sentinela SOC"));
    }
}
