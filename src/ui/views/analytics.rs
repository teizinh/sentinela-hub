use crate::models::HubIncident;
use crate::ui::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_ACCENT_PURPLE,
    COLOR_ACCENT_RED, COLOR_BORDER, COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};
use egui_plot::{Line, Plot, PlotPoints};
use std::collections::HashMap;

/// Helper to parse hour (0..=23) from timestamps like "YYYY-MM-DD HH:MM:SS" or ISO-8601.
pub fn parse_timestamp_hour(ts: &str) -> Option<u32> {
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
        return Some(chrono::Timelike::hour(&dt));
    }
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return Some(chrono::Timelike::hour(&dt));
    }
    let parts: Vec<&str> = ts.split([' ', 'T']).collect();
    if parts.len() >= 2 {
        let time_parts: Vec<&str> = parts[1].split(':').collect();
        if let Some(h_str) = time_parts.first() {
            if let Ok(h) = h_str.parse::<u32>() {
                if h < 24 {
                    return Some(h);
                }
            }
        }
    }
    None
}

/// Parses timestamps ("YYYY-MM-DD HH:MM:SS") and buckets hits by hour (0..=23).
pub fn bucket_incidents_by_hour(incidents: &[HubIncident]) -> Vec<(u32, usize)> {
    let mut hourly = [0usize; 24];
    for inc in incidents {
        if let Some(hour) = parse_timestamp_hour(&inc.timestamp) {
            if (hour as usize) < 24 {
                hourly[hour as usize] += inc.hit_count.max(1);
            }
        }
    }
    (0..=23).map(|h| (h, hourly[h as usize])).collect()
}

/// Maps incident service/payloads to MITRE ATT&CK techniques using `crate::ui::modal::map_to_mitre`
/// and aggregates count, sorted descending.
pub fn aggregate_mitre_techniques(incidents: &[HubIncident]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for inc in incidents {
        let (tech_id, _) = crate::ui::modal::map_to_mitre(
            &inc.service,
            inc.port,
            &inc.severity,
            inc.payload.as_deref(),
        );
        *counts.entry(tech_id.to_string()).or_insert(0) += inc.hit_count.max(1);
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sorted
}

/// Returns friendly description for a given MITRE ATT&CK technique ID.
pub fn mitre_name_for_id(id: &str) -> &'static str {
    match id {
        "T1059" => "Command and Scripting Interpreter",
        "T1486" => "Data Encrypted for Impact",
        "T1018" => "Remote System Discovery",
        "T1046" => "Network Service Scanning",
        "T1110.001" => "Brute Force: Password Guessing",
        "T1071.004" => "Application Layer Protocol: DNS",
        "T1048" => "Exfiltration Over Alternative Protocol",
        "T1021.002" => "Remote Services: SMB/Windows Admin Shares",
        "T1021.001" => "Remote Services: Remote Desktop Protocol",
        "T1021.004" => "Remote Services: Telnet",
        "T1190" => "Exploit Public-Facing Application",
        _ => "Técnica Não Catalogada",
    }
}

pub fn render_analytics_view(
    ui: &mut Ui,
    incidents: &[HubIncident],
    top_attackers: &[(String, usize, u8, String)],
) {
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.vertical(|ui| {
            // Section: Top Attackers & Services summary
            ui.columns(2, |cols| {
                // Col 1: Top Attackers
                cols[0].vertical(|ui| {
                    egui::Frame::none()
                        .fill(COLOR_PANEL_BG)
                        .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("🎯 TOP ATACANTES GLOBAIS")
                                    .size(13.0)
                                    .strong()
                                    .color(COLOR_ACCENT_RED),
                            );
                            ui.add_space(6.0);

                            if top_attackers.is_empty() {
                                ui.label(
                                    RichText::new("Nenhum atacante registado.")
                                        .size(11.0)
                                        .italics()
                                        .color(COLOR_TEXT_MUTED),
                                );
                            } else {
                                for (i, (ip, hits, score, country)) in top_attackers.iter().take(6).enumerate() {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(format!("{}.", i + 1))
                                                .size(11.0)
                                                .color(COLOR_TEXT_MUTED),
                                        );
                                        ui.label(
                                            RichText::new(ip)
                                                .size(12.0)
                                                .monospace()
                                                .strong()
                                                .color(Color32::WHITE),
                                        );
                                        ui.label(
                                            RichText::new(format!("• {} hits", hits))
                                                .size(11.0)
                                                .color(COLOR_ACCENT_AMBER),
                                        );
                                        ui.label(
                                            RichText::new(format!("• Perigo {}", score))
                                                .size(11.0)
                                                .color(if *score >= 70 {
                                                    COLOR_ACCENT_RED
                                                } else {
                                                    COLOR_ACCENT_CYAN
                                                }),
                                        );
                                        ui.label(
                                            RichText::new(format!("({})", country))
                                                .size(10.0)
                                                .color(COLOR_TEXT_MUTED),
                                        );
                                    });
                                    ui.add_space(4.0);
                                }
                            }
                        });
                });

                // Col 2: Services Targeted Breakdown
                cols[1].vertical(|ui| {
                    egui::Frame::none()
                        .fill(COLOR_PANEL_BG)
                        .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new("📡 SERVIÇOS MAIS VISADOS")
                                    .size(13.0)
                                    .strong()
                                    .color(COLOR_ACCENT_CYAN),
                            );
                            ui.add_space(6.0);

                            let mut service_counts: HashMap<String, usize> = HashMap::new();
                            for inc in incidents {
                                *service_counts.entry(inc.service.clone()).or_insert(0) += inc.hit_count.max(1);
                            }

                            let mut sorted_services: Vec<(String, usize)> = service_counts.into_iter().collect();
                            sorted_services.sort_by_key(|a| std::cmp::Reverse(a.1));

                            if sorted_services.is_empty() {
                                ui.label(
                                    RichText::new("Nenhum tráfego registado.")
                                        .size(11.0)
                                        .italics()
                                        .color(COLOR_TEXT_MUTED),
                                );
                            } else {
                                let total_service_hits: usize = sorted_services.iter().map(|s| s.1).sum();
                                for (srv, hits) in sorted_services.iter().take(6) {
                                    let pct = if total_service_hits > 0 {
                                        (*hits as f32 / total_service_hits as f32) * 100.0
                                    } else {
                                        0.0
                                    };

                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(srv)
                                                .size(12.0)
                                                .strong()
                                                .monospace()
                                                .color(COLOR_ACCENT_CYAN),
                                        );
                                        ui.label(
                                            RichText::new(format!("{} hits ({:.1}%)", hits, pct))
                                                .size(11.0)
                                                .color(COLOR_TEXT_MUTED),
                                        );
                                    });

                                    // Mini progress bar
                                    let progress = (pct / 100.0).clamp(0.0, 1.0);
                                    ui.add(egui::ProgressBar::new(progress).fill(COLOR_ACCENT_CYAN).animate(false));
                                    ui.add_space(4.0);
                                }
                            }
                        });
                });
            });

            ui.add_space(10.0);

            // Section: Real-time Attack Timeline Plot (egui_plot)
            egui::Frame::none()
                .fill(COLOR_PANEL_BG)
                .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("📈 TIMELINE DE ATIVIDADE HORÁRIA (24H)")
                                .size(13.0)
                                .strong()
                                .color(COLOR_ACCENT_CYAN),
                        );
                        ui.label(
                            RichText::new("— Distribuição Temporal de Ataques")
                                .size(11.0)
                                .color(COLOR_TEXT_MUTED),
                        );
                    });
                    ui.label(
                        RichText::new("Volume de incidentes por hora do dia com zoom e pan interativos.")
                            .size(11.0)
                            .color(COLOR_TEXT_MUTED),
                    );
                    ui.add_space(8.0);

                    let hourly_data = bucket_incidents_by_hour(incidents);
                    let max_val = hourly_data.iter().map(|(_, c)| *c).max().unwrap_or(0);
                    let points: PlotPoints = hourly_data
                        .into_iter()
                        .map(|(hour, count)| [hour as f64, count as f64])
                        .collect();

                    let line = Line::new(points)
                        .color(COLOR_ACCENT_CYAN)
                        .fill(0.0f32)
                        .stroke(Stroke::new(2.0f32, COLOR_ACCENT_CYAN))
                        .name("Incidentes");

                    Plot::new("attack_timeline")
                        .height(180.0)
                        .show_axes([true, true])
                        .show_grid(true)
                        .allow_zoom(true)
                        .allow_drag(true)
                        .allow_scroll(true)
                        .include_x(0.0)
                        .include_x(23.0)
                        .include_y(0.0)
                        .include_y(if max_val < 5 { 5.0 } else { max_val as f64 * 1.15 })
                        .x_axis_formatter(|mark, _| {
                            let h = mark.value.round() as i64;
                            if (0..=23).contains(&h) {
                                format!("{:02}:00", h)
                            } else {
                                String::new()
                            }
                        })
                        .show(ui, |plot_ui| {
                            plot_ui.line(line);
                        });
                });

            ui.add_space(10.0);

            // Section: MITRE ATT&CK Matrix Card
            egui::Frame::none()
                .fill(COLOR_PANEL_BG)
                .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("🎯 MATRIZ MITRE ATT&CK® (TOP 5 TÉCNICAS)")
                                .size(13.0)
                                .strong()
                                .color(COLOR_ACCENT_PURPLE),
                        );
                        ui.label(
                            RichText::new("— Táticas e Vetores Adversários")
                                .size(11.0)
                                .color(COLOR_TEXT_MUTED),
                        );
                    });
                    ui.label(
                        RichText::new("Mapeamento automático de ameaças correlacionado com o framework MITRE ATT&CK.")
                            .size(11.0)
                            .color(COLOR_TEXT_MUTED),
                    );
                    ui.add_space(8.0);

                    let top_mitre = aggregate_mitre_techniques(incidents);
                    if top_mitre.is_empty() {
                        ui.label(
                            RichText::new("Nenhuma técnica registada.")
                                .size(11.0)
                                .italics()
                                .color(COLOR_TEXT_MUTED),
                        );
                    } else {
                        let total_hits: usize = top_mitre.iter().map(|(_, hits)| *hits).sum();
                        let colors = [
                            COLOR_ACCENT_PURPLE,
                            COLOR_ACCENT_RED,
                            COLOR_ACCENT_AMBER,
                            COLOR_ACCENT_CYAN,
                            COLOR_ACCENT_GREEN,
                        ];

                        for (idx, (tech_id, hits)) in top_mitre.iter().take(5).enumerate() {
                            let color = colors[idx % colors.len()];
                            let pct = if total_hits > 0 {
                                (*hits as f32 / total_hits as f32) * 100.0
                            } else {
                                0.0
                            };
                            let tech_name = mitre_name_for_id(tech_id);

                            ui.horizontal(|ui| {
                                egui::Frame::none()
                                    .fill(color.linear_multiply(0.2f32))
                                    .stroke(Stroke::new(1.0f32, color))
                                    .rounding(3.0f32)
                                    .inner_margin(egui::vec2(6.0f32, 2.0f32))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(tech_id)
                                                .monospace()
                                                .strong()
                                                .size(11.0f32)
                                                .color(Color32::WHITE),
                                        );
                                    });

                                ui.label(
                                    RichText::new(tech_name)
                                        .size(12.0)
                                        .strong()
                                        .color(Color32::from_rgb(220, 228, 238)),
                                );

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label(
                                        RichText::new(format!("{} hits ({:.1}%)", hits, pct))
                                            .size(11.0)
                                            .color(COLOR_TEXT_MUTED),
                                    );
                                });
                            });

                            let progress = (pct / 100.0).clamp(0.0, 1.0);
                            ui.add(egui::ProgressBar::new(progress).fill(color).animate(false));
                            ui.add_space(4.0);
                        }
                    }
                });
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_incident(service: &str, port: u16, timestamp: &str, hits: usize) -> HubIncident {
        HubIncident {
            id: None,
            node_id: "node-test".into(),
            timestamp: timestamp.into(),
            ip: "192.168.1.100".into(),
            port,
            service: service.into(),
            severity: "ALERTA".into(),
            country: "PT".into(),
            city: "Lisbon".into(),
            isp: "MEO".into(),
            rdns: None,
            payload: None,
            threat_score: 50,
            hit_count: hits,
        }
    }

    #[test]
    fn test_bucket_incidents_by_hour() {
        let i1 = dummy_incident("SSH", 22, "2026-11-12 14:15:30", 3);
        let i2 = dummy_incident("HTTP", 80, "2026-11-12 14:45:00", 2);
        let i3 = dummy_incident("DNS", 53, "2026-11-12 15:10:00", 4);
        let incidents = vec![i1, i2, i3];

        let buckets = bucket_incidents_by_hour(&incidents);
        assert_eq!(buckets.len(), 24);
        assert_eq!(buckets[14], (14, 5));
        assert_eq!(buckets[15], (15, 4));
        assert_eq!(buckets[0], (0, 0));
        assert_eq!(buckets[23], (23, 0));
    }

    #[test]
    fn test_aggregate_mitre_techniques() {
        let i1 = dummy_incident("SSH", 22, "2026-11-12 14:00:00", 5);
        let i2 = dummy_incident("SSH", 2222, "2026-11-12 15:00:00", 3);
        let i3 = dummy_incident("DNS", 53, "2026-11-12 16:00:00", 2);
        let incidents = vec![i1, i2, i3];

        let techniques = aggregate_mitre_techniques(&incidents);
        assert!(!techniques.is_empty());
        assert_eq!(techniques[0], ("T1110.001".to_string(), 8));
        assert_eq!(techniques[1], ("T1071.004".to_string(), 2));
    }
}
