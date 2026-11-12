use crate::models::HubIncident;
use crate::ui::{
    severity_color, COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_RED, COLOR_BORDER,
    COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

pub fn render_incidents_view(
    ui: &mut Ui,
    incidents: &[HubIncident],
    search_query: &mut String,
    selected_severity: &mut String,
    selected_node: &Option<String>,
    toast_msg: &mut Option<(String, std::time::Instant)>,
) {
    ui.vertical(|ui| {
        // Controls bar: Search + Severity filter
        egui::Frame::none()
            .fill(COLOR_PANEL_BG)
            .stroke(Stroke::new(1.0f32, COLOR_BORDER))
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🔍").size(14.0));
                    ui.add(
                        egui::TextEdit::singleline(search_query)
                            .hint_text("Pesquisar IP, porta, nó, serviço...")
                            .desired_width(260.0),
                    );

                    if !search_query.is_empty() && ui.button("✖").clicked() {
                        search_query.clear();
                    }

                    ui.separator();

                    ui.label(RichText::new("Severidade:").color(COLOR_TEXT_MUTED));
                    let severities = ["TODAS", "CRÍTICO", "SWEEP", "MÉDIO", "SCAN", "ALERTA"];
                    for sev in severities {
                        let is_active = selected_severity == sev;
                        let text = if is_active {
                            RichText::new(sev).strong().color(Color32::WHITE)
                        } else {
                            RichText::new(sev).color(COLOR_TEXT_MUTED)
                        };
                        let fill = if is_active {
                            severity_color(sev)
                        } else {
                            Color32::from_rgb(33, 38, 45)
                        };

                        if ui.add(egui::Button::new(text).fill(fill)).clicked() {
                            *selected_severity = sev.to_string();
                        }
                    }

                    if let Some(node_id) = selected_node {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("Filtrado por Nó: {}", node_id))
                                .strong()
                                .color(COLOR_ACCENT_CYAN),
                        );
                    }
                });
            });

        ui.add_space(8.0);

        // Filter incidents
        let filtered: Vec<&HubIncident> = incidents
            .iter()
            .filter(|inc| {
                // Node filter
                if let Some(ref nid) = selected_node {
                    if &inc.node_id != nid {
                        return false;
                    }
                }

                // Severity filter
                if selected_severity != "TODAS"
                    && !inc.severity.eq_ignore_ascii_case(selected_severity)
                {
                    return false;
                }

                // Search query
                if !search_query.is_empty() {
                    let q = search_query.to_lowercase();
                    let matches = inc.ip.to_lowercase().contains(&q)
                        || inc.service.to_lowercase().contains(&q)
                        || inc.port.to_string().contains(&q)
                        || inc.node_id.to_lowercase().contains(&q)
                        || inc.country.to_lowercase().contains(&q)
                        || inc
                            .payload
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&q);
                    if !matches {
                        return false;
                    }
                }

                true
            })
            .collect();

        // Header info
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("A exibir {} incidentes", filtered.len()))
                    .size(11.0)
                    .color(COLOR_TEXT_MUTED),
            );
        });

        ui.add_space(4.0);

        // Table
        egui::ScrollArea::both()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("incidents_table")
                    .striped(true)
                    .spacing([12.0, 8.0])
                    .min_col_width(60.0)
                    .show(ui, |ui| {
                        // Header row
                        ui.label(RichText::new("NÓ").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("TIMESTAMP").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("ATACANTE (IP)").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("PORTA/SERV").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("SEVERIDADE").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("THREAT").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("ORIGEM / ISP").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("PAYLOAD / BANNER").strong().color(COLOR_TEXT_MUTED));
                        ui.label(RichText::new("AÇÃO").strong().color(COLOR_TEXT_MUTED));
                        ui.end_row();

                        if filtered.is_empty() {
                            ui.label(RichText::new("-").color(COLOR_TEXT_MUTED));
                            ui.label(RichText::new("Nenhum evento encontrado").italics().color(COLOR_TEXT_MUTED));
                            ui.end_row();
                            return;
                        }

                        for inc in filtered {
                            // Node badge
                            ui.label(
                                RichText::new(&inc.node_id)
                                    .size(11.0)
                                    .monospace()
                                    .color(COLOR_ACCENT_CYAN),
                            );

                            // Timestamp
                            ui.label(
                                RichText::new(&inc.timestamp)
                                    .size(11.0)
                                    .monospace()
                                    .color(COLOR_TEXT_MUTED),
                            );

                            // IP
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&inc.ip)
                                        .size(12.0)
                                        .monospace()
                                        .strong()
                                        .color(Color32::WHITE),
                                );
                                if let Some(ref rdns) = inc.rdns {
                                    ui.label(
                                        RichText::new(format!("({})", rdns))
                                            .size(10.0)
                                            .color(COLOR_TEXT_MUTED),
                                    );
                                }
                            });

                            // Port & Service
                            ui.label(
                                RichText::new(format!("{}/{}", inc.port, inc.service))
                                    .size(12.0)
                                    .monospace()
                                    .color(COLOR_ACCENT_AMBER),
                            );

                            // Severity
                            let s_color = severity_color(&inc.severity);
                            ui.label(
                                RichText::new(&inc.severity)
                                    .size(11.0)
                                    .strong()
                                    .color(s_color),
                            );

                            // Threat Score
                            let threat_color = if inc.threat_score >= 70 {
                                COLOR_ACCENT_RED
                            } else if inc.threat_score >= 40 {
                                COLOR_ACCENT_AMBER
                            } else {
                                COLOR_ACCENT_CYAN
                            };
                            ui.label(
                                RichText::new(format!("{}/100", inc.threat_score))
                                    .size(11.0)
                                    .strong()
                                    .color(threat_color),
                            );

                            // Country / ISP
                            let loc = if !inc.city.is_empty() {
                                format!("{}, {}", inc.city, inc.country)
                            } else {
                                inc.country.clone()
                            };
                            ui.label(
                                RichText::new(loc)
                                    .size(11.0)
                                    .color(COLOR_TEXT_MUTED),
                            );

                            // Payload / Banner
                            let payload_text = inc.payload.as_deref().unwrap_or("-");
                            let truncated = if payload_text.len() > 30 {
                                format!("{}...", &payload_text[..30])
                            } else {
                                payload_text.to_string()
                            };
                            ui.label(
                                RichText::new(truncated)
                                    .size(10.0)
                                    .monospace()
                                    .color(Color32::from_rgb(170, 180, 190)),
                            );

                            // Action button
                            let ban_btn = ui.add(
                                egui::Button::new(
                                    RichText::new("🚫 Banir")
                                        .size(10.0)
                                        .color(COLOR_ACCENT_RED),
                                )
                                .fill(Color32::from_rgb(45, 20, 20)),
                            );
                            if ban_btn.clicked() {
                                *toast_msg = Some((
                                    format!("IP {} bloqueado na firewall / lista negra local!", inc.ip),
                                    std::time::Instant::now(),
                                ));
                            }

                            ui.end_row();
                        }
                    });
            });
    });
}
