use crate::models::HubIncident;
use crate::ui::{
    severity_color, COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_RED, COLOR_BORDER,
    COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidentSortColumn {
    Timestamp,
    Ip,
    PortService,
    Threat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

pub fn render_incidents_view(
    ui: &mut Ui,
    incidents: &[HubIncident],
    search_query: &mut String,
    selected_severity: &mut String,
    selected_node: &Option<String>,
    toast_msg: &mut Option<(String, std::time::Instant)>,
    modal_incident: &mut Option<HubIncident>,
) {
    let sort_id = ui.id().with("incidents_table_sort_state");
    let (sort_col, sort_dir) = ui.data_mut(|d| {
        d.get_temp::<(IncidentSortColumn, SortDirection)>(sort_id)
            .unwrap_or((IncidentSortColumn::Timestamp, SortDirection::Descending))
    });
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
        let mut filtered: Vec<&HubIncident> = incidents
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

        // Sort incidents
        sort_incident_refs(&mut filtered, sort_col, sort_dir);

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
                        // Helper for sortable headers
                        let render_sort_header = |ui: &mut Ui, label: &str, col: IncidentSortColumn| {
                            let is_active = sort_col == col;
                            let arrow = if is_active {
                                match sort_dir {
                                    SortDirection::Ascending => " ▲",
                                    SortDirection::Descending => " ▼",
                                }
                            } else {
                                " ↕"
                            };
                            let text = format!("{}{}", label, arrow);
                            let color = if is_active {
                                COLOR_ACCENT_CYAN
                            } else {
                                COLOR_TEXT_MUTED
                            };

                            let btn = ui.add(
                                egui::Button::new(RichText::new(text).strong().color(color))
                                    .frame(false),
                            );
                            if btn.on_hover_text("Clique para ordenar").clicked() {
                                let new_dir = if is_active {
                                    match sort_dir {
                                        SortDirection::Ascending => SortDirection::Descending,
                                        SortDirection::Descending => SortDirection::Ascending,
                                    }
                                } else {
                                    match col {
                                        IncidentSortColumn::Threat
                                        | IncidentSortColumn::Timestamp => {
                                            SortDirection::Descending
                                        }
                                        IncidentSortColumn::Ip
                                        | IncidentSortColumn::PortService => {
                                            SortDirection::Ascending
                                        }
                                    }
                                };
                                ui.data_mut(|d| d.insert_temp(sort_id, (col, new_dir)));
                            }
                        };

                        // Header row
                        ui.label(RichText::new("NÓ").strong().color(COLOR_TEXT_MUTED));
                        render_sort_header(ui, "TIMESTAMP", IncidentSortColumn::Timestamp);
                        render_sort_header(ui, "ATACANTE (IP)", IncidentSortColumn::Ip);
                        render_sort_header(ui, "PORTA/SERV", IncidentSortColumn::PortService);
                        ui.label(RichText::new("SEVERIDADE").strong().color(COLOR_TEXT_MUTED));
                        render_sort_header(ui, "THREAT", IncidentSortColumn::Threat);
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

                            // IP (Clickable for Raio-X modal)
                            ui.horizontal(|ui| {
                                let ip_btn = ui.add(
                                    egui::Button::new(
                                        RichText::new(&inc.ip)
                                            .size(12.0)
                                            .monospace()
                                            .strong()
                                            .color(Color32::WHITE),
                                    )
                                    .frame(false),
                                );
                                if ip_btn
                                    .on_hover_text("Clique para abrir o Raio-X Forense")
                                    .clicked()
                                {
                                    *modal_incident = Some((*inc).clone());
                                }
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

                            // Action buttons: Raio-X + Banir
                            ui.horizontal(|ui| {
                                let rx_btn = ui.add(
                                    egui::Button::new(
                                        RichText::new("🔬 Raio-X")
                                            .size(10.0)
                                            .color(COLOR_ACCENT_CYAN),
                                    )
                                    .fill(Color32::from_rgb(20, 35, 50)),
                                );
                                if rx_btn
                                    .on_hover_text("Inspecionar incidente detalhado (Raio-X)")
                                    .clicked()
                                {
                                    *modal_incident = Some((*inc).clone());
                                }

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
                            });

                            ui.end_row();
                        }
                    });
            });
    });
}

pub fn sort_incident_refs<'a>(
    list: &mut [&'a HubIncident],
    col: IncidentSortColumn,
    dir: SortDirection,
) {
    match (col, dir) {
        (IncidentSortColumn::Timestamp, SortDirection::Ascending) => {
            list.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        }
        (IncidentSortColumn::Timestamp, SortDirection::Descending) => {
            list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        }
        (IncidentSortColumn::Ip, SortDirection::Ascending) => {
            list.sort_by(|a, b| {
                let ip_a = a.ip.parse::<std::net::IpAddr>().ok();
                let ip_b = b.ip.parse::<std::net::IpAddr>().ok();
                ip_a.cmp(&ip_b).then_with(|| a.ip.cmp(&b.ip))
            });
        }
        (IncidentSortColumn::Ip, SortDirection::Descending) => {
            list.sort_by(|a, b| {
                let ip_a = a.ip.parse::<std::net::IpAddr>().ok();
                let ip_b = b.ip.parse::<std::net::IpAddr>().ok();
                ip_b.cmp(&ip_a).then_with(|| b.ip.cmp(&a.ip))
            });
        }
        (IncidentSortColumn::PortService, SortDirection::Ascending) => {
            list.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.service.cmp(&b.service)));
        }
        (IncidentSortColumn::PortService, SortDirection::Descending) => {
            list.sort_by(|a, b| b.port.cmp(&a.port).then_with(|| b.service.cmp(&a.service)));
        }
        (IncidentSortColumn::Threat, SortDirection::Ascending) => {
            list.sort_by(|a, b| a.threat_score.cmp(&b.threat_score));
        }
        (IncidentSortColumn::Threat, SortDirection::Descending) => {
            list.sort_by(|a, b| b.threat_score.cmp(&a.threat_score));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_incident(ip: &str, port: u16, ts: &str, threat: u8) -> HubIncident {
        HubIncident {
            id: None,
            node_id: "node-1".into(),
            timestamp: ts.into(),
            ip: ip.into(),
            port,
            service: "SSH".into(),
            severity: "CRÍTICO".into(),
            country: "PT".into(),
            city: "Lisbon".into(),
            isp: "Vodafone".into(),
            rdns: None,
            payload: None,
            threat_score: threat,
            hit_count: 1,
        }
    }

    #[test]
    fn test_sorting_threat_score() {
        let i1 = dummy_incident("1.1.1.1", 22, "2026-11-12T10:00:00Z", 20);
        let i2 = dummy_incident("2.2.2.2", 80, "2026-11-12T11:00:00Z", 95);
        let i3 = dummy_incident("3.3.3.3", 443, "2026-11-12T09:00:00Z", 60);

        let mut list = vec![&i1, &i2, &i3];
        sort_incident_refs(&mut list, IncidentSortColumn::Threat, SortDirection::Descending);
        assert_eq!(list[0].threat_score, 95);
        assert_eq!(list[1].threat_score, 60);
        assert_eq!(list[2].threat_score, 20);

        sort_incident_refs(&mut list, IncidentSortColumn::Threat, SortDirection::Ascending);
        assert_eq!(list[0].threat_score, 20);
        assert_eq!(list[1].threat_score, 60);
        assert_eq!(list[2].threat_score, 95);
    }

    #[test]
    fn test_sorting_timestamp() {
        let i1 = dummy_incident("1.1.1.1", 22, "2026-11-12T10:00:00Z", 20);
        let i2 = dummy_incident("2.2.2.2", 80, "2026-11-12T11:00:00Z", 95);
        let i3 = dummy_incident("3.3.3.3", 443, "2026-11-12T09:00:00Z", 60);

        let mut list = vec![&i1, &i2, &i3];
        sort_incident_refs(&mut list, IncidentSortColumn::Timestamp, SortDirection::Descending);
        assert_eq!(list[0].timestamp, "2026-11-12T11:00:00Z");
        assert_eq!(list[1].timestamp, "2026-11-12T10:00:00Z");
        assert_eq!(list[2].timestamp, "2026-11-12T09:00:00Z");
    }

    #[test]
    fn test_sorting_ip_and_port() {
        let i1 = dummy_incident("10.0.0.10", 80, "2026-11-12T10:00:00Z", 10);
        let i2 = dummy_incident("10.0.0.2", 22, "2026-11-12T10:00:00Z", 20);

        let mut list = vec![&i1, &i2];
        sort_incident_refs(&mut list, IncidentSortColumn::Ip, SortDirection::Ascending);
        assert_eq!(list[0].ip, "10.0.0.2");
        assert_eq!(list[1].ip, "10.0.0.10");

        sort_incident_refs(&mut list, IncidentSortColumn::PortService, SortDirection::Ascending);
        assert_eq!(list[0].port, 22);
        assert_eq!(list[1].port, 80);
    }
}
