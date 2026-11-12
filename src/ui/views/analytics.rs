use crate::models::HubIncident;
use crate::ui::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_ACCENT_RED, COLOR_BORDER,
    COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};
use egui_plot::{Line, Plot, PlotPoints};
use std::collections::HashMap;

pub fn render_analytics_view(
    ui: &mut Ui,
    incidents: &[HubIncident],
    top_attackers: &[(String, usize, u8, String)],
) {
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
                        sorted_services.sort_by(|a, b| b.1.cmp(&a.1));

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

        // Section: Real-time Timeline Plot
        egui::Frame::none()
            .fill(COLOR_PANEL_BG)
            .stroke(Stroke::new(1.0f32, COLOR_BORDER))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("📈 TIMELINE DE SEVERIDADE DOS ATAQUES")
                        .size(13.0)
                        .strong()
                        .color(COLOR_ACCENT_GREEN),
                );
                ui.label(
                    RichText::new("Evolução do Threat Score ao longo dos últimos incidentes recebidos.")
                        .size(11.0)
                        .color(COLOR_TEXT_MUTED),
                );
                ui.add_space(8.0);

                let points: PlotPoints = incidents
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(idx, inc)| [idx as f64, inc.threat_score as f64])
                    .collect();

                let line = Line::new(points)
                    .color(COLOR_ACCENT_CYAN)
                    .stroke(Stroke::new(2.0f32, COLOR_ACCENT_CYAN))
                    .name("Threat Score");

                Plot::new("timeline_plot")
                    .height(200.0)
                    .show_axes([true, true])
                    .show_grid(true)
                    .show(ui, |plot_ui| {
                        plot_ui.line(line);
                    });
            });
    });
}
