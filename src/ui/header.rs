use super::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_ACCENT_RED, COLOR_BORDER,
    COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewTab {
    Incidents,
    Correlations,
    Analytics,
}

pub fn render_header(
    ui: &mut Ui,
    current_tab: &mut ViewTab,
    node_count: usize,
    incident_count: usize,
    correlation_count: usize,
    server_addr: &str,
) {
    egui::Frame::none()
        .fill(COLOR_PANEL_BG)
        .stroke(Stroke::new(1.0f32, COLOR_BORDER))
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Title and branding
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("🛡️ SENTINELA HUB")
                            .size(20.0)
                            .strong()
                            .color(COLOR_ACCENT_CYAN),
                    );
                    ui.label(
                        RichText::new("v0.1.0 SOC Multi-Host")
                            .size(12.0)
                            .color(COLOR_TEXT_MUTED),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // Status badge for server
                    ui.label(
                        RichText::new(format!("🟢 Ingestão: {}", server_addr))
                            .size(11.0)
                            .color(COLOR_ACCENT_GREEN),
                    );

                    ui.separator();

                    // Coordinated alerts metric
                    let corr_color = if correlation_count > 0 {
                        COLOR_ACCENT_RED
                    } else {
                        COLOR_TEXT_MUTED
                    };
                    ui.label(
                        RichText::new(format!("⚠️ {} Ataques Correlacionados", correlation_count))
                            .strong()
                            .size(12.0)
                            .color(corr_color),
                    );

                    ui.separator();

                    // Incidents metric
                    ui.label(
                        RichText::new(format!("⚡ {} Incidentes", incident_count))
                            .strong()
                            .size(12.0)
                            .color(COLOR_ACCENT_AMBER),
                    );

                    ui.separator();

                    // Online nodes metric
                    ui.label(
                        RichText::new(format!("🖥️ {} Agentes", node_count))
                            .strong()
                            .size(12.0)
                            .color(COLOR_ACCENT_CYAN),
                    );
                });
            });

            ui.add_space(8.0);

            // Tab Navigation Bar
            ui.horizontal(|ui| {
                let tab_button = |ui: &mut Ui, label: &str, _tab: ViewTab, is_active: bool| -> bool {
                    let text = if is_active {
                        RichText::new(label).strong().color(Color32::WHITE)
                    } else {
                        RichText::new(label).color(COLOR_TEXT_MUTED)
                    };
                    let bg = if is_active {
                        Color32::from_rgb(31, 111, 235) // Cyber Blue
                    } else {
                        Color32::from_rgb(33, 38, 45)
                    };
                    ui.add(egui::Button::new(text).fill(bg)).clicked()
                };

                let corr_label = if correlation_count > 0 {
                    format!("⚡ Correlações ({})", correlation_count)
                } else {
                    "⚡ Correlações".to_string()
                };

                if tab_button(
                    ui,
                    "🚨 Incidentes Globais",
                    ViewTab::Incidents,
                    *current_tab == ViewTab::Incidents,
                ) {
                    *current_tab = ViewTab::Incidents;
                }

                if tab_button(
                    ui,
                    &corr_label,
                    ViewTab::Correlations,
                    *current_tab == ViewTab::Correlations,
                ) {
                    *current_tab = ViewTab::Correlations;
                }

                if tab_button(
                    ui,
                    "📊 Métricas & Analytics",
                    ViewTab::Analytics,
                    *current_tab == ViewTab::Analytics,
                ) {
                    *current_tab = ViewTab::Analytics;
                }
            });
        });
}
