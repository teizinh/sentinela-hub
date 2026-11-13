use super::{
    apply_soc_theme, SocTheme, COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN,
    COLOR_ACCENT_RED, COLOR_BORDER, COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

/// Returns the current active SOC theme from context memory
pub fn get_soc_theme(ctx: &egui::Context) -> SocTheme {
    ctx.data_mut(|d| d.get_temp::<SocTheme>(egui::Id::new("soc_theme_state")).unwrap_or_default())
}

/// Returns whether audio alert notifications are currently enabled
pub fn is_audio_alert_enabled(ctx: &egui::Context) -> bool {
    ctx.data_mut(|d| d.get_temp::<bool>(egui::Id::new("soc_sound_alert_state")).unwrap_or(true))
}

/// Emits an audio bell alert if audio notifications are currently enabled
pub fn play_audio_alert_if_enabled(ctx: &egui::Context) {
    if is_audio_alert_enabled(ctx) {
        print!("\x07");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewTab {
    Incidents,
    ThreatMap,
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
    export_report: &mut bool,
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
                    // Status badge for server with live pulse indicator
                    ui.label(
                        RichText::new(format!("🟢 [60 FPS | Ingestão: {}]", server_addr))
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
                    "🗺️ Threat Map",
                    ViewTab::ThreatMap,
                    *current_tab == ViewTab::ThreatMap,
                ) {
                    *current_tab = ViewTab::ThreatMap;
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

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(
                            RichText::new("📄 Relatório SOC")
                                .size(11.0f32)
                                .strong()
                                .color(COLOR_ACCENT_GREEN),
                        )
                        .on_hover_text("Exportar Relatório Executivo SOC em Markdown")
                        .clicked()
                    {
                        *export_report = true;
                    }

                    ui.separator();

                    // Audio alert toggle button: [ 🔔 Som: ON / OFF ]
                    let sound_id = egui::Id::new("soc_sound_alert_state");
                    let sound_on = ui.data_mut(|d| d.get_temp::<bool>(sound_id).unwrap_or(true));
                    let sound_label = format!("🔔 Som: {}", if sound_on { "ON" } else { "OFF" });
                    let sound_color = if sound_on {
                        COLOR_ACCENT_GREEN
                    } else {
                        COLOR_TEXT_MUTED
                    };
                    if ui
                        .button(
                            RichText::new(sound_label)
                                .size(11.0f32)
                                .strong()
                                .color(sound_color),
                        )
                        .on_hover_text(if sound_on {
                            "Alertas sonoros ativados (clique para silenciar)"
                        } else {
                            "Alertas sonoros silenciados (clique para ativar)"
                        })
                        .clicked()
                    {
                        ui.data_mut(|d| d.insert_temp(sound_id, !sound_on));
                    }

                    ui.separator();

                    // Theme cycler button: [ 🎨 {theme.label()} ]
                    let theme_id = egui::Id::new("soc_theme_state");
                    let current_theme = ui.data_mut(|d| d.get_temp::<SocTheme>(theme_id).unwrap_or_default());
                    let theme_label = format!("🎨 {}", current_theme.label());
                    if ui
                        .button(
                            RichText::new(theme_label)
                                .size(11.0f32)
                                .strong()
                                .color(COLOR_ACCENT_CYAN),
                        )
                        .on_hover_text("Alternar tema SOC (Cyber Slate -> Matrix Green -> Crimson SOC)")
                        .clicked()
                    {
                        let next_theme = current_theme.next();
                        apply_soc_theme(ui.ctx(), next_theme);
                        ui.data_mut(|d| d.insert_temp(theme_id, next_theme));
                    }
                });
            });
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_header_theme_and_sound_controls() {
        let ctx = egui::Context::default();
        let mut current_tab = ViewTab::Incidents;
        let mut export_report = false;

        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                render_header(
                    ui,
                    &mut current_tab,
                    5,
                    42,
                    3,
                    "127.0.0.1:514",
                    &mut export_report,
                );
            });
        });

        // Default theme and audio state
        assert_eq!(get_soc_theme(&ctx), SocTheme::CyberSlate);
        assert!(is_audio_alert_enabled(&ctx));

        // Test theme mutation in context
        let theme_id = egui::Id::new("soc_theme_state");
        ctx.data_mut(|d| d.insert_temp(theme_id, SocTheme::MatrixGreen));
        assert_eq!(get_soc_theme(&ctx), SocTheme::MatrixGreen);

        // Test sound mutation in context
        let sound_id = egui::Id::new("soc_sound_alert_state");
        ctx.data_mut(|d| d.insert_temp(sound_id, false));
        assert!(!is_audio_alert_enabled(&ctx));
    }
}
