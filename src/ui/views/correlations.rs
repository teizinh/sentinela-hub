use crate::models::CorrelationAlert;
use crate::ui::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_ACCENT_PURPLE,
    COLOR_ACCENT_RED, COLOR_BORDER, COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

pub fn render_correlations_view(
    ui: &mut Ui,
    correlations: &[CorrelationAlert],
    toast_msg: &mut Option<(String, std::time::Instant)>,
) {
    ui.vertical(|ui| {
        // Info Banner
        egui::Frame::none()
            .fill(Color32::from_rgb(30, 20, 25))
            .stroke(Stroke::new(1.0f32, COLOR_ACCENT_RED))
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚠️").size(24.0));
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("DETEÇÃO DE ATAQUES COORDENADOS MULTI-HOST (SIEM)")
                                .size(14.0)
                                .strong()
                                .color(COLOR_ACCENT_RED),
                        );
                        ui.label(
                            RichText::new(
                                "O Sentinela Hub correlaciona fontes de ameaça que atacam 2 ou mais máquinas distintas na rede na mesma janela temporal. MITRE ATT&CK T1046 (Network Service Discovery) & T1110 (Brute Force).",
                            )
                            .size(11.0)
                            .color(COLOR_TEXT_MUTED),
                        );
                    });
                });
            });

        ui.add_space(10.0);

        if correlations.is_empty() {
            egui::Frame::none()
                .fill(COLOR_PANEL_BG)
                .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                .inner_margin(30.0)
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("🛡️").size(36.0));
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new("Nenhum ataque multi-host correlacionado de momento.")
                                .size(14.0)
                                .strong()
                                .color(COLOR_ACCENT_GREEN),
                        );
                        ui.label(
                            RichText::new(
                                "Quando o mesmo atacante atingir múltiplos agentes Sentinela, os incidentes serão agregados aqui automaticamente.",
                            )
                            .size(11.0)
                            .color(COLOR_TEXT_MUTED),
                        );
                    });
                });
            return;
        }

        // Active Alerts List
        egui::ScrollArea::vertical().show(ui, |ui| {
            for alert in correlations {
                egui::Frame::none()
                    .fill(COLOR_PANEL_BG)
                    .stroke(Stroke::new(1.5f32, COLOR_ACCENT_RED))
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        // Card Header
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("🚨 ATAQUE COORDENADO DETETADO")
                                    .size(12.0)
                                    .strong()
                                    .color(COLOR_ACCENT_RED),
                            );

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(
                                    RichText::new(format!("Perigo: {}/100", alert.threat_score))
                                        .size(13.0)
                                        .strong()
                                        .color(COLOR_ACCENT_RED),
                                );
                            });
                        });

                        ui.add_space(6.0);

                        // Attacker IP & Hit Count
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(&alert.attacker_ip)
                                    .size(18.0)
                                    .strong()
                                    .monospace()
                                    .color(Color32::WHITE),
                            );

                            ui.label(
                                RichText::new(format!("• {} hits agregados", alert.total_hits))
                                    .size(13.0)
                                    .strong()
                                    .color(COLOR_ACCENT_AMBER),
                            );

                            ui.label(
                                RichText::new(format!(
                                    "Janela: {} → {}",
                                    alert.first_seen, alert.last_seen
                                ))
                                .size(11.0)
                                .color(COLOR_TEXT_MUTED),
                            );
                        });

                        ui.add_space(8.0);

                        // Targeted Nodes List
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Alvos comprometidos / sondados:")
                                    .size(12.0)
                                    .color(COLOR_TEXT_MUTED),
                            );
                            for node in &alert.nodes_targeted {
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(20, 35, 50))
                                    .stroke(Stroke::new(1.0f32, COLOR_ACCENT_CYAN))
                                    .inner_margin(4.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(format!("🖥️ {}", node))
                                                .size(11.0)
                                                .strong()
                                                .color(COLOR_ACCENT_CYAN),
                                        );
                                    });
                            }
                        });

                        ui.add_space(4.0);

                        // Targeted Services List
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Serviços atacados:")
                                    .size(12.0)
                                    .color(COLOR_TEXT_MUTED),
                            );
                            for srv in &alert.targeted_services {
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(40, 25, 45))
                                    .stroke(Stroke::new(1.0f32, COLOR_ACCENT_PURPLE))
                                    .inner_margin(4.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(srv)
                                                .size(11.0)
                                                .strong()
                                                .color(COLOR_ACCENT_PURPLE),
                                        );
                                    });
                            }
                        });

                        ui.add_space(10.0);
                        ui.separator();
                        ui.add_space(6.0);

                        // Action Buttons
                        ui.horizontal(|ui| {
                            let ban_all = ui.add(
                                egui::Button::new(
                                    RichText::new("🚫 Bloquear em Todos os Agentes")
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(180, 40, 40)),
                            );
                            if ban_all.clicked() {
                                *toast_msg = Some((
                                    format!(
                                        "Ordem de bloqueio enviada para {} nós para banir {}",
                                        alert.nodes_targeted.len(),
                                        alert.attacker_ip
                                    ),
                                    std::time::Instant::now(),
                                ));
                            }

                            let copy_ioc = ui.button("📋 Copiar Indicador (IOC)");
                            if copy_ioc.clicked() {
                                ui.output_mut(|o| {
                                    o.copied_text = format!(
                                        "IOC Type: IP\nValue: {}\nThreat Score: {}\nTargets: {}\nServices: {}",
                                        alert.attacker_ip,
                                        alert.threat_score,
                                        alert.nodes_targeted.join(", "),
                                        alert.targeted_services.join(", ")
                                    );
                                });
                                *toast_msg = Some((
                                    format!("IOC {} copiado para o clipboard!", alert.attacker_ip),
                                    std::time::Instant::now(),
                                ));
                            }
                        });
                    });

                ui.add_space(10.0);
            }
        });
    });
}
