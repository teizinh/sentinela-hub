use super::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_BORDER, COLOR_PANEL_BG,
    COLOR_TEXT_MUTED,
};
use crate::models::AgentNode;
use egui::{Color32, RichText, Stroke, Ui};

pub fn render_sidebar(
    ui: &mut Ui,
    nodes: &[AgentNode],
    selected_node: &mut Option<String>,
) {
    egui::Frame::none()
        .fill(COLOR_PANEL_BG)
        .stroke(Stroke::new(1.0f32, COLOR_BORDER))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.label(
                RichText::new("AGENTES MONITORIZADOS")
                    .size(11.0)
                    .strong()
                    .color(COLOR_TEXT_MUTED),
            );
            ui.add_space(6.0);

            let all_selected = selected_node.is_none();
            let all_btn = ui.selectable_label(
                all_selected,
                RichText::new("🌐 Todos os Agentes").strong(),
            );
            if all_btn.clicked() {
                *selected_node = None;
            }

            ui.add_space(8.0);
            ui.separator();
            ui.add_space(8.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                if nodes.is_empty() {
                    ui.label(
                        RichText::new("Nenhum agente ligado.\nAguardando conexões...")
                            .size(11.0)
                            .italics()
                            .color(COLOR_TEXT_MUTED),
                    );
                    return;
                }

                for node in nodes {
                    let is_active = selected_node.as_deref() == Some(&node.id);
                    let (status_dot, dot_color) = if node.online {
                        ("●", COLOR_ACCENT_GREEN)
                    } else {
                        ("○", COLOR_TEXT_MUTED)
                    };

                    let frame_fill = if is_active {
                        Color32::from_rgb(33, 45, 60)
                    } else {
                        Color32::from_rgb(22, 27, 34)
                    };

                    let response = egui::Frame::none()
                        .fill(frame_fill)
                        .stroke(Stroke::new(1.0f32, if is_active { COLOR_ACCENT_CYAN } else { COLOR_BORDER }))
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(status_dot).color(dot_color).size(14.0));
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(&node.name)
                                                .strong()
                                                .size(13.0)
                                                .color(Color32::WHITE),
                                        );
                                        ui.label(
                                            RichText::new(format!("v{}", node.version))
                                                .size(10.0)
                                                .color(COLOR_TEXT_MUTED),
                                        );
                                    });

                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new(&node.ip)
                                                .monospace()
                                                .size(11.0)
                                                .color(COLOR_ACCENT_CYAN),
                                        );
                                        ui.label(
                                            RichText::new(format!("• {} hits", node.incident_count))
                                                .size(11.0)
                                                .color(COLOR_ACCENT_AMBER),
                                        );
                                    });

                                    ui.label(
                                        RichText::new(format!("ID: {}", node.id))
                                            .monospace()
                                            .size(9.0)
                                            .color(COLOR_TEXT_MUTED),
                                    );
                                });
                            });
                        });

                    if response.response.interact(egui::Sense::click()).clicked() {
                        if is_active {
                            *selected_node = None;
                        } else {
                            *selected_node = Some(node.id.clone());
                        }
                    }

                    ui.add_space(6.0);
                }
            });
        });
}
