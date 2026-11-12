use crate::models::CorrelationAlert;
use crate::ui::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_ACCENT_PURPLE,
    COLOR_ACCENT_RED, COLOR_BORDER, COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

/// Distributes `count` target nodes evenly in a circle around `center`.
pub fn calculate_radial_node_positions(
    center: egui::Pos2,
    radius: f32,
    count: usize,
) -> Vec<egui::Pos2> {
    if count == 0 {
        return Vec::new();
    }
    let step = 2.0 * std::f32::consts::PI / (count as f32);
    let start_angle = -std::f32::consts::FRAC_PI_2;
    (0..count)
        .map(|i| {
            let angle = start_angle + (i as f32) * step;
            egui::pos2(
                center.x + radius * angle.cos(),
                center.y + radius * angle.sin(),
            )
        })
        .collect()
}

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

        // Active Correlation Selection for Graph if multiple
        let active_idx_id = ui.id().with("selected_radial_correlation_alert_idx");
        let mut active_idx = ui.data_mut(|d| d.get_temp::<usize>(active_idx_id).unwrap_or(0));
        if active_idx >= correlations.len() {
            active_idx = 0;
        }

        if correlations.len() > 1 {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Foco do Grafo Radial:")
                        .size(11.0)
                        .color(COLOR_TEXT_MUTED),
                );
                for (idx, c) in correlations.iter().enumerate() {
                    let is_active = idx == active_idx;
                    let label = format!("{} (Perigo: {}/100)", c.attacker_ip, c.threat_score);
                    let btn = if is_active {
                        egui::Button::new(
                            RichText::new(format!("⚡ {}", label))
                                .size(11.0)
                                .strong()
                                .color(Color32::WHITE),
                        )
                        .fill(Color32::from_rgb(180, 40, 40))
                    } else {
                        egui::Button::new(
                            RichText::new(label)
                                .size(11.0)
                                .color(COLOR_TEXT_MUTED),
                        )
                        .fill(Color32::from_rgb(26, 32, 44))
                    };
                    if ui.add(btn).clicked() {
                        active_idx = idx;
                        ui.data_mut(|d| d.insert_temp(active_idx_id, active_idx));
                    }
                }
            });
            ui.add_space(6.0);
        }

        // Dedicated interactive radial attack graph canvas
        render_radial_attack_graph_canvas(ui, &correlations[active_idx], toast_msg);

        ui.add_space(12.0);

        // Section header for cards
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("ALERTAS DE CORRELAÇÃO AGREGADOS")
                    .size(12.0)
                    .strong()
                    .color(COLOR_TEXT_MUTED),
            );
            ui.label(
                RichText::new(format!("({} ativos)", correlations.len()))
                    .size(11.0)
                    .color(COLOR_ACCENT_RED),
            );
        });

        ui.add_space(6.0);

        // Active Alerts List
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (idx, alert) in correlations.iter().enumerate() {
                let is_graph_focused = idx == active_idx;
                egui::Frame::none()
                    .fill(COLOR_PANEL_BG)
                    .stroke(Stroke::new(
                        if is_graph_focused { 1.8f32 } else { 1.0f32 },
                        if is_graph_focused {
                            COLOR_ACCENT_RED
                        } else {
                            COLOR_BORDER
                        },
                    ))
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

                            if is_graph_focused {
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(45, 15, 20))
                                    .stroke(Stroke::new(1.0f32, COLOR_ACCENT_RED))
                                    .inner_margin(egui::vec2(6.0, 2.0))
                                    .rounding(3.0)
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new("⚡ EM FOCO NO GRAFO")
                                                .size(10.0)
                                                .strong()
                                                .color(COLOR_ACCENT_RED),
                                        );
                                    });
                            }

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

                            if !is_graph_focused && correlations.len() > 1 {
                                let focus_btn = ui.button("🎯 Focar no Grafo Radial");
                                if focus_btn.clicked() {
                                    ui.data_mut(|d| d.insert_temp(active_idx_id, idx));
                                }
                            }
                        });
                    });

                ui.add_space(10.0);
            }
        });
    });
}

/// Renders a dedicated interactive radial attack graph canvas displaying multi-node attack vectors.
fn render_radial_attack_graph_canvas(
    ui: &mut Ui,
    alert: &CorrelationAlert,
    toast_msg: &mut Option<(String, std::time::Instant)>,
) {
    ui.ctx().request_repaint();

    let canvas_size = egui::vec2(ui.available_width(), 270.0f32);
    let (response, painter) = ui.allocate_painter(canvas_size, egui::Sense::click());
    let rect = response.rect;

    if rect.width() < 10.0f32 || rect.height() < 10.0f32 {
        return;
    }

    // 1. Dark SOC canvas background & border
    painter.rect_filled(rect, 6.0f32, Color32::from_rgb(10, 14, 20));
    painter.rect_stroke(rect, 6.0f32, Stroke::new(1.0f32, COLOR_BORDER));

    // Canvas Header HUD
    painter.text(
        rect.min + egui::vec2(14.0f32, 12.0f32),
        egui::Align2::LEFT_TOP,
        "GRAFO RADIAL DE ATAQUE // TOPOLOGIA DISTRIBUÍDA",
        egui::FontId::proportional(10.5f32),
        COLOR_TEXT_MUTED,
    );
    painter.text(
        rect.right_top() + egui::vec2(-14.0f32, 12.0f32),
        egui::Align2::RIGHT_TOP,
        format!("ALVOS IMPACTADOS: {} NÓS", alert.nodes_targeted.len()),
        egui::FontId::proportional(10.5f32),
        COLOR_ACCENT_CYAN,
    );

    let center = rect.center();
    let radius = (rect.height() * 0.35f32).clamp(70.0f32, 115.0f32);

    // Subtle Concentric Radar Grid
    painter.circle_stroke(
        center,
        radius * 0.5f32,
        Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 60)),
    );
    painter.circle_stroke(
        center,
        radius,
        Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 80)),
    );
    painter.circle_stroke(
        center,
        radius * 1.3f32,
        Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 50)),
    );

    // Subtle Crosshair Axes
    let crosshair_stroke = Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 60));
    painter.line_segment(
        [
            egui::pos2(center.x - radius * 1.35f32, center.y),
            egui::pos2(center.x + radius * 1.35f32, center.y),
        ],
        crosshair_stroke,
    );
    painter.line_segment(
        [
            egui::pos2(center.x, center.y - radius * 1.35f32),
            egui::pos2(center.x, center.y + radius * 1.35f32),
        ],
        crosshair_stroke,
    );

    let time = ui.input(|i| i.time) as f32;

    // 2. Radar rings expanding from the center attacker beacon
    let max_radar_radius = radius * 1.35f32;
    for ring_i in 0..3 {
        let phase = (time * 0.65f32 + (ring_i as f32) * 0.33f32).fract();
        let ring_r = 16.0f32 + phase * (max_radar_radius - 16.0f32);
        let alpha = ((1.0f32 - phase) * 140.0f32) as u8;
        painter.circle_stroke(
            center,
            ring_r,
            Stroke::new(
                1.2f32,
                Color32::from_rgba_unmultiplied(248, 113, 113, alpha),
            ),
        );
    }

    // Calculate Orbiting Target Node Positions
    let target_positions =
        calculate_radial_node_positions(center, radius, alert.nodes_targeted.len());

    // 3. Connecting vectors: Animated laser attack lines connecting attacker to targeted nodes with service labels
    let count_targets = alert.nodes_targeted.len().max(1);
    for (i, node_pos) in target_positions.iter().enumerate() {
        let diff = *node_pos - center;
        let diff_len = (diff.x * diff.x + diff.y * diff.y).sqrt();
        let dir = if diff_len > 0.001f32 {
            diff / diff_len
        } else {
            egui::vec2(0.0f32, -1.0f32)
        };

        // Static Laser attack beam lines (glow + core)
        painter.line_segment(
            [center, *node_pos],
            Stroke::new(2.4f32, Color32::from_rgba_unmultiplied(248, 113, 113, 75)),
        );
        painter.line_segment(
            [center, *node_pos],
            Stroke::new(1.0f32, Color32::from_rgba_unmultiplied(255, 180, 180, 200)),
        );

        // Animated laser attack packet / bolt
        let laser_prog = (time * 1.3f32 + (i as f32) / (count_targets as f32)).fract();
        let pulse_pos = center + diff * laser_prog;
        painter.circle_filled(
            pulse_pos,
            5.0f32,
            Color32::from_rgba_unmultiplied(248, 113, 113, 180),
        );
        painter.circle_filled(pulse_pos, 2.5f32, Color32::WHITE);

        let trail_len = (20.0f32 * laser_prog).min(18.0f32);
        painter.line_segment(
            [pulse_pos - dir * trail_len, pulse_pos],
            Stroke::new(2.5f32, Color32::from_rgba_unmultiplied(248, 113, 113, 220)),
        );

        // Service labels (SSH, HTTP, etc.)
        let service_label = if alert.targeted_services.is_empty() {
            "ATTACK".to_string()
        } else {
            alert.targeted_services[i % alert.targeted_services.len()].clone()
        };
        let mid_pos = center + diff * 0.50f32;
        let badge_w = service_label.len() as f32 * 6.8f32 + 12.0f32;
        let badge_rect = egui::Rect::from_center_size(mid_pos, egui::vec2(badge_w, 16.0f32));
        painter.rect_filled(badge_rect, 3.0f32, Color32::from_rgb(34, 20, 38));
        painter.rect_stroke(badge_rect, 3.0f32, Stroke::new(1.0f32, COLOR_ACCENT_PURPLE));
        painter.text(
            mid_pos,
            egui::Align2::CENTER_CENTER,
            &service_label,
            egui::FontId::monospace(9.5f32),
            COLOR_ACCENT_PURPLE,
        );
    }

    // 4. Orbiting nodes: Targeted agent nodes drawn in emerald green
    for (i, node_pos) in target_positions.iter().enumerate() {
        let node_name = &alert.nodes_targeted[i];
        let diff = *node_pos - center;
        let diff_len = (diff.x * diff.x + diff.y * diff.y).sqrt();
        let dir = if diff_len > 0.001f32 {
            diff / diff_len
        } else {
            egui::vec2(0.0f32, -1.0f32)
        };

        // Emerald pulsing beacon
        let node_pulse = (time * 2.5f32 + (i as f32) * 1.5f32).sin() * 0.5f32 + 0.5f32;
        painter.circle_filled(
            *node_pos,
            14.0f32 + node_pulse * 4.0f32,
            Color32::from_rgba_unmultiplied(52, 211, 153, 35),
        );
        painter.circle_filled(
            *node_pos,
            8.0f32 + node_pulse * 2.0f32,
            Color32::from_rgba_unmultiplied(52, 211, 153, 90),
        );
        painter.circle_filled(*node_pos, 5.0f32, COLOR_ACCENT_GREEN);
        painter.circle_stroke(*node_pos, 5.0f32, Stroke::new(1.5f32, Color32::WHITE));

        // Node label positioned outward
        let label_pos = *node_pos + dir * 22.0f32;
        let align = if dir.x > 0.3f32 {
            egui::Align2::LEFT_CENTER
        } else if dir.x < -0.3f32 {
            egui::Align2::RIGHT_CENTER
        } else if dir.y > 0.0f32 {
            egui::Align2::CENTER_TOP
        } else {
            egui::Align2::CENTER_BOTTOM
        };
        painter.text(
            label_pos,
            align,
            format!("🖥️ {}", node_name),
            egui::FontId::proportional(11.0f32),
            COLOR_ACCENT_GREEN,
        );
    }

    // 5. Center node: Attacker IP in a glowing red pulsing beacon with threat score badge
    let beacon_pulse = (time * 3.0f32).sin() * 0.5f32 + 0.5f32;
    painter.circle_filled(
        center,
        26.0f32 + beacon_pulse * 6.0f32,
        Color32::from_rgba_unmultiplied(248, 113, 113, 35 + (beacon_pulse * 30.0f32) as u8),
    );
    painter.circle_filled(
        center,
        17.0f32 + beacon_pulse * 3.0f32,
        Color32::from_rgba_unmultiplied(220, 38, 38, 80 + (beacon_pulse * 40.0f32) as u8),
    );
    painter.circle_filled(center, 11.0f32, Color32::from_rgb(220, 38, 38));
    painter.circle_stroke(center, 11.0f32, Stroke::new(2.0f32, Color32::WHITE));
    painter.text(
        center,
        egui::Align2::CENTER_CENTER,
        "⚠️",
        egui::FontId::proportional(11.0f32),
        Color32::WHITE,
    );

    // Threat Score Badge (above center beacon)
    let score_pos = center + egui::vec2(0.0f32, -25.0f32);
    let score_text = format!("PERIGO: {}/100", alert.threat_score);
    let score_w = score_text.len() as f32 * 6.0f32 + 12.0f32;
    let score_rect = egui::Rect::from_center_size(score_pos, egui::vec2(score_w, 15.0f32));
    painter.rect_filled(score_rect, 3.0f32, Color32::from_rgb(45, 12, 18));
    painter.rect_stroke(score_rect, 3.0f32, Stroke::new(1.0f32, COLOR_ACCENT_RED));
    painter.text(
        score_pos,
        egui::Align2::CENTER_CENTER,
        &score_text,
        egui::FontId::proportional(9.0f32),
        COLOR_ACCENT_RED,
    );

    // Attacker IP (below center beacon)
    let ip_pos = center + egui::vec2(0.0f32, 25.0f32);
    let ip_text = &alert.attacker_ip;
    let ip_w = ip_text.len() as f32 * 7.5f32 + 16.0f32;
    let ip_rect = egui::Rect::from_center_size(ip_pos, egui::vec2(ip_w, 18.0f32));
    painter.rect_filled(ip_rect, 4.0f32, Color32::from_rgb(32, 15, 20));
    painter.rect_stroke(ip_rect, 4.0f32, Stroke::new(1.0f32, COLOR_ACCENT_RED));
    painter.text(
        ip_pos,
        egui::Align2::CENTER_CENTER,
        ip_text,
        egui::FontId::monospace(11.0f32),
        Color32::WHITE,
    );

    // Interactive Click
    if response.clicked() {
        if let Some(mouse) = response.interact_pointer_pos() {
            if mouse.distance(center) <= 30.0f32 || ip_rect.contains(mouse) {
                ui.output_mut(|o| o.copied_text = alert.attacker_ip.clone());
                *toast_msg = Some((
                    format!("IP do atacante {} copiado para o clipboard!", alert.attacker_ip),
                    std::time::Instant::now(),
                ));
            } else {
                for (i, node_pos) in target_positions.iter().enumerate() {
                    if mouse.distance(*node_pos) <= 20.0f32 {
                        let node_name = &alert.nodes_targeted[i];
                        *toast_msg = Some((
                            format!("Foco no nó alvo: {}", node_name),
                            std::time::Instant::now(),
                        ));
                        break;
                    }
                }
            }
        }
    }

    // Interactive Hover Tooltips
    response.on_hover_ui(|ui| {
        if let Some(mouse) = ui.input(|i| i.pointer.hover_pos()) {
            if mouse.distance(center) <= 30.0f32 || ip_rect.contains(mouse) || score_rect.contains(mouse) {
                ui.label(
                    RichText::new(format!("🚨 Atacante: {}", alert.attacker_ip))
                        .strong()
                        .color(COLOR_ACCENT_RED),
                );
                ui.label(format!("Nível de Perigo: {}/100", alert.threat_score));
                ui.label(format!("Hits Agregados: {}", alert.total_hits));
                ui.label(format!("Janela Temporal: {} → {}", alert.first_seen, alert.last_seen));
                ui.label(
                    RichText::new("(Clique no atacante para copiar o IP)")
                        .size(10.0f32)
                        .color(COLOR_TEXT_MUTED),
                );
            } else {
                let mut hovered_node = None;
                for (i, node_pos) in target_positions.iter().enumerate() {
                    if mouse.distance(*node_pos) <= 20.0f32 {
                        hovered_node = Some(&alert.nodes_targeted[i]);
                        break;
                    }
                }
                if let Some(node) = hovered_node {
                    ui.label(
                        RichText::new(format!("🖥️ Nó Sentinela Alvo: {}", node))
                            .strong()
                            .color(COLOR_ACCENT_GREEN),
                    );
                    ui.label("Estado: Sob Investigação de Ataque Coordenado");
                    ui.label(format!("Serviços Atacados: {}", alert.targeted_services.join(", ")));
                } else {
                    ui.label(RichText::new("Grafo Radial de Correlação SIEM").strong());
                    ui.label("Passe o cursor sobre o atacante ou nós para ver detalhes.");
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_radial_node_positions() {
        let center = egui::pos2(200.0, 150.0);
        let radius = 100.0;
        let positions = calculate_radial_node_positions(center, radius, 4);

        assert_eq!(positions.len(), 4);

        // Verify all 4 nodes are at distance `radius` from center
        for (i, pos) in positions.iter().enumerate() {
            let dist = ((pos.x - center.x).powi(2) + (pos.y - center.y).powi(2)).sqrt();
            assert!(
                (dist - radius).abs() < 1e-4,
                "Node {} distance from center expected {}, got {}",
                i,
                radius,
                dist
            );
        }

        // Verify 4 nodes are equidistant at 90-degree angles around center
        let expected_adjacent_dist = radius * std::f32::consts::SQRT_2;
        for i in 0..4 {
            let next = (i + 1) % 4;
            let d = ((positions[i].x - positions[next].x).powi(2)
                + (positions[i].y - positions[next].y).powi(2))
            .sqrt();
            assert!(
                (d - expected_adjacent_dist).abs() < 1e-4,
                "Distance between adjacent nodes {} and {} expected {}, got {}",
                i,
                next,
                expected_adjacent_dist,
                d
            );

            // Vector dot product between consecutive vectors from center should be 0 (cos 90 deg)
            let v1_x = positions[i].x - center.x;
            let v1_y = positions[i].y - center.y;
            let v2_x = positions[next].x - center.x;
            let v2_y = positions[next].y - center.y;
            let dot = (v1_x * v2_x + v1_y * v2_y) / (radius * radius);
            assert!(
                dot.abs() < 1e-4,
                "Dot product between adjacent vectors {} and {} should be 0 (90 deg), got {}",
                i,
                next,
                dot
            );
        }

        // Test empty count returns empty vector
        assert!(calculate_radial_node_positions(center, radius, 0).is_empty());
    }
}

