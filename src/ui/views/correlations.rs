use crate::models::CorrelationAlert;
use crate::ui::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_GREEN, COLOR_ACCENT_PURPLE,
    COLOR_ACCENT_RED, COLOR_BORDER, COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke, Ui};

/// Concentric threat tiers for radial correlation topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatTier {
    /// Outer Orbit: Probing / Threat Score < 50
    Probing,
    /// Middle Orbit: Active Attack / Score 50-80
    ActiveAttack,
    /// Inner Core Orbit: High Risk / Score > 80
    HighRisk,
}

impl ThreatTier {
    /// Classifies a threat score (0-100) into its concentric threat tier.
    pub fn from_score(score: u8) -> Self {
        if score > 80 {
            ThreatTier::HighRisk
        } else if score >= 50 {
            ThreatTier::ActiveAttack
        } else {
            ThreatTier::Probing
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ThreatTier::Probing => "Sondagem (Probing)",
            ThreatTier::ActiveAttack => "Ataque Ativo (Active Attack)",
            ThreatTier::HighRisk => "Alto Risco (High Risk)",
        }
    }

    pub fn orbit_name(&self) -> &'static str {
        match self {
            ThreatTier::Probing => "Órbita Externa (Probing)",
            ThreatTier::ActiveAttack => "Órbita Média (Ataque Ativo)",
            ThreatTier::HighRisk => "Órbita do Núcleo (Alto Risco)",
        }
    }

    pub fn hud_label(&self) -> &'static str {
        match self {
            ThreatTier::Probing => "ÓRBITA EXTERNA: SONDAGEM (<50)",
            ThreatTier::ActiveAttack => "ÓRBITA MÉDIA: ATAQUE ATIVO (50-80)",
            ThreatTier::HighRisk => "ÓRBITA DO NÚCLEO: ALTO RISCO (>80)",
        }
    }

    /// Radius multiplier relative to base canvas radius.
    /// Inner Core (High Risk) is closest to center (0.48), Middle is standard (0.85), Outer is wide (1.25).
    pub fn radius_multiplier(&self) -> f32 {
        match self {
            ThreatTier::HighRisk => 0.48,
            ThreatTier::ActiveAttack => 0.85,
            ThreatTier::Probing => 1.25,
        }
    }

    pub fn color(&self) -> Color32 {
        match self {
            ThreatTier::HighRisk => COLOR_ACCENT_RED,
            ThreatTier::ActiveAttack => COLOR_ACCENT_AMBER,
            ThreatTier::Probing => COLOR_ACCENT_CYAN,
        }
    }

    pub fn badge_bg(&self) -> Color32 {
        match self {
            ThreatTier::HighRisk => Color32::from_rgb(45, 15, 20),
            ThreatTier::ActiveAttack => Color32::from_rgb(45, 35, 15),
            ThreatTier::Probing => Color32::from_rgb(15, 35, 45),
        }
    }
}

/// Target selection for interactive detail card inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InspectTarget {
    Attacker,
    Sensor(usize),
}

/// Returns the orbit radius for a specific threat tier based on base radius.
pub fn calculate_tier_radius(base_radius: f32, tier: ThreatTier) -> f32 {
    base_radius * tier.radius_multiplier()
}

/// Returns the orbit radius corresponding to a threat score (0-100) based on base radius.
pub fn calculate_orbit_radius(base_radius: f32, threat_score: u8) -> f32 {
    let tier = ThreatTier::from_score(threat_score);
    calculate_tier_radius(base_radius, tier)
}

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

/// Distributes `count` target nodes along the orbit corresponding to `threat_score`.
pub fn calculate_radial_positions_for_threat(
    center: egui::Pos2,
    base_radius: f32,
    threat_score: u8,
    count: usize,
) -> Vec<egui::Pos2> {
    let radius = calculate_orbit_radius(base_radius, threat_score);
    calculate_radial_node_positions(center, radius, count)
}

/// Validates whether a node position (with given visual clearance radius) lies entirely within bounds.
pub fn is_node_within_bounds(pos: egui::Pos2, bounds: egui::Rect, node_radius: f32) -> bool {
    let inner = bounds.shrink(node_radius);
    inner.contains(pos)
}

/// Clamps a node position to ensure it stays within bounds respecting a safety margin.
pub fn clamp_node_position(pos: egui::Pos2, bounds: egui::Rect, margin: f32) -> egui::Pos2 {
    egui::pos2(
        pos.x.clamp(bounds.min.x + margin, bounds.max.x - margin),
        pos.y.clamp(bounds.min.y + margin, bounds.max.y - margin),
    )
}

/// Computes a safe base radius ensuring all concentric threat orbits stay inside bounds.
pub fn calculate_safe_base_radius(bounds: egui::Rect, padding: f32) -> f32 {
    let max_radius = ((bounds.height() * 0.5) - padding)
        .min((bounds.width() * 0.5) - padding)
        .max(20.0);
    let computed = max_radius / ThreatTier::Probing.radius_multiplier();
    computed.clamp(45.0, 115.0)
}

/// Extracts shared MITRE ATT&CK techniques associated with this correlation incident.
pub fn get_shared_mitre_techniques(alert: &CorrelationAlert) -> Vec<(&'static str, &'static str)> {
    let mut techniques = Vec::new();

    // 1. Multi-node correlated reconnaissance / scanning
    if alert.nodes_targeted.len() >= 2 {
        techniques.push(("T1046", "Network Service Discovery / Scanning"));
    }

    // 2. High hit count indicates automated brute force or aggressive probing
    if alert.total_hits >= 5 {
        techniques.push(("T1110", "Brute Force"));
    }

    // 3. Service-specific techniques
    for svc in &alert.targeted_services {
        let s_upper = svc.to_uppercase();
        if s_upper.contains("SSH") {
            let item = ("T1110.001", "Brute Force: Password Guessing");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        } else if s_upper.contains("HTTP") || s_upper.contains("WEB") || s_upper.contains("API") {
            let item = ("T1190", "Exploit Public-Facing Application");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        } else if s_upper.contains("RDP") {
            let item = ("T1021.001", "Remote Services: Remote Desktop Protocol");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        } else if s_upper.contains("SMB") {
            let item = ("T1021.002", "Remote Services: SMB/Windows Admin Shares");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        } else if s_upper.contains("DNS") {
            let item = ("T1071.004", "Application Layer Protocol: DNS");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        } else if s_upper.contains("FTP") {
            let item = ("T1048", "Exfiltration Over Alternative Protocol");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        } else if s_upper.contains("TELNET") {
            let item = ("T1021.004", "Remote Services: Telnet");
            if !techniques.contains(&item) {
                techniques.push(item);
            }
        }
    }

    if techniques.is_empty() {
        techniques.push(("T1046", "Network Service Discovery"));
    }

    techniques
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

    let canvas_size = egui::vec2(ui.available_width(), 285.0f32);
    let (response, painter) = ui.allocate_painter(canvas_size, egui::Sense::click());
    let rect = response.rect;

    if rect.width() < 10.0f32 || rect.height() < 10.0f32 {
        return;
    }

    // 1. Dark SOC canvas background & border
    painter.rect_filled(rect, 6.0f32, Color32::from_rgb(10, 14, 20));
    painter.rect_stroke(rect, 6.0f32, Stroke::new(1.0f32, COLOR_BORDER));

    let active_tier = ThreatTier::from_score(alert.threat_score);
    let mitre_techniques = get_shared_mitre_techniques(alert);

    // Canvas Header HUD
    painter.text(
        rect.min + egui::vec2(14.0f32, 12.0f32),
        egui::Align2::LEFT_TOP,
        "GRAFO RADIAL DE ATAQUE // TOPOLOGIA DISTRIBUÍDA",
        egui::FontId::proportional(10.5f32),
        COLOR_TEXT_MUTED,
    );

    let hud_status = format!(
        "[{}]  ALVOS: {} NÓS",
        active_tier.orbit_name().to_uppercase(),
        alert.nodes_targeted.len()
    );
    painter.text(
        rect.right_top() + egui::vec2(-14.0f32, 12.0f32),
        egui::Align2::RIGHT_TOP,
        hud_status,
        egui::FontId::proportional(10.5f32),
        active_tier.color(),
    );

    let center = rect.center();
    let base_radius = calculate_safe_base_radius(rect, 34.0f32);
    let time = ui.input(|i| i.time) as f32;

    // 2. Concentric Threat Orbit Rings
    // Outer Orbit: Probing / Threat Score < 50
    // Middle Orbit: Active Attack / Score 50-80
    // Inner Core Orbit: High Risk / Score > 80
    let tiers = [
        ThreatTier::HighRisk,
        ThreatTier::ActiveAttack,
        ThreatTier::Probing,
    ];

    for tier in &tiers {
        let r = calculate_tier_radius(base_radius, *tier);
        let is_active = *tier == active_tier;
        let c = tier.color();

        if is_active {
            // Glowing aura for the active threat orbit ring
            let glow_alpha = (45.0f32 + (time * 3.0f32).sin().abs() * 35.0f32) as u8;
            painter.circle_stroke(
                center,
                r,
                Stroke::new(3.2f32, Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), glow_alpha)),
            );
            painter.circle_stroke(center, r, Stroke::new(1.8f32, c));

            // Orbiting accent tick / beacon along active orbit
            let tick_angle = time * 0.8f32;
            let tick_pos = egui::pos2(center.x + r * tick_angle.cos(), center.y + r * tick_angle.sin());
            painter.circle_filled(tick_pos, 3.5f32, c);
            painter.circle_filled(tick_pos, 1.8f32, Color32::WHITE);
        } else {
            // Subtle concentric reference orbit
            painter.circle_stroke(
                center,
                r,
                Stroke::new(0.7f32, Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 40)),
            );
        }

        // Concentric Orbit HUD Label along top edge of ring
        let label_pos = egui::pos2(center.x + r * 0.55f32, center.y - r * 0.83f32);
        if label_pos.x > rect.min.x + 20.0f32 && label_pos.x < rect.max.x - 20.0f32 && label_pos.y > rect.min.y + 24.0f32 {
            painter.text(
                label_pos,
                egui::Align2::LEFT_CENTER,
                tier.hud_label(),
                egui::FontId::monospace(8.0f32),
                if is_active { c } else { Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), 100) },
            );
        }
    }

    // Subtle Crosshair Axes
    let crosshair_stroke = Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 50));
    let max_orbit_r = calculate_tier_radius(base_radius, ThreatTier::Probing) + 12.0f32;
    painter.line_segment(
        [egui::pos2(center.x - max_orbit_r, center.y), egui::pos2(center.x + max_orbit_r, center.y)],
        crosshair_stroke,
    );
    painter.line_segment(
        [egui::pos2(center.x, center.y - max_orbit_r), egui::pos2(center.x, center.y + max_orbit_r)],
        crosshair_stroke,
    );

    // Radar rings expanding from center attacker beacon
    for ring_i in 0..3 {
        let phase = (time * 0.65f32 + (ring_i as f32) * 0.33f32).fract();
        let ring_r = 16.0f32 + phase * (max_orbit_r - 16.0f32);
        let alpha = ((1.0f32 - phase) * 110.0f32) as u8;
        painter.circle_stroke(
            center,
            ring_r,
            Stroke::new(
                1.0f32,
                Color32::from_rgba_unmultiplied(active_tier.color().r(), active_tier.color().g(), active_tier.color().b(), alpha),
            ),
        );
    }

    // Calculate Orbiting Target Node Positions along the active threat orbit ring
    let active_radius = calculate_orbit_radius(base_radius, alert.threat_score);
    let raw_positions = calculate_radial_node_positions(center, active_radius, alert.nodes_targeted.len());
    let target_positions: Vec<egui::Pos2> = raw_positions
        .into_iter()
        .map(|p| clamp_node_position(p, rect, 24.0f32))
        .collect();

    // 3. Connecting vectors: Pulsating animated edges between attacker nodes and correlated sensors
    let count_targets = alert.nodes_targeted.len().max(1);
    for (i, node_pos) in target_positions.iter().enumerate() {
        let diff = *node_pos - center;
        let diff_len = (diff.x * diff.x + diff.y * diff.y).sqrt();
        let dir = if diff_len > 0.001f32 {
            diff / diff_len
        } else {
            egui::vec2(0.0f32, -1.0f32)
        };

        // Pulsating animated edge glow and core beam
        let edge_pulse = (time * 3.5f32 + (i as f32) * 1.3f32).sin() * 0.5f32 + 0.5f32;
        let pulse_alpha = (45.0f32 + edge_pulse * 85.0f32) as u8;
        let beam_color = active_tier.color();

        // Wide pulsating outer glow
        painter.line_segment(
            [center, *node_pos],
            Stroke::new(
                2.2f32 + edge_pulse * 2.6f32,
                Color32::from_rgba_unmultiplied(beam_color.r(), beam_color.g(), beam_color.b(), pulse_alpha),
            ),
        );
        // Bright core laser stroke
        painter.line_segment(
            [center, *node_pos],
            Stroke::new(
                1.1f32 + edge_pulse * 0.5f32,
                Color32::from_rgba_unmultiplied(255, 230, 230, (170.0f32 + edge_pulse * 80.0f32) as u8),
            ),
        );

        // Animated pulsating laser attack packets / bolts flowing along edge
        let laser_prog = (time * 1.35f32 + (i as f32) / (count_targets as f32)).fract();
        let pulse_pos = center + diff * laser_prog;
        painter.circle_filled(
            pulse_pos,
            4.8f32 + edge_pulse * 1.4f32,
            Color32::from_rgba_unmultiplied(beam_color.r(), beam_color.g(), beam_color.b(), 190),
        );
        painter.circle_filled(pulse_pos, 2.2f32, Color32::WHITE);

        let trail_len = (18.0f32 * laser_prog).min(16.0f32);
        painter.line_segment(
            [pulse_pos - dir * trail_len, pulse_pos],
            Stroke::new(2.4f32, Color32::from_rgba_unmultiplied(beam_color.r(), beam_color.g(), beam_color.b(), 220)),
        );

        // Pulsing impact ripple burst when energy packet arrives at sensor node
        if laser_prog > 0.82f32 {
            let impact_t = (laser_prog - 0.82f32) / 0.18f32;
            let impact_r = 7.0f32 + impact_t * 14.0f32;
            let impact_alpha = ((1.0f32 - impact_t) * 190.0f32) as u8;
            painter.circle_stroke(
                *node_pos,
                impact_r,
                Stroke::new(
                    1.4f32 * (1.0f32 - impact_t),
                    Color32::from_rgba_unmultiplied(beam_color.r(), beam_color.g(), beam_color.b(), impact_alpha),
                ),
            );
        }

        // Targeted Service badge centered on the edge
        let service_label = if alert.targeted_services.is_empty() {
            "PROBE".to_string()
        } else {
            alert.targeted_services[i % alert.targeted_services.len()].clone()
        };
        let mid_pos = center + diff * 0.50f32;
        let badge_w = service_label.len() as f32 * 6.5f32 + 10.0f32;
        let badge_rect = egui::Rect::from_center_size(mid_pos, egui::vec2(badge_w, 15.0f32));
        painter.rect_filled(badge_rect, 3.0f32, Color32::from_rgb(30, 20, 35));
        painter.rect_stroke(badge_rect, 3.0f32, Stroke::new(1.0f32, COLOR_ACCENT_PURPLE));
        painter.text(
            mid_pos,
            egui::Align2::CENTER_CENTER,
            &service_label,
            egui::FontId::monospace(9.0f32),
            COLOR_ACCENT_PURPLE,
        );
    }

    // 4. Orbiting nodes: Targeted agent sensor nodes drawn in emerald green
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

        // Node label positioned outward with subtle background pill for legibility
        let label_pos = *node_pos + dir * 20.0f32;
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
            egui::FontId::proportional(10.5f32),
            COLOR_ACCENT_GREEN,
        );
    }

    // 5. Center node: Attacker IP in a glowing red pulsing beacon with threat score badge
    let beacon_pulse = (time * 3.0f32).sin() * 0.5f32 + 0.5f32;
    painter.circle_filled(
        center,
        25.0f32 + beacon_pulse * 6.0f32,
        Color32::from_rgba_unmultiplied(active_tier.color().r(), active_tier.color().g(), active_tier.color().b(), 35 + (beacon_pulse * 30.0f32) as u8),
    );
    painter.circle_filled(
        center,
        16.0f32 + beacon_pulse * 3.0f32,
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
    let score_pos = center + egui::vec2(0.0f32, -26.0f32);
    let score_text = format!("PERIGO: {}/100", alert.threat_score);
    let score_w = score_text.len() as f32 * 6.0f32 + 12.0f32;
    let score_rect = egui::Rect::from_center_size(score_pos, egui::vec2(score_w, 15.0f32));
    painter.rect_filled(score_rect, 3.0f32, active_tier.badge_bg());
    painter.rect_stroke(score_rect, 3.0f32, Stroke::new(1.0f32, active_tier.color()));
    painter.text(
        score_pos,
        egui::Align2::CENTER_CENTER,
        &score_text,
        egui::FontId::proportional(9.0f32),
        active_tier.color(),
    );

    // Attacker IP (below center beacon)
    let ip_pos = center + egui::vec2(0.0f32, 26.0f32);
    let ip_text = &alert.attacker_ip;
    let ip_w = ip_text.len() as f32 * 7.5f32 + 16.0f32;
    let ip_rect = egui::Rect::from_center_size(ip_pos, egui::vec2(ip_w, 18.0f32));
    painter.rect_filled(ip_rect, 4.0f32, Color32::from_rgb(32, 15, 20));
    painter.rect_stroke(ip_rect, 4.0f32, Stroke::new(1.0f32, COLOR_ACCENT_RED));
    painter.text(
        ip_pos,
        egui::Align2::CENTER_CENTER,
        ip_text,
        egui::FontId::monospace(10.5f32),
        Color32::WHITE,
    );

    // 6. Interactive Click Selection for Persistent Detail Card
    let inspect_state_id = ui.id().with("selected_radial_node_inspect_target");
    let mut selected_target: Option<InspectTarget> = ui.data_mut(|d| d.get_temp(inspect_state_id));

    if response.clicked() {
        if let Some(mouse) = response.interact_pointer_pos() {
            if mouse.distance(center) <= 30.0f32 || ip_rect.contains(mouse) || score_rect.contains(mouse) {
                // Click on attacker toggles attacker inspection & copies IP
                selected_target = if selected_target == Some(InspectTarget::Attacker) {
                    None
                } else {
                    Some(InspectTarget::Attacker)
                };
                ui.output_mut(|o| o.copied_text = alert.attacker_ip.clone());
                *toast_msg = Some((
                    format!("Invasor {} inspecionado (IP copiado)", alert.attacker_ip),
                    std::time::Instant::now(),
                ));
            } else {
                let mut hit_sensor = false;
                for (i, node_pos) in target_positions.iter().enumerate() {
                    if mouse.distance(*node_pos) <= 22.0f32 {
                        selected_target = if selected_target == Some(InspectTarget::Sensor(i)) {
                            None
                        } else {
                            Some(InspectTarget::Sensor(i))
                        };
                        let node_name = &alert.nodes_targeted[i];
                        *toast_msg = Some((
                            format!("Foco de inspeção no sensor: {}", node_name),
                            std::time::Instant::now(),
                        ));
                        hit_sensor = true;
                        break;
                    }
                }
                if !hit_sensor {
                    // Click on background clears selection
                    selected_target = None;
                }
            }
            ui.data_mut(|d| d.insert_temp(inspect_state_id, selected_target));
        }
    }

    // 7. Interactive Persistent Node Detail Card on Canvas Overlay (when clicked/selected)
    if let Some(target) = selected_target {
        let card_w = 230.0f32;
        let card_h = 105.0f32;
        let card_pos = egui::pos2(rect.max.x - card_w - 10.0f32, rect.max.y - card_h - 10.0f32);
        let card_rect = egui::Rect::from_min_size(card_pos, egui::vec2(card_w, card_h));

        // Glassmorphism card frame
        painter.rect_filled(card_rect, 6.0f32, Color32::from_rgba_unmultiplied(12, 16, 24, 235));
        painter.rect_stroke(card_rect, 6.0f32, Stroke::new(1.2f32, active_tier.color()));

        match target {
            InspectTarget::Attacker => {
                // Header badge
                painter.text(
                    card_pos + egui::vec2(10.0f32, 8.0f32),
                    egui::Align2::LEFT_TOP,
                    "INVASOR CORRELACIONADO (IOC)",
                    egui::FontId::proportional(9.5f32),
                    active_tier.color(),
                );
                // IP & Threat badge
                painter.text(
                    card_pos + egui::vec2(10.0f32, 24.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("IP: {}", alert.attacker_ip),
                    egui::FontId::monospace(11.0f32),
                    Color32::WHITE,
                );
                painter.text(
                    card_pos + egui::vec2(10.0f32, 40.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("Perigo: {}/100 ({})", alert.threat_score, active_tier.label()),
                    egui::FontId::proportional(10.0f32),
                    active_tier.color(),
                );
                // Affected sensor node count
                painter.text(
                    card_pos + egui::vec2(10.0f32, 56.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("Sensores Afetados: {} nós", alert.nodes_targeted.len()),
                    egui::FontId::proportional(10.0f32),
                    COLOR_ACCENT_CYAN,
                );
                // Shared MITRE techniques
                let mitre_summary: Vec<&str> = mitre_techniques.iter().map(|(id, _)| *id).collect();
                painter.text(
                    card_pos + egui::vec2(10.0f32, 72.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("MITRE ATT&CK: {}", mitre_summary.join(", ")),
                    egui::FontId::monospace(9.5f32),
                    COLOR_ACCENT_PURPLE,
                );
                painter.text(
                    card_pos + egui::vec2(10.0f32, 88.0f32),
                    egui::Align2::LEFT_TOP,
                    "(Clique novamente no nó para fechar)",
                    egui::FontId::proportional(8.5f32),
                    COLOR_TEXT_MUTED,
                );
            }
            InspectTarget::Sensor(idx) => {
                let sensor_name = alert.nodes_targeted.get(idx).cloned().unwrap_or_else(|| "Desconhecido".to_string());
                painter.text(
                    card_pos + egui::vec2(10.0f32, 8.0f32),
                    egui::Align2::LEFT_TOP,
                    "NÓ SENSOR SENTINELA (ALVO)",
                    egui::FontId::proportional(9.5f32),
                    COLOR_ACCENT_GREEN,
                );
                painter.text(
                    card_pos + egui::vec2(10.0f32, 24.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("Host: {}", sensor_name),
                    egui::FontId::monospace(11.0f32),
                    Color32::WHITE,
                );
                painter.text(
                    card_pos + egui::vec2(10.0f32, 40.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("Cluster: Nó {} de {} afetados", idx + 1, alert.nodes_targeted.len()),
                    egui::FontId::proportional(10.0f32),
                    COLOR_ACCENT_CYAN,
                );
                painter.text(
                    card_pos + egui::vec2(10.0f32, 56.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("Nível de Perigo: {}/100", alert.threat_score),
                    egui::FontId::proportional(10.0f32),
                    active_tier.color(),
                );
                let mitre_summary: Vec<&str> = mitre_techniques.iter().map(|(id, _)| *id).collect();
                painter.text(
                    card_pos + egui::vec2(10.0f32, 72.0f32),
                    egui::Align2::LEFT_TOP,
                    format!("MITRE ATT&CK: {}", mitre_summary.join(", ")),
                    egui::FontId::monospace(9.5f32),
                    COLOR_ACCENT_PURPLE,
                );
                painter.text(
                    card_pos + egui::vec2(10.0f32, 88.0f32),
                    egui::Align2::LEFT_TOP,
                    "(Clique novamente no nó para fechar)",
                    egui::FontId::proportional(8.5f32),
                    COLOR_TEXT_MUTED,
                );
            }
        }
    }

    // 8. Interactive Hover Tooltip Cards
    response.on_hover_ui(|ui| {
        if let Some(mouse) = ui.input(|i| i.pointer.hover_pos()) {
            if mouse.distance(center) <= 30.0f32 || ip_rect.contains(mouse) || score_rect.contains(mouse) {
                // Attacker Detail Hover Card
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🚨").size(16.0f32));
                    ui.label(
                        RichText::new(format!("Atacante Coordenado: {}", alert.attacker_ip))
                            .strong()
                            .color(COLOR_ACCENT_RED),
                    );
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Threat Score:");
                    egui::Frame::none()
                        .fill(active_tier.badge_bg())
                        .stroke(Stroke::new(1.0f32, active_tier.color()))
                        .inner_margin(egui::vec2(6.0f32, 2.0f32))
                        .rounding(3.0f32)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("{}/100 • {}", alert.threat_score, active_tier.label()))
                                    .size(10.0f32)
                                    .strong()
                                    .color(active_tier.color()),
                            );
                        });
                });
                ui.label(format!("Órbita de Ameaça: {}", active_tier.orbit_name()));
                ui.label(format!("Nós Sensores Afetados: {} nós ({})", alert.nodes_targeted.len(), alert.nodes_targeted.join(", ")));
                ui.label(format!("Hits Agregados: {}", alert.total_hits));
                ui.label(format!("Janela Temporal: {} → {}", alert.first_seen, alert.last_seen));

                ui.add_space(4.0f32);
                ui.label(RichText::new("Técnicas MITRE ATT&CK Partilhadas:").strong().color(COLOR_ACCENT_PURPLE));
                for (tech_id, tech_name) in &mitre_techniques {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(*tech_id).monospace().strong().color(COLOR_ACCENT_PURPLE));
                        ui.label(RichText::new(*tech_name).color(Color32::WHITE));
                    });
                }
                ui.add_space(2.0f32);
                ui.label(
                    RichText::new("(Clique para selecionar ou copiar o IP)")
                        .size(10.0f32)
                        .color(COLOR_TEXT_MUTED),
                );
            } else {
                let mut hovered_node = None;
                for (i, node_pos) in target_positions.iter().enumerate() {
                    if mouse.distance(*node_pos) <= 22.0f32 {
                        hovered_node = Some((i, &alert.nodes_targeted[i]));
                        break;
                    }
                }
                if let Some((idx, node)) = hovered_node {
                    // Sensor Node Detail Hover Card
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("🖥️").size(16.0f32));
                        ui.label(
                            RichText::new(format!("Nó Sentinela Alvo: {}", node))
                                .strong()
                                .color(COLOR_ACCENT_GREEN),
                        );
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Nível de Perigo:");
                        egui::Frame::none()
                            .fill(active_tier.badge_bg())
                            .stroke(Stroke::new(1.0f32, active_tier.color()))
                            .inner_margin(egui::vec2(6.0f32, 2.0f32))
                            .rounding(3.0f32)
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(format!("{}/100 • {}", alert.threat_score, active_tier.label()))
                                        .size(10.0f32)
                                        .strong()
                                        .color(active_tier.color()),
                                );
                            });
                    });
                    ui.label(format!("Cluster de Ataque: Nó {} de {} sensores afetados", idx + 1, alert.nodes_targeted.len()));
                    ui.label(format!("Serviços Atacados: {}", alert.targeted_services.join(", ")));
                    ui.label(format!("Invasor Origem: {}", alert.attacker_ip));

                    ui.add_space(4.0f32);
                    ui.label(RichText::new("Técnicas MITRE ATT&CK:").strong().color(COLOR_ACCENT_PURPLE));
                    for (tech_id, tech_name) in &mitre_techniques {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(*tech_id).monospace().strong().color(COLOR_ACCENT_PURPLE));
                            ui.label(RichText::new(*tech_name).color(Color32::WHITE));
                        });
                    }
                    ui.add_space(2.0f32);
                    ui.label(
                        RichText::new("(Clique no nó sensor para fixar detalhes no ecrã)")
                            .size(10.0f32)
                            .color(COLOR_TEXT_MUTED),
                    );
                } else {
                    ui.label(RichText::new("Grafo Radial de Correlação SIEM").strong());
                    ui.label(format!("Órbita Ativa: {} (Score {}/100)", active_tier.orbit_name(), alert.threat_score));
                    ui.label(format!("Sensores Afetados: {} nós em monitorização", alert.nodes_targeted.len()));
                    ui.label("Passe o cursor ou clique no atacante ou nós para inspecionar.");
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

    #[test]
    fn test_threat_tier_classification() {
        // Outer Orbit / Probing: Threat Score < 50
        assert_eq!(ThreatTier::from_score(0), ThreatTier::Probing);
        assert_eq!(ThreatTier::from_score(25), ThreatTier::Probing);
        assert_eq!(ThreatTier::from_score(49), ThreatTier::Probing);

        // Middle Orbit / Active Attack: Score 50-80
        assert_eq!(ThreatTier::from_score(50), ThreatTier::ActiveAttack);
        assert_eq!(ThreatTier::from_score(65), ThreatTier::ActiveAttack);
        assert_eq!(ThreatTier::from_score(80), ThreatTier::ActiveAttack);

        // Inner Core Orbit / High Risk: Score > 80
        assert_eq!(ThreatTier::from_score(81), ThreatTier::HighRisk);
        assert_eq!(ThreatTier::from_score(95), ThreatTier::HighRisk);
        assert_eq!(ThreatTier::from_score(100), ThreatTier::HighRisk);
    }

    #[test]
    fn test_radius_calculation_across_threat_tiers() {
        let base_radius = 100.0f32;

        let r_inner = calculate_tier_radius(base_radius, ThreatTier::HighRisk);
        let r_mid = calculate_tier_radius(base_radius, ThreatTier::ActiveAttack);
        let r_outer = calculate_tier_radius(base_radius, ThreatTier::Probing);

        // Verify tier hierarchy: Inner Core < Middle Orbit < Outer Orbit
        assert!(r_inner < r_mid, "Inner core orbit must be smaller than middle orbit");
        assert!(r_mid < r_outer, "Middle orbit must be smaller than outer orbit");

        // Verify exact multipliers
        assert!((r_inner - 48.0).abs() < 1e-4);
        assert!((r_mid - 85.0).abs() < 1e-4);
        assert!((r_outer - 125.0).abs() < 1e-4);

        // Verify calculate_orbit_radius mapping across score boundary points
        assert_eq!(calculate_orbit_radius(base_radius, 30), r_outer);
        assert_eq!(calculate_orbit_radius(base_radius, 49), r_outer);
        assert_eq!(calculate_orbit_radius(base_radius, 50), r_mid);
        assert_eq!(calculate_orbit_radius(base_radius, 80), r_mid);
        assert_eq!(calculate_orbit_radius(base_radius, 81), r_inner);
        assert_eq!(calculate_orbit_radius(base_radius, 99), r_inner);
    }

    #[test]
    fn test_node_coordinate_distribution_multi_counts() {
        let center = egui::pos2(300.0, 300.0);
        let base_radius = 80.0f32;

        for count in [1, 2, 3, 5, 8, 12] {
            let positions = calculate_radial_node_positions(center, base_radius, count);
            assert_eq!(positions.len(), count);

            // Verify each node is at base_radius distance
            for pos in &positions {
                let dist = pos.distance(center);
                assert!((dist - base_radius).abs() < 1e-3, "Distance should match radius");
            }

            // Verify angular separation between adjacent nodes
            if count > 1 {
                let expected_step = 2.0 * std::f32::consts::PI / (count as f32);
                for i in 0..count {
                    let next = (i + 1) % count;
                    let angle_i = (positions[i].y - center.y).atan2(positions[i].x - center.x);
                    let angle_next = (positions[next].y - center.y).atan2(positions[next].x - center.x);
                    let mut diff = angle_next - angle_i;
                    if diff < 0.0 {
                        diff += 2.0 * std::f32::consts::PI;
                    }
                    assert!(
                        (diff - expected_step).abs() < 1e-4,
                        "Angular step between {} and {} expected {}, got {}",
                        i,
                        next,
                        expected_step,
                        diff
                    );
                }
            }
        }
    }

    #[test]
    fn test_radial_positions_for_threat_tiers() {
        let center = egui::pos2(250.0, 200.0);
        let base_radius = 100.0f32;

        // Probing score (e.g. 40) should be at outer orbit (125.0)
        let pos_probing = calculate_radial_positions_for_threat(center, base_radius, 40, 3);
        assert_eq!(pos_probing.len(), 3);
        for p in &pos_probing {
            assert!((p.distance(center) - 125.0).abs() < 1e-3);
        }

        // Active Attack score (e.g. 70) should be at middle orbit (85.0)
        let pos_active = calculate_radial_positions_for_threat(center, base_radius, 70, 3);
        assert_eq!(pos_active.len(), 3);
        for p in &pos_active {
            assert!((p.distance(center) - 85.0).abs() < 1e-3);
        }

        // High Risk score (e.g. 95) should be at inner core orbit (48.0)
        let pos_high = calculate_radial_positions_for_threat(center, base_radius, 95, 3);
        assert_eq!(pos_high.len(), 3);
        for p in &pos_high {
            assert!((p.distance(center) - 48.0).abs() < 1e-3);
        }
    }

    #[test]
    fn test_node_bounds_checks_and_clamping() {
        let bounds = egui::Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(400.0, 300.0));
        let node_radius = 15.0f32;

        // Position squarely inside bounds
        let inside_pos = egui::pos2(300.0, 250.0);
        assert!(is_node_within_bounds(inside_pos, bounds, node_radius));

        // Position too close to left border (less than node_radius margin)
        let near_border_pos = egui::pos2(110.0, 250.0);
        assert!(!is_node_within_bounds(near_border_pos, bounds, node_radius));

        // Position completely outside bounds
        let outside_pos = egui::pos2(50.0, 250.0);
        assert!(!is_node_within_bounds(outside_pos, bounds, node_radius));

        // Clamping brings out-of-bounds position within margins
        let clamped = clamp_node_position(outside_pos, bounds, node_radius);
        assert_eq!(clamped.x, bounds.min.x + node_radius);
        assert_eq!(clamped.y, 250.0);
        assert!(is_node_within_bounds(clamped, bounds, node_radius));

        // Test clamping on all 4 corners
        let far_top_left = egui::pos2(0.0, 0.0);
        let clamped_tl = clamp_node_position(far_top_left, bounds, 10.0);
        assert_eq!(clamped_tl, egui::pos2(110.0, 110.0));

        let far_bottom_right = egui::pos2(1000.0, 1000.0);
        let clamped_br = clamp_node_position(far_bottom_right, bounds, 10.0);
        assert_eq!(clamped_br, egui::pos2(490.0, 390.0));
    }

    #[test]
    fn test_calculate_safe_base_radius() {
        let bounds = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(600.0, 280.0));
        let padding = 34.0f32;
        let safe_base = calculate_safe_base_radius(bounds, padding);

        // Ensure outermost orbit (multiplier 1.25) does not exceed height clearance
        let max_orbit = calculate_tier_radius(safe_base, ThreatTier::Probing);
        let max_allowed = (bounds.height() * 0.5) - padding;
        assert!(
            max_orbit <= max_allowed + 1e-2,
            "Max orbit {} should fit within max allowed {}",
            max_orbit,
            max_allowed
        );
    }

    #[test]
    fn test_shared_mitre_techniques_extraction() {
        let alert = CorrelationAlert {
            id: Some(1),
            attacker_ip: "198.51.100.99".to_string(),
            nodes_targeted: vec!["laptop-01".to_string(), "vps-oracle".to_string()],
            first_seen: "2026-11-13 10:00:00".to_string(),
            last_seen: "2026-11-13 10:05:00".to_string(),
            total_hits: 15,
            threat_score: 92,
            targeted_services: vec!["SSH".to_string(), "HTTP".to_string()],
        };

        let techniques = get_shared_mitre_techniques(&alert);

        // Must include multi-node discovery (T1046)
        assert!(techniques.iter().any(|(id, _)| *id == "T1046"));
        // Must include brute force for hits >= 5 (T1110)
        assert!(techniques.iter().any(|(id, _)| *id == "T1110"));
        // Must include SSH password guessing (T1110.001)
        assert!(techniques.iter().any(|(id, _)| *id == "T1110.001"));
        // Must include HTTP exploitation (T1190)
        assert!(techniques.iter().any(|(id, _)| *id == "T1190"));

        // No duplicates
        let mut seen = std::collections::HashSet::new();
        for (id, _) in &techniques {
            assert!(seen.insert(*id), "Duplicate technique {}", id);
        }
    }
}

