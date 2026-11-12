use crate::models::HubIncident;
use crate::ui::{
    severity_color, COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_PURPLE, COLOR_ACCENT_RED,
    COLOR_BORDER, COLOR_PANEL_BG, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke};

/// Formats a byte slice into canonical 16-byte aligned hexdump output:
/// `00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f  |SSH-2.0-OpenSSH_|`
pub fn format_hexdump(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let total_chunks = data.len().div_ceil(16);

    for (line_idx, chunk) in data.chunks(16).enumerate() {
        let offset = line_idx * 16;
        out.push_str(&format!("{:08x}  ", offset));

        // Format 16 hex byte columns with padding
        for j in 0..16 {
            if j < chunk.len() {
                out.push_str(&format!("{:02x}", chunk[j]));
            } else {
                out.push_str("  ");
            }

            if j == 7 {
                out.push_str("  ");
            } else if j < 15 {
                out.push(' ');
            }
        }

        // ASCII representation
        out.push_str("  |");
        for b in chunk {
            if (32..=126).contains(b) {
                out.push(*b as char);
            } else {
                out.push('.');
            }
        }
        out.push('|');

        if line_idx + 1 < total_chunks {
            out.push('\n');
        }
    }

    out
}

/// Evaluates incident parameters and tags the attack with MITRE ATT&CK Technique ID & Name.
pub fn map_to_mitre(
    service: &str,
    port: u16,
    severity: &str,
    payload: Option<&str>,
) -> (&'static str, &'static str) {
    // 1. Inspect payload for command injection or ransomware indicators
    if let Some(p) = payload {
        let p_lower = p.to_lowercase();
        if p_lower.contains("/bin/sh")
            || p_lower.contains("/bin/bash")
            || p_lower.contains("bash -c")
            || p_lower.contains("sh -c")
            || p_lower.contains("cmd.exe")
            || p_lower.contains("powershell")
            || p_lower.contains("eval(")
        {
            return ("T1059", "Command and Scripting Interpreter");
        }
        if p_lower.contains("ransom")
            || p_lower.contains("encrypt")
            || p_lower.contains(".locked")
            || p_lower.contains("decrypt")
        {
            return ("T1486", "Data Encrypted for Impact");
        }
    }

    // 2. Service and port-specific mappings
    let s_upper = service.to_uppercase();
    let sev_upper = severity.to_uppercase();

    if s_upper.contains("SWEEP") || sev_upper.contains("SWEEP") {
        ("T1018", "Remote System Discovery")
    } else if s_upper.contains("SCAN") || sev_upper.contains("SCAN") {
        ("T1046", "Network Service Scanning")
    } else if s_upper.contains("SSH") || port == 22 || port == 2222 {
        ("T1110.001", "Brute Force: Password Guessing")
    } else if s_upper.contains("DNS") || port == 53 {
        ("T1071.004", "Application Layer Protocol: DNS")
    } else if s_upper.contains("FTP") || port == 21 || s_upper.contains("EXFIL") {
        ("T1048", "Exfiltration Over Alternative Protocol")
    } else if s_upper.contains("SMB") || port == 445 || port == 139 {
        ("T1021.002", "Remote Services: SMB/Windows Admin Shares")
    } else if s_upper.contains("RDP") || port == 3389 {
        ("T1021.001", "Remote Services: Remote Desktop Protocol")
    } else if s_upper.contains("TELNET") || port == 23 {
        ("T1021.004", "Remote Services: Telnet")
    } else if s_upper.contains("HTTP")
        || s_upper.contains("WEB")
        || port == 80
        || port == 443
        || port == 8080
        || sev_upper.contains("CRIT")
    {
        ("T1190", "Exploit Public-Facing Application")
    } else {
        ("T1046", "Network Service Scanning")
    }
}

/// Renders the Forensic Raio-X Modal window anchored at center.
pub fn render_raio_x_modal(
    ctx: &egui::Context,
    incident: &HubIncident,
    close_modal: &mut bool,
    toast_msg: &mut Option<(String, std::time::Instant)>,
) {
    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
        *close_modal = true;
    }

    let mut is_open = true;

    egui::Window::new("🔬 RAIO-X FORENSE")
        .open(&mut is_open)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0f32, 0.0f32))
        .resizable(true)
        .collapsible(false)
        .default_width(640.0f32)
        .default_height(520.0f32)
        .show(ctx, |ui| {
            ui.spacing_mut().item_spacing = egui::vec2(8.0f32, 8.0f32);

            // 1. Header Information & Badges
            egui::Frame::none()
                .fill(COLOR_PANEL_BG)
                .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                .rounding(6.0f32)
                .inner_margin(10.0f32)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let id_str = match incident.id {
                            Some(id) => format!("#{}", id),
                            None => "Novo".to_string(),
                        };
                        ui.label(
                            RichText::new(format!("INCIDENTE {}", id_str))
                                .strong()
                                .size(14.0f32)
                                .color(COLOR_ACCENT_CYAN),
                        );

                        ui.separator();

                        ui.label(
                            RichText::new(format!("Nó: {}", incident.node_id))
                                .monospace()
                                .color(COLOR_TEXT_MUTED),
                        );

                        ui.separator();

                        ui.label(
                            RichText::new(&incident.timestamp)
                                .monospace()
                                .size(11.0f32)
                                .color(COLOR_TEXT_MUTED),
                        );
                    });

                    ui.add_space(6.0f32);

                    ui.horizontal(|ui| {
                        // Severity Pill Badge
                        let s_color = severity_color(&incident.severity);
                        egui::Frame::none()
                            .fill(s_color.linear_multiply(0.18f32))
                            .stroke(Stroke::new(1.0f32, s_color))
                            .rounding(4.0f32)
                            .inner_margin(egui::vec2(8.0f32, 3.0f32))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(&incident.severity)
                                        .size(11.0f32)
                                        .strong()
                                        .color(s_color),
                                );
                            });

                        // Threat Score Pill
                        let threat_color = if incident.threat_score >= 70 {
                            COLOR_ACCENT_RED
                        } else if incident.threat_score >= 40 {
                            COLOR_ACCENT_AMBER
                        } else {
                            COLOR_ACCENT_CYAN
                        };

                        egui::Frame::none()
                            .fill(threat_color.linear_multiply(0.18f32))
                            .stroke(Stroke::new(1.0f32, threat_color))
                            .rounding(4.0f32)
                            .inner_margin(egui::vec2(8.0f32, 3.0f32))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(format!("Threat Score: {}/100", incident.threat_score))
                                        .size(11.0f32)
                                        .strong()
                                        .color(threat_color),
                                );
                            });

                        ui.label(
                            RichText::new(format!("Total: {} ocorrência(s)", incident.hit_count))
                                .size(11.0f32)
                                .color(COLOR_TEXT_MUTED),
                        );
                    });
                });

            // 2. MITRE ATT&CK Attribution Card
            let (tech_id, tech_name) = map_to_mitre(
                &incident.service,
                incident.port,
                &incident.severity,
                incident.payload.as_deref(),
            );

            egui::Frame::none()
                .fill(Color32::from_rgb(20, 24, 33))
                .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                .rounding(6.0f32)
                .inner_margin(8.0f32)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("🎯 MITRE ATT&CK®:")
                                .strong()
                                .size(12.0f32)
                                .color(COLOR_ACCENT_PURPLE),
                        );

                        egui::Frame::none()
                            .fill(COLOR_ACCENT_PURPLE.linear_multiply(0.2f32))
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
                                .strong()
                                .size(12.0f32)
                                .color(Color32::from_rgb(220, 228, 238)),
                        );
                    });
                });

            // 3. Deep Network Attribution
            egui::Frame::none()
                .fill(COLOR_PANEL_BG)
                .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                .rounding(6.0f32)
                .inner_margin(10.0f32)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("🌐 Atribuição de Rede & Geolocalização")
                            .strong()
                            .color(COLOR_ACCENT_CYAN),
                    );

                    ui.add_space(4.0f32);

                    egui::Grid::new("raio_x_network_grid")
                        .num_columns(2)
                        .spacing([16.0f32, 6.0f32])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Atacante (IP):").color(COLOR_TEXT_MUTED));
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(&incident.ip)
                                        .monospace()
                                        .strong()
                                        .color(Color32::WHITE),
                                );
                                if let Some(ref rdns) = incident.rdns {
                                    ui.label(
                                        RichText::new(format!("({})", rdns))
                                            .monospace()
                                            .size(11.0f32)
                                            .color(COLOR_TEXT_MUTED),
                                    );
                                }
                            });
                            ui.end_row();

                            ui.label(RichText::new("Porta / Serviço:").color(COLOR_TEXT_MUTED));
                            ui.label(
                                RichText::new(format!("{}/{}", incident.port, incident.service))
                                    .monospace()
                                    .color(COLOR_ACCENT_AMBER),
                            );
                            ui.end_row();

                            ui.label(RichText::new("Localização:").color(COLOR_TEXT_MUTED));
                            let loc = if !incident.city.is_empty() {
                                format!("{}, {}", incident.city, incident.country)
                            } else {
                                incident.country.clone()
                            };
                            ui.label(RichText::new(loc).color(Color32::WHITE));
                            ui.end_row();

                            ui.label(RichText::new("ISP / Organização:").color(COLOR_TEXT_MUTED));
                            ui.label(RichText::new(&incident.isp).color(Color32::WHITE));
                            ui.end_row();
                        });
                });

            // 4. Payload Hexdump
            ui.label(
                RichText::new("📦 Inspecção de Payload Forense (Hexdump Canónico)")
                    .strong()
                    .color(COLOR_ACCENT_CYAN),
            );

            let payload_str = incident.payload.as_deref().unwrap_or("");
            if !payload_str.is_empty() {
                let dump = format_hexdump(payload_str.as_bytes());

                egui::Frame::none()
                    .fill(Color32::from_rgb(1, 4, 9))
                    .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                    .rounding(4.0f32)
                    .inner_margin(8.0f32)
                    .show(ui, |ui| {
                        egui::ScrollArea::both()
                            .max_height(160.0f32)
                            .auto_shrink([false, false])
                            .show(ui, |ui| {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(&dump)
                                            .monospace()
                                            .size(11.0f32)
                                            .color(Color32::from_rgb(201, 209, 217)),
                                    ),
                                );
                            });
                    });
            } else {
                egui::Frame::none()
                    .fill(Color32::from_rgb(1, 4, 9))
                    .stroke(Stroke::new(1.0f32, COLOR_BORDER))
                    .rounding(4.0f32)
                    .inner_margin(12.0f32)
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new("Nenhum payload capturado neste incidente.")
                                .italics()
                                .color(COLOR_TEXT_MUTED),
                        );
                    });
            }

            ui.add_space(4.0f32);

            // 5. Actions Footer
            ui.separator();
            ui.horizontal(|ui| {
                let ban_btn = ui.add(
                    egui::Button::new(
                        RichText::new("🚫 Banir IP")
                            .strong()
                            .color(COLOR_ACCENT_RED),
                    )
                    .fill(Color32::from_rgb(45, 20, 20)),
                );
                if ban_btn.clicked() {
                    let rule = format!("sudo iptables -A INPUT -s {} -j DROP", incident.ip);
                    ctx.output_mut(|o| o.copied_text = rule.clone());
                    *toast_msg = Some((
                        format!("Regra copiada: {}", rule),
                        std::time::Instant::now(),
                    ));
                }

                let copy_json_btn = ui.add(
                    egui::Button::new(
                        RichText::new("📋 Copiar JSON")
                            .color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(33, 38, 45)),
                );
                if copy_json_btn.clicked() {
                    if let Ok(json) = serde_json::to_string_pretty(incident) {
                        ctx.output_mut(|o| o.copied_text = json);
                        *toast_msg = Some((
                            "JSON do incidente copiado para o clipboard!".to_string(),
                            std::time::Instant::now(),
                        ));
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(RichText::new("✕ Fechar").color(Color32::WHITE)).clicked() {
                        *close_modal = true;
                    }
                });
            });
        });

    if !is_open {
        *close_modal = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hexdump_standard() {
        assert_eq!(format_hexdump(b""), "");

        let payload = b"SSH-2.0-OpenSSH_9.2p1";
        let dump = format_hexdump(payload);

        // Verify line 1 (16 bytes)
        assert!(dump.contains("00000000"));
        assert!(dump.contains("53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f"));
        assert!(dump.contains("|SSH-2.0-OpenSSH_|"));

        // Verify line 2 (5 bytes aligned)
        assert!(dump.contains("00000010"));
        assert!(dump.contains("39 2e 32 70 31"));
        assert!(dump.contains("|9.2p1|"));

        // Verify non-printable bytes replacement with '.'
        let binary_payload = [0x00, 0x01, 0x41, 0x7f, 0xff];
        let bin_dump = format_hexdump(&binary_payload);
        assert!(bin_dump.contains("00 01 41 7f ff"));
        assert!(bin_dump.contains("|..A..|"));
    }

    #[test]
    fn test_map_to_mitre_ssh_and_dns() {
        // SSH service should map to T1110.001
        let (tech_id, tech_name) = map_to_mitre("SSH", 22, "CRÍTICO", None);
        assert_eq!(tech_id, "T1110.001");
        assert!(tech_name.contains("Brute Force"));

        // Case insensitivity & port fallback
        let (tech_id_port, _) = map_to_mitre("unknown", 2222, "ALERTA", None);
        assert_eq!(tech_id_port, "T1110.001");

        // DNS service should map to T1071.004
        let (dns_id, dns_name) = map_to_mitre("DNS", 53, "MÉDIO", None);
        assert_eq!(dns_id, "T1071.004");
        assert!(dns_name.contains("DNS"));

        // Payload with shell script injection
        let (cmd_id, _) = map_to_mitre("HTTP", 80, "CRÍTICO", Some("/bin/bash -c id"));
        assert_eq!(cmd_id, "T1059");

        // Ransomware keyword
        let (ransom_id, _) = map_to_mitre("SMB", 445, "CRÍTICO", Some("WannaCry ransomware encryption key"));
        assert_eq!(ransom_id, "T1486");

        // Remote Discovery / Sweep
        let (sweep_id, _) = map_to_mitre("ICMP", 0, "SWEEP", None);
        assert_eq!(sweep_id, "T1018");

        // Port scanning
        let (scan_id, _) = map_to_mitre("SCAN", 8080, "SCAN", None);
        assert_eq!(scan_id, "T1046");
    }
}
