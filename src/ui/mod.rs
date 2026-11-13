pub mod header;
pub mod modal;
pub mod report;
pub mod sidebar;
pub mod views;

use egui::{Color32, Stroke, Visuals};

pub const COLOR_BG_DARK: Color32 = Color32::from_rgb(13, 17, 23); // #0D1117
pub const COLOR_PANEL_BG: Color32 = Color32::from_rgb(22, 27, 34); // #161B22
pub const COLOR_ACCENT_CYAN: Color32 = Color32::from_rgb(56, 189, 248); // #38BDF8
pub const COLOR_ACCENT_GREEN: Color32 = Color32::from_rgb(52, 211, 153); // #34D399
pub const COLOR_ACCENT_AMBER: Color32 = Color32::from_rgb(251, 191, 36); // #FBBF24
pub const COLOR_ACCENT_RED: Color32 = Color32::from_rgb(248, 113, 113); // #F87171
pub const COLOR_ACCENT_PURPLE: Color32 = Color32::from_rgb(192, 132, 252); // #C084FC
pub const COLOR_TEXT_MUTED: Color32 = Color32::from_rgb(139, 148, 158); // #8B949E
pub const COLOR_BORDER: Color32 = Color32::from_rgb(48, 54, 61); // #30363D

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SocTheme {
    #[default]
    CyberSlate,
    MatrixGreen,
    CrimsonSoc,
}

impl SocTheme {
    pub fn next(&self) -> Self {
        match self {
            SocTheme::CyberSlate => SocTheme::MatrixGreen,
            SocTheme::MatrixGreen => SocTheme::CrimsonSoc,
            SocTheme::CrimsonSoc => SocTheme::CyberSlate,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            SocTheme::CyberSlate => "Cyber Slate",
            SocTheme::MatrixGreen => "Matrix Green",
            SocTheme::CrimsonSoc => "Crimson SOC",
        }
    }
}

pub fn apply_soc_theme(ctx: &egui::Context, theme: SocTheme) {
    let mut visuals = Visuals::dark();
    match theme {
        SocTheme::CyberSlate => {
            // Default dark navy #0D1117, cyan #38BDF8, emerald #34D399
            visuals.override_text_color = Some(Color32::from_rgb(240, 246, 252));
            visuals.panel_fill = Color32::from_rgb(13, 17, 23);
            visuals.window_fill = Color32::from_rgb(22, 27, 34);
            visuals.faint_bg_color = Color32::from_rgb(27, 33, 41);
            visuals.extreme_bg_color = Color32::from_rgb(1, 4, 9);
            visuals.window_stroke = Stroke::new(1.0f32, Color32::from_rgb(48, 54, 61));
            visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(22, 27, 34);
            visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(48, 54, 61));
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(33, 38, 45);
            visuals.widgets.hovered.bg_fill = Color32::from_rgb(45, 52, 62);
            visuals.widgets.active.bg_fill = Color32::from_rgb(56, 64, 76);
        }
        SocTheme::MatrixGreen => {
            // Obsidian #050805, phosphor green #00FF66, dark green #0D2818
            visuals.override_text_color = Some(Color32::from_rgb(0, 255, 102));
            visuals.panel_fill = Color32::from_rgb(5, 8, 5);
            visuals.window_fill = Color32::from_rgb(13, 40, 24);
            visuals.faint_bg_color = Color32::from_rgb(9, 25, 15);
            visuals.extreme_bg_color = Color32::from_rgb(2, 4, 2);
            visuals.window_stroke = Stroke::new(1.0f32, Color32::from_rgb(0, 255, 102));
            visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(13, 40, 24);
            visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(0, 170, 68));
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(18, 52, 32);
            visuals.widgets.hovered.bg_fill = Color32::from_rgb(25, 75, 45);
            visuals.widgets.active.bg_fill = Color32::from_rgb(35, 100, 60);
        }
        SocTheme::CrimsonSoc => {
            // Black #0E0505, ruby red #FF3344, dark burgundy #2B0E11
            visuals.override_text_color = Some(Color32::from_rgb(255, 200, 205));
            visuals.panel_fill = Color32::from_rgb(14, 5, 5);
            visuals.window_fill = Color32::from_rgb(43, 14, 17);
            visuals.faint_bg_color = Color32::from_rgb(28, 9, 11);
            visuals.extreme_bg_color = Color32::from_rgb(6, 2, 2);
            visuals.window_stroke = Stroke::new(1.0f32, Color32::from_rgb(255, 51, 68));
            visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(43, 14, 17);
            visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, Color32::from_rgb(120, 25, 35));
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(55, 18, 22);
            visuals.widgets.hovered.bg_fill = Color32::from_rgb(80, 25, 30);
            visuals.widgets.active.bg_fill = Color32::from_rgb(110, 35, 42);
        }
    }
    ctx.set_visuals(visuals);
}

pub fn apply_cyber_theme(ctx: &egui::Context) {
    apply_soc_theme(ctx, SocTheme::CyberSlate);
}

pub fn severity_color(severity: &str) -> Color32 {
    match severity.to_uppercase().as_str() {
        "CRÍTICO" | "CRITICO" => COLOR_ACCENT_RED,
        "SWEEP" => COLOR_ACCENT_PURPLE,
        "MÉDIO" | "MEDIO" => COLOR_ACCENT_AMBER,
        "SCAN" => COLOR_ACCENT_CYAN,
        "ALERTA" => COLOR_ACCENT_GREEN,
        _ => COLOR_TEXT_MUTED,
    }
}

pub fn render_severity_pill(ui: &mut egui::Ui, severity: &str) {
    let color = severity_color(severity);
    let bg = Color32::from_rgba_unmultiplied(color.r(), color.g(), color.b(), 35);
    egui::Frame::none()
        .fill(bg)
        .stroke(Stroke::new(1.0f32, color))
        .rounding(10.0f32)
        .inner_margin(egui::vec2(8.0f32, 2.0f32))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(severity).size(10.0f32).strong().color(color));
        });
}

/// Renders a subtle pulsating red gradient vignette along the four borders of `rect`
/// when `intensity > 0.0f32` (e.g. after a CRÍTICO incident arrived recently)
/// to notify the SOC analyst visually.
pub fn render_alarm_vignette(painter: &egui::Painter, rect: egui::Rect, intensity: f32) {
    if intensity <= 0.0 || rect.width() <= 0.0 || rect.height() <= 0.0 {
        return;
    }

    let clamped = intensity.clamp(0.0, 1.0);
    // Depth of the vignette inwards from the edges
    let border_depth = (rect.height().min(rect.width()) * 0.08).clamp(16.0, 50.0);

    let max_alpha = (clamped * 180.0) as u8;
    if max_alpha == 0 {
        return;
    }

    let outer_col = Color32::from_rgba_unmultiplied(239, 68, 68, max_alpha);
    let inner_col = Color32::from_rgba_unmultiplied(239, 68, 68, 0);

    let mut mesh = egui::Mesh::default();

    let p0 = egui::pos2(rect.min.x, rect.min.y);
    let p1 = egui::pos2(rect.max.x, rect.min.y);
    let p2 = egui::pos2(rect.max.x, rect.max.y);
    let p3 = egui::pos2(rect.min.x, rect.max.y);

    let p4 = egui::pos2(rect.min.x + border_depth, rect.min.y + border_depth);
    let p5 = egui::pos2(rect.max.x - border_depth, rect.min.y + border_depth);
    let p6 = egui::pos2(rect.max.x - border_depth, rect.max.y - border_depth);
    let p7 = egui::pos2(rect.min.x + border_depth, rect.max.y - border_depth);

    let uv = egui::epaint::WHITE_UV;

    mesh.vertices.push(egui::epaint::Vertex {
        pos: p0,
        uv,
        color: outer_col,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: p1,
        uv,
        color: outer_col,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: p2,
        uv,
        color: outer_col,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: p3,
        uv,
        color: outer_col,
    });

    mesh.vertices.push(egui::epaint::Vertex {
        pos: p4,
        uv,
        color: inner_col,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: p5,
        uv,
        color: inner_col,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: p6,
        uv,
        color: inner_col,
    });
    mesh.vertices.push(egui::epaint::Vertex {
        pos: p7,
        uv,
        color: inner_col,
    });

    // Top trapezoid: 0, 1, 5, 4
    mesh.add_triangle(0, 1, 5);
    mesh.add_triangle(0, 5, 4);

    // Right trapezoid: 1, 2, 6, 5
    mesh.add_triangle(1, 2, 6);
    mesh.add_triangle(1, 6, 5);

    // Bottom trapezoid: 3, 6, 2 and 3, 7, 6
    mesh.add_triangle(3, 6, 2);
    mesh.add_triangle(3, 7, 6);

    // Left trapezoid: 0, 4, 7 and 0, 7, 3
    mesh.add_triangle(0, 4, 7);
    mesh.add_triangle(0, 7, 3);

    painter.add(egui::Shape::Mesh(mesh));

    // Outer subtle boundary stroke
    let stroke_alpha = (clamped * 200.0f32) as u8;
    painter.rect_stroke(
        rect,
        0.0f32,
        Stroke::new(1.5f32, Color32::from_rgba_unmultiplied(239, 68, 68, stroke_alpha)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soc_theme_cycle() {
        let theme = SocTheme::CyberSlate;
        let next1 = theme.next();
        assert_eq!(next1, SocTheme::MatrixGreen);
        let next2 = next1.next();
        assert_eq!(next2, SocTheme::CrimsonSoc);
        let next3 = next2.next();
        assert_eq!(next3, SocTheme::CyberSlate);
    }

    #[test]
    fn test_soc_theme_labels() {
        assert_eq!(SocTheme::CyberSlate.label(), "Cyber Slate");
        assert_eq!(SocTheme::MatrixGreen.label(), "Matrix Green");
        assert_eq!(SocTheme::CrimsonSoc.label(), "Crimson SOC");
    }

    #[test]
    fn test_apply_soc_theme() {
        let ctx = egui::Context::default();
        apply_soc_theme(&ctx, SocTheme::CyberSlate);
        apply_soc_theme(&ctx, SocTheme::MatrixGreen);
        apply_soc_theme(&ctx, SocTheme::CrimsonSoc);
    }

    #[test]
    fn test_render_alarm_vignette() {
        let ctx = egui::Context::default();
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let rect = egui::Rect::from_min_size(
                    egui::pos2(0.0, 0.0),
                    egui::vec2(800.0, 600.0),
                );
                let painter = ui.painter();
                // Test intensity <= 0.0 does not draw
                render_alarm_vignette(painter, rect, 0.0);
                render_alarm_vignette(painter, rect, -0.5);

                // Test intensity > 0.0 renders successfully
                render_alarm_vignette(painter, rect, 0.75);
                render_alarm_vignette(painter, rect, 1.0);
            });
        });
    }
}


