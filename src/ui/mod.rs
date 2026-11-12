pub mod header;
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

pub fn apply_cyber_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();
    visuals.override_text_color = Some(Color32::from_rgb(240, 246, 252));
    visuals.panel_fill = COLOR_BG_DARK;
    visuals.window_fill = COLOR_PANEL_BG;
    visuals.faint_bg_color = Color32::from_rgb(27, 33, 41);
    visuals.extreme_bg_color = Color32::from_rgb(1, 4, 9);
    visuals.window_stroke = Stroke::new(1.0f32, COLOR_BORDER);
    visuals.widgets.noninteractive.bg_fill = COLOR_PANEL_BG;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0f32, COLOR_BORDER);
    visuals.widgets.inactive.bg_fill = Color32::from_rgb(33, 38, 45);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(45, 52, 62);
    visuals.widgets.active.bg_fill = Color32::from_rgb(56, 64, 76);
    ctx.set_visuals(visuals);
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
