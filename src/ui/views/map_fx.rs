//! Dynamic visual effects for Sentinela Hub Threat Map.
//! Provides expanding impact shockwaves, missile tracer particles, and severity-coded FX management.

use egui::{Color32, Painter, Pos2, Stroke};
use std::time::{Duration, Instant};

/// Standard severity color constants.
pub const COLOR_CRIMSON: Color32 = Color32::from_rgb(220, 20, 60);
pub const COLOR_PULSING_CRIMSON: Color32 = COLOR_CRIMSON;
pub const COLOR_AMBER: Color32 = Color32::from_rgb(251, 191, 36);
pub const COLOR_CYAN: Color32 = Color32::from_rgb(56, 189, 248);

/// Resolves appropriate FX color according to severity level.
///
/// Palettes:
/// - Critical -> Pulsing crimson (`COLOR_CRIMSON`)
/// - High / Medium -> Amber (`COLOR_AMBER`)
/// - Normal / Low / Scan / Default -> Cyan (`COLOR_CYAN`)
pub fn color_for_severity(severity: &str) -> Color32 {
    let s = severity.trim().to_lowercase();
    if s.contains("crit") || s.contains("crít") {
        COLOR_CRIMSON
    } else if s.contains("high")
        || s.contains("alt")
        || s.contains("med")
        || s.contains("méd")
        || s.contains("warn")
    {
        COLOR_AMBER
    } else {
        COLOR_CYAN
    }
}

/// Represents an animated shockwave expanding outwards from an attack impact point on the Threat Map.
#[derive(Clone, Debug)]
pub struct ImpactShockwave {
    pub center: Pos2,
    pub radius: f32,
    pub max_radius: f32,
    pub color: Color32,
    pub created_at: Instant,
    pub duration: Duration,
}

impl ImpactShockwave {
    /// Creates a new `ImpactShockwave` initialized at zero radius.
    pub fn new(
        center: Pos2,
        max_radius: f32,
        color: Color32,
        created_at: Instant,
        duration: Duration,
    ) -> Self {
        Self {
            center,
            radius: 0.0,
            max_radius,
            color,
            created_at,
            duration,
        }
    }

    /// Updates the shockwave's radius based on elapsed time.
    ///
    /// Returns `true` while the effect is active, and `false` when expired.
    pub fn update(&mut self, now: Instant) -> bool {
        if now < self.created_at {
            self.radius = 0.0;
            return true;
        }
        let elapsed = now.duration_since(self.created_at);
        if elapsed >= self.duration {
            self.radius = self.max_radius;
            return false;
        }
        let progress = elapsed.as_secs_f32() / self.duration.as_secs_f32().max(0.0001);
        self.radius = self.max_radius * progress.clamp(0.0, 1.0);
        true
    }

    /// Renders the expanding shockwave ripple, secondary echo wave, and impact flash.
    pub fn paint(&self, painter: &Painter) {
        if self.max_radius <= 0.0 {
            return;
        }
        let progress = (self.radius / self.max_radius).clamp(0.0, 1.0);
        let alpha_factor = (1.0 - progress).clamp(0.0, 1.0);
        let base_alpha = (self.color.a() as f32 * alpha_factor) as u8;

        if base_alpha == 0 {
            return;
        }

        // Detect critical pulsing crimson to modulate ring vibrancy
        let is_crimson = self.color.r() > 180 && self.color.g() < 80;
        let ring_alpha = if is_crimson {
            let pulse = ((self.radius * 0.4).sin().abs() * 0.3 + 0.7).clamp(0.5, 1.0);
            ((base_alpha as f32 * pulse) as u8).min(255)
        } else {
            base_alpha
        };

        let ring_col = Color32::from_rgba_unmultiplied(
            self.color.r(),
            self.color.g(),
            self.color.b(),
            ring_alpha,
        );

        // 1. Primary outer shockwave boundary
        let stroke_width = (2.5f32 * (1.0f32 - progress * 0.5f32)).max(1.0f32);
        painter.circle_stroke(self.center, self.radius, Stroke::new(stroke_width, ring_col));

        // 2. Secondary inner echo wave
        if self.radius > 6.0f32 {
            let inner_r = self.radius * 0.65f32;
            let inner_alpha = (ring_alpha as f32 * 0.45f32) as u8;
            let inner_col = Color32::from_rgba_unmultiplied(
                self.color.r(),
                self.color.g(),
                self.color.b(),
                inner_alpha,
            );
            painter.circle_stroke(self.center, inner_r, Stroke::new(1.0f32, inner_col));
        }

        // 3. Bright core flash during initial 30% of lifespan
        if progress < 0.3f32 {
            let core_ratio = 1.0f32 - (progress / 0.3f32);
            let core_alpha = (core_ratio * 255.0f32) as u8;
            let core_radius = (4.0f32 * core_ratio).max(1.0f32);
            painter.circle_filled(
                self.center,
                core_radius,
                Color32::from_rgba_unmultiplied(255, 255, 255, core_alpha),
            );
        }
    }
}

/// Represents an animated ballistic missile / tracer particle traveling between two points.
#[derive(Clone, Debug)]
pub struct MissileTracer {
    pub start: Pos2,
    pub end: Pos2,
    pub ctrl: Pos2,
    pub current_pos: Pos2,
    pub color: Color32,
    pub head_radius: f32,
    pub created_at: Instant,
    pub duration: Duration,
    pub history: Vec<Pos2>,
}

impl MissileTracer {
    /// Creates a new `MissileTracer` trajectory.
    pub fn new(
        start: Pos2,
        end: Pos2,
        ctrl: Pos2,
        color: Color32,
        created_at: Instant,
        duration: Duration,
    ) -> Self {
        Self {
            start,
            end,
            ctrl,
            current_pos: start,
            color,
            head_radius: 3.5f32,
            created_at,
            duration,
            history: Vec::new(),
        }
    }

    /// Evaluates quadratic Bezier position: `B(t) = (1-t)^2 * P0 + 2*(1-t)*t * P1 + t^2 * P2`.
    fn eval_bezier(&self, t: f32) -> Pos2 {
        let t = t.clamp(0.0f32, 1.0f32);
        let one_minus_t = 1.0f32 - t;
        let x = one_minus_t * one_minus_t * self.start.x
            + 2.0f32 * one_minus_t * t * self.ctrl.x
            + t * t * self.end.x;
        let y = one_minus_t * one_minus_t * self.start.y
            + 2.0f32 * one_minus_t * t * self.ctrl.y
            + t * t * self.end.y;
        Pos2::new(x, y)
    }

    /// Updates the missile particle along its flight trajectory.
    ///
    /// Returns `true` while the missile is inflight, and `false` when target impact is reached.
    pub fn update(&mut self, now: Instant) -> bool {
        if now < self.created_at {
            self.current_pos = self.start;
            return true;
        }
        let elapsed = now.duration_since(self.created_at);
        if elapsed >= self.duration {
            self.current_pos = self.end;
            return false;
        }
        let t = elapsed.as_secs_f32() / self.duration.as_secs_f32().max(0.0001f32);
        self.current_pos = self.eval_bezier(t);
        self.history.push(self.current_pos);
        if self.history.len() > 10 {
            self.history.remove(0);
        }
        true
    }

    /// Paints the missile tracer head, glow halo, and trailing particle wake.
    pub fn paint(&self, painter: &Painter) {
        // Draw trailing wake particles
        let hist_len = self.history.len();
        for (i, &pos) in self.history.iter().enumerate() {
            let ratio = (i + 1) as f32 / hist_len as f32;
            let alpha = (self.color.a() as f32 * ratio * 0.6f32) as u8;
            let radius = self.head_radius * (0.3f32 + 0.6f32 * ratio);
            let trail_col = Color32::from_rgba_unmultiplied(
                self.color.r(),
                self.color.g(),
                self.color.b(),
                alpha,
            );
            painter.circle_filled(pos, radius, trail_col);
        }

        // Outer glow halo
        let halo_col = Color32::from_rgba_unmultiplied(
            self.color.r(),
            self.color.g(),
            self.color.b(),
            90,
        );
        painter.circle_filled(self.current_pos, self.head_radius * 1.8f32, halo_col);

        // Core warhead particle
        painter.circle_filled(self.current_pos, self.head_radius, self.color);

        // High-energy white core center
        painter.circle_filled(
            self.current_pos,
            (self.head_radius * 0.45f32).max(1.0f32),
            Color32::WHITE,
        );
    }
}

/// Central manager coordinating active shockwave ripples and missile tracer effects on the Threat Map.
#[derive(Clone, Debug, Default)]
pub struct MapFxManager {
    pub impacts: Vec<ImpactShockwave>,
    pub tracers: Vec<MissileTracer>,
}

impl MapFxManager {
    /// Creates a new empty `MapFxManager`.
    pub fn new() -> Self {
        Self {
            impacts: Vec::new(),
            tracers: Vec::new(),
        }
    }

    /// Resolves color palette matching severity.
    pub fn color_for_severity(severity: &str) -> Color32 {
        color_for_severity(severity)
    }

    /// Spawns a new impact shockwave at `pos` with visual parameters tuned to `severity`.
    pub fn add_impact(&mut self, pos: Pos2, severity: &str) {
        let color = Self::color_for_severity(severity);
        let s_lower = severity.to_lowercase();
        let (max_radius, duration) = if s_lower.contains("crit") || s_lower.contains("crít") {
            (45.0f32, Duration::from_millis(1500))
        } else if s_lower.contains("high")
            || s_lower.contains("alt")
            || s_lower.contains("med")
            || s_lower.contains("méd")
        {
            (32.0f32, Duration::from_millis(1200))
        } else {
            (22.0f32, Duration::from_millis(900))
        };

        self.impacts.push(ImpactShockwave::new(
            pos,
            max_radius,
            color,
            Instant::now(),
            duration,
        ));
    }

    /// Adds a shockwave with explicit parameters.
    pub fn add_impact_with_params(
        &mut self,
        pos: Pos2,
        max_radius: f32,
        color: Color32,
        created_at: Instant,
        duration: Duration,
    ) {
        self.impacts.push(ImpactShockwave::new(
            pos,
            max_radius,
            color,
            created_at,
            duration,
        ));
    }

    /// Adds a custom missile tracer.
    pub fn add_tracer(&mut self, tracer: MissileTracer) {
        self.tracers.push(tracer);
    }

    /// Spawns a missile tracer traveling along quadratic Bezier curve `(start, ctrl, end)`.
    pub fn add_missile(
        &mut self,
        start: Pos2,
        end: Pos2,
        ctrl: Pos2,
        severity: &str,
        duration: Duration,
    ) {
        let color = Self::color_for_severity(severity);
        self.tracers.push(MissileTracer::new(
            start,
            end,
            ctrl,
            color,
            Instant::now(),
            duration,
        ));
    }

    /// Updates internal animations and retains only active effects.
    pub fn update(&mut self, now: Instant) {
        self.impacts.retain_mut(|s| s.update(now));
        self.tracers.retain_mut(|t| t.update(now));
    }

    /// Updates all active effects to `now` and renders them to `painter`. Expired effects are pruned.
    pub fn update_and_paint(&mut self, painter: &Painter, now: Instant) {
        self.impacts.retain_mut(|shockwave| {
            let active = shockwave.update(now);
            if active {
                shockwave.paint(painter);
            }
            active
        });

        self.tracers.retain_mut(|tracer| {
            let active = tracer.update(now);
            if active {
                tracer.paint(painter);
            }
            active
        });
    }

    /// Returns `true` if there are no active shockwaves or tracers.
    pub fn is_empty(&self) -> bool {
        self.impacts.is_empty() && self.tracers.is_empty()
    }

    /// Clears all active effects immediately.
    pub fn clear(&mut self) {
        self.impacts.clear();
        self.tracers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shockwave_expansion_and_expiration() {
        let t0 = Instant::now();
        let duration = Duration::from_millis(1000);
        let max_radius = 50.0;
        let mut shockwave = ImpactShockwave {
            center: Pos2::new(100.0, 200.0),
            radius: 0.0,
            max_radius,
            color: COLOR_CYAN,
            created_at: t0,
            duration,
        };

        // Before or at t0: should be active with 0 radius
        assert!(shockwave.update(t0));
        assert_eq!(shockwave.radius, 0.0);

        // Halfway through duration: should be active and around half radius
        let t_mid = t0 + Duration::from_millis(500);
        assert!(shockwave.update(t_mid));
        assert!((shockwave.radius - 25.0).abs() < 1.0);

        // Quarter way
        let t_q = t0 + Duration::from_millis(250);
        assert!(shockwave.update(t_q));
        assert!((shockwave.radius - 12.5).abs() < 1.0);

        // At expiration: returns false
        let t_end = t0 + Duration::from_millis(1000);
        assert!(!shockwave.update(t_end));
        assert_eq!(shockwave.radius, max_radius);

        // After expiration: returns false
        let t_after = t0 + Duration::from_millis(1500);
        assert!(!shockwave.update(t_after));
    }

    #[test]
    fn test_color_selection_by_severity() {
        // Critical -> pulsing crimson
        assert_eq!(color_for_severity("Critical"), COLOR_CRIMSON);
        assert_eq!(color_for_severity("CRITICAL"), COLOR_CRIMSON);
        assert_eq!(color_for_severity("Crítico"), COLOR_CRIMSON);
        assert_eq!(color_for_severity("CRÍTICO"), COLOR_CRIMSON);
        assert_eq!(color_for_severity("critico"), COLOR_CRIMSON);

        // High -> amber
        assert_eq!(color_for_severity("High"), COLOR_AMBER);
        assert_eq!(color_for_severity("HIGH"), COLOR_AMBER);
        assert_eq!(color_for_severity("Alto"), COLOR_AMBER);
        assert_eq!(color_for_severity("ALTA"), COLOR_AMBER);
        assert_eq!(color_for_severity("MÉDIO"), COLOR_AMBER);
        assert_eq!(color_for_severity("medio"), COLOR_AMBER);
        assert_eq!(color_for_severity("Warning"), COLOR_AMBER);

        // Normal -> cyan
        assert_eq!(color_for_severity("Normal"), COLOR_CYAN);
        assert_eq!(color_for_severity("NORMAL"), COLOR_CYAN);
        assert_eq!(color_for_severity("Low"), COLOR_CYAN);
        assert_eq!(color_for_severity("SCAN"), COLOR_CYAN);
        assert_eq!(color_for_severity("Sweep"), COLOR_CYAN);
        assert_eq!(color_for_severity("unknown"), COLOR_CYAN);

        // MapFxManager static helper check
        assert_eq!(MapFxManager::color_for_severity("Critical"), COLOR_CRIMSON);
        assert_eq!(MapFxManager::color_for_severity("High"), COLOR_AMBER);
        assert_eq!(MapFxManager::color_for_severity("Normal"), COLOR_CYAN);
    }

    #[test]
    fn test_manager_lifecycle() {
        let mut manager = MapFxManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.impacts.len(), 0);

        let pos1 = Pos2::new(120.0, 240.0);
        manager.add_impact(pos1, "Critical");
        assert_eq!(manager.impacts.len(), 1);
        assert_eq!(manager.impacts[0].center, pos1);
        assert_eq!(manager.impacts[0].color, COLOR_CRIMSON);

        let pos2 = Pos2::new(300.0, 150.0);
        manager.add_impact(pos2, "High");
        assert_eq!(manager.impacts.len(), 2);
        assert_eq!(manager.impacts[1].color, COLOR_AMBER);

        let pos3 = Pos2::new(450.0, 380.0);
        manager.add_impact(pos3, "Normal");
        assert_eq!(manager.impacts.len(), 3);
        assert_eq!(manager.impacts[2].color, COLOR_CYAN);

        let t0 = manager.impacts[0].created_at;
        let t_active = t0 + Duration::from_millis(200);
        manager.update(t_active);
        assert_eq!(manager.impacts.len(), 3);

        // Advance to when Normal expires (900ms) but Critical is still active (1500ms)
        let t_partial = t0 + Duration::from_millis(1000);
        manager.update(t_partial);
        assert!(manager.impacts.len() < 3);

        // Advance to full expiration
        let t_future = t0 + Duration::from_secs(5);
        manager.update(t_future);
        assert_eq!(manager.impacts.len(), 0);
        assert!(manager.is_empty());
    }

    #[test]
    fn test_missile_tracer_trajectory_and_lifecycle() {
        let t0 = Instant::now();
        let duration = Duration::from_millis(1000);
        let start = Pos2::new(0.0, 0.0);
        let ctrl = Pos2::new(50.0, -20.0);
        let end = Pos2::new(100.0, 0.0);

        let mut tracer = MissileTracer::new(start, end, ctrl, COLOR_AMBER, t0, duration);
        assert_eq!(tracer.current_pos, start);

        // Update halfway
        let t_mid = t0 + Duration::from_millis(500);
        assert!(tracer.update(t_mid));
        assert!(tracer.current_pos.x > 30.0 && tracer.current_pos.x < 70.0);
        assert!(!tracer.history.is_empty());

        // Update at finish
        let t_end = t0 + Duration::from_millis(1000);
        assert!(!tracer.update(t_end));
        assert_eq!(tracer.current_pos, end);
    }

    #[test]
    fn test_manager_update_and_paint() {
        let mut manager = MapFxManager::new();
        let pos = Pos2::new(200.0, 150.0);
        manager.add_impact(pos, "Critical");
        manager.add_missile(
            Pos2::new(0.0, 0.0),
            pos,
            Pos2::new(100.0, 50.0),
            "Critical",
            Duration::from_millis(1000),
        );

        let ctx = egui::Context::default();
        let painter = ctx.layer_painter(egui::LayerId::background());

        let t0 = Instant::now();
        manager.update_and_paint(&painter, t0);
        assert_eq!(manager.impacts.len(), 1);
        assert_eq!(manager.tracers.len(), 1);

        // Paint at expiration time
        let t_future = t0 + Duration::from_secs(10);
        manager.update_and_paint(&painter, t_future);
        assert_eq!(manager.impacts.len(), 0);
        assert_eq!(manager.tracers.len(), 0);
        assert!(manager.is_empty());
    }
}
