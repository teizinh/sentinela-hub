use crate::ui::{
    COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN, COLOR_ACCENT_RED, COLOR_BORDER, COLOR_PANEL_BG,
    COLOR_TEXT_MUTED,
};
use egui::{
    epaint::Vertex, Align2, Color32, FontId, Pos2, Rect, Shape, Stroke, Ui, Vec2,
};

/// Helper to determine if a severity string represents a critical incident.
pub fn is_critical_severity(severity: &str) -> bool {
    let s = severity.trim();
    s.eq_ignore_ascii_case("CRITICAL")
        || s.eq_ignore_ascii_case("CRITICO")
        || s.to_uppercase() == "CRÍTICO"
}

/// Represents an individual incident entry recorded in the timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineIncident {
    pub timestamp: u64,
    pub severity: String,
    pub is_critical: bool,
}

/// Attack velocity and timeline visualization manager.
#[derive(Debug, Clone)]
pub struct AttackTimeline {
    /// Window duration in minutes.
    pub window_minutes: usize,
    /// Ordered buffer of recorded incidents within the sliding window.
    pub incidents: Vec<TimelineIncident>,
    /// Incident velocity threshold for danger line callout.
    pub danger_threshold: usize,
}

impl Default for AttackTimeline {
    fn default() -> Self {
        Self::new(60)
    }
}

impl AttackTimeline {
    /// Creates a new `AttackTimeline` instance with the specified window in minutes.
    pub fn new(window_minutes: usize) -> Self {
        Self {
            window_minutes: window_minutes.max(1),
            incidents: Vec::new(),
            danger_threshold: 10,
        }
    }

    /// Sets the danger threshold for velocity callouts.
    pub fn with_danger_threshold(mut self, threshold: usize) -> Self {
        self.danger_threshold = threshold;
        self
    }

    /// Updates the danger threshold.
    pub fn set_danger_threshold(&mut self, threshold: usize) {
        self.danger_threshold = threshold;
    }

    /// Records an incident at a given unix timestamp (in seconds) and severity.
    /// Maintains the buffer sorted and prunes incidents that fall outside the sliding window.
    pub fn record_incident(&mut self, timestamp: u64, severity: &str) {
        let is_crit = is_critical_severity(severity);
        self.incidents.push(TimelineIncident {
            timestamp,
            severity: severity.to_string(),
            is_critical: is_crit,
        });
        self.incidents.sort_by_key(|i| i.timestamp);

        if let Some(latest) = self.incidents.last().map(|i| i.timestamp) {
            let window_secs = (self.window_minutes.max(1) * 60) as u64;
            let cutoff = latest.saturating_sub(window_secs);
            self.incidents.retain(|i| i.timestamp >= cutoff);
        }
    }

    /// Explicitly prunes incidents that are older than `now_ts - window_minutes * 60` or future to `now_ts`.
    pub fn prune_expired(&mut self, now_ts: u64) {
        let window_secs = (self.window_minutes.max(1) * 60) as u64;
        let cutoff = now_ts.saturating_sub(window_secs);
        self.incidents.retain(|i| i.timestamp >= cutoff && i.timestamp <= now_ts);
    }

    /// Aggregates incidents into `num_buckets` time buckets covering `[now_ts - window_secs, now_ts]`.
    /// Each bucket returns `(bucket_time, total_count, critical_count)`.
    pub fn get_buckets(&self, now_ts: u64, num_buckets: usize) -> Vec<(u64, usize, usize)> {
        if num_buckets == 0 {
            return Vec::new();
        }

        let window_secs = (self.window_minutes.max(1) * 60) as u64;
        let start_ts = now_ts.saturating_sub(window_secs);

        let mut buckets = Vec::with_capacity(num_buckets);
        for b in 0..num_buckets {
            let b_start = start_ts + (b as u64 * window_secs) / (num_buckets as u64);
            buckets.push((b_start, 0usize, 0usize));
        }

        if window_secs == 0 {
            return buckets;
        }

        for inc in &self.incidents {
            if inc.timestamp >= start_ts && inc.timestamp <= now_ts {
                let offset = inc.timestamp.saturating_sub(start_ts);
                let mut b_idx = (offset as usize * num_buckets) / (window_secs as usize);
                if b_idx >= num_buckets {
                    b_idx = num_buckets - 1;
                }
                buckets[b_idx].1 += 1;
                if inc.is_critical {
                    buckets[b_idx].2 += 1;
                }
            }
        }

        buckets
    }

    /// Calculates the peak velocity rate (incidents per 1-minute bucket) within the active window ending at `now_ts`.
    pub fn peak_rate(&self, now_ts: u64) -> usize {
        let buckets = self.get_buckets(now_ts, self.window_minutes.max(1));
        buckets.into_iter().map(|(_, tot, _)| tot).max().unwrap_or(0)
    }

    /// Renders the interactive incident velocity & attack timeline visualizer.
    /// Draws an egui mesh/lines with filled gradient underneath, threshold danger line, and peak callout tag.
    pub fn render(&self, ui: &mut Ui, desired_size: Vec2, now_ts: u64) {
        let (response, painter) = ui.allocate_painter(desired_size, egui::Sense::hover());
        let rect = response.rect;
        if rect.width() <= 10.0 || rect.height() <= 10.0 {
            return;
        }

        // Draw background container
        painter.rect_filled(rect, 4.0_f32, COLOR_PANEL_BG);
        painter.rect_stroke(rect, 4.0_f32, Stroke::new(1.0_f32, COLOR_BORDER));

        let pad_left = 34.0_f32;
        let pad_right = 16.0_f32;
        let pad_top = 22.0_f32;
        let pad_bottom = 22.0_f32;

        let chart_rect = Rect::from_min_max(
            Pos2::new(rect.left() + pad_left, rect.top() + pad_top),
            Pos2::new(rect.right() - pad_right, rect.bottom() - pad_bottom),
        );
        if chart_rect.width() <= 5.0_f32 || chart_rect.height() <= 5.0_f32 {
            return;
        }

        // Compute buckets
        let num_buckets = ((chart_rect.width() / 10.0_f32) as usize).clamp(12, 60);
        let buckets = self.get_buckets(now_ts, num_buckets);
        if buckets.is_empty() {
            return;
        }

        let peak = self.peak_rate(now_ts);
        let max_bucket_val = buckets.iter().map(|(_, tot, _)| *tot).max().unwrap_or(0);
        let threshold = self.danger_threshold;

        let max_val = max_bucket_val.max(peak).max(threshold);
        let y_max = (max_val as f32 * 1.3_f32).max(4.0_f32);

        // Draw grid lines
        let grid_stroke = Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(48, 54, 61, 80));
        let text_color = COLOR_TEXT_MUTED;

        // Bottom baseline
        painter.line_segment([chart_rect.left_bottom(), chart_rect.right_bottom()], grid_stroke);
        painter.text(
            Pos2::new(chart_rect.left() - 4.0_f32, chart_rect.bottom()),
            Align2::RIGHT_CENTER,
            "0",
            FontId::monospace(10.0_f32),
            text_color,
        );

        // Threshold danger line
        let danger_ratio = (threshold as f32) / y_max;
        if danger_ratio <= 1.0_f32 {
            let danger_y = chart_rect.bottom() - danger_ratio * chart_rect.height();
            let danger_stroke =
                Stroke::new(1.2_f32, Color32::from_rgba_unmultiplied(248, 113, 113, 160));
            let mut x = chart_rect.left();
            while x < chart_rect.right() {
                let next_x = (x + 8.0_f32).min(chart_rect.right());
                painter.line_segment(
                    [Pos2::new(x, danger_y), Pos2::new(next_x, danger_y)],
                    danger_stroke,
                );
                x += 14.0_f32;
            }
            painter.text(
                Pos2::new(chart_rect.left() - 4.0_f32, danger_y),
                Align2::RIGHT_CENTER,
                format!("{}", threshold),
                FontId::monospace(10.0_f32),
                COLOR_ACCENT_RED,
            );
            painter.text(
                Pos2::new(chart_rect.right() - 4.0_f32, danger_y - 2.0_f32),
                Align2::RIGHT_BOTTOM,
                format!("DANGER THRESHOLD ({})", threshold),
                FontId::monospace(9.0_f32),
                Color32::from_rgba_unmultiplied(248, 113, 113, 200),
            );
        }

        // Map bucket points
        let mut points: Vec<Pos2> = Vec::with_capacity(buckets.len());
        let mut colors: Vec<Color32> = Vec::with_capacity(buckets.len());
        let mut peak_pos: Option<(Pos2, usize)> = None;
        let mut highest_val = 0;

        for (i, &(_time, total, critical)) in buckets.iter().enumerate() {
            let x = chart_rect.left()
                + (i as f32 / (buckets.len() - 1).max(1) as f32) * chart_rect.width();
            let y_ratio = (total as f32) / y_max;
            let y = chart_rect.bottom() - y_ratio * chart_rect.height();
            let pos = Pos2::new(x, y);
            points.push(pos);

            let color = if critical > 0 {
                COLOR_ACCENT_RED
            } else if total >= threshold {
                COLOR_ACCENT_AMBER
            } else {
                COLOR_ACCENT_CYAN
            };
            colors.push(color);

            if total > highest_val {
                highest_val = total;
                peak_pos = Some((pos, total));
            }
        }

        let callout = if let Some(p) = peak_pos {
            p
        } else {
            (Pos2::new(chart_rect.center().x, chart_rect.bottom()), 0)
        };

        // Mesh with gradient fill underneath
        let mut mesh = egui::Mesh::default();
        let uv = egui::epaint::WHITE_UV;

        for i in 0..points.len() {
            let p_top = points[i];
            let p_bot = Pos2::new(points[i].x, chart_rect.bottom());

            let top_color = Color32::from_rgba_unmultiplied(
                colors[i].r(),
                colors[i].g(),
                colors[i].b(),
                150,
            );
            let bot_color = Color32::from_rgba_unmultiplied(
                colors[i].r(),
                colors[i].g(),
                colors[i].b(),
                8,
            );

            mesh.vertices.push(Vertex {
                pos: p_top,
                uv,
                color: top_color,
            });
            mesh.vertices.push(Vertex {
                pos: p_bot,
                uv,
                color: bot_color,
            });

            if i > 0 {
                let top_prev = ((i - 1) * 2) as u32;
                let bot_prev = top_prev + 1;
                let top_curr = (i * 2) as u32;
                let bot_curr = top_curr + 1;

                mesh.add_triangle(top_prev, top_curr, bot_curr);
                mesh.add_triangle(top_prev, bot_curr, bot_prev);
            }
        }
        painter.add(Shape::Mesh(mesh));

        // Draw line segments
        for i in 0..points.len().saturating_sub(1) {
            let col = colors[i];
            painter.line_segment([points[i], points[i + 1]], Stroke::new(2.0_f32, col));
        }

        // Draw points and critical rings
        for (i, &pt) in points.iter().enumerate() {
            if buckets[i].1 > 0 {
                let col = colors[i];
                painter.circle_filled(pt, 2.5_f32, col);
                if buckets[i].2 > 0 {
                    painter.circle_stroke(pt, 5.0_f32, Stroke::new(1.2_f32, COLOR_ACCENT_RED));
                }
            }
        }

        // Peak callout tag
        let (p_pt, p_rate) = callout;
        let tag_text = format!("PEAK: {}/m", p_rate.max(peak));
        let font = FontId::monospace(10.0_f32);
        let tag_offset_y = 16.0_f32;
        let tag_center = Pos2::new(
            p_pt.x.clamp(chart_rect.left() + 35.0_f32, chart_rect.right() - 35.0_f32),
            (p_pt.y - tag_offset_y).max(chart_rect.top() + 8.0_f32),
        );

        let text_size = painter
            .layout_no_wrap(tag_text.clone(), font.clone(), Color32::WHITE)
            .size();
        let pad = Vec2::new(6.0_f32, 3.0_f32);
        let tag_rect = Rect::from_center_size(tag_center, text_size + pad * 2.0_f32);

        let tag_bg = if p_rate.max(peak) >= threshold {
            Color32::from_rgb(127, 29, 29)
        } else {
            Color32::from_rgb(15, 23, 42)
        };
        let tag_border = if p_rate.max(peak) >= threshold {
            COLOR_ACCENT_RED
        } else {
            COLOR_ACCENT_CYAN
        };

        painter.rect_filled(tag_rect, 3.0_f32, tag_bg);
        painter.rect_stroke(tag_rect, 3.0_f32, Stroke::new(1.0_f32, tag_border));
        painter.line_segment(
            [p_pt, Pos2::new(tag_center.x, tag_rect.bottom())],
            Stroke::new(1.0_f32, tag_border),
        );
        painter.text(
            tag_center,
            Align2::CENTER_CENTER,
            tag_text,
            font,
            Color32::WHITE,
        );

        // Hover Tooltip
        if let Some(hover_pos) = response.hover_pos() {
            if chart_rect.contains(hover_pos) {
                let rel_x = (hover_pos.x - chart_rect.left()) / chart_rect.width();
                let b_idx =
                    ((rel_x * (buckets.len() - 1) as f32).round() as usize).min(buckets.len() - 1);
                let b_pt = points[b_idx];
                let (b_time, b_tot, b_crit) = buckets[b_idx];

                painter.line_segment(
                    [
                        Pos2::new(b_pt.x, chart_rect.top()),
                        Pos2::new(b_pt.x, chart_rect.bottom()),
                    ],
                    Stroke::new(1.0_f32, Color32::from_rgba_unmultiplied(255, 255, 255, 80)),
                );
                painter.circle_filled(b_pt, 4.0_f32, Color32::WHITE);

                egui::show_tooltip(
                    ui.ctx(),
                    ui.layer_id(),
                    egui::Id::new("timeline_tooltip"),
                    |ui| {
                        ui.label(egui::RichText::new("⏱ Attack Velocity").strong());
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Bucket Time:").color(COLOR_TEXT_MUTED));
                            ui.label(format!("{}", b_time));
                        });
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Incidents:").color(COLOR_TEXT_MUTED));
                            let col = if b_tot >= threshold {
                                COLOR_ACCENT_RED
                            } else {
                                COLOR_ACCENT_CYAN
                            };
                            ui.label(
                                egui::RichText::new(format!("{} inc", b_tot))
                                    .color(col)
                                    .strong(),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Critical:").color(COLOR_TEXT_MUTED));
                            let col = if b_crit > 0 {
                                COLOR_ACCENT_RED
                            } else {
                                COLOR_TEXT_MUTED
                            };
                            ui.label(
                                egui::RichText::new(format!("{}", b_crit))
                                    .color(col)
                                    .strong(),
                            );
                        });
                    },
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeline_bucket_aggregation() {
        let mut timeline = AttackTimeline::new(10); // 10 minutes = 600s
        let now = 1000;
        // Window is [400, 1000]
        // 5 buckets -> each covers 120s:
        // Bucket 0: [400, 520)
        // Bucket 1: [520, 640)
        // Bucket 2: [640, 760)
        // Bucket 3: [760, 880)
        // Bucket 4: [880, 1000]

        timeline.record_incident(450, "LOW");
        timeline.record_incident(530, "CRITICAL");
        timeline.record_incident(550, "ALTO");
        timeline.record_incident(900, "CRÍTICO");
        timeline.record_incident(950, "CRITICO");

        let buckets = timeline.get_buckets(now, 5);
        assert_eq!(buckets.len(), 5);

        // Bucket 0: timestamp 400, total 1, critical 0
        assert_eq!(buckets[0].0, 400);
        assert_eq!(buckets[0].1, 1);
        assert_eq!(buckets[0].2, 0);

        // Bucket 1: timestamp 520, total 2, critical 1
        assert_eq!(buckets[1].0, 520);
        assert_eq!(buckets[1].1, 2);
        assert_eq!(buckets[1].2, 1);

        // Bucket 2: timestamp 640, total 0, critical 0
        assert_eq!(buckets[2].0, 640);
        assert_eq!(buckets[2].1, 0);
        assert_eq!(buckets[2].2, 0);

        // Bucket 3: timestamp 760, total 0, critical 0
        assert_eq!(buckets[3].0, 760);
        assert_eq!(buckets[3].1, 0);
        assert_eq!(buckets[3].2, 0);

        // Bucket 4: timestamp 880, total 2, critical 2
        assert_eq!(buckets[4].0, 880);
        assert_eq!(buckets[4].1, 2);
        assert_eq!(buckets[4].2, 2);
    }

    #[test]
    fn test_timeline_window_expiration() {
        let mut timeline = AttackTimeline::new(5); // 5 minutes = 300s
        let now = 1000;
        // Window: [700, 1000]

        // Expired incidents (before 700)
        timeline.record_incident(200, "CRITICAL");
        timeline.record_incident(500, "LOW");
        timeline.record_incident(699, "HIGH");

        // Active incidents inside window [700, 1000]
        timeline.record_incident(700, "LOW");
        timeline.record_incident(850, "CRITICAL");
        timeline.record_incident(1000, "CRITICAL");

        let buckets = timeline.get_buckets(now, 3);
        assert_eq!(buckets.len(), 3);

        let total_counted: usize = buckets.iter().map(|b| b.1).sum();
        let critical_counted: usize = buckets.iter().map(|b| b.2).sum();
        assert_eq!(total_counted, 3);
        assert_eq!(critical_counted, 2);

        // Pruning removes expired entries
        timeline.prune_expired(now);
        assert_eq!(timeline.incidents.len(), 3);
        assert_eq!(timeline.incidents[0].timestamp, 700);
        assert_eq!(timeline.incidents[2].timestamp, 1000);
    }

    #[test]
    fn test_timeline_peak_calculation() {
        let mut timeline = AttackTimeline::new(10); // 10 minutes = 600s
        let now = 2000;
        // Window: [1400, 2000]

        // 5 incidents at t=1720 (minute bucket [1680, 1740) or [1700, 1760))
        for _ in 0..5 {
            timeline.record_incident(1720, "CRITICAL");
        }
        // 2 incidents at t=1900
        for _ in 0..2 {
            timeline.record_incident(1900, "LOW");
        }
        // 10 expired incidents at t=1000 (outside window)
        for _ in 0..10 {
            timeline.record_incident(1000, "HIGH");
        }

        // Peak rate within active window [1400, 2000] must be 5
        assert_eq!(timeline.peak_rate(now), 5);
    }

    #[test]
    fn test_timeline_critical_severity_variants() {
        assert!(is_critical_severity("CRITICAL"));
        assert!(is_critical_severity("critical"));
        assert!(is_critical_severity("CRÍTICO"));
        assert!(is_critical_severity("crítico"));
        assert!(is_critical_severity("CRITICO"));
        assert!(is_critical_severity("critico"));
        assert!(!is_critical_severity("LOW"));
        assert!(!is_critical_severity("MEDIUM"));
        assert!(!is_critical_severity("ALTO"));
        assert!(!is_critical_severity("SCAN"));
        assert!(!is_critical_severity("INFO"));
    }

    #[test]
    fn test_timeline_empty_and_zero_buckets() {
        let timeline = AttackTimeline::new(10);
        assert_eq!(timeline.peak_rate(1000), 0);
        assert_eq!(timeline.get_buckets(1000, 0), Vec::new());

        let empty_buckets = timeline.get_buckets(1000, 4);
        assert_eq!(empty_buckets.len(), 4);
        for b in empty_buckets {
            assert_eq!(b.1, 0);
            assert_eq!(b.2, 0);
        }
    }

    #[test]
    fn test_timeline_render_smoke() {
        let mut timeline = AttackTimeline::new(10);
        timeline.record_incident(900, "CRITICAL");
        timeline.record_incident(950, "LOW");

        let ctx = egui::Context::default();
        let _ = ctx.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                timeline.render(ui, Vec2::new(300.0, 150.0), 1000);
            });
        });
    }
}
