use crate::models::{AgentNode, HubIncident};
use crate::ui::views::map_data::get_continent_outlines;
use crate::ui::{
    render_severity_pill, severity_color, COLOR_ACCENT_AMBER, COLOR_ACCENT_CYAN,
    COLOR_ACCENT_GREEN, COLOR_BORDER, COLOR_TEXT_MUTED,
};
use egui::{Color32, RichText, Stroke};
use std::time::{Duration, Instant};

/// Country centroid table mapping lowercase country codes and names to (latitude, longitude).
const COUNTRY_CENTROIDS: &[(&[&str], f32, f32)] = &[
    (&["pt", "portugal", "república portuguesa"], 39.50, -8.00),
    (&["de", "germany", "alemanha", "deutschland"], 51.16, 10.45),
    (&["us", "usa", "united states", "estados unidos"], 37.09, -95.71),
    (&["cn", "china", "república popular da china"], 35.86, 104.19),
    (&["ru", "russia", "rússia", "russian federation", "federação russa"], 61.52, 105.31),
    (&["br", "brazil", "brasil"], -14.23, -51.92),
    (&["gb", "uk", "united kingdom", "reino unido", "great britain", "england"], 55.37, -3.43),
    (&["fr", "france", "frança"], 46.22, 2.21),
    (&["nl", "netherlands", "holanda", "países baixos"], 52.13, 5.29),
    (&["ca", "canada", "canadá"], 56.13, -106.34),
    (&["jp", "japan", "japão"], 36.20, 138.25),
    (&["in", "india", "índia"], 20.59, 78.96),
    (&["au", "australia", "austrália"], -25.27, 133.77),
    (&["es", "spain", "espanha"], 40.46, -3.74),
    (&["it", "italy", "itália"], 41.87, 12.56),
    (&["ua", "ukraine", "ucrânia"], 48.37, 31.16),
    (&["pl", "poland", "polónia", "polonia"], 51.91, 19.14),
    (&["kr", "south korea", "coreia do sul", "korea"], 35.90, 127.76),
    (&["kp", "north korea", "coreia do norte"], 40.33, 127.51),
    (&["sg", "singapore", "singapura"], 1.35, 103.81),
    (&["vn", "vietnam", "vietname"], 14.05, 108.27),
    (&["tr", "turkey", "turquia", "türkiye"], 38.96, 35.24),
    (&["ir", "iran", "irão", "islâmica do irã"], 32.42, 53.68),
    (&["il", "israel"], 31.04, 34.85),
    (&["se", "sweden", "suécia"], 60.12, 18.64),
    (&["ch", "switzerland", "suíça"], 46.81, 8.22),
    (&["ro", "romania", "roménia"], 45.94, 24.96),
    (&["tw", "taiwan"], 23.69, 120.96),
    (&["za", "south africa", "áfrica do sul"], -30.55, 22.93),
    (&["mx", "mexico", "méxico"], 23.63, -102.55),
    (&["ar", "argentina"], -38.41, -63.61),
    (&["ie", "ireland", "irlanda"], 53.14, -7.69),
    (&["bg", "bulgaria", "bulgária"], 42.73, 25.48),
    (&["id", "indonesia", "indonésia"], -0.78, 113.92),
    (&["no", "norway", "noruega"], 60.47, 8.46),
    (&["fi", "finland", "finlândia"], 61.92, 25.74),
    (&["be", "belgium", "bélgica"], 50.50, 4.47),
    (&["at", "austria", "áustria"], 47.51, 14.55),
    (&["cz", "czech republic", "czechia", "república checa"], 49.81, 15.47),
    (&["dk", "denmark", "dinamarca"], 56.26, 9.50),
    (&["gr", "greece", "grécia"], 39.07, 21.82),
    (&["cl", "chile"], -35.67, -71.54),
    (&["co", "colombia", "colômbia"], 4.57, -74.29),
    (&["eg", "egypt", "egito"], 26.82, 30.80),
    (&["ng", "nigeria", "nigéria"], 9.08, 8.67),
    (&["sa", "saudi arabia", "arábia saudita"], 23.88, 45.07),
    (&["ae", "uae", "united arab emirates", "emirados árabes unidos"], 23.42, 53.84),
    (&["hk", "hong kong"], 22.31, 114.16),
    (&["th", "thailand", "tailândia"], 15.87, 100.99),
    (&["ph", "philippines", "filipinas"], 12.87, 121.77),
    (&["my", "malaysia", "malásia"], 4.21, 101.97),
    (&["nz", "new zealand", "nova zelândia"], -40.90, 174.88),
    (&["pk", "pakistan", "paquistão"], 30.37, 69.34),
];

/// Common tech/cloud city coordinates mapping.
const CITY_COORDINATES: &[(&[&str], f32, f32)] = &[
    (&["lisboa", "lisbon"], 38.72, -9.14),
    (&["porto"], 41.15, -8.62),
    (&["frankfurt"], 50.11, 8.68),
    (&["berlin", "berlim"], 52.52, 13.40),
    (&["munich", "munique"], 48.13, 11.58),
    (&["london", "londres"], 51.50, -0.12),
    (&["paris"], 48.85, 2.35),
    (&["amsterdam", "amesterdão", "amsterdã"], 52.36, 4.90),
    (&["madrid"], 40.41, -3.70),
    (&["rome", "roma"], 41.90, 12.49),
    (&["new york", "nova iorque"], 40.71, -74.00),
    (&["washington"], 38.90, -77.03),
    (&["los angeles"], 34.05, -118.24),
    (&["san francisco"], 37.77, -122.41),
    (&["chicago"], 41.87, -87.62),
    (&["mountain view"], 37.38, -122.08),
    (&["ashburn"], 39.04, -77.48),
    (&["dallas"], 32.77, -96.79),
    (&["seattle"], 47.60, -122.33),
    (&["tokyo", "tóquio"], 35.67, 139.65),
    (&["beijing", "pequim"], 39.90, 116.40),
    (&["shanghai", "xangai"], 31.23, 121.47),
    (&["shenzhen"], 22.54, 114.05),
    (&["moscow", "moscovo", "moscou"], 55.75, 37.61),
    (&["saint petersburg", "são petersburgo"], 59.93, 30.33),
    (&["singapore", "singapura"], 1.35, 103.81),
    (&["sydney"], -33.86, 151.20),
    (&["melbourne"], -37.81, 144.96),
    (&["são paulo", "sao paulo"], -23.55, -46.63),
    (&["rio de janeiro"], -22.90, -43.17),
    (&["toronto"], 43.65, -79.38),
    (&["montreal"], 45.50, -73.56),
    (&["vancouver"], 49.28, -123.12),
    (&["dublin"], 53.34, -6.26),
    (&["zurich", "zurique"], 47.37, 8.54),
    (&["stockholm", "estocolmo"], 59.32, 18.06),
    (&["warsaw", "varsóvia"], 52.22, 21.01),
    (&["kyiv", "kiev"], 50.45, 30.52),
    (&["tel aviv"], 32.08, 34.78),
    (&["dubai"], 25.20, 55.27),
    (&["seoul", "seul"], 37.56, 126.97),
];

/// Checks whether an IPv4 or IPv6 address is private / local (RFC 1918 / RFC 4193).
pub fn is_rfc1918(ip: &str) -> bool {
    let trimmed = ip.trim();
    if trimmed.starts_with("10.") || trimmed.starts_with("192.168.") || trimmed.starts_with("127.") {
        return true;
    }
    if let Some(rest) = trimmed.strip_prefix("172.") {
        if let Some(first_dot) = rest.find('.') {
            if let Ok(octet) = rest[..first_dot].parse::<u8>() {
                if (16..=31).contains(&octet) {
                    return true;
                }
            }
        }
    }
    if trimmed.starts_with("169.254.")
        || trimmed == "::1"
        || trimmed.starts_with("fc")
        || trimmed.starts_with("fd")
        || trimmed.starts_with("fe80")
    {
        return true;
    }
    false
}

/// Default geographic coordinates for the primary SOC command hub (Portugal).
pub fn default_target_coordinates() -> (f32, f32) {
    (39.50, -8.00)
}

/// Resolves the geographic coordinates of a target AgentNode based on its name or location.
pub fn resolve_node_coordinates(node: &AgentNode) -> (f32, f32) {
    let name_lower = node.name.to_lowercase();
    if name_lower.contains("frankfurt") || name_lower.contains("germany") || name_lower.contains("de") {
        (50.11, 8.68)
    } else if name_lower.contains("london") || name_lower.contains("uk") {
        (51.50, -0.12)
    } else if name_lower.contains("us") || name_lower.contains("oracle") || name_lower.contains("aws") {
        (37.09, -95.71)
    } else if name_lower.contains("paris") || name_lower.contains("france") {
        (48.85, 2.35)
    } else if name_lower.contains("tokyo") || name_lower.contains("japan") {
        (35.67, 139.65)
    } else if name_lower.contains("amsterdam") || name_lower.contains("nl") {
        (52.36, 4.90)
    } else {
        default_target_coordinates()
    }
}

/// Resolves geographic `(latitude, longitude)` from country name/code, city name, and IP address.
///
/// Features:
/// - RFC 1918 / LAN offset around the default target node (`lat + 2.0, lon - 3.0`).
/// - Centroid matching across top world countries and major tech cities.
/// - Deterministic hash fallback for unknown public IPs to ensure stable coordinates without NaN.
pub fn resolve_coordinates(country: &str, city: &str, ip: &str) -> (f32, f32) {
    let country_trim = country.trim();
    let country_lower = country_trim.to_lowercase();
    let city_lower = city.trim().to_lowercase();

    // 1. Detect RFC 1918 / Private LAN / Local Wi-Fi attacks
    let is_local_text = country_lower.contains("local")
        || country_lower.contains("lan")
        || country_lower.contains("wi-fi")
        || city_lower.contains("sub-rede")
        || city_lower.contains("local");

    if is_rfc1918(ip) || is_local_text {
        // Spec 5.2: Offset slightly around the target node: (lat + 2.0, lon - 3.0)
        let (node_lat, node_lon) = default_target_coordinates();
        return (node_lat + 2.0, node_lon - 3.0);
    }

    // 2. Lookup in Country Centroid table
    if !country_lower.is_empty() {
        for (names, lat, lon) in COUNTRY_CENTROIDS {
            for name in *names {
                if country_lower == *name
                    || country_lower.contains(name)
                    || (*name).contains(&country_lower)
                {
                    return (*lat, *lon);
                }
            }
        }
    }

    // 3. Lookup in City coordinates table
    if !city_lower.is_empty() {
        for (names, lat, lon) in CITY_COORDINATES {
            for name in *names {
                if city_lower == *name || city_lower.contains(name) {
                    return (*lat, *lon);
                }
            }
        }
    }

    // 4. Deterministic hash fallback for unknown public IPs
    let hash = ip.bytes().fold(5381u32, |acc, b| acc.wrapping_mul(33).wrapping_add(b as u32));
    let lat = ((hash % 105) as f32) - 45.0; // Range: -45.0 .. 60.0
    let lon = (((hash / 105) % 260) as f32) - 120.0; // Range: -120.0 .. 140.0

    (lat.clamp(-90.0, 90.0), lon.clamp(-180.0, 180.0))
}

/// Projects equirectangular geographic coordinates `(lat, lon)` into screen canvas space.
///
/// Formula:
/// - `x = rect.min.x + (lon + 180.0) / 360.0 * rect.width()`
/// - `y = rect.min.y + (90.0 - lat) / 180.0 * rect.height()`
///
/// Bounds safety:
/// Safely clamps inputs to prevent NaN and ensures rendered positions stay within `rect`.
pub fn project_to_screen(lat: f32, lon: f32, rect: egui::Rect) -> egui::Pos2 {
    let safe_lat = if lat.is_nan() { 0.0 } else { lat.clamp(-90.0, 90.0) };
    let safe_lon = if lon.is_nan() { 0.0 } else { lon.clamp(-180.0, 180.0) };

    let norm_x = (safe_lon + 180.0) / 360.0;
    let norm_y = (90.0 - safe_lat) / 180.0;

    let x = (rect.min.x + norm_x * rect.width()).clamp(rect.min.x, rect.max.x);
    let y = (rect.min.y + norm_y * rect.height()).clamp(rect.min.y, rect.max.y);

    egui::pos2(x, y)
}

/// Calculates the quadratic Bezier control point lifted upwards with altitude damping.
///
/// Damps control-point elevation across long cross-hemisphere trajectories
/// to prevent clipping outside the top viewport.
pub fn compute_control_point(start: egui::Pos2, end: egui::Pos2) -> egui::Pos2 {
    let mid_x = (start.x + end.x) * 0.5;
    let mid_y = (start.y + end.y) * 0.5;
    let dx = end.x - start.x;
    let dy = end.y - start.y;
    let dist = (dx * dx + dy * dy).sqrt();

    // Quadratic Bezier lift: dist * 0.25 with sub-linear damping for long spans
    let raw_lift = dist * 0.25;
    let damped_lift = raw_lift / (1.0 + dist / 600.0);
    let lift = damped_lift.clamp(15.0, 120.0);

    egui::pos2(mid_x, mid_y - lift)
}

/// Parametric Quadratic Bezier curve interpolation: B(t) = (1-t)^2 * P0 + 2*(1-t)*t * P1 + t^2 * P2.
pub fn quadratic_bezier(p0: egui::Pos2, p1: egui::Pos2, p2: egui::Pos2, t: f32) -> egui::Pos2 {
    let t = t.clamp(0.0, 1.0);
    let one_minus_t = 1.0 - t;
    let x = one_minus_t * one_minus_t * p0.x + 2.0 * one_minus_t * t * p1.x + t * t * p2.x;
    let y = one_minus_t * one_minus_t * p0.y + 2.0 * one_minus_t * t * p1.y + t * t * p2.y;
    egui::pos2(x, y)
}

/// Represents an animated attack trajectory arc connecting an attacker's origin
/// to a target agent node beacon on the 2D Threat Map canvas.
#[derive(Clone, Debug)]
pub struct ActiveAttackArc {
    pub incident: HubIncident,
    pub origin_geo: (f32, f32),
    pub target_geo: (f32, f32),
    pub start_pos: egui::Pos2,
    pub end_pos: egui::Pos2,
    pub ctrl_pos: egui::Pos2,
    pub created_at: Instant,
    pub flight_duration: Duration,
}

impl ActiveAttackArc {
    /// Creates a new `ActiveAttackArc` connecting screen coordinates `start_pos` and `end_pos`.
    pub fn new(
        incident: HubIncident,
        start_pos: egui::Pos2,
        end_pos: egui::Pos2,
        created_at: Instant,
    ) -> Self {
        let origin_geo = resolve_coordinates(&incident.country, &incident.city, &incident.ip);
        let target_geo = default_target_coordinates();
        let ctrl_pos = compute_control_point(start_pos, end_pos);
        Self {
            incident,
            origin_geo,
            target_geo,
            start_pos,
            end_pos,
            ctrl_pos,
            created_at,
            flight_duration: Duration::from_millis(2200),
        }
    }

    /// Creates an `ActiveAttackArc` directly from geographic coordinates and canvas rect.
    pub fn from_geo(
        incident: HubIncident,
        origin_geo: (f32, f32),
        target_geo: (f32, f32),
        rect: egui::Rect,
        created_at: Instant,
    ) -> Self {
        let start_pos = project_to_screen(origin_geo.0, origin_geo.1, rect);
        let end_pos = project_to_screen(target_geo.0, target_geo.1, rect);
        let ctrl_pos = compute_control_point(start_pos, end_pos);
        Self {
            incident,
            origin_geo,
            target_geo,
            start_pos,
            end_pos,
            ctrl_pos,
            created_at,
            flight_duration: Duration::from_millis(2200),
        }
    }

    /// Sets custom flight duration for this arc.
    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.flight_duration = duration;
        self
    }

    /// Re-projects screen coordinates when the canvas rectangle changes.
    pub fn update_projection(&mut self, rect: egui::Rect) {
        self.start_pos = project_to_screen(self.origin_geo.0, self.origin_geo.1, rect);
        self.end_pos = project_to_screen(self.target_geo.0, self.target_geo.1, rect);
        self.ctrl_pos = compute_control_point(self.start_pos, self.end_pos);
    }

    /// Returns the current flight position of the travelling particle along the Bezier curve.
    /// Returns `None` once the flight duration has elapsed.
    pub fn particle_pos(&self, now: Instant) -> Option<egui::Pos2> {
        if now < self.created_at {
            return Some(self.start_pos);
        }
        let elapsed = now.duration_since(self.created_at);
        if elapsed > self.flight_duration {
            return None;
        }
        let t = (elapsed.as_secs_f32() / self.flight_duration.as_secs_f32()).clamp(0.0, 1.0);
        Some(quadratic_bezier(self.start_pos, self.ctrl_pos, self.end_pos, t))
    }

    /// Returns the progress of the particle flight in `0.0..=1.0`.
    pub fn progress(&self, now: Instant) -> f32 {
        if now < self.created_at {
            0.0
        } else {
            let elapsed = now.duration_since(self.created_at);
            (elapsed.as_secs_f32() / self.flight_duration.as_secs_f32()).clamp(0.0, 1.0)
        }
    }

    /// Whether the arc has reached the end of its 20-second display lifespan.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.duration_since(self.created_at) >= Duration::from_secs(20)
    }

    /// Calculates arc opacity alpha in `0.0..=1.0` with smooth fade-out during its final 5 seconds.
    pub fn alpha(&self, now: Instant) -> f32 {
        let elapsed = now.duration_since(self.created_at).as_secs_f32();
        if elapsed >= 20.0 {
            0.0
        } else if elapsed >= 15.0 {
            (20.0 - elapsed) / 5.0
        } else {
            1.0
        }
    }

    /// Creates an `ActiveAttackArc` directly from an incident and target coordinates.
    pub fn from_incident(
        incident: HubIncident,
        target_geo: (f32, f32),
        created_at: Instant,
    ) -> Self {
        let origin_geo = resolve_coordinates(&incident.country, &incident.city, &incident.ip);
        Self {
            incident,
            origin_geo,
            target_geo,
            start_pos: egui::Pos2::ZERO,
            end_pos: egui::Pos2::ZERO,
            ctrl_pos: egui::Pos2::ZERO,
            created_at,
            flight_duration: Duration::from_millis(2200),
        }
    }
}

/// Inverts screen canvas coordinates back to equirectangular geographic coordinates (lat, lon).
pub fn screen_to_geo(pos: egui::Pos2, rect: egui::Rect) -> (f32, f32) {
    if rect.width() <= 0.0 || rect.height() <= 0.0 {
        return (0.0, 0.0);
    }
    let norm_x = ((pos.x - rect.min.x) / rect.width()).clamp(0.0, 1.0);
    let norm_y = ((pos.y - rect.min.y) / rect.height()).clamp(0.0, 1.0);
    let lon = norm_x * 360.0 - 180.0;
    let lat = 90.0 - norm_y * 180.0;
    (lat, lon)
}

/// Renders the real-time 2D Threat Map view with continental silhouettes,
/// animated Bezier attack arcs, glowing target beacons, and live HUD overlay.
pub fn render_threat_map_view(
    ui: &mut egui::Ui,
    nodes: &[AgentNode],
    incidents: &[HubIncident],
    arcs: &mut Vec<ActiveAttackArc>,
    selected_node: &mut Option<String>,
    modal_incident: &mut Option<HubIncident>,
) {
    let now = Instant::now();
    // 1. Prune expired arcs older than 20 seconds
    arcs.retain(|arc| !arc.is_expired(now));

    // Request continuous repaint for 60 FPS animation
    ui.ctx().request_repaint();

    // 2. Allocate interactive painter canvas
    let available = ui.available_size_before_wrap();
    let (response, painter) = ui.allocate_painter(available, egui::Sense::click());
    let rect = response.rect;

    if rect.width() < 10.0 || rect.height() < 10.0 {
        return;
    }

    // 3. Draw dark SOC canvas background
    painter.rect_filled(rect, 4.0, Color32::from_rgb(10, 14, 20));

    // 4. Draw latitude & longitude grid lines
    // Parallels (latitudes every 30 degrees)
    for lat in [-60.0f32, -30.0f32, 0.0f32, 30.0f32, 60.0f32] {
        let y = rect.min.y + (90.0f32 - lat) / 180.0f32 * rect.height();
        let stroke = if lat == 0.0f32 {
            Stroke::new(1.0f32, Color32::from_rgba_unmultiplied(56, 189, 248, 45))
        } else {
            Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 60))
        };
        painter.line_segment([egui::pos2(rect.min.x, y), egui::pos2(rect.max.x, y)], stroke);
    }
    // Meridians (longitudes every 30 degrees)
    for lon_deg in (-150..=150).step_by(30) {
        let lon = lon_deg as f32;
        let x = rect.min.x + (lon + 180.0f32) / 360.0f32 * rect.width();
        let stroke = if lon_deg == 0 {
            Stroke::new(1.0f32, Color32::from_rgba_unmultiplied(56, 189, 248, 45))
        } else {
            Stroke::new(0.5f32, Color32::from_rgba_unmultiplied(48, 54, 61, 60))
        };
        painter.line_segment([egui::pos2(x, rect.min.y), egui::pos2(x, rect.max.y)], stroke);
    }

    // 5. Draw continental silhouettes & cyber borders
    let continent_polygons = get_continent_outlines();
    for polygon in continent_polygons {
        let screen_pts: Vec<egui::Pos2> = polygon
            .iter()
            .map(|&(lat, lon)| project_to_screen(lat, lon, rect))
            .collect();
        if screen_pts.len() >= 3 {
            painter.add(egui::Shape::Path(egui::epaint::PathShape::convex_polygon(
                screen_pts.clone(),
                Color32::from_rgb(18, 24, 34),
                Stroke::new(1.0f32, Color32::from_rgba_unmultiplied(56, 189, 248, 65)),
            )));
            painter.add(egui::Shape::Path(egui::epaint::PathShape::closed_line(
                screen_pts,
                Stroke::new(1.0f32, Color32::from_rgba_unmultiplied(56, 189, 248, 80)),
            )));
        }
    }

    // 6. Draw Target Nodes (Agent beacons with expanding radar rings)
    let time = ui.input(|i| i.time) as f32;
    let pulse1 = (time * 1.5f32).fract();
    let pulse2 = (time * 1.5f32 + 0.5f32).fract();

    // Default node if none registered
    let target_nodes: Vec<(String, (f32, f32))> = if nodes.is_empty() {
        vec![("soc-central-pt".to_string(), default_target_coordinates())]
    } else {
        nodes
            .iter()
            .map(|n| (n.name.clone(), resolve_node_coordinates(n)))
            .collect()
    };

    for (node_name, (node_lat, node_lon)) in &target_nodes {
        let node_pos = project_to_screen(*node_lat, *node_lon, rect);

        // Radar ring 1
        painter.circle_stroke(
            node_pos,
            5.0f32 + pulse1 * 20.0f32,
            Stroke::new(
                1.2f32,
                Color32::from_rgba_unmultiplied(
                    52,
                    211,
                    153,
                    ((1.0f32 - pulse1) * 160.0f32) as u8,
                ),
            ),
        );
        // Radar ring 2
        painter.circle_stroke(
            node_pos,
            5.0f32 + pulse2 * 20.0f32,
            Stroke::new(
                1.0f32,
                Color32::from_rgba_unmultiplied(
                    52,
                    211,
                    153,
                    ((1.0f32 - pulse2) * 120.0f32) as u8,
                ),
            ),
        );

        // Core beacon
        painter.circle_filled(
            node_pos,
            7.0f32,
            Color32::from_rgba_unmultiplied(52, 211, 153, 50),
        );
        painter.circle_filled(node_pos, 4.5f32, COLOR_ACCENT_GREEN);
        painter.circle_stroke(node_pos, 4.5f32, Stroke::new(1.5f32, Color32::WHITE));

        // Node label
        painter.text(
            node_pos + egui::vec2(10.0f32, -8.0f32),
            egui::Align2::LEFT_CENTER,
            node_name,
            egui::FontId::proportional(11.0f32),
            COLOR_ACCENT_GREEN,
        );

        // Hit-test click on node to toggle filter
        if response.clicked() {
            if let Some(mouse) = response.interact_pointer_pos() {
                if mouse.distance(node_pos) <= 16.0f32 {
                    *selected_node = if *selected_node == Some(node_name.clone()) {
                        None
                    } else {
                        Some(node_name.clone())
                    };
                }
            }
        }
    }

    // 7. Update, filter, and render active attack arcs and particles
    for arc in arcs.iter_mut() {
        arc.update_projection(rect);

        // Filter by selected node if set
        if let Some(filter_node) = selected_node {
            if &arc.incident.node_id != filter_node {
                continue;
            }
        }

        let alpha = arc.alpha(now);
        if alpha <= 0.0f32 {
            continue;
        }

        let base_col = severity_color(&arc.incident.severity);
        let arc_col = Color32::from_rgba_unmultiplied(
            base_col.r(),
            base_col.g(),
            base_col.b(),
            (alpha * 175.0f32) as u8,
        );

        // Tessellate quadratic Bezier curve
        let num_segments = 24;
        let mut curve_pts = Vec::with_capacity(num_segments + 1);
        for i in 0..=num_segments {
            let t = i as f32 / num_segments as f32;
            curve_pts.push(quadratic_bezier(arc.start_pos, arc.ctrl_pos, arc.end_pos, t));
        }
        painter.add(egui::Shape::Path(egui::epaint::PathShape::line(
            curve_pts,
            Stroke::new(1.6f32, arc_col),
        )));

        // Origin attacker beacon
        let origin_col = Color32::from_rgba_unmultiplied(
            base_col.r(),
            base_col.g(),
            base_col.b(),
            (alpha * 220.0f32) as u8,
        );
        painter.circle_filled(arc.start_pos, 3.5f32, origin_col);
        painter.circle_stroke(arc.start_pos, 3.5f32, Stroke::new(1.0f32, Color32::WHITE));

        // Local Wi-Fi / RFC 1918 indicator
        if is_rfc1918(&arc.incident.ip) {
            painter.circle_stroke(
                arc.start_pos,
                7.0f32,
                Stroke::new(1.0f32, COLOR_ACCENT_CYAN),
            );
            painter.text(
                arc.start_pos + egui::vec2(9.0f32, -4.0f32),
                egui::Align2::LEFT_CENTER,
                "LAN/Wi-Fi",
                egui::FontId::proportional(9.0f32),
                COLOR_ACCENT_CYAN,
            );
        }

        // Flying particle with glow head
        if let Some(pos) = arc.particle_pos(now) {
            painter.circle_filled(
                pos,
                5.0f32,
                Color32::from_rgba_unmultiplied(base_col.r(), base_col.g(), base_col.b(), 100),
            );
            painter.circle_filled(pos, 2.5f32, Color32::WHITE);
        }

        // Interactive click on origin beacon
        if response.clicked() {
            if let Some(mouse) = response.interact_pointer_pos() {
                if mouse.distance(arc.start_pos) <= 12.0f32 {
                    *modal_incident = Some(arc.incident.clone());
                }
            }
        }
    }

    // 8. Live Attacks HUD Overlay in bottom-left
    let hud_width = 370.0f32.min(rect.width() * 0.45f32);
    let hud_height = 200.0f32.min(rect.height() * 0.45f32);
    let hud_rect = egui::Rect::from_min_size(
        egui::pos2(rect.min.x + 16.0f32, rect.max.y - hud_height - 16.0f32),
        egui::vec2(hud_width, hud_height),
    );

    ui.allocate_ui_at_rect(hud_rect, |ui| {
        egui::Frame::none()
            .fill(Color32::from_rgba_unmultiplied(22, 27, 34, 235))
            .stroke(Stroke::new(1.0f32, COLOR_BORDER))
            .rounding(8.0f32)
            .inner_margin(10.0f32)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("⚡ ATAQUES EM TEMPO REAL")
                            .size(11.0f32)
                            .strong()
                            .color(COLOR_ACCENT_CYAN),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{} ATIVOS", arcs.len()))
                                .size(10.0f32)
                                .color(COLOR_TEXT_MUTED),
                        );
                    });
                });
                ui.separator();

                egui::ScrollArea::vertical()
                    .id_source("map_hud_feed")
                    .show(ui, |ui| {
                        let feed = incidents.iter().take(5);
                        for inc in feed {
                            ui.horizontal(|ui| {
                                render_severity_pill(ui, &inc.severity);
                                let resp = ui.selectable_label(
                                    false,
                                    RichText::new(&inc.ip)
                                        .size(11.0f32)
                                        .monospace()
                                        .color(Color32::WHITE),
                                );
                                if resp.clicked() {
                                    *modal_incident = Some(inc.clone());
                                }
                                ui.label(
                                    RichText::new(format!(":{} {}", inc.port, inc.service))
                                        .size(10.0f32)
                                        .color(COLOR_TEXT_MUTED),
                                );
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .small_button("🔬")
                                            .on_hover_text("Abrir Raio-X Forense")
                                            .clicked()
                                        {
                                            *modal_incident = Some(inc.clone());
                                        }
                                    },
                                );
                            });
                        }
                    });
            });
    });

    // 9. Status HUD / Legend in top-right
    let legend_rect = egui::Rect::from_min_size(
        egui::pos2(rect.max.x - 210.0f32, rect.min.y + 16.0f32),
        egui::vec2(194.0f32, 95.0f32),
    );
    ui.allocate_ui_at_rect(legend_rect, |ui| {
        egui::Frame::none()
            .fill(Color32::from_rgba_unmultiplied(22, 27, 34, 220))
            .stroke(Stroke::new(1.0f32, COLOR_BORDER))
            .rounding(6.0f32)
            .inner_margin(8.0f32)
            .show(ui, |ui| {
                ui.label(
                    RichText::new("🗺️ THREAT MAP")
                        .size(10.0f32)
                        .strong()
                        .color(COLOR_ACCENT_GREEN),
                );
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🟢 SOC Beacons:").size(10.0f32).color(COLOR_TEXT_MUTED));
                    ui.label(
                        RichText::new(format!("{}", nodes.len().max(1)))
                            .size(10.0f32)
                            .strong()
                            .color(Color32::WHITE),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚡ Trajetórias:").size(10.0f32).color(COLOR_TEXT_MUTED));
                    ui.label(
                        RichText::new(format!("{}", arcs.len()))
                            .size(10.0f32)
                            .strong()
                            .color(COLOR_ACCENT_AMBER),
                    );
                });
                if let Some(hover) = response.hover_pos() {
                    let (lat, lon) = screen_to_geo(hover, rect);
                    ui.label(
                        RichText::new(format!("🌐 {:.1}°, {:.1}°", lat, lon))
                            .size(9.0f32)
                            .monospace()
                            .color(COLOR_ACCENT_CYAN),
                    );
                }
            });
    });

    // 10. Node Filter indicator in top-left (if active)
    let mut clear_node_filter = false;
    if let Some(node_name) = selected_node.clone() {
        let filter_rect = egui::Rect::from_min_size(
            egui::pos2(rect.min.x + 16.0f32, rect.min.y + 16.0f32),
            egui::vec2(220.0f32, 36.0f32),
        );
        ui.allocate_ui_at_rect(filter_rect, |ui| {
            egui::Frame::none()
                .fill(Color32::from_rgba_unmultiplied(22, 27, 34, 230))
                .stroke(Stroke::new(1.0f32, COLOR_ACCENT_GREEN))
                .rounding(6.0f32)
                .inner_margin(6.0f32)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("Filtro: {}", node_name))
                                .size(11.0f32)
                                .color(COLOR_ACCENT_GREEN),
                        );
                        if ui.small_button("✕").on_hover_text("Limpar Filtro").clicked() {
                            clear_node_filter = true;
                        }
                    });
                });
        });
    }
    if clear_node_filter {
        *selected_node = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use crate::models::HubIncident;

    #[test]
    fn test_resolve_coordinates_countries() {
        let pt = resolve_coordinates("Portugal", "Lisboa", "194.65.0.1");
        assert!(pt.0 > 36.0 && pt.0 < 43.0, "Portugal latitude out of range: {}", pt.0);
        assert!(pt.1 > -12.0 && pt.1 < -6.0, "Portugal longitude out of range: {}", pt.1);

        let de = resolve_coordinates("Germany", "Frankfurt", "80.80.80.80");
        assert!(de.0 > 47.0 && de.0 < 56.0, "Germany latitude out of range: {}", de.0);
        assert!(de.1 > 5.0 && de.1 < 16.0, "Germany longitude out of range: {}", de.1);

        let us = resolve_coordinates("United States", "New York", "8.8.8.8");
        assert!(us.0 > 24.0 && us.0 < 50.0, "US latitude out of range: {}", us.0);
        assert!(us.1 > -130.0 && us.1 < -60.0, "US longitude out of range: {}", us.1);

        let cn = resolve_coordinates("China", "Beijing", "1.1.1.1");
        assert!(cn.0 > 18.0 && cn.0 < 54.0, "China latitude out of range: {}", cn.0);
        assert!(cn.1 > 73.0 && cn.1 < 136.0, "China longitude out of range: {}", cn.1);
    }

    #[test]
    fn test_project_to_screen_bounds() {
        let rect = egui::Rect::from_min_size(egui::pos2(100.0, 50.0), egui::vec2(800.0, 400.0));

        // Top-left: Lat 90, Lon -180
        let tl = project_to_screen(90.0, -180.0, rect);
        assert!((tl.x - 100.0).abs() < 1e-3, "Expected x=100.0, got {}", tl.x);
        assert!((tl.y - 50.0).abs() < 1e-3, "Expected y=50.0, got {}", tl.y);

        // Bottom-right: Lat -90, Lon 180
        let br = project_to_screen(-90.0, 180.0, rect);
        assert!((br.x - 900.0).abs() < 1e-3, "Expected x=900.0, got {}", br.x);
        assert!((br.y - 450.0).abs() < 1e-3, "Expected y=450.0, got {}", br.y);

        // Center: Lat 0, Lon 0
        let center = project_to_screen(0.0, 0.0, rect);
        assert!((center.x - 500.0).abs() < 1e-3, "Expected center x=500.0, got {}", center.x);
        assert!((center.y - 250.0).abs() < 1e-3, "Expected center y=250.0, got {}", center.y);

        // Extreme bounds and NaN safety: must clamp and not panic or return NaN
        let out_bounds = project_to_screen(120.0, -200.0, rect);
        assert!((out_bounds.x - 100.0).abs() < 1e-3);
        assert!((out_bounds.y - 50.0).abs() < 1e-3);

        let nan_point = project_to_screen(f32::NAN, f32::NAN, rect);
        assert!(!nan_point.x.is_nan());
        assert!(!nan_point.y.is_nan());
        assert!(nan_point.x >= rect.min.x && nan_point.x <= rect.max.x);
        assert!(nan_point.y >= rect.min.y && nan_point.y <= rect.max.y);
    }

    #[test]
    fn test_active_attack_arc_flight() {
        let incident = HubIncident {
            id: Some(1),
            node_id: "node-pt".to_string(),
            timestamp: "2026-11-12 18:00:00".to_string(),
            ip: "8.8.8.8".to_string(),
            port: 22,
            service: "SSH".to_string(),
            severity: "ALTO".to_string(),
            country: "United States".to_string(),
            city: "Mountain View".to_string(),
            isp: "Google LLC".to_string(),
            rdns: None,
            payload: None,
            threat_score: 80,
            hit_count: 1,
        };

        let start_pos = egui::pos2(100.0, 200.0);
        let end_pos = egui::pos2(500.0, 200.0);
        let t0 = Instant::now();
        let arc = ActiveAttackArc::new(incident, start_pos, end_pos, t0);

        // At t = 0 (launch)
        let p0 = arc.particle_pos(t0).expect("Particle should be active at t0");
        assert!((p0.x - start_pos.x).abs() < 1e-2);
        assert!((p0.y - start_pos.y).abs() < 1e-2);

        // At midpoint of flight
        let half_time = t0 + arc.flight_duration / 2;
        let p_mid = arc.particle_pos(half_time).expect("Particle should be active at half time");
        assert!((p_mid.x - 300.0).abs() < 5.0, "Expected mid x near 300, got {}", p_mid.x);
        // Bezier arch lifts upward (smaller y in egui coordinates)
        assert!(p_mid.y < start_pos.y, "Arc should curve upwards (y < start_pos.y), got {}", p_mid.y);

        // At end of flight
        let end_time = t0 + arc.flight_duration;
        let p_end = arc.particle_pos(end_time).expect("Particle should be active at end time");
        assert!((p_end.x - end_pos.x).abs() < 1e-2);
        assert!((p_end.y - end_pos.y).abs() < 1e-2);

        // After flight completes
        let post_flight = t0 + arc.flight_duration + Duration::from_millis(50);
        assert!(arc.particle_pos(post_flight).is_none(), "Particle should be gone after flight duration");
    }

    #[test]
    fn test_resolve_coordinates_rfc1918_and_fallback() {
        // RFC 1918 private network IPs
        let lan1 = resolve_coordinates("Rede Local (Wi-Fi)", "Sub-rede wlo1", "172.20.200.174");
        assert!((lan1.0 - 41.5).abs() < 1e-2);
        assert!((lan1.1 - (-11.0)).abs() < 1e-2);

        let lan2 = resolve_coordinates("", "", "192.168.1.100");
        assert!((lan2.0 - 41.5).abs() < 1e-2);
        assert!((lan2.1 - (-11.0)).abs() < 1e-2);

        let lan3 = resolve_coordinates("", "", "10.0.0.1");
        assert!((lan3.0 - 41.5).abs() < 1e-2);
        assert!((lan3.1 - (-11.0)).abs() < 1e-2);

        // Deterministic fallback for unknown public IP
        let unknown = resolve_coordinates("UnknownLand", "Nowhere", "203.0.113.195");
        assert!(unknown.0 >= -90.0 && unknown.0 <= 90.0);
        assert!(unknown.1 >= -180.0 && unknown.1 <= 180.0);
    }

    #[test]
    fn test_active_attack_arc_lifecycle() {
        let incident = HubIncident {
            id: Some(2),
            node_id: "node-pt".to_string(),
            timestamp: "2026-11-12 18:00:00".to_string(),
            ip: "1.1.1.1".to_string(),
            port: 53,
            service: "DNS".to_string(),
            severity: "MÉDIO".to_string(),
            country: "Australia".to_string(),
            city: "Sydney".to_string(),
            isp: "Cloudflare".to_string(),
            rdns: None,
            payload: None,
            threat_score: 40,
            hit_count: 5,
        };

        let t0 = Instant::now();
        let rect = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1000.0, 500.0));
        let mut arc = ActiveAttackArc::from_geo(incident, (-33.86, 151.20), (39.5, -8.0), rect, t0);

        assert_eq!(arc.progress(t0), 0.0);
        assert_eq!(arc.alpha(t0), 1.0);
        assert!(!arc.is_expired(t0));

        // Progress halfway
        let mid = t0 + arc.flight_duration / 2;
        let prog = arc.progress(mid);
        assert!((prog - 0.5).abs() < 0.05);

        // Re-projection update test
        let new_rect = egui::Rect::from_min_size(egui::pos2(100.0, 100.0), egui::vec2(800.0, 400.0));
        arc.update_projection(new_rect);
        assert!(arc.start_pos.x >= 100.0 && arc.start_pos.x <= 900.0);
        assert!(arc.end_pos.x >= 100.0 && arc.end_pos.x <= 900.0);

        // Alpha fade out after 17 seconds
        let t_fade = t0 + Duration::from_secs(17);
        let alpha = arc.alpha(t_fade);
        assert!(alpha < 1.0 && alpha > 0.0, "Expected alpha in fade out range, got {}", alpha);

        // Expired after 20 seconds
        let t_exp = t0 + Duration::from_secs(21);
        assert!(arc.is_expired(t_exp));
        assert_eq!(arc.alpha(t_exp), 0.0);
    }

    #[test]
    fn test_screen_to_geo_invertibility() {
        let rect = egui::Rect::from_min_size(egui::pos2(100.0, 50.0), egui::vec2(800.0, 400.0));

        let original_coords = [(0.0, 0.0), (39.5, -8.0), (-33.86, 151.2), (51.16, 10.45)];
        for &(lat, lon) in &original_coords {
            let screen_pos = project_to_screen(lat, lon, rect);
            let (inv_lat, inv_lon) = screen_to_geo(screen_pos, rect);
            assert!((inv_lat - lat).abs() < 1e-2, "Lat inversion mismatch: {} vs {}", inv_lat, lat);
            assert!((inv_lon - lon).abs() < 1e-2, "Lon inversion mismatch: {} vs {}", inv_lon, lon);
        }
    }

    #[test]
    fn test_active_attack_arc_from_incident() {
        let incident = HubIncident {
            id: Some(3),
            node_id: "soc-central-pt".to_string(),
            timestamp: "2026-11-12 18:30:00".to_string(),
            ip: "185.220.101.5".to_string(),
            port: 22,
            service: "SSH".to_string(),
            severity: "CRÍTICO".to_string(),
            country: "Germany".to_string(),
            city: "Frankfurt".to_string(),
            isp: "Tor Exit Node".to_string(),
            rdns: None,
            payload: None,
            threat_score: 95,
            hit_count: 12,
        };

        let t0 = Instant::now();
        let mut arc = ActiveAttackArc::from_incident(incident, (39.5, -8.0), t0);
        let rect = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(1000.0, 500.0));
        arc.update_projection(rect);

        assert!(arc.start_pos.x > 0.0 && arc.start_pos.x < 1000.0);
        assert!(arc.end_pos.x > 0.0 && arc.end_pos.x < 1000.0);
        assert!(arc.ctrl_pos.y < (arc.start_pos.y + arc.end_pos.y) * 0.5);
    }
}
