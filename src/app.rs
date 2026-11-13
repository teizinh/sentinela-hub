use crate::correlation::CorrelationEngine;
use crate::db::Database;
use crate::models::{AgentNode, CorrelationAlert, HubIncident};
use crate::server::HubEvent;
use crate::threat_intel::ThreatIntelFeed;
use crate::ui::header::{render_header, ViewTab};
use crate::ui::sidebar::render_sidebar;
use crate::ui::views::analytics::render_analytics_view;
use crate::ui::views::correlations::render_correlations_view;
use crate::ui::views::incidents::render_incidents_view;
use crate::ui::views::map::ActiveAttackArc;
use crate::ui::{apply_cyber_theme, COLOR_ACCENT_GREEN, COLOR_PANEL_BG};
use egui::{RichText, Stroke};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

pub struct HubApp {
    db: Database,
    event_rx: Receiver<HubEvent>,
    correlation_engine: CorrelationEngine,
    threat_intel: ThreatIntelFeed,
    nodes: Vec<AgentNode>,
    incidents: Vec<HubIncident>,
    correlations: Vec<CorrelationAlert>,
    top_attackers: Vec<(String, usize, u8, String)>,
    active_arcs: Vec<ActiveAttackArc>,
    current_tab: ViewTab,
    search_query: String,
    selected_severity: String,
    selected_node: Option<String>,
    pub selected_incident: Option<HubIncident>,
    server_addr: String,
    toast_msg: Option<(String, Instant)>,
    last_db_refresh: Instant,
    last_critical_alert: Option<Instant>,
}

impl HubApp {
    pub fn new(
        _cc: &eframe::CreationContext<'_>,
        db: Database,
        event_rx: Receiver<HubEvent>,
        server_addr: String,
    ) -> Self {
        apply_cyber_theme(&_cc.egui_ctx);

        let nodes = db.get_nodes().unwrap_or_default();
        let incidents = db.get_recent_incidents(500).unwrap_or_default();
        let top_attackers = db.get_top_attackers(10).unwrap_or_default();

        let mut correlation_engine = CorrelationEngine::default();
        for inc in &incidents {
            correlation_engine.process_incident(inc);
        }
        let correlations = correlation_engine.get_active_correlations();

        // Seed up to 10 historical attack trajectories with staggered offsets
        let mut active_arcs = Vec::new();
        let seed_count = incidents.len().min(10);
        for (i, inc) in incidents.iter().take(seed_count).enumerate() {
            let target_geo = nodes
                .iter()
                .find(|n| n.id == inc.node_id)
                .map(crate::ui::views::map::resolve_node_coordinates)
                .unwrap_or_else(crate::ui::views::map::default_target_coordinates);
            let offset = Duration::from_millis((i as u64) * 600);
            let created_at = Instant::now().checked_sub(offset).unwrap_or_else(Instant::now);
            active_arcs.push(ActiveAttackArc::from_incident(
                inc.clone(),
                target_geo,
                created_at,
            ));
        }

        Self {
            db,
            event_rx,
            correlation_engine,
            threat_intel: ThreatIntelFeed::default(),
            nodes,
            incidents,
            correlations,
            top_attackers,
            active_arcs,
            current_tab: ViewTab::Incidents,
            search_query: String::new(),
            selected_severity: "TODAS".to_string(),
            selected_node: None,
            selected_incident: None,
            server_addr,
            toast_msg: None,
            last_db_refresh: Instant::now(),
            last_critical_alert: None,
        }
    }

    fn refresh_from_db(&mut self) {
        if let Ok(nodes) = self.db.get_nodes() {
            self.nodes = nodes;
        }
        if let Ok(attackers) = self.db.get_top_attackers(10) {
            self.top_attackers = attackers;
        }
    }

    fn seed_arcs_if_empty(&mut self) {
        if self.active_arcs.is_empty() && !self.incidents.is_empty() {
            let seed_count = self.incidents.len().min(10);
            for (i, inc) in self.incidents.iter().take(seed_count).enumerate() {
                let target_geo = self
                    .nodes
                    .iter()
                    .find(|n| n.id == inc.node_id)
                    .map(crate::ui::views::map::resolve_node_coordinates)
                    .unwrap_or_else(crate::ui::views::map::default_target_coordinates);
                let offset = Duration::from_millis((i as u64) * 600);
                let created_at = Instant::now().checked_sub(offset).unwrap_or_else(Instant::now);
                self.active_arcs.push(ActiveAttackArc::from_incident(
                    inc.clone(),
                    target_geo,
                    created_at,
                ));
            }
        }
    }
}

impl eframe::App for HubApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut new_event = false;

        // Drain incoming network events
        while let Ok(event) = self.event_rx.try_recv() {
            new_event = true;
            match event {
                HubEvent::NewIncident(mut inc) => {
                    self.threat_intel.enrich_incident(&mut inc);
                    self.correlation_engine.process_incident(&inc);
                    let target_geo = self
                        .nodes
                        .iter()
                        .find(|n| n.id == inc.node_id)
                        .map(crate::ui::views::map::resolve_node_coordinates)
                        .unwrap_or_else(crate::ui::views::map::default_target_coordinates);
                    let arc = ActiveAttackArc::from_incident(
                        inc.clone(),
                        target_geo,
                        Instant::now(),
                    );
                    self.active_arcs.push(arc);
                    if self.active_arcs.len() > 100 {
                        self.active_arcs.remove(0);
                    }
                    if inc.severity.to_uppercase() == "CRÍTICO" || inc.severity.to_uppercase() == "CRITICO" {
                        self.last_critical_alert = Some(Instant::now());
                        crate::ui::header::play_audio_alert_if_enabled(ctx);
                    }
                    self.incidents.insert(0, inc);
                    if self.incidents.len() > 1000 {
                        self.incidents.truncate(1000);
                    }
                    self.correlations = self.correlation_engine.get_active_correlations();
                }
                HubEvent::NodeHeartbeat(_node) => {
                    self.refresh_from_db();
                }
            }
        }

        // Periodic refresh (every 3 seconds)
        if new_event || self.last_db_refresh.elapsed() > Duration::from_secs(3) {
            self.refresh_from_db();
            self.last_db_refresh = Instant::now();
        }

        // Repaint request for live data
        if new_event {
            ctx.request_repaint();
        }

        // Header Panel
        let mut export_report = false;
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            render_header(
                ui,
                &mut self.current_tab,
                self.nodes.iter().filter(|n| n.online).count(),
                self.incidents.len(),
                self.correlations.len(),
                &self.server_addr,
                &mut export_report,
            );
        });

        if export_report {
            let report = crate::ui::report::export_executive_report(&self.incidents, &self.correlations);
            let dir = std::path::Path::new("/home/salvadorpontes/.local/share/sentinela-hub");
            let _ = std::fs::create_dir_all(dir);
            let file_path = dir.join("relatorio_soc.md");
            let _ = std::fs::write(&file_path, &report);
            ctx.output_mut(|o| o.copied_text = report);
            self.toast_msg = Some((
                "Relatório Executivo SOC exportado e copiado para o clipboard!".to_string(),
                Instant::now(),
            ));
        }

        // Toast notification banner
        if let Some((msg, created_at)) = &self.toast_msg {
            if created_at.elapsed() < Duration::from_secs(4) {
                egui::TopBottomPanel::bottom("toast_panel").show(ctx, |ui| {
                    egui::Frame::none()
                        .fill(COLOR_PANEL_BG)
                        .stroke(Stroke::new(1.0f32, COLOR_ACCENT_GREEN))
                        .inner_margin(8.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("✅").size(14.0));
                                ui.label(
                                    RichText::new(msg)
                                        .size(12.0)
                                        .strong()
                                        .color(COLOR_ACCENT_GREEN),
                                );
                            });
                        });
                });
            } else {
                self.toast_msg = None;
            }
        }

        // Left Sidebar: Nodes
        egui::SidePanel::left("left_sidebar")
            .resizable(true)
            .default_width(220.0)
            .min_width(180.0)
            .show(ctx, |ui| {
                render_sidebar(ui, &self.nodes, &mut self.selected_node);
            });

        // Central Content Area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                ViewTab::Incidents => {
                    render_incidents_view(
                        ui,
                        &self.incidents,
                        &mut self.search_query,
                        &mut self.selected_severity,
                        &self.selected_node,
                        &mut self.toast_msg,
                        &mut self.selected_incident,
                    );
                }
                ViewTab::ThreatMap => {
                    self.seed_arcs_if_empty();
                    crate::ui::views::map::render_threat_map_view(
                        ui,
                        &self.nodes,
                        &self.incidents,
                        &mut self.active_arcs,
                        &mut self.selected_node,
                        &mut self.selected_incident,
                    );
                }
                ViewTab::Correlations => {
                    render_correlations_view(ui, &self.correlations, &mut self.toast_msg);
                }
                ViewTab::Analytics => {
                    render_analytics_view(ui, &self.incidents, &self.top_attackers);
                }
            }
        });

        // Forensic Raio-X Modal
        if let Some(inc) = &self.selected_incident {
            let mut close = false;
            crate::ui::modal::render_raio_x_modal(ctx, inc, &mut close, &mut self.toast_msg);
            if close {
                self.selected_incident = None;
            }
        }

        // Screen alarm vignette if a critical incident arrived recently (< 4 seconds)
        if let Some(t_crit) = self.last_critical_alert {
            let elapsed = t_crit.elapsed().as_secs_f32();
            if elapsed < 4.0f32 {
                let intensity = (4.0f32 - elapsed) / 4.0f32
                    * ((ctx.input(|i| i.time) as f32 * 5.0f32).sin() * 0.35f32 + 0.65f32);
                let painter = ctx.layer_painter(egui::LayerId::new(
                    egui::Order::Foreground,
                    egui::Id::new("alarm_vignette"),
                ));
                crate::ui::render_alarm_vignette(
                    &painter,
                    ctx.screen_rect(),
                    intensity.clamp(0.0f32, 1.0f32),
                );
                ctx.request_repaint();
            } else {
                self.last_critical_alert = None;
            }
        }
    }
}
