use crate::correlation::CorrelationEngine;
use crate::db::Database;
use crate::models::{AgentNode, CorrelationAlert, HubIncident};
use crate::server::HubEvent;
use crate::ui::header::{render_header, ViewTab};
use crate::ui::sidebar::render_sidebar;
use crate::ui::views::analytics::render_analytics_view;
use crate::ui::views::correlations::render_correlations_view;
use crate::ui::views::incidents::render_incidents_view;
use crate::ui::{apply_cyber_theme, COLOR_ACCENT_GREEN, COLOR_PANEL_BG};
use egui::{RichText, Stroke};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

pub struct HubApp {
    db: Database,
    event_rx: Receiver<HubEvent>,
    correlation_engine: CorrelationEngine,
    nodes: Vec<AgentNode>,
    incidents: Vec<HubIncident>,
    correlations: Vec<CorrelationAlert>,
    top_attackers: Vec<(String, usize, u8, String)>,
    current_tab: ViewTab,
    search_query: String,
    selected_severity: String,
    selected_node: Option<String>,
    server_addr: String,
    toast_msg: Option<(String, Instant)>,
    last_db_refresh: Instant,
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

        Self {
            db,
            event_rx,
            correlation_engine,
            nodes,
            incidents,
            correlations,
            top_attackers,
            current_tab: ViewTab::Incidents,
            search_query: String::new(),
            selected_severity: "TODAS".to_string(),
            selected_node: None,
            server_addr,
            toast_msg: None,
            last_db_refresh: Instant::now(),
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
}

impl eframe::App for HubApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut new_event = false;

        // Drain incoming network events
        while let Ok(event) = self.event_rx.try_recv() {
            new_event = true;
            match event {
                HubEvent::NewIncident(inc) => {
                    self.correlation_engine.process_incident(&inc);
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
        egui::TopBottomPanel::top("top_header").show(ctx, |ui| {
            render_header(
                ui,
                &mut self.current_tab,
                self.nodes.iter().filter(|n| n.online).count(),
                self.incidents.len(),
                self.correlations.len(),
                &self.server_addr,
            );
        });

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
    }
}
