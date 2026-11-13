pub mod alerts;
pub mod app;
pub mod campaigns;
pub mod correlation;
pub mod db;
pub mod models;
pub mod server;
pub mod threat_intel;
pub mod ui;

use app::HubApp;
use db::Database;
use server::{HubEvent, IngestionServer};
use std::path::PathBuf;
use std::sync::mpsc::channel;

fn get_db_path() -> PathBuf {
    if let Ok(path) = std::env::var("SENTINELA_HUB_DB") {
        PathBuf::from(path)
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let dir = PathBuf::from(home).join(".local/share/sentinela-hub");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("sentinela_hub.db")
    }
}

fn main() -> eframe::Result<()> {
    let bind_addr = std::env::var("SENTINELA_HUB_ADDR").unwrap_or_else(|_| "0.0.0.0:8765".to_string());
    let db_path = get_db_path();

    println!("[*] A inicializar Sentinela Hub v{}", env!("CARGO_PKG_VERSION"));
    println!("[*] Base de dados SQLite: {}", db_path.display());

    let db = Database::open(&db_path).expect("Falha ao abrir base de dados SQLite");
    let (event_tx, event_rx) = channel::<HubEvent>();

    // Start background Tokio runtime for telemetry ingestion
    let server_db = db.clone();
    let server_bind = bind_addr.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Falha ao criar Tokio runtime para Ingestion Server");

        rt.block_on(async move {
            let server = IngestionServer::new(server_db, event_tx, server_bind);
            if let Err(e) = server.run().await {
                eprintln!("[!] Ingestion server terminado com erro: {}", e);
            }
        });
    });

    // Native desktop GUI options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("Sentinela Hub - SIEM & Multi-Host SOC"),
        ..Default::default()
    };

    let gui_db = db.clone();
    let display_addr = bind_addr.clone();

    eframe::run_native(
        "Sentinela Hub",
        options,
        Box::new(move |cc| {
            Ok(Box::new(HubApp::new(cc, gui_db, event_rx, display_addr)))
        }),
    )
}
