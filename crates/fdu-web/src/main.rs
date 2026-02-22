//! Flash Drive UnCorruptor — Web GUI server (Phase 3).
//!
//! This is a placeholder that will be expanded in Phase 3 with:
//! - REST API for device listing, scanning, recovery
//! - WebSocket for real-time progress updates
//! - Embedded Preact SPA frontend

use axum::{routing::get, Json, Router};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/devices", get(list_devices));

    let addr = "127.0.0.1:3000";
    tracing::info!("Flash Drive UnCorruptor web GUI starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index() -> &'static str {
    "Flash Drive UnCorruptor — Web GUI (Phase 3: under construction)"
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn list_devices() -> Json<serde_json::Value> {
    match fdu_device_enum::enumerate_devices() {
        Ok(devices) => Json(json!({
            "devices": devices,
        })),
        Err(e) => Json(json!({
            "error": e.to_string(),
        })),
    }
}
