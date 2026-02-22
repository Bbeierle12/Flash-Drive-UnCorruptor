//! `fdu report <device>` — generate a security report.

use anyhow::{Context, Result};
use fdu_audit::{AuditConfig, AuditEngine};

pub fn run(device: &str, format: &str, output: Option<String>) -> Result<()> {
    let dev = crate::commands::scan::open_device(device)?;

    // Run full audit
    let mut engine = AuditEngine::new(AuditConfig::default());
    engine.register_defaults();

    let report = engine
        .scan(&*dev, None)
        .context("Audit scan failed")?;

    let text = match format.to_lowercase().as_str() {
        "json" => fdu_audit::report::format_json(&report)
            .context("JSON serialization failed")?,
        _ => fdu_audit::report::format_text(&report),
    };

    match output {
        Some(path) => {
            std::fs::write(&path, &text)
                .context(format!("Failed to write report to {}", path))?;
            eprintln!("Report written to {}", path);
        }
        None => {
            println!("{}", text);
        }
    }

    Ok(())
}
