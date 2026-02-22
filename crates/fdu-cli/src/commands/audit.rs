//! `fdu audit <device>` — run a full security audit.

use anyhow::{Context, Result};
use colored::Colorize;
use fdu_audit::{AuditConfig, AuditEngine, Phase};
use fdu_models::Severity;

pub fn run(device: &str, phase: Option<String>, min_severity: &str, json: bool) -> Result<()> {
    let dev = crate::commands::scan::open_device(device)?;

    // Parse min severity
    let min_sev = match min_severity.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" | "med" => Severity::Medium,
        "high" => Severity::High,
        "critical" | "crit" => Severity::Critical,
        _ => {
            anyhow::bail!("Unknown severity: {}. Use: info, low, medium, high, critical", min_severity);
        }
    };

    // Build config
    let mut config = AuditConfig {
        min_severity: min_sev,
        ..AuditConfig::default()
    };

    // If a specific phase is requested, skip all others
    if let Some(ref phase_str) = phase {
        let target_phase = match phase_str.to_lowercase().as_str() {
            "usb" => Phase::Usb,
            "disk" => Phase::Disk,
            "filesystem" | "fs" => Phase::Filesystem,
            "content" => Phase::Content,
            "forensics" => Phase::Forensics,
            _ => {
                anyhow::bail!(
                    "Unknown phase: {}. Use: usb, disk, filesystem, content, forensics",
                    phase_str
                );
            }
        };

        for p in [Phase::Usb, Phase::Disk, Phase::Filesystem, Phase::Content, Phase::Forensics] {
            if p != target_phase {
                config.skip_phases.push(p);
            }
        }
    }

    // Build engine
    let mut engine = AuditEngine::new(config);
    engine.register_defaults();

    if !json {
        println!(
            "{} {} {}",
            "FDU Security Audit".bold().green(),
            "→".dimmed(),
            device.bold()
        );
        println!();
    }

    // Run audit (no USB fingerprint when scanning disk images)
    let report = engine
        .scan(&*dev, None)
        .context("Audit scan failed")?;

    if json {
        let json_out = fdu_audit::report::format_json(&report)
            .context("JSON serialization failed")?;
        println!("{}", json_out);
    } else {
        println!("{}", fdu_audit::report::format_text(&report));

        // Summary line
        let color = match report.overall_risk {
            Severity::Info | Severity::Low => "green",
            Severity::Medium => "yellow",
            Severity::High | Severity::Critical => "red",
        };

        let risk_str = format!("{}", report.overall_risk);
        let risk_colored = match color {
            "green" => risk_str.green(),
            "yellow" => risk_str.yellow(),
            _ => risk_str.red(),
        };

        println!(
            "Overall Risk: {}  |  Safe to Mount: {}",
            risk_colored,
            if report.safe_to_mount {
                "YES".green().to_string()
            } else {
                "NO".red().bold().to_string()
            },
        );
    }

    Ok(())
}
