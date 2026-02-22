//! `fdu usb list` and `fdu usb inspect` — USB device inspection.

use anyhow::{Context, Result};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Table};
use fdu_models::Severity;

pub fn run_list(json: bool) -> Result<()> {
    let fingerprints =
        fdu_usb::enumerate_usb_devices().context("USB enumeration failed")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&fingerprints)?);
        return Ok(());
    }

    if fingerprints.is_empty() {
        println!("No USB devices found.");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec![
        "VID:PID",
        "Manufacturer",
        "Product",
        "Serial",
        "Classes",
        "Threats",
    ]);

    for fp in &fingerprints {
        let findings = fdu_usb::detect_badusb(fp);
        let max_severity = findings.iter().map(|f| f.severity).max();

        let threat_str = match max_severity {
            None => "None".green().to_string(),
            Some(Severity::Info | Severity::Low) => "Low".yellow().to_string(),
            Some(Severity::Medium) => "Medium".yellow().bold().to_string(),
            Some(Severity::High) => "High".red().to_string(),
            Some(Severity::Critical) => "CRITICAL".red().bold().to_string(),
        };

        let classes: Vec<String> = fp
            .interface_classes
            .iter()
            .map(|c| format!("0x{:02X}", c))
            .collect();

        table.add_row(vec![
            fp.vid_pid(),
            fp.manufacturer.clone().unwrap_or_else(|| "-".into()),
            fp.product.clone().unwrap_or_else(|| "-".into()),
            fp.serial.clone().unwrap_or_else(|| "-".into()),
            classes.join(", "),
            threat_str,
        ]);
    }

    println!("{}", "USB Devices".bold().green());
    println!("{table}");
    println!("\n{} device(s) found", fingerprints.len());

    Ok(())
}

pub fn run_inspect(device: &str, json: bool) -> Result<()> {
    let fingerprints =
        fdu_usb::enumerate_usb_devices().context("USB enumeration failed")?;

    // Find matching device by VID:PID or partial name match
    let fp = fingerprints
        .iter()
        .find(|fp| {
            fp.vid_pid() == device
                || fp
                    .product
                    .as_ref()
                    .map(|p| p.to_lowercase().contains(&device.to_lowercase()))
                    .unwrap_or(false)
        })
        .context(format!("No USB device matching '{}' found", device))?;

    let findings = fdu_usb::detect_badusb(fp);

    if json {
        let output = serde_json::json!({
            "fingerprint": fp,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("{}", "USB Device Inspection".bold().green());
    println!("  VID:PID:      {}", fp.vid_pid().bold());
    println!(
        "  Manufacturer: {}",
        fp.manufacturer.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "  Product:      {}",
        fp.product.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "  Serial:       {}",
        fp.serial.as_deref().unwrap_or("(none)")
    );
    println!("  Device Class: 0x{:02X}", fp.device_class);
    println!(
        "  Interfaces:   {:?}",
        fp.interface_classes
            .iter()
            .map(|c| format!("0x{:02X}", c))
            .collect::<Vec<_>>()
    );
    println!("  BCD Device:   0x{:04X}", fp.bcd_device);
    println!("  Raw Desc:     {} bytes", fp.descriptors_raw.len());

    if findings.is_empty() {
        println!("\n  {} No security issues detected.", "✓".green());
    } else {
        println!("\n  {} {} finding(s):", "⚠".yellow(), findings.len());
        for f in &findings {
            let sev = match f.severity {
                Severity::Info | Severity::Low => format!("{}", f.severity).dimmed().to_string(),
                Severity::Medium => format!("{}", f.severity).yellow().to_string(),
                Severity::High => format!("{}", f.severity).red().to_string(),
                Severity::Critical => format!("{}", f.severity).red().bold().to_string(),
            };
            println!("    [{}] {}", sev, f.title);
            println!("      {}", f.description);
        }
    }

    Ok(())
}
