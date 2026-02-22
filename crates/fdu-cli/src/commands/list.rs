//! `fdu list` — enumerate connected removable drives.

use comfy_table::{presets::UTF8_FULL, Table, Cell};
use fdu_core::models::format_bytes;

pub fn run(json: bool, include_internal: bool) -> anyhow::Result<()> {
    let devices = fdu_device_enum::enumerate_devices()
        .map_err(|e| anyhow::anyhow!("Failed to enumerate devices: {}", e))?;

    let filtered: Vec<_> = if include_internal {
        devices
    } else {
        devices.into_iter().filter(|d| d.is_removable).collect()
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
        return Ok(());
    }

    if filtered.is_empty() {
        println!("No removable drives found.");
        println!();
        println!("Tips:");
        println!("  - Make sure your USB drive is plugged in");
        println!("  - Use --include-internal to see all block devices");
        println!("  - Run with sudo if devices aren't detected");
        return Ok(());
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Device", "Model", "Size", "Mount Point", "Transport"]);

    for dev in &filtered {
        let mount = dev
            .mount_point
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "(not mounted)".into());

        let transport = dev.transport.as_deref().unwrap_or("unknown");

        table.add_row(vec![
            Cell::new(&dev.device_path),
            Cell::new(format!("{} {}", dev.vendor, dev.model).trim()),
            Cell::new(format_bytes(dev.size_bytes)),
            Cell::new(&mount),
            Cell::new(transport),
        ]);
    }

    println!("{table}");
    println!();
    println!(
        "Found {} removable device(s). Use 'fdu scan <DEVICE>' to check integrity.",
        filtered.len()
    );

    Ok(())
}
