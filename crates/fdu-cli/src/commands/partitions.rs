//! `fdu partitions <device>` — show partition layout.

use anyhow::{Context, Result};
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Table};
use fdu_core::models::format_bytes;

pub fn run(device: &str, json: bool) -> Result<()> {
    let dev = crate::commands::scan::open_device(device)?;
    let layout =
        fdu_disk::analyze_partitions(&*dev).context("Partition analysis failed")?;

    if json {
        println!("{}", serde_json::to_string_pretty(&layout)?);
        return Ok(());
    }

    println!(
        "{} {} {}",
        "Partition Layout".bold().green(),
        "→".dimmed(),
        device.bold()
    );
    println!(
        "  Scheme:    {:?}",
        layout.scheme
    );
    println!(
        "  Sectors:   {} ({})",
        layout.total_sectors,
        format_bytes(layout.total_sectors * layout.sector_size as u64)
    );
    println!();

    if layout.partitions.is_empty() {
        println!("  No partitions found.");
    } else {
        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec![
            "#", "Type", "Label", "Start LBA", "End LBA", "Size", "Filesystem", "Flags",
        ]);

        for p in &layout.partitions {
            let mut flags = Vec::new();
            if p.flags.bootable {
                flags.push("boot");
            }
            if p.flags.system {
                flags.push("system");
            }
            if p.flags.hidden {
                flags.push("hidden");
            }

            table.add_row(vec![
                p.index.to_string(),
                p.type_label.clone(),
                p.label.clone().unwrap_or_else(|| "-".into()),
                p.start_lba.to_string(),
                p.end_lba.to_string(),
                format_bytes(p.size_bytes),
                p.fs_type
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "-".into()),
                if flags.is_empty() {
                    "-".into()
                } else {
                    flags.join(", ")
                },
            ]);
        }

        println!("{table}");
    }

    // Show unallocated regions
    if !layout.unallocated_regions.is_empty() {
        println!("\n  {} Unallocated regions:", "Gaps:".bold());
        for (start, end) in &layout.unallocated_regions {
            let sectors = end - start + 1;
            println!(
                "    LBA {}-{} ({} sectors, {})",
                start,
                end,
                sectors,
                format_bytes(sectors * layout.sector_size as u64)
            );
        }
    }

    // Run threat detectors
    let findings = fdu_disk::detect_disk_threats(&layout);
    if !findings.is_empty() {
        println!("\n  {} {} threat(s) detected:", "⚠".yellow(), findings.len());
        for f in &findings {
            println!("    [{}] {}", f.severity, f.title);
        }
    }

    Ok(())
}
