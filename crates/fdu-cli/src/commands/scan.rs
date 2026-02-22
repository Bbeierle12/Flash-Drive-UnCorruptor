//! `fdu scan` — scan a device for filesystem integrity issues.

use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use fdu_core::device::traits::Device;
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::*;

pub fn run(device_path: &str, _deep: bool, json: bool) -> anyhow::Result<()> {
    println!("Scanning {}...", device_path);
    println!();

    // Open device (use image mode for files, block device mode for /dev/*)
    let dev = open_device(device_path)?;

    // Detect filesystem
    let fs_type = detect_filesystem(dev.as_ref())?;
    println!("Detected filesystem: {}", fs_type);
    println!();

    // Run validation based on filesystem type
    let report = match fs_type {
        FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
            let fs = Fat32Fs::new(dev.as_ref())?;
            fs.validate()?
        }
        _ => {
            anyhow::bail!(
                "Filesystem '{}' scanning is not yet supported. \
                 Currently supported: FAT12/16/32.",
                fs_type
            );
        }
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Print metadata
    println!("=== Filesystem Info ===");
    println!(
        "  Type:          {}",
        report.metadata.fs_type
    );
    println!(
        "  Total size:    {}",
        format_bytes(report.metadata.total_bytes)
    );
    println!(
        "  Used:          {}",
        format_bytes(report.metadata.used_bytes)
    );
    println!(
        "  Free:          {}",
        format_bytes(report.metadata.free_bytes)
    );
    println!(
        "  Cluster size:  {} bytes",
        report.metadata.cluster_size
    );
    if let Some(ref label) = report.metadata.volume_label {
        println!("  Volume label:  {}", label);
    }
    println!(
        "  Scan time:     {} ms",
        report.scan_duration_ms
    );
    println!();

    // Print issues
    if report.issues.is_empty() {
        println!("No issues found — filesystem appears healthy!");
    } else {
        println!(
            "=== Issues Found ({} errors, {} warnings) ===",
            report.error_count(),
            report.warning_count()
        );
        println!();

        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header(vec!["Severity", "Code", "Description", "Repairable"]);

        for issue in &report.issues {
            let severity_cell = match issue.severity {
                Severity::Critical => Cell::new("CRITICAL").fg(Color::Red),
                Severity::Error => Cell::new("ERROR").fg(Color::Red),
                Severity::Warning => Cell::new("WARN").fg(Color::Yellow),
                Severity::Info => Cell::new("INFO").fg(Color::Cyan),
            };

            table.add_row(vec![
                severity_cell,
                Cell::new(&issue.code),
                Cell::new(&issue.message),
                Cell::new(if issue.repairable { "Yes" } else { "No" }),
            ]);
        }

        println!("{table}");
    }

    println!();
    if report.is_healthy() {
        println!("Result: HEALTHY");
    } else {
        println!("Result: ISSUES DETECTED — run 'fdu repair {}' to attempt fixes", device_path);
    }

    Ok(())
}

/// Open a device — handles both block devices and image files.
pub fn open_device(_path: &str) -> anyhow::Result<Box<dyn Device>> {
    #[cfg(target_os = "linux")]
    {
        use fdu_core::device::linux::LinuxDevice;

        if _path.starts_with("/dev/") {
            Ok(Box::new(LinuxDevice::open(_path, false)?))
        } else {
            // Assume it's a disk image file
            Ok(Box::new(LinuxDevice::open_image(_path)?))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Direct device access is only supported on Linux in Phase 1. Use a disk image file instead.");
    }
}
