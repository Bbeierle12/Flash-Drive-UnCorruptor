//! `fdu scan` — unified device scan (filesystem + hardware + security).

use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
use fdu_core::device::traits::Device;
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::exfat::ExFatFs;
use fdu_core::fs::ext4::ExtFs;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::ntfs::NtfsFs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::*;

pub fn run(device_path: &str, deep: bool, json: bool) -> anyhow::Result<()> {
    println!("Scanning {}...", device_path);
    println!();

    // Open device
    let dev = open_device(device_path)?;

    // ── Phase 1: Filesystem Validation ──────────────────────────────
    println!("=== Phase 1: Filesystem Check ===");
    println!();

    let fs_type = detect_filesystem(dev.as_ref())?;
    println!("Detected filesystem: {}", fs_type);
    println!();

    let report = match fs_type {
        FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
            let fs = Fat32Fs::new(dev.as_ref())?;
            fs.validate()?
        }
        FsType::ExFat => {
            let fs = ExFatFs::new(dev.as_ref())?;
            fs.validate()?
        }
        FsType::Ext2 | FsType::Ext3 | FsType::Ext4 => {
            let fs = ExtFs::new(dev.as_ref())?;
            fs.validate()?
        }
        FsType::Ntfs => {
            let fs = NtfsFs::new(dev.as_ref())?;
            fs.validate()?
        }
        _ => {
            println!(
                "Filesystem '{}' scanning is not yet supported.\n\
                 Currently supported: FAT12/16/32, exFAT, ext2/3/4, NTFS.\n",
                fs_type
            );
            // Don't bail — continue to hardware and security phases
            println!("Skipping filesystem validation, continuing with hardware checks...");
            println!();
            return run_hardware_and_security(dev.as_ref(), device_path, deep, json);
        }
    };

    if json {
        // In JSON mode, just output the filesystem report
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Print filesystem metadata
    println!("  Type:          {}", report.metadata.fs_type);
    println!("  Total size:    {}", format_bytes(report.metadata.total_bytes));
    println!("  Used:          {}", format_bytes(report.metadata.used_bytes));
    println!("  Free:          {}", format_bytes(report.metadata.free_bytes));
    println!("  Cluster size:  {} bytes", report.metadata.cluster_size);
    if let Some(ref label) = report.metadata.volume_label {
        println!("  Volume label:  {}", label);
    }
    println!("  Scan time:     {} ms", report.scan_duration_ms);
    println!();

    // Print filesystem issues
    if report.issues.is_empty() {
        println!("  Result: HEALTHY — no filesystem issues found.");
    } else {
        println!(
            "  Issues: {} errors, {} warnings",
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

    // ── Phase 2 & 3: Hardware + Security ────────────────────────────
    run_hardware_and_security(dev.as_ref(), device_path, deep, json)?;

    // Final verdict
    println!("================================================================");
    if report.is_healthy() {
        println!("SCAN COMPLETE: No issues detected.");
    } else {
        let repairable_count = report.issues.iter().filter(|i| i.repairable).count();
        println!(
            "SCAN COMPLETE: {} issues found ({} repairable).",
            report.issues.len(),
            repairable_count
        );
        println!(
            "Run 'fdu repair {} --unsafe-mode' to attempt fixes.",
            device_path
        );
    }

    Ok(())
}

fn run_hardware_and_security(
    dev: &dyn Device,
    device_path: &str,
    deep: bool,
    _json: bool,
) -> anyhow::Result<()> {
    use fdu_core::diagnostics::{detect_fake_flash, scan_entropy};
    use indicatif::{ProgressBar, ProgressStyle};

    let device_size = dev.size();
    let sector_size = dev.sector_size();

    // ── Phase 2: Hardware Diagnostics ───────────────────────────────
    println!("=== Phase 2: Hardware Diagnostics ===");
    println!();
    println!(
        "  Device size: {} ({} sectors of {} bytes)",
        format_bytes(device_size),
        device_size / sector_size as u64,
        sector_size
    );
    println!();

    // Entropy analysis
    println!("  --- Entropy Analysis ---");
    let entropy_pb = ProgressBar::new(0);
    entropy_pb.set_style(
        ProgressStyle::with_template("  Scanning: [{bar:30.cyan/blue}] {pos}/{len} blocks")
            .unwrap()
            .progress_chars("=>-"),
    );
    let entropy_progress: Box<dyn Fn(u64, u64) + Send> = Box::new(move |current, total| {
        entropy_pb.set_length(total);
        entropy_pb.set_position(current);
        if current >= total {
            entropy_pb.finish_and_clear();
        }
    });
    match scan_entropy(dev, Some(entropy_progress)) {
        Ok(result) => {
            println!("  Blocks scanned:     {}", result.blocks_scanned);
            println!(
                "  Average entropy:    {:.2} bits/byte",
                result.average_entropy
            );
            if result.high_entropy_blocks.is_empty() {
                println!("  High-entropy:       None (good)");
            } else {
                println!(
                    "  High-entropy:       {} suspicious blocks",
                    result.high_entropy_blocks.len()
                );
                for block in result.high_entropy_blocks.iter().take(5) {
                    println!(
                        "    Offset {:#x}: {:.2} bits/byte",
                        block.offset, block.entropy
                    );
                }
                if result.high_entropy_blocks.len() > 5 {
                    println!(
                        "    ... and {} more",
                        result.high_entropy_blocks.len() - 5
                    );
                }
            }
            if !result.debug_signatures_found.is_empty() {
                println!(
                    "  Debug signatures:   {} FOUND",
                    result.debug_signatures_found.len()
                );
                for hit in &result.debug_signatures_found {
                    println!(
                        "    Offset {:#x}: {} ({} reps)",
                        hit.offset, hit.description, hit.repetitions
                    );
                }
            }
        }
        Err(e) => println!("  Entropy scan error: {}", e),
    }
    println!();

    // Fake flash detection
    println!("  --- Capacity Verification ---");
    let cap_pb = ProgressBar::new(0);
    cap_pb.set_style(
        ProgressStyle::with_template("  Probing:  [{bar:30.cyan/blue}] {pos}/{len} offsets")
            .unwrap()
            .progress_chars("=>-"),
    );
    let cap_progress: Box<dyn Fn(u64, u64) + Send> = Box::new(move |current, total| {
        cap_pb.set_length(total);
        cap_pb.set_position(current);
        if current + 1 >= total {
            cap_pb.finish_and_clear();
        }
    });
    match detect_fake_flash(dev, Some(cap_progress)) {
        Ok(result) => {
            if result.is_fake {
                println!("  WARNING: {}", result.description);
            } else {
                println!("  Capacity appears genuine.");
            }
        }
        Err(e) => println!("  Capacity check error: {}", e),
    }
    println!();

    // Bad sector scan (only with --deep)
    if deep {
        println!("  --- Bad Sector Scan ---");
        let total_sectors = device_size / sector_size as u64;
        let pb = ProgressBar::new(total_sectors);
        pb.set_style(
            ProgressStyle::with_template(
                "  {spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} sectors ({eta} remaining)",
            )
            .unwrap()
            .progress_chars("=>-"),
        );

        let progress_cb: Box<dyn Fn(u64, u64) + Send> = Box::new(move |current, _total| {
            pb.set_position(current);
        });

        use fdu_core::diagnostics::scan_bad_sectors;
        let report = scan_bad_sectors(dev, Some(progress_cb))?;
        println!();

        println!("  Total sectors:  {}", report.total_sectors);
        println!("  Bad sectors:    {}", report.bad_sector_count());
        println!("  Health score:   {:.1}%", report.health_score());
        if let Some(speed) = report.read_speed_mbps {
            println!("  Read speed:     {:.1} MB/s", speed);
        }
        println!("  Scan time:      {} ms", report.scan_duration_ms);

        if !report.bad_sectors.is_empty() {
            println!();
            println!("  Bad sector locations:");
            for &sector in report.bad_sectors.iter().take(20) {
                println!(
                    "    Sector {} (offset {:#x})",
                    sector,
                    sector * sector_size as u64
                );
            }
            if report.bad_sector_count() > 20 {
                println!("    ... and {} more", report.bad_sector_count() - 20);
            }
        }
    } else {
        println!("  Skipping bad sector scan. Use --deep for a full sector-by-sector test.");
    }
    println!();

    // ── Phase 3: Security Audit ─────────────────────────────────────
    println!("=== Phase 3: Security Audit ===");
    println!();

    let config = fdu_audit::AuditConfig::default();
    let mut engine = fdu_audit::AuditEngine::new(config);
    engine.register_defaults();

    match engine.scan(dev, None) {
        Ok(report) => {
            if report.findings.is_empty() {
                println!("  No security threats detected.");
            } else {
                println!("  Findings: {}", report.findings.len());
                for finding in &report.findings {
                    let sev = format!("[{:?}]", finding.severity);
                    println!("  {} {} — {}", sev, finding.title, finding.description);
                }
            }
            println!();

            let safe_str = if report.safe_to_mount { "YES" } else { "NO" };
            println!(
                "  Overall risk: {:?}  |  Safe to mount: {}",
                report.overall_risk, safe_str
            );
        }
        Err(e) => println!("  Security audit error: {}", e),
    }
    println!();

    let _ = device_path; // used in caller's final verdict
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
