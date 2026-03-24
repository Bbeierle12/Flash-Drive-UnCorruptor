//! `fdu diagnose` — run health diagnostics on a device.

use fdu_core::device::traits::Device;
use fdu_core::diagnostics::{scan_bad_sectors, scan_entropy, detect_fake_flash};
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::exfat::ExFatFs;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::ext4::ExtFs;
use fdu_core::fs::ntfs::NtfsFs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::format_bytes;
use indicatif::{ProgressBar, ProgressStyle};

pub fn run(device_path: &str, check_bad_sectors: bool, json: bool) -> anyhow::Result<()> {
    println!("Running diagnostics on {}...", device_path);
    println!();

    let dev = open_device(device_path)?;

    let device_size = dev.size();
    let sector_size = dev.sector_size();
    println!("Device: {}", dev.name());
    println!("Size:   {} ({} sectors of {} bytes)", format_bytes(device_size), device_size / sector_size as u64, sector_size);
    println!();

    // ── Filesystem detection & validation ──────────────────────────
    println!("=== Filesystem Check ===");
    match detect_filesystem(dev.as_ref()) {
        Ok(fs_type) => {
            println!("  Detected: {}", fs_type);
            match fs_type {
                fdu_core::models::FsType::Fat32
                | fdu_core::models::FsType::Fat16
                | fdu_core::models::FsType::Fat12 => {
                    match Fat32Fs::new(dev.as_ref()) {
                        Ok(fs) => match fs.validate() {
                            Ok(report) => {
                                let errors = report.error_count();
                                let warnings = report.warning_count();
                                if errors == 0 && warnings == 0 {
                                    println!("  Status:   HEALTHY");
                                } else {
                                    println!("  Status:   {} errors, {} warnings", errors, warnings);
                                    for issue in &report.issues {
                                        println!("    [{:?}] {} — {}", issue.severity, issue.code, issue.message);
                                    }
                                }
                            }
                            Err(e) => println!("  Validation error: {}", e),
                        },
                        Err(e) => println!("  Parse error: {}", e),
                    }
                }
                fdu_core::models::FsType::ExFat => {
                    match ExFatFs::new(dev.as_ref()) {
                        Ok(fs) => match fs.validate() {
                            Ok(report) => {
                                let errors = report.error_count();
                                let warnings = report.warning_count();
                                if errors == 0 && warnings == 0 {
                                    println!("  Status:   HEALTHY");
                                } else {
                                    println!("  Status:   {} errors, {} warnings", errors, warnings);
                                    for issue in &report.issues {
                                        println!("    [{:?}] {} — {}", issue.severity, issue.code, issue.message);
                                    }
                                }
                            }
                            Err(e) => println!("  Validation error: {}", e),
                        },
                        Err(e) => println!("  Parse error: {}", e),
                    }
                }
                fdu_core::models::FsType::Ext2
                | fdu_core::models::FsType::Ext3
                | fdu_core::models::FsType::Ext4 => {
                    match ExtFs::new(dev.as_ref()) {
                        Ok(fs) => match fs.validate() {
                            Ok(report) => {
                                let errors = report.error_count();
                                let warnings = report.warning_count();
                                if errors == 0 && warnings == 0 {
                                    println!("  Status:   HEALTHY");
                                } else {
                                    println!("  Status:   {} errors, {} warnings", errors, warnings);
                                    for issue in &report.issues {
                                        println!("    [{:?}] {} — {}", issue.severity, issue.code, issue.message);
                                    }
                                }
                            }
                            Err(e) => println!("  Validation error: {}", e),
                        },
                        Err(e) => println!("  Parse error: {}", e),
                    }
                }
                fdu_core::models::FsType::Ntfs => {
                    match NtfsFs::new(dev.as_ref()) {
                        Ok(fs) => match fs.validate() {
                            Ok(report) => {
                                let errors = report.error_count();
                                let warnings = report.warning_count();
                                if errors == 0 && warnings == 0 {
                                    println!("  Status:   HEALTHY");
                                } else {
                                    println!("  Status:   {} errors, {} warnings", errors, warnings);
                                    for issue in &report.issues {
                                        println!("    [{:?}] {} — {}", issue.severity, issue.code, issue.message);
                                    }
                                }
                            }
                            Err(e) => println!("  Validation error: {}", e),
                        },
                        Err(e) => println!("  Parse error: {}", e),
                    }
                }
                _ => {
                    println!("  Status:   Validation not supported for {}", fs_type);
                }
            }
        }
        Err(_) => {
            println!("  Detected: Unknown / No filesystem");
            println!("  Status:   Cannot validate — no recognized filesystem");
        }
    }
    println!();

    // ── Entropy analysis ───────────────────────────────────────────
    println!("=== Entropy Analysis ===");
    let entropy_pb = ProgressBar::new(0);
    entropy_pb.set_style(
        ProgressStyle::with_template(
            "  Scanning: [{bar:30.cyan/blue}] {pos}/{len} blocks",
        )
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
    match scan_entropy(dev.as_ref(), Some(entropy_progress)) {
        Ok(result) => {
            println!("  Blocks scanned:     {}", result.blocks_scanned);
            println!("  Average entropy:    {:.2} bits/byte", result.average_entropy);
            if result.high_entropy_blocks.is_empty() {
                println!("  High-entropy:       None (good)");
            } else {
                println!("  High-entropy:       {} suspicious blocks", result.high_entropy_blocks.len());
                for block in result.high_entropy_blocks.iter().take(5) {
                    println!("    Offset {:#x}: {:.2} bits/byte", block.offset, block.entropy);
                }
                if result.high_entropy_blocks.len() > 5 {
                    println!("    ... and {} more", result.high_entropy_blocks.len() - 5);
                }
            }
            if !result.debug_signatures_found.is_empty() {
                println!("  Debug signatures:   {} FOUND", result.debug_signatures_found.len());
                for hit in &result.debug_signatures_found {
                    println!("    Offset {:#x}: {} ({} reps)", hit.offset, hit.description, hit.repetitions);
                }
            }
        }
        Err(e) => println!("  Error: {}", e),
    }
    println!();

    // ── Fake flash detection ───────────────────────────────────────
    println!("=== Capacity Verification ===");
    let cap_pb = ProgressBar::new(0);
    cap_pb.set_style(
        ProgressStyle::with_template(
            "  Probing:  [{bar:30.cyan/blue}] {pos}/{len} offsets",
        )
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
    match detect_fake_flash(dev.as_ref(), Some(cap_progress)) {
        Ok(result) => {
            if result.is_fake {
                println!("  WARNING: {}", result.description);
            } else {
                println!("  Capacity appears genuine");
            }
        }
        Err(e) => println!("  Error: {}", e),
    }
    println!();

    // ── Bad sector scan (optional) ─────────────────────────────────
    if !check_bad_sectors {
        println!("Skipping bad sector scan. Use --bad-sectors for a full sector-by-sector test.");
        return Ok(());
    }

    println!("=== Bad Sector Scan ===");
    let total_sectors = device_size / sector_size as u64;
    let pb = ProgressBar::new(total_sectors);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} sectors ({eta} remaining)",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let progress_cb: Box<dyn Fn(u64, u64) + Send> = Box::new(move |current, _total| {
        pb.set_position(current);
    });

    let report = scan_bad_sectors(dev.as_ref(), Some(progress_cb))?;
    println!(); // clear progress bar line

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("  Total sectors:  {}", report.total_sectors);
    println!("  Bad sectors:    {}", report.bad_sector_count());
    println!("  Health score:   {:.1}%", report.health_score());

    if let Some(speed) = report.read_speed_mbps {
        println!("  Read speed:     {:.1} MB/s", speed);
    }

    println!("  Scan time:      {} ms", report.scan_duration_ms);
    println!();

    if report.bad_sectors.is_empty() {
        println!("Result: ALL SECTORS READABLE");
    } else {
        println!(
            "Result: {} BAD SECTORS DETECTED",
            report.bad_sector_count()
        );
        println!();
        println!("Bad sector locations:");
        for &sector in report.bad_sectors.iter().take(20) {
            println!("  Sector {} (offset {:#x})", sector, sector * sector_size as u64);
        }
        if report.bad_sector_count() > 20 {
            println!("  ... and {} more", report.bad_sector_count() - 20);
        }
        println!();
        println!("Recommendation: Back up all data immediately and replace the drive.");
    }

    Ok(())
}

fn open_device(_path: &str) -> anyhow::Result<Box<dyn Device>> {
    #[cfg(target_os = "linux")]
    {
        use fdu_core::device::linux::LinuxDevice;
        if _path.starts_with("/dev/") {
            Ok(Box::new(LinuxDevice::open(_path, false)?))
        } else {
            Ok(Box::new(LinuxDevice::open_image(_path)?))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Direct device access is only supported on Linux.");
    }
}
