//! `fdu diagnose` — run health diagnostics on a device.

use fdu_core::device::traits::Device;
use fdu_core::diagnostics::scan_bad_sectors;
use fdu_core::models::format_bytes;
use indicatif::{ProgressBar, ProgressStyle};

pub fn run(device_path: &str, check_bad_sectors: bool, json: bool) -> anyhow::Result<()> {
    println!("Running diagnostics on {}...", device_path);
    println!();

    let dev = open_device(device_path)?;

    let device_size = dev.size();
    println!("Device: {}", dev.name());
    println!("Size:   {}", format_bytes(device_size));
    println!();

    if !check_bad_sectors {
        println!("Quick diagnostic mode. Use --bad-sectors for a full sector scan.");
        println!();

        // Quick health check: read first and last sectors
        let mut buf = vec![0u8; 512];
        match dev.read_at(0, &mut buf) {
            Ok(_) => println!("  First sector:  OK"),
            Err(e) => println!("  First sector:  FAILED ({})", e),
        }

        let last_sector_offset = device_size.saturating_sub(512);
        match dev.read_at(last_sector_offset, &mut buf) {
            Ok(_) => println!("  Last sector:   OK"),
            Err(e) => println!("  Last sector:   FAILED ({})", e),
        }

        println!();
        println!("Quick check passed. Run with --bad-sectors for a thorough scan.");
        return Ok(());
    }

    // Full bad sector scan with progress bar
    let total_sectors = device_size / 512;
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

    // Finish progress bar
    println!();
    println!();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("=== Diagnostic Report ===");
    println!("  Total sectors:  {}", report.total_sectors);
    println!("  Bad sectors:    {}", report.bad_sector_count());
    println!("  Health score:   {:.1}%", report.health_score());

    if let Some(speed) = report.read_speed_mbps {
        println!("  Read speed:     {:.1} MB/s", speed);
    }

    println!("  Scan time:      {} ms", report.scan_duration_ms);
    println!();

    if report.bad_sectors.is_empty() {
        println!("Result: ALL SECTORS READABLE — drive appears healthy");
    } else {
        println!(
            "Result: {} BAD SECTORS DETECTED — drive may be failing",
            report.bad_sector_count()
        );
        println!();
        println!("Bad sector locations:");
        for &sector in report.bad_sectors.iter().take(20) {
            println!("  Sector {} (offset {:#x})", sector, sector * 512);
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
        anyhow::bail!("Direct device access is only supported on Linux in Phase 1.");
    }
}
