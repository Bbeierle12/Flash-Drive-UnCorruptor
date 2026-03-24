//! `fdu recover` — attempt to recover deleted files.

use fdu_core::device::traits::Device;
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::*;
use fdu_core::recovery::carving;
use indicatif::{ProgressBar, ProgressStyle};
use std::fs;

pub fn run(
    device_path: &str,
    output_dir: &str,
    strategy: &str,
    file_types: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    println!("WARNING: This command currently performs a recovery SCAN only.");
    println!("         File extraction to disk is not yet implemented.");
    println!("         Do NOT delete original media based on these results.");
    println!();
    println!("Scanning for recoverable files on {}...", device_path);
    println!("Output directory: {}", output_dir);
    println!();

    // Ensure output directory exists
    fs::create_dir_all(output_dir)?;

    let dev = open_device(device_path)?;
    let fs_type = detect_filesystem(dev.as_ref())?;

    let file_type_filter: Vec<String> = file_types
        .map(|ft| ft.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let strategy = match strategy {
        "carving" => RecoveryStrategy::SignatureCarving,
        "cluster" | "cluster-scan" => RecoveryStrategy::ClusterScan,
        "both" => RecoveryStrategy::Both,
        other => anyhow::bail!(
            "Unknown recovery strategy '{}'. Valid options: carving, cluster, cluster-scan, both",
            other
        ),
    };

    let mut all_recoverable = Vec::new();

    // Strategy 1: Filesystem-level deleted file scanning
    if matches!(
        strategy,
        RecoveryStrategy::ClusterScan | RecoveryStrategy::Both
    ) {
        println!("Phase 1: Scanning filesystem for deleted entries...");
        match fs_type {
            FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
                let fs = Fat32Fs::new(dev.as_ref())?;
                match fs.scan_deleted() {
                    Ok(deleted) => {
                        println!("  Found {} deleted entries", deleted.len());
                        all_recoverable.extend(deleted);
                    }
                    Err(e) => {
                        println!("  Warning: Could not scan deleted entries: {}", e);
                    }
                }
            }
            _ => {
                println!("  Skipping (filesystem-level scanning not supported for {})", fs_type);
            }
        }
    }

    // Strategy 2: Raw signature carving
    if matches!(
        strategy,
        RecoveryStrategy::SignatureCarving | RecoveryStrategy::Both
    ) {
        println!("Phase 2: Scanning for file signatures (magic bytes)...");

        let pb = ProgressBar::new(dev.size());
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );

        let progress_cb: Box<dyn Fn(u64, u64) + Send> = Box::new(move |current, _total| {
            pb.set_position(current);
        });

        let carved = carving::scan_signatures(dev.as_ref(), &file_type_filter, Some(progress_cb))?;
        println!();
        println!("  Found {} file signatures", carved.len());
        all_recoverable.extend(carved);
    }

    if json {
        let _total_bytes: u64 = all_recoverable.iter().map(|f| f.estimated_size).sum();
        let report = RecoveryReport {
            device_id: device_path.to_string(),
            files_found: all_recoverable.len(),
            // NOTE: extraction to disk is not yet implemented — these reflect
            // scan results only (files found, not yet written to output_dir).
            files_recovered: 0,
            bytes_recovered: 0,
            recovered_files: Vec::new(),
            scan_duration_ms: 0,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!();
    println!("=== Recovery Scan Results ===");
    println!("  Files found: {}", all_recoverable.len());
    println!();

    if all_recoverable.is_empty() {
        println!("No recoverable files found.");
        return Ok(());
    }

    // List found files
    for (i, file) in all_recoverable.iter().take(50).enumerate() {
        let _name = file
            .original_name
            .as_deref()
            .unwrap_or("(unknown name)");
        println!(
            "  [{}] {} — {} at offset {:#x} (confidence: {:.0}%)",
            i + 1,
            file.file_type,
            format_bytes(file.estimated_size),
            file.offset,
            file.confidence * 100.0,
        );
    }

    if all_recoverable.len() > 50 {
        println!("  ... and {} more", all_recoverable.len() - 50);
    }

    println!();
    println!("NOTE: File extraction to disk is NOT yet implemented.");
    println!("      The files listed above have NOT been saved to '{}'.", output_dir);
    println!("      Do NOT delete or format the original media.");

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
