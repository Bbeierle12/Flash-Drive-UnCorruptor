//! `fdu repair` — repair filesystem issues (destructive, requires --unsafe-mode).

use fdu_core::device::traits::Device;
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::models::*;
use fdu_core::repair::fat32::{self, Fat32Bpb};

pub fn run(
    device_path: &str,
    unsafe_mode: bool,
    fix_fat: bool,
    remove_bad_chains: bool,
    backup_first: bool,
) -> anyhow::Result<()> {
    if !unsafe_mode {
        anyhow::bail!(
            "Repair writes directly to the device and can cause data loss.\n\n\
             To proceed, you must acknowledge this by passing --unsafe-mode:\n\
             \x20 fdu repair {} --unsafe-mode\n\n\
             Recommended: add --backup-first to save critical structures before repair:\n\
             \x20 fdu repair {} --unsafe-mode --backup-first",
            device_path,
            device_path,
        );
    }

    println!("WARNING: This will WRITE to {}.", device_path);
    println!("         Make sure you have a backup before proceeding.");
    println!();

    // Open device in writable mode
    let mut dev = open_device_writable(device_path)?;

    // Detect filesystem
    let fs_type = detect_filesystem(dev.as_ref())?;
    println!("Detected filesystem: {}", fs_type);

    match fs_type {
        FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
            repair_fat(dev.as_mut(), device_path, fix_fat, remove_bad_chains, backup_first)?;
        }
        other => {
            anyhow::bail!(
                "Repair for '{}' is not yet supported. Currently supported: FAT12/16/32.\n\
                 ext2/3/4 and NTFS repair is planned.",
                other
            );
        }
    }

    Ok(())
}

fn repair_fat(
    dev: &mut dyn Device,
    device_path: &str,
    fix_fat: bool,
    remove_bad_chains: bool,
    backup_first: bool,
) -> anyhow::Result<()> {
    let bpb = Fat32Bpb::parse(dev)?;
    println!("Parsed BPB: {} bytes/sector, {} sectors/cluster, {} FATs",
        bpb.bytes_per_sector, bpb.sectors_per_cluster, bpb.num_fats);
    println!();

    // If neither --fix-fat nor --remove-bad-chains specified, enable both
    let (fix_fat, remove_bad_chains) = if !fix_fat && !remove_bad_chains {
        println!("No specific repair flags given — running all repairs.");
        (true, true)
    } else {
        (fix_fat, remove_bad_chains)
    };

    let options = RepairOptions {
        confirm_unsafe: true,
        backup_first,
        fix_fat,
        remove_bad_chains,
    };

    println!("Running repairs...");
    println!();

    let report = fat32::run_all_repairs(dev, &bpb, &options)?;

    if report.fixes_applied.is_empty() {
        println!("No repairs needed — filesystem appears clean.");
    } else {
        println!("=== Repair Report ===");
        for (i, fix) in report.fixes_applied.iter().enumerate() {
            println!("  [{}] {}", i + 1, fix);
        }
        println!();
        println!("Total fixes applied: {}", report.errors_fixed);

        if let Some(ref backup) = report.backup_path {
            println!("Backup saved to: {}", backup.display());
        }
    }

    println!();
    println!("Done. Run 'fdu scan {}' to verify the repair.", device_path);

    Ok(())
}

fn open_device_writable(_path: &str) -> anyhow::Result<Box<dyn Device>> {
    #[cfg(target_os = "linux")]
    {
        use fdu_core::device::linux::LinuxDevice;
        if _path.starts_with("/dev/") {
            Ok(Box::new(LinuxDevice::open(_path, true)?))
        } else {
            // For image files, open writable
            Ok(Box::new(LinuxDevice::open(_path, true)?))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("Direct device access is only supported on Linux.");
    }
}
