//! Linux device enumeration via sysfs and /proc/mounts.

use crate::{EnumError, EnumeratedDevice};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Enumerate removable block devices on Linux by reading sysfs.
pub fn enumerate() -> Result<Vec<EnumeratedDevice>, EnumError> {
    let mut devices = Vec::new();
    let mut mount_points = read_mount_points()?;

    let sys_block = Path::new("/sys/block");
    if !sys_block.exists() {
        return Ok(devices);
    }

    let entries = fs::read_dir(sys_block)?;

    for entry in entries {
        let entry = entry?;
        let block_name = entry.file_name().to_string_lossy().to_string();

        // Skip loop, ram, and dm devices
        if block_name.starts_with("loop")
            || block_name.starts_with("ram")
            || block_name.starts_with("dm-")
        {
            continue;
        }

        let dev_path = entry.path();

        // Check if removable
        let is_removable = read_sysfs_value(&dev_path.join("removable"))
            .map(|v| v.trim() == "1")
            .unwrap_or(false);

        // Get size (in 512-byte sectors)
        let size_sectors = read_sysfs_value(&dev_path.join("size"))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let size_bytes = size_sectors * 512;

        // Get device model
        let model = read_sysfs_value(&dev_path.join("device/model"))
            .unwrap_or_else(|| "Unknown".to_string())
            .trim()
            .to_string();

        // Get vendor
        let vendor = read_sysfs_value(&dev_path.join("device/vendor"))
            .unwrap_or_else(|| "Unknown".to_string())
            .trim()
            .to_string();

        // Get transport type from device path
        let transport = detect_transport(&dev_path);

        let device_path_str = format!("/dev/{}", block_name);

        // Check for partitions (e.g., sdb1, sdb2)
        let partitions = find_partitions(&dev_path, &block_name)?;

        if partitions.is_empty() {
            // No partitions — treat the whole device as one
            let mount_point = mount_points.remove(&device_path_str);
            devices.push(EnumeratedDevice {
                device_path: device_path_str.clone(),
                parent_device: None,
                model: model.clone(),
                vendor: vendor.clone(),
                size_bytes,
                is_removable,
                mount_point,
                transport: transport.clone(),
            });
        } else {
            // Add each partition
            for (part_name, part_size) in partitions {
                let part_path = format!("/dev/{}", part_name);
                let mount_point = mount_points.remove(&part_path);
                devices.push(EnumeratedDevice {
                    device_path: part_path,
                    parent_device: Some(device_path_str.clone()),
                    model: model.clone(),
                    vendor: vendor.clone(),
                    size_bytes: part_size,
                    is_removable,
                    mount_point,
                    transport: transport.clone(),
                });
            }
        }
    }

    Ok(devices)
}

/// Find partitions under a block device in sysfs.
fn find_partitions(
    dev_path: &Path,
    block_name: &str,
) -> Result<Vec<(String, u64)>, EnumError> {
    let mut partitions = Vec::new();

    let entries = fs::read_dir(dev_path)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        // Partition entries start with the parent name (e.g., sdb1 under sdb)
        if name.starts_with(block_name) && name != *block_name {
            let part_path = entry.path();
            let size_sectors = read_sysfs_value(&part_path.join("size"))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0);
            partitions.push((name, size_sectors * 512));
        }
    }

    partitions.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(partitions)
}

/// Read /proc/mounts to get device → mount point mappings.
fn read_mount_points() -> Result<HashMap<String, PathBuf>, EnumError> {
    let mut mounts = HashMap::new();

    let content = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(_) => return Ok(mounts), // Non-fatal
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let device = parts[0].to_string();
            let mount = PathBuf::from(parts[1]);
            mounts.insert(device, mount);
        }
    }

    Ok(mounts)
}

/// Try to detect transport type (USB, ATA, etc.) from sysfs path.
fn detect_transport(dev_path: &Path) -> Option<String> {
    // Resolve the device symlink and look for "usb" in the path
    if let Ok(resolved) = fs::read_link(dev_path.join("device")) {
        let resolved_str = resolved.to_string_lossy();
        if resolved_str.contains("usb") {
            return Some("usb".to_string());
        }
        if resolved_str.contains("ata") {
            return Some("ata".to_string());
        }
        if resolved_str.contains("nvme") {
            return Some("nvme".to_string());
        }
        if resolved_str.contains("mmc") {
            return Some("mmc".to_string());
        }
    }
    None
}

/// Read a sysfs attribute file, returning None on failure.
fn read_sysfs_value(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}
