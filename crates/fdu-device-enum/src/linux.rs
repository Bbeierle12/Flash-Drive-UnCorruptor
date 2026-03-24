//! Linux device enumeration via sysfs and /proc/mounts.

use crate::{EnumError, EnumeratedDevice};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Enumerate ALL block devices on Linux by reading sysfs (removable and non-removable).
/// Includes NVMe, SATA, SAS, eMMC, SD cards, virtual disks — everything.
pub fn enumerate_all() -> Result<Vec<EnumeratedDevice>, EnumError> {
    enumerate_inner(false)
}

/// Enumerate removable block devices only (USB, SD cards).
pub fn enumerate() -> Result<Vec<EnumeratedDevice>, EnumError> {
    enumerate_inner(true)
}

/// Inner implementation: if `removable_only` is true, only return removable devices.
fn enumerate_inner(removable_only: bool) -> Result<Vec<EnumeratedDevice>, EnumError> {
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

        // If only listing removable devices, skip non-removable ones
        if removable_only && !is_removable {
            continue;
        }

        // sysfs "size" is always in 512-byte units regardless of actual
        // hardware sector size.
        let size_sectors = read_sysfs_value(&dev_path.join("size"))
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        let size_bytes = size_sectors * 512;

        // Read the actual logical sector size from sysfs (typically 512 or 4096).
        let sector_size = read_sysfs_value(&dev_path.join("queue/logical_block_size"))
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(512);

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
                sector_size,
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
                    sector_size,
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
            // /proc/mounts encodes special characters using octal escapes
            // (e.g., spaces as \040).  Decode them so paths match correctly.
            let device = decode_mount_escapes(parts[0]);
            let mount = PathBuf::from(decode_mount_escapes(parts[1]));
            mounts.insert(device, mount);
        }
    }

    Ok(mounts)
}

/// Try to detect transport type (USB, ATA, etc.) from sysfs path.
fn detect_transport(dev_path: &Path) -> Option<String> {
    // Resolve the device symlink and look for transport indicators in the path.
    // Also try canonicalizing the full path for deeper sysfs trees.
    let resolved_str = fs::read_link(dev_path.join("device"))
        .map(|p| p.to_string_lossy().to_string())
        .or_else(|_| {
            fs::canonicalize(dev_path.join("device"))
                .map(|p| p.to_string_lossy().to_string())
        })
        .ok()?;

    // Order matters: check more specific transports first.
    let transport_keywords: &[(&str, &str)] = &[
        ("thunderbolt", "thunderbolt"),
        ("usb", "usb"),
        ("nvme", "nvme"),
        ("mmc", "mmc"),
        ("firewire", "firewire"),
        ("ieee1394", "firewire"),
        ("virtio", "virtio"),
        ("scsi", "scsi"),
        ("ata", "ata"),
    ];

    // Match against path segments (split on '/') to avoid false positives
    // like "musicbox" matching "usb".
    let segments: Vec<&str> = resolved_str.split('/').collect();
    for &(keyword, transport) in transport_keywords {
        if segments.iter().any(|seg| seg.starts_with(keyword) || seg.contains(&format!(":{}", keyword)) || *seg == keyword) {
            return Some(transport.to_string());
        }
    }

    None
}

/// Decode octal escape sequences used in /proc/mounts (e.g., `\040` → space).
///
/// Mount paths may contain multi-byte UTF-8 characters encoded as sequences of
/// octal escapes (e.g., 日 = `\346\227\245`).  We collect raw bytes and convert
/// to a String at the end to handle these correctly.
fn decode_mount_escapes(s: &str) -> String {
    let mut bytes: Vec<u8> = Vec::with_capacity(s.len());
    let mut chars = s.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'\\' {
            // Try to read a 3-digit octal escape
            let remaining = chars.as_slice();
            if remaining.len() >= 3
                && remaining[0].is_ascii_digit()
                && remaining[1].is_ascii_digit()
                && remaining[2].is_ascii_digit()
            {
                let oct_str = std::str::from_utf8(&remaining[..3]).unwrap();
                if let Ok(val) = u8::from_str_radix(oct_str, 8) {
                    bytes.push(val);
                    // Advance past the 3 octal digits
                    chars.next();
                    chars.next();
                    chars.next();
                } else {
                    bytes.push(b'\\');
                }
            } else {
                bytes.push(b'\\');
            }
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8(bytes).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Read a sysfs attribute file, returning None on failure.
fn read_sysfs_value(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}
