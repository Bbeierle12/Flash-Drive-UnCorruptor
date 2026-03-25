//! exFAT repair operations.
//!
//! Handles: boot signature, backup boot sector, FAT desync,
//! volume dirty flag clearing, and circular chain breaking.

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};
use crate::models::{RepairOptions, RepairReport};

/// Parsed exFAT boot region parameters needed for repair.
#[derive(Debug, Clone)]
pub struct ExFatBpb {
    pub bytes_per_sector_shift: u8,
    pub sectors_per_cluster_shift: u8,
    pub fat_offset: u32,
    pub fat_length: u32,
    pub cluster_heap_offset: u32,
    pub cluster_count: u32,
    pub first_cluster_of_root: u32,
    pub number_of_fats: u8,
    pub volume_flags: u16,
}

impl ExFatBpb {
    pub fn bytes_per_sector(&self) -> u64 {
        1u64 << self.bytes_per_sector_shift
    }

    pub fn parse(device: &dyn Device) -> Result<Self> {
        let boot = device.read_exact_at(0, 512)?;

        if &boot[3..11] != b"EXFAT   " {
            return Err(Error::FilesystemCorrupted("Not an exFAT filesystem".into()));
        }

        Ok(Self {
            bytes_per_sector_shift: boot[108],
            sectors_per_cluster_shift: boot[109],
            fat_offset: u32::from_le_bytes(boot[80..84].try_into().unwrap()),
            fat_length: u32::from_le_bytes(boot[84..88].try_into().unwrap()),
            cluster_heap_offset: u32::from_le_bytes(boot[88..92].try_into().unwrap()),
            cluster_count: u32::from_le_bytes(boot[92..96].try_into().unwrap()),
            first_cluster_of_root: u32::from_le_bytes(boot[96..100].try_into().unwrap()),
            number_of_fats: boot[110],
            volume_flags: u16::from_le_bytes(boot[106..108].try_into().unwrap()),
        })
    }

    fn fat_start_byte(&self, fat_index: u32) -> u64 {
        let bps = self.bytes_per_sector();
        (self.fat_offset as u64 + fat_index as u64 * self.fat_length as u64) * bps
    }

    fn fat_size_bytes(&self) -> u64 {
        self.fat_length as u64 * self.bytes_per_sector()
    }
}

/// Read a single FAT entry.
pub fn read_fat_entry(device: &dyn Device, bpb: &ExFatBpb, cluster: u32) -> Result<u32> {
    let offset = bpb.fat_start_byte(0) + cluster as u64 * 4;
    let data = device.read_exact_at(offset, 4)?;
    Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
}

/// Write a FAT entry to all copies of the FAT.
pub fn write_fat_entry(device: &mut dyn Device, bpb: &ExFatBpb, cluster: u32, value: u32) -> Result<()> {
    let bytes = value.to_le_bytes();
    for fat_idx in 0..bpb.number_of_fats as u32 {
        let offset = bpb.fat_start_byte(fat_idx) + cluster as u64 * 4;
        device.write_at(offset, &bytes)?;
    }
    Ok(())
}

/// Restore boot signature 0x55AA at offset 510 if missing.
/// Tries backup boot sector (sector 12) first.
pub fn repair_boot_signature(device: &mut dyn Device, bpb: &ExFatBpb) -> Result<Vec<String>> {
    let mut fixes = Vec::new();
    let boot = device.read_exact_at(0, 512)?;

    if boot[510] == 0x55 && boot[511] == 0xAA {
        return Ok(fixes);
    }

    // Try restoring from backup at sector 12
    let bps = bpb.bytes_per_sector();
    let backup_offset = 12 * bps;
    if let Ok(backup) = device.read_exact_at(backup_offset, bps as usize) {
        if backup.len() >= 512 && backup[510] == 0x55 && backup[511] == 0xAA {
            // Copy entire backup boot sector to sector 0
            device.write_at(0, &backup)?;
            fixes.push("Restored boot sector from backup (sector 12)".into());
            return Ok(fixes);
        }
    }

    // Fallback: write signature directly
    device.write_at(510, &[0x55, 0xAA])?;
    fixes.push("Wrote boot signature 0x55AA directly".into());
    Ok(fixes)
}

/// Copy primary boot region (sectors 0-11) to backup (sectors 12-23).
pub fn repair_backup_boot(device: &mut dyn Device, bpb: &ExFatBpb) -> Result<Vec<String>> {
    let mut fixes = Vec::new();
    let bps = bpb.bytes_per_sector();

    // Compare sector 0 with sector 12
    let primary = device.read_exact_at(0, bps as usize)?;
    let backup_offset = 12 * bps;
    let backup = device.read_exact_at(backup_offset, bps as usize)?;

    if primary == backup {
        return Ok(fixes);
    }

    // Copy all 12 boot region sectors
    for sector in 0..12u64 {
        let data = device.read_exact_at(sector * bps, bps as usize)?;
        device.write_at((sector + 12) * bps, &data)?;
    }
    fixes.push("Copied primary boot region (sectors 0-11) to backup (sectors 12-23)".into());
    Ok(fixes)
}

/// Synchronize FAT2 from FAT1 if they differ.
pub fn repair_fat_desync(device: &mut dyn Device, bpb: &ExFatBpb) -> Result<Vec<String>> {
    let mut fixes = Vec::new();

    if bpb.number_of_fats < 2 {
        return Ok(fixes);
    }

    let fat1_start = bpb.fat_start_byte(0);
    let fat2_start = bpb.fat_start_byte(1);
    let fat_bytes = bpb.fat_size_bytes();
    let chunk_size = 4096u64;

    let mut offset = 0u64;
    let mut mismatched = false;
    while offset < fat_bytes {
        let read_len = chunk_size.min(fat_bytes - offset) as usize;
        let f1 = device.read_exact_at(fat1_start + offset, read_len)?;
        let f2 = device.read_exact_at(fat2_start + offset, read_len)?;

        if f1 != f2 {
            device.write_at(fat2_start + offset, &f1)?;
            mismatched = true;
        }
        offset += chunk_size;
    }

    if mismatched {
        fixes.push("Synchronized FAT2 from FAT1".into());
    }
    Ok(fixes)
}

/// Clear the volume dirty flag (bit 1 of VolumeFlags at boot offset 106).
pub fn repair_dirty_flag(device: &mut dyn Device, bpb: &ExFatBpb) -> Result<Vec<String>> {
    let mut fixes = Vec::new();

    if bpb.volume_flags & 0x0002 == 0 {
        return Ok(fixes);
    }

    let new_flags = bpb.volume_flags & !0x0002;
    let bytes = new_flags.to_le_bytes();
    device.write_at(106, &bytes)?;

    // Also update backup
    let backup_offset = 12 * bpb.bytes_per_sector() + 106;
    device.write_at(backup_offset, &bytes)?;

    fixes.push("Cleared volume dirty flag".into());
    Ok(fixes)
}

/// Detect and break circular cluster chains.
pub fn repair_circular_chains(device: &mut dyn Device, bpb: &ExFatBpb) -> Result<Vec<String>> {
    let mut fixes = Vec::new();

    for cluster in 2..=bpb.cluster_count + 1 {
        let mut visited = std::collections::HashSet::new();
        let mut current = cluster;

        loop {
            if current < 2 || current >= 0xFFFFFFF7 {
                break;
            }
            if current > bpb.cluster_count + 1 {
                break;
            }
            if !visited.insert(current) {
                // Cycle found — break it by writing EOC
                write_fat_entry(device, bpb, current, 0xFFFFFFFF)?;
                fixes.push(format!("Broke circular chain at cluster {}", current));
                break;
            }
            match read_fat_entry(device, bpb, current) {
                Ok(next) => current = next,
                Err(_) => break,
            }
        }
    }

    Ok(fixes)
}

/// Run all exFAT repairs.
pub fn run_all_repairs(
    device: &mut dyn Device,
    bpb: &ExFatBpb,
    options: &RepairOptions,
) -> Result<RepairReport> {
    if !options.confirm_unsafe {
        return Err(Error::ConfirmationRequired);
    }

    let mut all_fixes = Vec::new();

    // 1. Boot signature
    all_fixes.extend(repair_boot_signature(device, bpb)?);

    // 2. Backup boot sector
    all_fixes.extend(repair_backup_boot(device, bpb)?);

    // 3. Dirty flag
    all_fixes.extend(repair_dirty_flag(device, bpb)?);

    // 4. FAT desync
    if options.fix_fat {
        all_fixes.extend(repair_fat_desync(device, bpb)?);
    }

    // 5. Circular chains
    if options.remove_bad_chains {
        all_fixes.extend(repair_circular_chains(device, bpb)?);
    }

    let errors_fixed = all_fixes.len();
    Ok(RepairReport {
        device_id: device.id().to_string(),
        fixes_applied: all_fixes,
        errors_fixed,
        bytes_written: 0,
        backup_path: None,
    })
}
