//! Unified disk layout types and analysis entry point.

use crate::gpt::parse_gpt;
use crate::mbr::parse_mbr;
use crate::DiskError;
use fdu_core::device::Device;
use fdu_core::models::FsType;
use serde::{Deserialize, Serialize};

/// The partitioning scheme detected on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionScheme {
    /// Classic Master Boot Record.
    Mbr,
    /// GUID Partition Table.
    Gpt,
    /// Both MBR and GPT present (hybrid/protective).
    Hybrid,
    /// No recognized partition table.
    None,
}

/// Flags on a partition entry.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct PartitionFlags {
    /// MBR: bootable flag (0x80).  GPT: "legacy BIOS bootable" attribute.
    pub bootable: bool,
    /// GPT: required for platform operation.
    pub system: bool,
    /// GPT: EFI firmware should not produce a partition entry in the UI.
    pub hidden: bool,
}

/// Information about a single partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionInfo {
    /// Partition index (0-based).
    pub index: u8,
    /// Type identifier — MBR type byte as hex string, or GPT GUID.
    pub type_id: String,
    /// Human-readable label for the partition type.
    pub type_label: String,
    /// Partition label/name (GPT only).
    pub label: Option<String>,
    /// First LBA of the partition.
    pub start_lba: u64,
    /// Last LBA of the partition (inclusive).
    pub end_lba: u64,
    /// Partition size in bytes.
    pub size_bytes: u64,
    /// Detected filesystem inside this partition, if any.
    pub fs_type: Option<FsType>,
    /// Partition flags.
    pub flags: PartitionFlags,
}

impl PartitionInfo {
    /// Number of sectors spanned by this partition.
    pub fn sector_count(&self) -> u64 {
        if self.end_lba >= self.start_lba {
            self.end_lba - self.start_lba + 1
        } else {
            0
        }
    }
}

/// Unified view of a device's partition layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskLayout {
    /// Detected partitioning scheme.
    pub scheme: PartitionScheme,
    /// Parsed partition entries.
    pub partitions: Vec<PartitionInfo>,
    /// Unallocated regions as (start_lba, end_lba) pairs.
    pub unallocated_regions: Vec<(u64, u64)>,
    /// Total device size in sectors.
    pub total_sectors: u64,
    /// Sector size in bytes.
    pub sector_size: u32,
}

impl DiskLayout {
    /// Total allocated bytes across all partitions.
    pub fn allocated_bytes(&self) -> u64 {
        self.partitions.iter().map(|p| p.size_bytes).sum()
    }

    /// Total unallocated bytes.
    pub fn unallocated_bytes(&self) -> u64 {
        self.unallocated_regions
            .iter()
            .filter(|(start, end)| end >= start)
            .map(|(start, end)| (end - start + 1).saturating_mul(self.sector_size as u64))
            .sum()
    }
}

/// Analyze a device's partition layout.
pub(crate) fn analyze(device: &dyn Device) -> Result<DiskLayout, DiskError> {
    let sector_size = device.sector_size();
    if sector_size == 0 {
        return Err(DiskError::DeviceRead("sector_size is 0".into()));
    }
    let total_sectors = device.size() / sector_size as u64;

    if total_sectors < 1 {
        return Err(DiskError::DeviceTooSmall);
    }

    // Read LBA 0 (MBR / protective MBR)
    let mut sector0 = vec![0u8; sector_size as usize];
    device
        .read_at(0, &mut sector0)
        .map_err(|e| DiskError::DeviceRead(e.to_string()))?;

    let has_mbr_sig = sector0.len() >= 512 && sector0[510] == 0x55 && sector0[511] == 0xAA;
    let mbr_result = if has_mbr_sig {
        Some(parse_mbr(&sector0, sector_size))
    } else {
        None
    };

    // Check for GPT at LBA 1
    let gpt_result = if total_sectors > 1 {
        let mut lba1 = vec![0u8; sector_size as usize];
        let offset = sector_size as u64;
        match device.read_at(offset, &mut lba1) {
            Ok(_) => parse_gpt(&lba1, device, sector_size, total_sectors).ok(),
            Err(_) => None,
        }
    } else {
        None
    };

    // Determine scheme and merge partitions
    let (scheme, partitions) = match (&mbr_result, &gpt_result) {
        (Some(_mbr_parts), Some(gpt_parts)) => {
            // GPT with protective MBR — prefer GPT
            (PartitionScheme::Hybrid, gpt_parts.clone())
        }
        (None, Some(gpt_parts)) => (PartitionScheme::Gpt, gpt_parts.clone()),
        (Some(mbr_parts), None) => {
            let parts: Vec<_> = mbr_parts
                .iter()
                .filter(|p| p.size_bytes > 0)
                .cloned()
                .collect();
            if parts.is_empty() {
                (PartitionScheme::None, vec![])
            } else {
                (PartitionScheme::Mbr, parts)
            }
        }
        (None, None) => (PartitionScheme::None, vec![]),
    };

    // Calculate unallocated regions
    let unallocated_regions = find_gaps(&partitions, total_sectors);

    Ok(DiskLayout {
        scheme,
        partitions,
        unallocated_regions,
        total_sectors,
        sector_size,
    })
}

/// Find gaps between partitions (unallocated space).
fn find_gaps(partitions: &[PartitionInfo], total_sectors: u64) -> Vec<(u64, u64)> {
    if partitions.is_empty() {
        if total_sectors > 0 {
            return vec![(0, total_sectors - 1)];
        }
        return vec![];
    }

    let mut sorted: Vec<_> = partitions.iter().collect();
    sorted.sort_by_key(|p| p.start_lba);

    let mut gaps = Vec::new();

    // Gap before first partition.
    // MBR reserves sector 0; GPT reserves LBAs 0-33 (header + entry array).
    // Use sector 34 as first usable for GPT, 1 for MBR.
    let first_usable = if partitions.iter().any(|p| p.start_lba >= 34) {
        34_u64 // GPT: standard first usable LBA
    } else {
        1_u64 // MBR: sector 0 is the MBR itself
    };
    if sorted[0].start_lba > first_usable {
        gaps.push((first_usable, sorted[0].start_lba - 1));
    }

    // Gaps between partitions
    for window in sorted.windows(2) {
        let end_prev = window[0].end_lba;
        let start_next = window[1].start_lba;
        if start_next > end_prev + 1 {
            gaps.push((end_prev + 1, start_next - 1));
        }
    }

    // Gap after last partition
    if let Some(last) = sorted.last() {
        if last.end_lba + 1 < total_sectors {
            gaps.push((last.end_lba + 1, total_sectors - 1));
        }
    }

    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_sector_count() {
        let p = PartitionInfo {
            index: 0,
            type_id: "0x0C".into(),
            type_label: "FAT32 LBA".into(),
            label: None,
            start_lba: 2048,
            end_lba: 4095,
            size_bytes: (4095 - 2048 + 1) * 512,
            fs_type: Some(FsType::Fat32),
            flags: PartitionFlags::default(),
        };
        assert_eq!(p.sector_count(), 2048);
    }

    #[test]
    fn find_gaps_simple() {
        let partitions = vec![
            PartitionInfo {
                index: 0,
                type_id: "0x0C".into(),
                type_label: "FAT32".into(),
                label: None,
                start_lba: 100,
                end_lba: 199,
                size_bytes: 100 * 512,
                fs_type: None,
                flags: PartitionFlags::default(),
            },
            PartitionInfo {
                index: 1,
                type_id: "0x83".into(),
                type_label: "Linux".into(),
                label: None,
                start_lba: 300,
                end_lba: 499,
                size_bytes: 200 * 512,
                fs_type: None,
                flags: PartitionFlags::default(),
            },
        ];

        let gaps = find_gaps(&partitions, 1000);
        assert_eq!(gaps.len(), 3); // before first, between, after last
        // first_usable is 34 (GPT heuristic: first partition >= 34)
        assert_eq!(gaps[0], (34, 99));
        assert_eq!(gaps[1], (200, 299));
        assert_eq!(gaps[2], (500, 999));
    }

    #[test]
    fn empty_disk_is_one_big_gap() {
        let gaps = find_gaps(&[], 1000);
        assert_eq!(gaps, vec![(0, 999)]);
    }
}
