//! MBR (Master Boot Record) partition table parser.
//!
//! The MBR sits in the first 512 bytes of a disk. Bytes 446–509 contain
//! four 16-byte partition entries, and bytes 510–511 hold the 0x55AA signature.

use crate::layout::{PartitionFlags, PartitionInfo};
use tracing::debug;

/// MBR partition entry offsets within the 512-byte boot sector.
const PARTITION_TABLE_OFFSET: usize = 446;
const ENTRY_SIZE: usize = 16;
const MAX_ENTRIES: usize = 4;

/// Parse the four MBR partition entries from a 512-byte (or larger) boot sector.
pub fn parse_mbr(sector0: &[u8], sector_size: u32) -> Vec<PartitionInfo> {
    if sector0.len() < 512 {
        return vec![];
    }

    let mut partitions = Vec::new();

    for i in 0..MAX_ENTRIES {
        let offset = PARTITION_TABLE_OFFSET + i * ENTRY_SIZE;
        let entry = &sector0[offset..offset + ENTRY_SIZE];

        let status = entry[0];
        let type_byte = entry[4];
        let start_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let num_sectors = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;

        // Skip empty entries
        if type_byte == 0x00 || num_sectors == 0 {
            continue;
        }

        let end_lba = start_lba + num_sectors - 1;
        let size_bytes = num_sectors * sector_size as u64;

        let type_label = mbr_type_name(type_byte);
        let bootable = status == 0x80;

        debug!(
            index = i,
            type_byte = format!("0x{:02X}", type_byte),
            start_lba,
            num_sectors,
            bootable,
            "Parsed MBR partition entry"
        );

        partitions.push(PartitionInfo {
            index: i as u8,
            type_id: format!("0x{:02X}", type_byte),
            type_label: type_label.to_string(),
            label: None,
            start_lba,
            end_lba,
            size_bytes,
            fs_type: mbr_type_to_fstype(type_byte),
            flags: PartitionFlags {
                bootable,
                system: false,
                hidden: false,
            },
        });
    }

    partitions
}

/// Map an MBR partition type byte to a human-readable name.
pub fn mbr_type_name(type_byte: u8) -> &'static str {
    match type_byte {
        0x00 => "Empty",
        0x01 => "FAT12",
        0x04 => "FAT16 (<32MB)",
        0x05 => "Extended (CHS)",
        0x06 => "FAT16 (>32MB)",
        0x07 => "NTFS/exFAT/HPFS",
        0x0B => "FAT32 (CHS)",
        0x0C => "FAT32 (LBA)",
        0x0E => "FAT16 (LBA)",
        0x0F => "Extended (LBA)",
        0x11 => "Hidden FAT12",
        0x14 => "Hidden FAT16 (<32MB)",
        0x16 => "Hidden FAT16 (>32MB)",
        0x17 => "Hidden NTFS",
        0x1B => "Hidden FAT32 (CHS)",
        0x1C => "Hidden FAT32 (LBA)",
        0x1E => "Hidden FAT16 (LBA)",
        0x27 => "Windows RE",
        0x42 => "Windows Dynamic",
        0x82 => "Linux Swap",
        0x83 => "Linux",
        0x85 => "Linux Extended",
        0x8E => "Linux LVM",
        0xAF => "HFS/HFS+",
        0xEE => "GPT Protective",
        0xEF => "EFI System",
        0xFD => "Linux RAID",
        _ => "Unknown",
    }
}

/// Best-effort mapping from MBR type byte to `FsType`.
fn mbr_type_to_fstype(type_byte: u8) -> Option<fdu_core::models::FsType> {
    use fdu_core::models::FsType;
    match type_byte {
        0x01 => Some(FsType::Fat12),
        0x04 | 0x06 | 0x0E | 0x14 | 0x16 | 0x1E => Some(FsType::Fat16),
        0x0B | 0x0C | 0x1B | 0x1C => Some(FsType::Fat32),
        0x07 => Some(FsType::Ntfs), // could also be exFAT or HPFS
        0x83 => Some(FsType::Ext4), // could be ext2/3 — would need superblock read
        0xAF => Some(FsType::HfsPlus),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 512-byte MBR with a single FAT32 partition.
    fn make_test_mbr(type_byte: u8, start: u32, sectors: u32, bootable: bool) -> Vec<u8> {
        let mut mbr = vec![0u8; 512];

        // Boot signature
        mbr[510] = 0x55;
        mbr[511] = 0xAA;

        // First partition entry at offset 446
        let offset = PARTITION_TABLE_OFFSET;
        mbr[offset] = if bootable { 0x80 } else { 0x00 };
        mbr[offset + 4] = type_byte;
        mbr[offset + 8..offset + 12].copy_from_slice(&start.to_le_bytes());
        mbr[offset + 12..offset + 16].copy_from_slice(&sectors.to_le_bytes());

        mbr
    }

    #[test]
    fn parse_single_fat32_partition() {
        let mbr = make_test_mbr(0x0C, 2048, 60416, true);
        let parts = parse_mbr(&mbr, 512);

        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].type_id, "0x0C");
        assert_eq!(parts[0].type_label, "FAT32 (LBA)");
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].end_lba, 62463);
        assert!(parts[0].flags.bootable);
        assert_eq!(parts[0].fs_type, Some(fdu_core::models::FsType::Fat32));
    }

    #[test]
    fn empty_mbr_no_partitions() {
        let mut mbr = vec![0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;

        let parts = parse_mbr(&mbr, 512);
        assert!(parts.is_empty());
    }

    #[test]
    fn short_sector_returns_empty() {
        let mbr = vec![0u8; 256]; // too short
        let parts = parse_mbr(&mbr, 512);
        assert!(parts.is_empty());
    }

    #[test]
    fn multiple_partitions() {
        let mut mbr = vec![0u8; 512];
        mbr[510] = 0x55;
        mbr[511] = 0xAA;

        // Partition 1: FAT32 starting at LBA 2048, 60416 sectors
        let o1 = PARTITION_TABLE_OFFSET;
        mbr[o1 + 4] = 0x0C;
        mbr[o1 + 8..o1 + 12].copy_from_slice(&2048u32.to_le_bytes());
        mbr[o1 + 12..o1 + 16].copy_from_slice(&60416u32.to_le_bytes());

        // Partition 2: Linux starting at LBA 62464, 100000 sectors
        let o2 = PARTITION_TABLE_OFFSET + ENTRY_SIZE;
        mbr[o2 + 4] = 0x83;
        mbr[o2 + 8..o2 + 12].copy_from_slice(&62464u32.to_le_bytes());
        mbr[o2 + 12..o2 + 16].copy_from_slice(&100000u32.to_le_bytes());

        let parts = parse_mbr(&mbr, 512);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].type_label, "FAT32 (LBA)");
        assert_eq!(parts[1].type_label, "Linux");
    }

    #[test]
    fn type_name_coverage() {
        assert_eq!(mbr_type_name(0xEE), "GPT Protective");
        assert_eq!(mbr_type_name(0xEF), "EFI System");
        assert_eq!(mbr_type_name(0xFF), "Unknown");
    }
}
