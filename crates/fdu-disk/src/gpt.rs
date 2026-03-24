//! GPT (GUID Partition Table) parser.
//!
//! GPT resides at LBA 1 (the header) followed by partition entry arrays.
//! We parse manually from raw bytes read through the `Device` trait, rather
//! than using external crate structs, to keep the dependency surface minimal.

use crate::layout::{PartitionFlags, PartitionInfo};
use crate::DiskError;
use fdu_core::device::Device;
use tracing::debug;

/// GPT header magic: "EFI PART"
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

/// Standard GPT partition entry size.
const GPT_ENTRY_SIZE: usize = 128;

/// Parse GPT from LBA 1 data and the device (for reading partition entries).
pub fn parse_gpt(
    lba1: &[u8],
    device: &dyn Device,
    sector_size: u32,
    _total_sectors: u64,
) -> Result<Vec<PartitionInfo>, DiskError> {
    if lba1.len() < 92 {
        return Err(DiskError::InvalidGpt("Header too short".into()));
    }

    // Verify signature
    if &lba1[0..8] != GPT_SIGNATURE {
        return Err(DiskError::InvalidGpt("Missing EFI PART signature".into()));
    }

    // Parse header fields
    let partition_entry_lba = u64::from_le_bytes(lba1[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(lba1[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(lba1[84..88].try_into().unwrap()) as usize;

    debug!(
        partition_entry_lba,
        num_entries,
        entry_size,
        "Parsed GPT header"
    );

    if entry_size < GPT_ENTRY_SIZE {
        return Err(DiskError::InvalidGpt(format!(
            "Entry size {} < minimum {}",
            entry_size, GPT_ENTRY_SIZE
        )));
    }

    // Cap entries to a reasonable limit to prevent abuse
    let num_entries = num_entries.min(256) as usize;

    // Read all partition entries
    let entries_bytes_needed = num_entries * entry_size;
    let entries_offset = partition_entry_lba * sector_size as u64;
    let mut entries_buf = vec![0u8; entries_bytes_needed];

    device
        .read_at(entries_offset, &mut entries_buf)
        .map_err(|e| DiskError::DeviceRead(format!("Reading GPT entries: {}", e)))?;

    let mut partitions = Vec::new();

    for i in 0..num_entries {
        let offset = i * entry_size;
        let entry = &entries_buf[offset..offset + entry_size.min(entries_buf.len() - offset)];

        if entry.len() < GPT_ENTRY_SIZE {
            break;
        }

        // Type GUID (bytes 0-15) — all zeros means unused
        let type_guid = &entry[0..16];
        if type_guid.iter().all(|&b| b == 0) {
            continue;
        }

        let start_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let end_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let attributes = u64::from_le_bytes(entry[48..56].try_into().unwrap());

        // Parse partition name (UTF-16LE, bytes 56-127)
        let name_raw = &entry[56..128];
        let name: String = name_raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .filter_map(|c| char::from_u32(c as u32))
            .collect();

        // Reject malformed entries where end < start to avoid underflow
        if end_lba < start_lba {
            debug!(
                index = i,
                start_lba,
                end_lba,
                "Skipping GPT entry with end_lba < start_lba"
            );
            continue;
        }

        let type_guid_str = format_guid(type_guid);
        let type_label = gpt_type_name(&type_guid_str);
        let size_bytes = (end_lba - start_lba + 1) * sector_size as u64;

        debug!(
            index = i,
            type_guid = type_guid_str,
            start_lba,
            end_lba,
            name = name,
            "Parsed GPT entry"
        );

        partitions.push(PartitionInfo {
            index: i as u8,
            type_id: type_guid_str.clone(),
            type_label: type_label.to_string(),
            label: if name.is_empty() { None } else { Some(name) },
            start_lba,
            end_lba,
            size_bytes,
            fs_type: gpt_type_to_fstype(&type_guid_str),
            flags: PartitionFlags {
                bootable: attributes & (1 << 2) != 0, // Legacy BIOS bootable
                system: attributes & 1 != 0,           // Required partition
                hidden: attributes & (1 << 62) != 0,   // No drive letter
            },
        });
    }

    Ok(partitions)
}

/// Format a 16-byte mixed-endian GUID as a standard string.
fn format_guid(bytes: &[u8]) -> String {
    // Microsoft mixed-endian GUID layout:
    // bytes[0..4] little-endian, bytes[4..6] LE, bytes[6..8] LE, rest big-endian
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Map a GPT type GUID to a human-readable name.
fn gpt_type_name(guid: &str) -> &'static str {
    match guid {
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b" => "EFI System",
        "024dee41-33e7-11d3-9d69-0008c781f39f" => "MBR Partition Scheme",
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => "Microsoft Basic Data",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae" => "Microsoft Reserved",
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac" => "Windows Recovery",
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => "Linux Filesystem",
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f" => "Linux Swap",
        "e6d6d379-f507-44c2-a23c-238f2a3df928" => "Linux LVM",
        "933ac7e1-2eb4-4f13-b844-0e14e2aef915" => "Linux /home",
        "48465300-0000-11aa-aa11-00306543ecac" => "HFS+",
        "7c3457ef-0000-11aa-aa11-00306543ecac" => "APFS",
        _ => "Unknown",
    }
}

/// Best-effort mapping from GPT type GUID to `FsType`.
fn gpt_type_to_fstype(guid: &str) -> Option<fdu_core::models::FsType> {
    use fdu_core::models::FsType;
    match guid {
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" => Some(FsType::Ntfs), // often NTFS or FAT
        "0fc63daf-8483-4772-8e79-3d69d8477de4" => Some(FsType::Ext4),
        "48465300-0000-11aa-aa11-00306543ecac" => Some(FsType::HfsPlus),
        "7c3457ef-0000-11aa-aa11-00306543ecac" => Some(FsType::Apfs),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fdu_core::device::MockDevice;

    /// Build a minimal GPT disk image in memory with one partition.
    fn make_gpt_image(start_lba: u64, end_lba: u64, type_guid: &[u8; 16]) -> Vec<u8> {
        let sector_size = 512usize;
        let total_sectors = (end_lba + 100) as usize; // room after partition
        let mut disk = vec![0u8; total_sectors * sector_size];

        // Protective MBR at LBA 0
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // MBR entry: type 0xEE (GPT protective)
        disk[446 + 4] = 0xEE;
        disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes()); // start LBA 1
        let mbr_size = (total_sectors - 1).min(u32::MAX as usize) as u32;
        disk[446 + 12..446 + 16].copy_from_slice(&mbr_size.to_le_bytes());

        // GPT header at LBA 1
        let gpt_offset = sector_size;
        disk[gpt_offset..gpt_offset + 8].copy_from_slice(GPT_SIGNATURE);
        // Partition entry LBA = 2
        disk[gpt_offset + 72..gpt_offset + 80].copy_from_slice(&2u64.to_le_bytes());
        // Number of entries = 1
        disk[gpt_offset + 80..gpt_offset + 84].copy_from_slice(&1u32.to_le_bytes());
        // Entry size = 128
        disk[gpt_offset + 84..gpt_offset + 88].copy_from_slice(&128u32.to_le_bytes());

        // GPT partition entry at LBA 2
        let entry_offset = 2 * sector_size;
        disk[entry_offset..entry_offset + 16].copy_from_slice(type_guid);
        // Unique partition GUID (arbitrary)
        disk[entry_offset + 16..entry_offset + 32]
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        // Start LBA
        disk[entry_offset + 32..entry_offset + 40].copy_from_slice(&start_lba.to_le_bytes());
        // End LBA
        disk[entry_offset + 40..entry_offset + 48].copy_from_slice(&end_lba.to_le_bytes());
        // Name: "TestPart" in UTF-16LE
        let name = "TestPart";
        for (i, ch) in name.chars().enumerate() {
            let utf16 = ch as u16;
            disk[entry_offset + 56 + i * 2] = utf16 as u8;
            disk[entry_offset + 56 + i * 2 + 1] = (utf16 >> 8) as u8;
        }

        disk
    }

    // Microsoft Basic Data GUID in mixed-endian bytes
    const BASIC_DATA_GUID: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26,
        0x99, 0xC7,
    ];

    #[test]
    fn parse_single_gpt_partition() {
        let disk = make_gpt_image(2048, 10239, &BASIC_DATA_GUID);
        let device = MockDevice::from_bytes(disk);

        let mut lba1 = vec![0u8; 512];
        device.read_at(512, &mut lba1).unwrap();

        let parts = parse_gpt(&lba1, &device, 512, device.size() / 512).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].start_lba, 2048);
        assert_eq!(parts[0].end_lba, 10239);
        assert_eq!(parts[0].label.as_deref(), Some("TestPart"));
    }

    #[test]
    fn missing_signature_errors() {
        let lba1 = vec![0u8; 512]; // no EFI PART signature
        let device = MockDevice::new(1024 * 1024);
        let result = parse_gpt(&lba1, &device, 512, 2048);
        assert!(result.is_err());
    }

    #[test]
    fn malformed_end_lba_less_than_start() {
        // end_lba < start_lba should be skipped, not panic
        let disk = make_gpt_image(10000, 5000, &BASIC_DATA_GUID);
        let device = MockDevice::from_bytes(disk);

        let mut lba1 = vec![0u8; 512];
        device.read_at(512, &mut lba1).unwrap();

        let parts = parse_gpt(&lba1, &device, 512, device.size() / 512).unwrap();
        assert!(parts.is_empty(), "Malformed entry should be skipped");
    }

    #[test]
    fn parse_verifies_size_bytes() {
        let disk = make_gpt_image(2048, 10239, &BASIC_DATA_GUID);
        let device = MockDevice::from_bytes(disk);

        let mut lba1 = vec![0u8; 512];
        device.read_at(512, &mut lba1).unwrap();

        let parts = parse_gpt(&lba1, &device, 512, device.size() / 512).unwrap();
        assert_eq!(parts[0].size_bytes, (10239 - 2048 + 1) * 512);
    }

    #[test]
    fn guid_formatting() {
        // EFI System Partition GUID in mixed-endian
        let bytes: [u8; 16] = [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B,
        ];
        let formatted = format_guid(&bytes);
        assert_eq!(formatted, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    }
}
