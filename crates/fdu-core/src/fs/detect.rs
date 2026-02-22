//! Filesystem detection from raw device bytes.
//!
//! Reads the first few sectors of a device and identifies the filesystem
//! by examining magic bytes and boot sector structures.

use crate::device::traits::Device;
use crate::errors::Result;
use crate::models::FsType;

/// Detect the filesystem type from raw device data.
///
/// Reads the boot sector (sector 0) and checks for known signatures:
/// - FAT12/16/32: OEM name, FAT type string, boot signature 0x55AA
/// - exFAT: "EXFAT   " at offset 3
/// - NTFS: "NTFS    " at offset 3
/// - ext2/3/4: magic number 0xEF53 at offset 1080
/// - HFS+: magic number 0x482B at offset 1024
pub fn detect_filesystem(device: &dyn Device) -> Result<FsType> {
    // Read first 4 sectors (2048 bytes) — enough for all FS signatures
    let mut buf = vec![0u8; 2048];
    let n = device.read_at(0, &mut buf)?;
    if n < 512 {
        return Ok(FsType::Unknown);
    }

    // Check for exFAT first (offset 3: "EXFAT   ")
    if n >= 11 && &buf[3..11] == b"EXFAT   " {
        return Ok(FsType::ExFat);
    }

    // Check for NTFS (offset 3: "NTFS    ")
    if n >= 11 && &buf[3..11] == b"NTFS    " {
        return Ok(FsType::Ntfs);
    }

    // Check for FAT (boot signature 0x55AA at 510-511)
    if n >= 512 && buf[510] == 0x55 && buf[511] == 0xAA {
        // Determine FAT variant from the BPB
        return Ok(detect_fat_variant(&buf));
    }

    // Check for ext2/3/4 (superblock at offset 1024, magic 0xEF53 at offset 1080)
    if n >= 1082 {
        let magic = u16::from_le_bytes([buf[1080], buf[1081]]);
        if magic == 0xEF53 {
            // Distinguish ext2/3/4 by feature flags
            return Ok(detect_ext_variant(&buf));
        }
    }

    // Check for HFS+ (offset 1024: signature 0x482B "H+")
    if n >= 1026 {
        let sig = u16::from_be_bytes([buf[1024], buf[1025]]);
        if sig == 0x482B {
            return Ok(FsType::HfsPlus);
        }
    }

    Ok(FsType::Unknown)
}

/// Determine FAT12/16/32 from the BIOS Parameter Block.
fn detect_fat_variant(boot_sector: &[u8]) -> FsType {
    // Check the filesystem type string at offset 54 (FAT12/16) or 82 (FAT32)
    if boot_sector.len() >= 90 {
        let fat32_type = &boot_sector[82..90];
        if fat32_type.starts_with(b"FAT32") {
            return FsType::Fat32;
        }
    }

    if boot_sector.len() >= 62 {
        let fat_type = &boot_sector[54..62];
        if fat_type.starts_with(b"FAT16") {
            return FsType::Fat16;
        }
        if fat_type.starts_with(b"FAT12") {
            return FsType::Fat12;
        }
        if fat_type.starts_with(b"FAT") {
            // Generic FAT — determine by cluster count
            return detect_fat_by_cluster_count(boot_sector);
        }
    }

    // Fallback: check total sectors and cluster count
    detect_fat_by_cluster_count(boot_sector)
}

/// Determine FAT variant by computing the number of data clusters.
fn detect_fat_by_cluster_count(bpb: &[u8]) -> FsType {
    if bpb.len() < 36 {
        return FsType::Unknown;
    }

    let bytes_per_sector = u16::from_le_bytes([bpb[11], bpb[12]]) as u64;
    let sectors_per_cluster = bpb[13] as u64;
    let reserved_sectors = u16::from_le_bytes([bpb[14], bpb[15]]) as u64;
    let num_fats = bpb[16] as u64;
    let root_entry_count = u16::from_le_bytes([bpb[17], bpb[18]]) as u64;

    let total_sectors_16 = u16::from_le_bytes([bpb[19], bpb[20]]) as u64;
    let total_sectors_32 = u32::from_le_bytes([bpb[32], bpb[33], bpb[34], bpb[35]]) as u64;
    let total_sectors = if total_sectors_16 != 0 {
        total_sectors_16
    } else {
        total_sectors_32
    };

    let fat_size_16 = u16::from_le_bytes([bpb[22], bpb[23]]) as u64;
    let fat_size_32 = if bpb.len() >= 40 {
        u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]) as u64
    } else {
        0
    };
    let fat_size = if fat_size_16 != 0 {
        fat_size_16
    } else {
        fat_size_32
    };

    if bytes_per_sector == 0 || sectors_per_cluster == 0 {
        return FsType::Unknown;
    }

    let root_dir_sectors =
        (root_entry_count * 32).div_ceil(bytes_per_sector);

    let data_sectors =
        total_sectors - (reserved_sectors + (num_fats * fat_size) + root_dir_sectors);
    let cluster_count = data_sectors / sectors_per_cluster;

    if cluster_count < 4085 {
        FsType::Fat12
    } else if cluster_count < 65525 {
        FsType::Fat16
    } else {
        FsType::Fat32
    }
}

/// Determine ext2/3/4 variant from superblock feature flags.
fn detect_ext_variant(superblock_buf: &[u8]) -> FsType {
    // Feature compat flags at offset 1116 (0x45C)
    // Feature incompat flags at offset 1120 (0x460)
    if superblock_buf.len() < 1124 {
        return FsType::Ext2;
    }

    let incompat_flags =
        u32::from_le_bytes([superblock_buf[1120], superblock_buf[1121], superblock_buf[1122], superblock_buf[1123]]);

    // INCOMPAT_EXTENTS (0x40) is ext4
    if incompat_flags & 0x0040 != 0 {
        return FsType::Ext4;
    }

    // INCOMPAT_JOURNAL_DEV or HAS_JOURNAL (compat 0x4) means ext3
    let compat_flags =
        u32::from_le_bytes([superblock_buf[1116], superblock_buf[1117], superblock_buf[1118], superblock_buf[1119]]);

    if compat_flags & 0x0004 != 0 {
        return FsType::Ext3;
    }

    FsType::Ext2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    #[test]
    fn test_detect_unknown_empty() {
        let dev = MockDevice::new(4096);
        assert_eq!(detect_filesystem(&dev).unwrap(), FsType::Unknown);
    }

    #[test]
    fn test_detect_ntfs() {
        let mut dev = MockDevice::new(4096);
        // NTFS signature at offset 3
        dev.set_data(3, b"NTFS    ");
        assert_eq!(detect_filesystem(&dev).unwrap(), FsType::Ntfs);
    }

    #[test]
    fn test_detect_exfat() {
        let mut dev = MockDevice::new(4096);
        // exFAT signature at offset 3
        dev.set_data(3, b"EXFAT   ");
        assert_eq!(detect_filesystem(&dev).unwrap(), FsType::ExFat);
    }

    #[test]
    fn test_detect_fat32_by_type_string() {
        let mut dev = MockDevice::new(4096);
        // Boot signature
        dev.set_data(510, &[0x55, 0xAA]);
        // FAT32 type string at offset 82
        dev.set_data(82, b"FAT32   ");
        assert_eq!(detect_filesystem(&dev).unwrap(), FsType::Fat32);
    }

    #[test]
    fn test_detect_ext4() {
        let mut dev = MockDevice::new(4096);
        // ext magic at offset 1080
        dev.set_data(1080, &[0x53, 0xEF]);
        // INCOMPAT_EXTENTS flag (0x40) at offset 1120
        dev.set_data(1116, &[0x00, 0x00, 0x00, 0x00]); // compat
        dev.set_data(1120, &[0x40, 0x00, 0x00, 0x00]); // incompat
        assert_eq!(detect_filesystem(&dev).unwrap(), FsType::Ext4);
    }

    #[test]
    fn test_detect_hfs_plus() {
        let mut dev = MockDevice::new(4096);
        // HFS+ signature at offset 1024 (big-endian 0x482B = "H+")
        dev.set_data(1024, &[0x48, 0x2B]);
        assert_eq!(detect_filesystem(&dev).unwrap(), FsType::HfsPlus);
    }
}
