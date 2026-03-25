//! exFAT filesystem implementation.
//!
//! exFAT (Extensible File Allocation Table) is commonly used on SD cards,
//! USB flash drives, and other removable media > 32 GB.
//!
//! Key structures:
//! - Boot sector (sector 0): OEM "EXFAT   ", VBR, cluster heap params
//! - Backup boot sector (sector 12)
//! - FAT (File Allocation Table): cluster chain map
//! - Allocation bitmap: tracks free/used clusters
//! - Upcase table: Unicode case mapping
//! - Root directory: directory entry stream

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};
use crate::models::*;
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

/// Parsed exFAT boot region parameters.
#[derive(Debug, Clone)]
struct ExFatBpb {
    /// Byte offset of the partition (usually 0 for images).
    partition_offset: u64,
    /// Total number of sectors on the volume.
    volume_length: u64,
    /// Sector offset of the FAT.
    fat_offset: u32,
    /// Length of the FAT in sectors.
    fat_length: u32,
    /// Sector offset of the cluster heap (data region).
    cluster_heap_offset: u32,
    /// Total clusters in the cluster heap.
    cluster_count: u32,
    /// Cluster number of the root directory's first cluster.
    first_cluster_of_root: u32,
    /// Volume serial number.
    volume_serial: u32,
    /// Bytes per sector as a power of 2 (e.g., 9 = 512).
    bytes_per_sector_shift: u8,
    /// Sectors per cluster as a power of 2.
    sectors_per_cluster_shift: u8,
    /// Number of FATs (1 or 2).
    number_of_fats: u8,
    /// Percentage of clusters in use (0..100, or 0xFF = unknown).
    percent_in_use: u8,
    /// Volume flags (bit 0 = active FAT, bit 1 = volume dirty, bit 2 = media failure).
    volume_flags: u16,
}

impl ExFatBpb {
    fn bytes_per_sector(&self) -> u64 {
        1u64 << self.bytes_per_sector_shift
    }

    fn sectors_per_cluster(&self) -> u64 {
        1u64 << self.sectors_per_cluster_shift
    }

    fn bytes_per_cluster(&self) -> u64 {
        self.bytes_per_sector() * self.sectors_per_cluster()
    }

    fn is_dirty(&self) -> bool {
        self.volume_flags & 0x0002 != 0
    }

    fn has_media_failure(&self) -> bool {
        self.volume_flags & 0x0004 != 0
    }
}

/// exFAT filesystem backed by a device.
pub struct ExFatFs<'a> {
    device: &'a dyn Device,
    bpb: ExFatBpb,
    /// True if boot signature 0x55AA was missing during parse.
    boot_sig_missing: bool,
}

impl<'a> ExFatFs<'a> {
    /// Parse an exFAT filesystem from a device.
    pub fn new(device: &'a dyn Device) -> Result<Self> {
        let boot = device.read_exact_at(0, 512)?;

        // Verify OEM name "EXFAT   " at offset 3
        if &boot[3..11] != b"EXFAT   " {
            return Err(Error::FilesystemCorrupted(
                "Missing exFAT OEM signature".into(),
            ));
        }

        // Check boot signature — record but don't bail, so we can still scan
        let boot_sig_missing = boot[510] != 0x55 || boot[511] != 0xAA;

        // Bytes 0-2 must be jump boot code (0xEB 0x76 0x90 is standard)
        // Bytes 11-63 must be zero ("MustBeZero" field)
        let must_be_zero = &boot[11..64];
        let zero_violation = must_be_zero.iter().any(|&b| b != 0);

        let partition_offset = u64::from_le_bytes(boot[64..72].try_into().unwrap());
        let volume_length = u64::from_le_bytes(boot[72..80].try_into().unwrap());
        let fat_offset = u32::from_le_bytes(boot[80..84].try_into().unwrap());
        let fat_length = u32::from_le_bytes(boot[84..88].try_into().unwrap());
        let cluster_heap_offset = u32::from_le_bytes(boot[88..92].try_into().unwrap());
        let cluster_count = u32::from_le_bytes(boot[92..96].try_into().unwrap());
        let first_cluster_of_root = u32::from_le_bytes(boot[96..100].try_into().unwrap());
        let volume_serial = u32::from_le_bytes(boot[100..104].try_into().unwrap());
        // FS revision at 104..106 (we don't validate)
        let volume_flags = u16::from_le_bytes(boot[106..108].try_into().unwrap());
        let bytes_per_sector_shift = boot[108];
        let sectors_per_cluster_shift = boot[109];
        let number_of_fats = boot[110];
        let percent_in_use = boot[112];

        // Basic sanity
        if bytes_per_sector_shift < 9 || bytes_per_sector_shift > 12 {
            return Err(Error::FilesystemCorrupted(format!(
                "Invalid bytes_per_sector_shift: {} (expected 9..12)",
                bytes_per_sector_shift
            )));
        }
        if sectors_per_cluster_shift > 25u8.saturating_sub(bytes_per_sector_shift) {
            return Err(Error::FilesystemCorrupted(format!(
                "Invalid sectors_per_cluster_shift: {}",
                sectors_per_cluster_shift
            )));
        }
        if number_of_fats == 0 || number_of_fats > 2 {
            return Err(Error::FilesystemCorrupted(format!(
                "Invalid number_of_fats: {} (expected 1 or 2)",
                number_of_fats
            )));
        }

        let bpb = ExFatBpb {
            partition_offset,
            volume_length,
            fat_offset,
            fat_length,
            cluster_heap_offset,
            cluster_count,
            first_cluster_of_root,
            volume_serial,
            bytes_per_sector_shift,
            sectors_per_cluster_shift,
            number_of_fats,
            percent_in_use,
            volume_flags,
        };

        let _ = (zero_violation, volume_serial); // used in validate()

        Ok(Self { device, bpb, boot_sig_missing })
    }

    /// Byte offset for a given cluster number (clusters start at 2).
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let bps = self.bpb.bytes_per_sector();
        let heap_start = self.bpb.cluster_heap_offset as u64 * bps;
        heap_start + (cluster as u64 - 2) * self.bpb.bytes_per_cluster()
    }

    /// Read a FAT entry for a given cluster.
    fn read_fat_entry(&self, cluster: u32) -> Result<u32> {
        let bps = self.bpb.bytes_per_sector();
        let fat_start = self.bpb.fat_offset as u64 * bps;
        let entry_offset = fat_start + cluster as u64 * 4;
        let data = self.device.read_exact_at(entry_offset, 4)?;
        Ok(u32::from_le_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Follow a cluster chain. Returns Err on circular chains.
    fn follow_chain(&self, start: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = start;

        loop {
            if current < 2 || current > self.bpb.cluster_count + 1 {
                break;
            }
            // 0xFFFFFFF7 = bad cluster, 0xFFFFFFFF = end of chain
            if current >= 0xFFFFFFF7 {
                break;
            }
            if !visited.insert(current) {
                return Err(Error::FilesystemCorrupted(format!(
                    "Circular cluster chain at cluster {}",
                    current
                )));
            }
            chain.push(current);
            current = self.read_fat_entry(current)?;
        }
        Ok(chain)
    }

    /// Validate boot region integrity.
    fn validate_boot(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        // Check boot signature
        if self.boot_sig_missing {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "EXFAT_BOOT_SIG_MISSING".into(),
                message: "Boot signature 0x55AA is missing — boot sector is corrupted".into(),
                repairable: true,
            });
        }

        // Check volume dirty flag
        if self.bpb.is_dirty() {
            issues.push(FsIssue {
                severity: Severity::Warning,
                code: "EXFAT_DIRTY".into(),
                message: "Volume dirty flag is set — was not cleanly unmounted".into(),
                repairable: true,
            });
        }

        // Check media failure flag
        if self.bpb.has_media_failure() {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "EXFAT_MEDIA_FAILURE".into(),
                message: "Media failure flag is set — device may have bad sectors".into(),
                repairable: false,
            });
        }

        // Validate MustBeZero field
        if let Ok(boot) = self.device.read_exact_at(0, 512) {
            let must_be_zero = &boot[11..64];
            if must_be_zero.iter().any(|&b| b != 0) {
                issues.push(FsIssue {
                    severity: Severity::Warning,
                    code: "EXFAT_MUSTBEZERO".into(),
                    message: "Boot sector MustBeZero field is non-zero — possible corruption".into(),
                    repairable: true,
                });
            }
        }

        // Validate root cluster is within range
        if self.bpb.first_cluster_of_root < 2
            || self.bpb.first_cluster_of_root > self.bpb.cluster_count + 1
        {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "EXFAT_INVALID_ROOT".into(),
                message: format!(
                    "Root directory cluster {} is out of range (2..{})",
                    self.bpb.first_cluster_of_root,
                    self.bpb.cluster_count + 1
                ),
                repairable: false,
            });
        }

        // Validate FAT offset and length
        if self.bpb.fat_offset == 0 || self.bpb.fat_length == 0 {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "EXFAT_INVALID_FAT".into(),
                message: "FAT offset or length is zero".into(),
                repairable: false,
            });
        }

        // Check backup boot sector (sectors 12..23 mirror sectors 0..11)
        let bps = self.bpb.bytes_per_sector();
        let backup_offset = 12 * bps;
        match (
            self.device.read_exact_at(0, bps as usize),
            self.device.read_exact_at(backup_offset, bps as usize),
        ) {
            (Ok(primary), Ok(backup)) => {
                if primary != backup {
                    issues.push(FsIssue {
                        severity: Severity::Warning,
                        code: "EXFAT_BACKUP_MISMATCH".into(),
                        message: "Backup boot sector does not match primary".into(),
                        repairable: true,
                    });
                }
            }
            _ => {
                issues.push(FsIssue {
                    severity: Severity::Error,
                    code: "EXFAT_BACKUP_UNREADABLE".into(),
                    message: "Cannot read backup boot sector".into(),
                    repairable: false,
                });
            }
        }

        // Check FAT1 vs FAT2 consistency (if 2 FATs)
        if self.bpb.number_of_fats >= 2 {
            let fat1_start = self.bpb.fat_offset as u64 * bps;
            let fat2_start = fat1_start + self.bpb.fat_length as u64 * bps;
            let check_size = (4096).min(self.bpb.fat_length as u64 * bps) as usize;

            match (
                self.device.read_exact_at(fat1_start, check_size),
                self.device.read_exact_at(fat2_start, check_size),
            ) {
                (Ok(f1), Ok(f2)) => {
                    if f1 != f2 {
                        issues.push(FsIssue {
                            severity: Severity::Warning,
                            code: "EXFAT_FAT_MISMATCH".into(),
                            message: "FAT1 and FAT2 do not match".into(),
                            repairable: true,
                        });
                    }
                }
                _ => {
                    issues.push(FsIssue {
                        severity: Severity::Error,
                        code: "EXFAT_FAT_UNREADABLE".into(),
                        message: "Cannot read one or both FATs".into(),
                        repairable: false,
                    });
                }
            }
        }

        issues
    }
}

impl<'a> crate::fs::traits::FileSystemOps for ExFatFs<'a> {
    fn metadata(&self) -> Result<FsMetadata> {
        let cluster_size = self.bpb.bytes_per_cluster() as u32;
        let total_clusters = self.bpb.cluster_count as u64;
        let total_bytes = total_clusters * cluster_size as u64;

        // Count free clusters by scanning FAT
        let mut free_clusters = 0u64;
        for cluster in 2..=self.bpb.cluster_count + 1 {
            match self.read_fat_entry(cluster) {
                Ok(0) => free_clusters += 1,
                Ok(_) => {}
                Err(_) => continue,
            }
        }

        let free_bytes = free_clusters * cluster_size as u64;

        Ok(FsMetadata {
            fs_type: FsType::ExFat,
            total_bytes,
            used_bytes: total_bytes.saturating_sub(free_bytes),
            free_bytes,
            cluster_size,
            total_clusters,
            volume_label: None, // exFAT stores label in root directory entries
        })
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        if path != Path::new("/") && path != Path::new("") {
            return Err(Error::Unimplemented(
                "Subdirectory listing for exFAT".into(),
            ));
        }

        let chain = self.follow_chain(self.bpb.first_cluster_of_root)?;
        let mut entries = Vec::new();

        for &cluster in &chain {
            let data = self.device.read_exact_at(
                self.cluster_offset(cluster),
                self.bpb.bytes_per_cluster() as usize,
            )?;

            for i in (0..data.len()).step_by(32) {
                if i + 32 > data.len() {
                    break;
                }
                let entry_type = data[i];

                // 0x00 = end of directory
                if entry_type == 0x00 {
                    return Ok(entries);
                }

                // 0x85 = file directory entry (in-use)
                // 0x05 = deleted file directory entry
                if entry_type == 0x85 {
                    // exFAT file entry: type(1) + count(1) + checksum(2) + attrs(2) + ...
                    let attrs = u16::from_le_bytes([data[i + 4], data[i + 5]]);
                    let is_dir = attrs & 0x10 != 0;

                    // File name is in subsequent 0xC1 (FileName) entries
                    // For now, collect basic info
                    let mut name_parts = Vec::new();
                    let secondary_count = data[i + 1] as usize;

                    let mut size_bytes = 0u64;
                    for s in 1..=secondary_count {
                        let si = i + s * 32;
                        if si + 32 > data.len() {
                            break;
                        }
                        let stype = data[si];
                        if stype == 0xC0 {
                            // Stream extension entry — contains size
                            size_bytes = u64::from_le_bytes(
                                data[si + 8..si + 16].try_into().unwrap_or([0; 8]),
                            );
                        } else if stype == 0xC1 {
                            // File name entry — UTF-16LE at offset 2, 15 chars max
                            let name_data = &data[si + 2..si + 32];
                            let chars: String = name_data
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .take_while(|&c| c != 0)
                                .filter_map(|c| char::from_u32(c as u32))
                                .collect();
                            name_parts.push(chars);
                        }
                    }

                    let name = name_parts.join("");
                    if !name.is_empty() {
                        entries.push(DirEntry {
                            name: name.clone(),
                            path: Path::new("/").join(&name),
                            is_dir,
                            size_bytes,
                            created: None,
                            modified: None,
                        });
                    }
                }
            }
        }

        Ok(entries)
    }

    fn validate(&self) -> Result<ValidationReport> {
        let start = Instant::now();
        let metadata = self.metadata()?;
        let mut issues = self.validate_boot();

        // Try listing root directory
        match self.list_dir(Path::new("/")) {
            Ok(_) => {}
            Err(e) => {
                issues.push(FsIssue {
                    severity: Severity::Critical,
                    code: "EXFAT_ROOT_UNREADABLE".into(),
                    message: format!("Cannot read root directory: {}", e),
                    repairable: false,
                });
            }
        }

        Ok(ValidationReport {
            device_id: self.device.id().to_string(),
            fs_type: FsType::ExFat,
            metadata,
            issues,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn scan_deleted(&self) -> Result<Vec<RecoverableFile>> {
        let chain = self.follow_chain(self.bpb.first_cluster_of_root)?;
        let mut deleted = Vec::new();

        for &cluster in &chain {
            let data = self.device.read_exact_at(
                self.cluster_offset(cluster),
                self.bpb.bytes_per_cluster() as usize,
            )?;

            for i in (0..data.len()).step_by(32) {
                if i + 32 > data.len() {
                    break;
                }
                let entry_type = data[i];
                if entry_type == 0x00 {
                    break;
                }
                // 0x05 = deleted file entry (0x85 with bit 7 cleared)
                if entry_type == 0x05 {
                    let secondary_count = data[i + 1] as usize;
                    let mut first_cluster = 0u32;
                    let mut size = 0u64;
                    let mut name_parts = Vec::new();

                    for s in 1..=secondary_count {
                        let si = i + s * 32;
                        if si + 32 > data.len() {
                            break;
                        }
                        let stype = data[si];
                        if stype == 0x40 {
                            // Deleted stream extension
                            first_cluster = u32::from_le_bytes(
                                data[si + 20..si + 24].try_into().unwrap_or([0; 4]),
                            );
                            size = u64::from_le_bytes(
                                data[si + 8..si + 16].try_into().unwrap_or([0; 8]),
                            );
                        } else if stype == 0x41 {
                            // Deleted file name
                            let name_data = &data[si + 2..si + 32];
                            let chars: String = name_data
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .take_while(|&c| c != 0)
                                .filter_map(|c| char::from_u32(c as u32))
                                .collect();
                            name_parts.push(chars);
                        }
                    }

                    if first_cluster >= 2 && size > 0 {
                        let name = name_parts.join("");
                        deleted.push(RecoverableFile {
                            file_type: guess_file_type(&name),
                            signature: Vec::new(),
                            offset: self.cluster_offset(first_cluster),
                            estimated_size: size,
                            confidence: 0.5,
                            original_name: if name.is_empty() {
                                None
                            } else {
                                Some(name)
                            },
                        });
                    }
                }
            }
        }

        Ok(deleted)
    }

    fn repair(&mut self, options: &RepairOptions) -> Result<RepairReport> {
        if !options.confirm_unsafe {
            return Err(Error::ConfirmationRequired);
        }
        Err(Error::Unimplemented("exFAT repair".into()))
    }
}

/// Guess file type from filename extension.
fn guess_file_type(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_uppercase();
    match ext.as_str() {
        "JPG" | "JPEG" => "JPEG".into(),
        "PNG" => "PNG".into(),
        "PDF" => "PDF".into(),
        "DOC" | "DOCX" => "DOC".into(),
        "XLS" | "XLSX" => "XLS".into(),
        "ZIP" => "ZIP".into(),
        "MP4" | "MOV" => "Video".into(),
        "MP3" | "WAV" | "FLAC" => "Audio".into(),
        _ => ext,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;
    use crate::fs::traits::FileSystemOps;

    /// Build a minimal exFAT image for testing.
    fn make_exfat_image() -> Vec<u8> {
        let bps: u64 = 512;
        let spc: u64 = 8; // 8 sectors per cluster = 4KB clusters
        let total_sectors: u64 = 2048; // 1 MB
        let size = (total_sectors * bps) as usize;
        let mut img = vec![0u8; size];

        // Boot sector
        img[0] = 0xEB; // jump
        img[1] = 0x76;
        img[2] = 0x90;
        img[3..11].copy_from_slice(b"EXFAT   ");
        // MustBeZero: bytes 11..64 are already zero

        // Partition offset = 0
        img[64..72].copy_from_slice(&0u64.to_le_bytes());
        // Volume length
        img[72..80].copy_from_slice(&total_sectors.to_le_bytes());
        // FAT offset = sector 24
        img[80..84].copy_from_slice(&24u32.to_le_bytes());
        // FAT length = 8 sectors
        img[84..88].copy_from_slice(&8u32.to_le_bytes());
        // Cluster heap offset = sector 32
        img[88..92].copy_from_slice(&32u32.to_le_bytes());
        // Cluster count
        let cluster_count = (total_sectors - 32) / spc;
        img[92..96].copy_from_slice(&(cluster_count as u32).to_le_bytes());
        // First cluster of root = 2
        img[96..100].copy_from_slice(&2u32.to_le_bytes());
        // Volume serial
        img[100..104].copy_from_slice(&0x12345678u32.to_le_bytes());
        // FS revision 1.0
        img[104] = 0x00;
        img[105] = 0x01;
        // Volume flags = 0 (clean)
        img[106..108].copy_from_slice(&0u16.to_le_bytes());
        // bytes_per_sector_shift = 9 (512)
        img[108] = 9;
        // sectors_per_cluster_shift = 3 (8)
        img[109] = 3;
        // number_of_fats = 1
        img[110] = 1;
        // percent_in_use = 0xFF (unknown)
        img[112] = 0xFF;
        // Boot signature
        img[510] = 0x55;
        img[511] = 0xAA;

        // FAT: cluster 0 and 1 are reserved (media descriptor + EOC)
        let fat_start = 24 * bps as usize;
        // Cluster 0: media type
        img[fat_start..fat_start + 4].copy_from_slice(&0xFFFFFFF8u32.to_le_bytes());
        // Cluster 1: EOC
        img[fat_start + 4..fat_start + 8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // Cluster 2 (root dir): end of chain
        img[fat_start + 8..fat_start + 12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());

        // Backup boot sector at sector 12 — copy sector 0
        let backup_start = 12 * bps as usize;
        let boot_copy: Vec<u8> = img[0..bps as usize].to_vec();
        img[backup_start..backup_start + bps as usize].copy_from_slice(&boot_copy);

        img
    }

    #[test]
    fn parse_valid_exfat() {
        let img = make_exfat_image();
        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev);
        assert!(fs.is_ok(), "Failed to parse valid exFAT: {:?}", fs.err());
    }

    #[test]
    fn metadata_returns_exfat_type() {
        let img = make_exfat_image();
        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev).unwrap();
        let meta = fs.metadata().unwrap();
        assert_eq!(meta.fs_type, FsType::ExFat);
        assert!(meta.total_bytes > 0);
    }

    #[test]
    fn validate_clean_image() {
        let img = make_exfat_image();
        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        // Clean image should have no errors
        assert!(
            report.issues.iter().all(|i| !matches!(i.severity, Severity::Error | Severity::Critical)),
            "Clean exFAT should have no errors: {:?}",
            report.issues
        );
    }

    #[test]
    fn detect_dirty_flag() {
        let mut img = make_exfat_image();
        // Set volume dirty flag (bit 1)
        img[106] = 0x02;
        // Update backup
        img[12 * 512 + 106] = 0x02;

        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        assert!(
            report.issues.iter().any(|i| i.code == "EXFAT_DIRTY"),
            "Should detect dirty flag"
        );
    }

    #[test]
    fn detect_backup_mismatch() {
        let mut img = make_exfat_image();
        // Corrupt the backup boot sector
        img[12 * 512 + 100] = 0xFF;

        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        assert!(
            report.issues.iter().any(|i| i.code == "EXFAT_BACKUP_MISMATCH"),
            "Should detect backup mismatch"
        );
    }

    #[test]
    fn detect_media_failure_flag() {
        let mut img = make_exfat_image();
        // Set media failure flag (bit 2)
        img[106] = 0x04;
        img[12 * 512 + 106] = 0x04;

        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        assert!(
            report.issues.iter().any(|i| i.code == "EXFAT_MEDIA_FAILURE"),
            "Should detect media failure flag"
        );
    }

    #[test]
    fn missing_oem_rejected() {
        let mut img = make_exfat_image();
        img[3..11].copy_from_slice(b"\x00\x00\x00\x00\x00\x00\x00\x00");
        let dev = MockDevice::from_bytes(img);
        assert!(ExFatFs::new(&dev).is_err());
    }

    #[test]
    fn list_dir_empty_root() {
        let img = make_exfat_image();
        let dev = MockDevice::from_bytes(img);
        let fs = ExFatFs::new(&dev).unwrap();
        let entries = fs.list_dir(Path::new("/")).unwrap();
        assert!(entries.is_empty());
    }
}
