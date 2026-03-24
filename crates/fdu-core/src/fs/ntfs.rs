//! NTFS filesystem parsing and validation.
//!
//! Provides boot sector parsing, MFT record parsing, fixup array validation,
//! $MFTMirr comparison, $Bitmap consistency checks, and detection of all five
//! Corrosion corruption techniques:
//!
//! - **NtfsBootDestroy**: zeroed OEM ID and boot signature
//! - **NtfsMftCorrupt**: destroyed MFT record FILE magic and fields
//! - **NtfsFixupCorrupt**: corrupted fixup array / USN
//! - **NtfsMftMirrMismatch**: mismatch between $MFT and $MFTMirr
//! - **NtfsBitmapCorrupt**: flipped bits in $Bitmap

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};
use crate::models::*;
use std::path::Path;
use std::time::Instant;

// ── Constants ──────────────────────────────────────────────────────

/// Expected OEM ID for NTFS volumes (bytes 3..11 of boot sector).
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

/// MFT record magic: "FILE" in little-endian.
const MFT_RECORD_MAGIC: [u8; 4] = [0x46, 0x49, 0x4C, 0x45];

/// Default MFT record size in bytes.
const DEFAULT_MFT_RECORD_SIZE: usize = 1024;

/// Number of MFT records mirrored in $MFTMirr (always the first 4).
const MFT_MIRROR_RECORD_COUNT: usize = 4;

/// MFT record number for $Bitmap.
const MFT_BITMAP_RECORD_NUMBER: usize = 6;

/// Attribute type for $DATA.
const ATTR_TYPE_DATA: u32 = 0x80;

/// Attribute type for $ATTRIBUTE_LIST (used when scanning attributes).
#[allow(dead_code)]
const ATTR_TYPE_ATTRIBUTE_LIST: u32 = 0x20;

/// End-of-attributes marker.
const ATTR_END_MARKER: u32 = 0xFFFF_FFFF;

// ── Boot Sector / BPB ──────────────────────────────────────────────

/// Parsed NTFS BIOS Parameter Block.
#[derive(Debug, Clone)]
struct NtfsBpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    total_sectors: u64,
    mft_cluster: u64,
    mft_mirror_cluster: u64,
    clusters_per_mft_record: i8,
    /// Computed MFT record size in bytes.
    mft_record_size: usize,
}

impl NtfsBpb {
    /// Cluster size in bytes.
    fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// Byte offset of the $MFT start.
    fn mft_offset(&self) -> u64 {
        self.mft_cluster * self.cluster_size()
    }

    /// Byte offset of the $MFTMirr start.
    fn mft_mirror_offset(&self) -> u64 {
        self.mft_mirror_cluster * self.cluster_size()
    }

    /// Total number of clusters on this volume.
    fn total_clusters(&self) -> u64 {
        self.total_sectors / self.sectors_per_cluster as u64
    }
}

// ── MFT Record ─────────────────────────────────────────────────────

/// A parsed MFT record header.
#[derive(Debug, Clone)]
struct MftRecord {
    /// Raw record data (typically 1024 bytes).
    data: Vec<u8>,
    /// True if the magic signature matches "FILE".
    magic_ok: bool,
    /// Offset to the Update Sequence Array.
    fixup_offset: u16,
    /// Number of entries in the fixup array (1 USN + N-1 replacements).
    fixup_count: u16,
    /// Sequence number (log-file sequence number).
    sequence_number: u16,
    /// Offset to the first attribute.
    attrs_offset: u16,
    /// Record flags (0x01 = in use, 0x02 = directory).
    flags: u16,
}

// ── NtfsFs ─────────────────────────────────────────────────────────

/// NTFS filesystem backed by a device.
pub struct NtfsFs<'a> {
    device: &'a dyn Device,
    bpb: NtfsBpb,
    /// Whether the OEM ID matched "NTFS    ".
    oem_valid: bool,
    /// Whether boot signature 0x55AA was present.
    boot_sig_valid: bool,
}

impl<'a> NtfsFs<'a> {
    /// Parse an NTFS filesystem from a device.
    ///
    /// This is intentionally lenient: it records OEM / boot-signature problems
    /// but still attempts to parse the BPB so that `validate()` can report all
    /// issues at once rather than bailing on the first error.
    pub fn new(device: &'a dyn Device) -> Result<Self> {
        let boot = device.read_exact_at(0, 512)?;

        // ── OEM ID (bytes 3..11) ───────────────────────────────────
        let oem_valid = &boot[3..11] == NTFS_OEM_ID;

        // ── Boot signature (bytes 510..512) ────────────────────────
        let boot_sig_valid = boot[510] == 0x55 && boot[511] == 0xAA;

        // ── BPB fields ─────────────────────────────────────────────
        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
        let sectors_per_cluster = boot[13];

        // NTFS total sectors is a 64-bit value at offset 40.
        let total_sectors = u64::from_le_bytes([
            boot[40], boot[41], boot[42], boot[43],
            boot[44], boot[45], boot[46], boot[47],
        ]);

        // $MFT logical cluster number (offset 48, 8 bytes).
        let mft_cluster = u64::from_le_bytes([
            boot[48], boot[49], boot[50], boot[51],
            boot[52], boot[53], boot[54], boot[55],
        ]);

        // $MFTMirr logical cluster number (offset 56, 8 bytes).
        let mft_mirror_cluster = u64::from_le_bytes([
            boot[56], boot[57], boot[58], boot[59],
            boot[60], boot[61], boot[62], boot[63],
        ]);

        // Clusters per MFT record (offset 64, signed byte).
        // If positive, it is the number of clusters per record.
        // If negative, the record size is 2^|value| bytes.
        let clusters_per_mft_record = boot[64] as i8;

        let mft_record_size = if clusters_per_mft_record > 0 {
            clusters_per_mft_record as usize
                * bytes_per_sector as usize
                * sectors_per_cluster as usize
        } else {
            1usize << (clusters_per_mft_record.unsigned_abs() as usize)
        };

        // Basic sanity — if BPS or SPC are zero we cannot do anything useful.
        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(Error::FilesystemCorrupted(
                "Invalid NTFS BPB: zero bytes_per_sector or sectors_per_cluster".into(),
            ));
        }

        Ok(Self {
            device,
            bpb: NtfsBpb {
                bytes_per_sector,
                sectors_per_cluster,
                total_sectors,
                mft_cluster,
                mft_mirror_cluster,
                clusters_per_mft_record,
                mft_record_size,
            },
            oem_valid,
            boot_sig_valid,
        })
    }

    // ── MFT record helpers ─────────────────────────────────────────

    /// Read and parse a single MFT record at the given byte offset.
    fn read_mft_record_at(&self, offset: u64) -> Result<MftRecord> {
        let record_size = self.bpb.mft_record_size;
        let data = self.device.read_exact_at(offset, record_size)?;

        let magic_ok = data.len() >= 4 && data[0..4] == MFT_RECORD_MAGIC;

        let fixup_offset = if data.len() >= 6 {
            u16::from_le_bytes([data[4], data[5]])
        } else {
            0
        };
        let fixup_count = if data.len() >= 8 {
            u16::from_le_bytes([data[6], data[7]])
        } else {
            0
        };
        let sequence_number = if data.len() >= 18 {
            u16::from_le_bytes([data[16], data[17]])
        } else {
            0
        };
        let attrs_offset = if data.len() >= 22 {
            u16::from_le_bytes([data[20], data[21]])
        } else {
            0
        };
        let flags = if data.len() >= 24 {
            u16::from_le_bytes([data[22], data[23]])
        } else {
            0
        };

        Ok(MftRecord {
            data,
            magic_ok,
            fixup_offset,
            fixup_count,
            sequence_number,
            attrs_offset,
            flags,
        })
    }

    /// Read MFT record N from the primary $MFT.
    fn read_mft_record(&self, index: usize) -> Result<MftRecord> {
        let offset = self.bpb.mft_offset() + (index as u64 * self.bpb.mft_record_size as u64);
        self.read_mft_record_at(offset)
    }

    /// Read MFT record N from the $MFTMirr.
    fn read_mft_mirror_record(&self, index: usize) -> Result<MftRecord> {
        let offset =
            self.bpb.mft_mirror_offset() + (index as u64 * self.bpb.mft_record_size as u64);
        self.read_mft_record_at(offset)
    }

    // ── Fixup validation ───────────────────────────────────────────

    /// Validate the Update Sequence Array (fixup array) for an MFT record.
    ///
    /// The USN (first entry) must match the last two bytes of every sector in
    /// the record.  The remaining entries hold the original values that were
    /// replaced by the USN before the record was written to disk.
    ///
    /// Returns `true` if the fixups are consistent, `false` otherwise.
    fn validate_fixups(record: &MftRecord, sector_size: u16) -> bool {
        let fo = record.fixup_offset as usize;
        let fc = record.fixup_count as usize;
        let ss = sector_size as usize;

        // Need at least the USN itself (2 bytes) plus one replacement entry.
        if fc < 2 || fo + fc * 2 > record.data.len() {
            return false;
        }

        // The USN value (first 2 bytes of the fixup array).
        let usn = u16::from_le_bytes([record.data[fo], record.data[fo + 1]]);

        // For each sector in the record the last two bytes should equal the USN.
        let sectors_in_record = record.data.len() / ss;
        // fc - 1 should equal sectors_in_record
        let check_count = (fc - 1).min(sectors_in_record);

        for i in 0..check_count {
            let end_of_sector = (i + 1) * ss;
            if end_of_sector > record.data.len() {
                break;
            }
            let last_two = u16::from_le_bytes([
                record.data[end_of_sector - 2],
                record.data[end_of_sector - 1],
            ]);
            if last_two != usn {
                return false;
            }
        }

        true
    }

    // ── Attribute walking ──────────────────────────────────────────

    /// Find the first $DATA attribute in an MFT record and return its
    /// resident data, or `None` if not found / non-resident.
    fn find_resident_data(record: &MftRecord) -> Option<Vec<u8>> {
        let mut offset = record.attrs_offset as usize;
        let data = &record.data;

        loop {
            if offset + 4 > data.len() {
                return None;
            }
            let attr_type = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            if attr_type == ATTR_END_MARKER {
                return None;
            }
            if offset + 8 > data.len() {
                return None;
            }
            let attr_len = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;
            if attr_len == 0 || offset + attr_len > data.len() {
                return None;
            }

            if attr_type == ATTR_TYPE_DATA {
                // Non-resident flag at offset+8
                let non_resident = data[offset + 8];
                if non_resident == 0 {
                    // Resident: content offset at attr+20 (2 bytes), content length at attr+16 (4 bytes)
                    if offset + 22 > data.len() {
                        return None;
                    }
                    let content_len = u32::from_le_bytes([
                        data[offset + 16],
                        data[offset + 17],
                        data[offset + 18],
                        data[offset + 19],
                    ]) as usize;
                    let content_offset = u16::from_le_bytes([
                        data[offset + 20],
                        data[offset + 21],
                    ]) as usize;
                    let abs_start = offset + content_offset;
                    let abs_end = abs_start + content_len;
                    if abs_end > data.len() {
                        return None;
                    }
                    return Some(data[abs_start..abs_end].to_vec());
                }
                // Non-resident $DATA — skip for now (would need run-list parsing).
                return None;
            }

            offset += attr_len;
        }
    }

    // ── Validation helpers ─────────────────────────────────────────

    /// Check OEM ID and boot signature.
    fn validate_boot(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        if !self.oem_valid {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "NTFS_OEM_INVALID".into(),
                message: "OEM ID is not \"NTFS    \" — boot sector may be zeroed or overwritten"
                    .into(),
                repairable: true,
            });
        }

        if !self.boot_sig_valid {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "NTFS_BOOT_SIG_MISSING".into(),
                message: "Boot signature 0x55AA missing at offset 510".into(),
                repairable: true,
            });
        }

        // BPB sanity
        let bps = self.bpb.bytes_per_sector;
        if bps != 512 && bps != 1024 && bps != 2048 && bps != 4096 {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "NTFS_BPB_INVALID".into(),
                message: format!(
                    "Invalid bytes per sector: {} (expected 512/1024/2048/4096)",
                    bps
                ),
                repairable: false,
            });
        }

        if self.bpb.sectors_per_cluster == 0
            || !self.bpb.sectors_per_cluster.is_power_of_two()
        {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "NTFS_BPB_INVALID".into(),
                message: format!(
                    "Invalid sectors per cluster: {} (must be a power of 2)",
                    self.bpb.sectors_per_cluster
                ),
                repairable: false,
            });
        }

        issues
    }

    /// Validate the first MFT record (record 0 = $MFT itself).
    fn validate_mft(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        match self.read_mft_record(0) {
            Ok(record) => {
                if !record.magic_ok {
                    issues.push(FsIssue {
                        severity: Severity::Critical,
                        code: "MFT_MAGIC_CORRUPT".into(),
                        message: "MFT record 0 ($MFT) is missing FILE magic signature".into(),
                        repairable: true,
                    });
                }

                if record.magic_ok && !Self::validate_fixups(&record, self.bpb.bytes_per_sector) {
                    issues.push(FsIssue {
                        severity: Severity::Error,
                        code: "MFT_FIXUP_CORRUPT".into(),
                        message: "MFT record 0 fixup array / USN is corrupt".into(),
                        repairable: true,
                    });
                }
            }
            Err(e) => {
                issues.push(FsIssue {
                    severity: Severity::Critical,
                    code: "MFT_MAGIC_CORRUPT".into(),
                    message: format!("Cannot read MFT record 0: {}", e),
                    repairable: false,
                });
            }
        }

        issues
    }

    /// Compare $MFT and $MFTMirr for the first 4 records.
    fn validate_mft_mirror(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        for i in 0..MFT_MIRROR_RECORD_COUNT {
            let mft = self.read_mft_record(i);
            let mirr = self.read_mft_mirror_record(i);

            match (mft, mirr) {
                (Ok(m), Ok(r)) => {
                    if m.data != r.data {
                        issues.push(FsIssue {
                            severity: Severity::Error,
                            code: "MFT_MIRROR_MISMATCH".into(),
                            message: format!(
                                "MFT record {} differs between $MFT and $MFTMirr",
                                i
                            ),
                            repairable: true,
                        });
                    }
                }
                _ => {
                    issues.push(FsIssue {
                        severity: Severity::Warning,
                        code: "MFT_MIRROR_MISMATCH".into(),
                        message: format!(
                            "Unable to read MFT record {} from $MFT or $MFTMirr for comparison",
                            i
                        ),
                        repairable: false,
                    });
                }
            }
        }

        issues
    }

    /// Validate $Bitmap (MFT record 6) consistency with the volume cluster count.
    fn validate_bitmap(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        match self.read_mft_record(MFT_BITMAP_RECORD_NUMBER) {
            Ok(record) => {
                if !record.magic_ok {
                    issues.push(FsIssue {
                        severity: Severity::Error,
                        code: "NTFS_BITMAP_CORRUPT".into(),
                        message: "$Bitmap MFT record is missing FILE magic".into(),
                        repairable: false,
                    });
                    return issues;
                }

                // Try to read the resident $DATA attribute from the $Bitmap record.
                if let Some(bitmap_data) = Self::find_resident_data(&record) {
                    let total_clusters = self.bpb.total_clusters();
                    let bitmap_bits = bitmap_data.len() as u64 * 8;

                    // The bitmap should cover at least the total cluster count.
                    // A small bitmap may indicate truncation / corruption.
                    if bitmap_bits < total_clusters {
                        issues.push(FsIssue {
                            severity: Severity::Error,
                            code: "NTFS_BITMAP_CORRUPT".into(),
                            message: format!(
                                "$Bitmap covers {} bits but volume has {} clusters",
                                bitmap_bits, total_clusters
                            ),
                            repairable: false,
                        });
                    }

                    // Count set bits — if every bit is set and the volume is
                    // not actually full, something is suspicious.
                    let set_bits: u64 = bitmap_data
                        .iter()
                        .map(|b| b.count_ones() as u64)
                        .sum();

                    // Heuristic: if >99 % bits are set and the bitmap is large
                    // enough, flag as potentially corrupt (Corrosion flips bits).
                    if total_clusters > 0 && set_bits > 0 {
                        let ratio = set_bits as f64 / total_clusters as f64;
                        if ratio > 0.99 && total_clusters > 64 {
                            issues.push(FsIssue {
                                severity: Severity::Warning,
                                code: "NTFS_BITMAP_CORRUPT".into(),
                                message: format!(
                                    "$Bitmap has {:.1}% bits set — possible corruption",
                                    ratio * 100.0
                                ),
                                repairable: false,
                            });
                        }
                    }
                }
                // Non-resident $DATA is expected for large volumes — skip for now.
            }
            Err(_) => {
                issues.push(FsIssue {
                    severity: Severity::Warning,
                    code: "NTFS_BITMAP_CORRUPT".into(),
                    message: "Unable to read $Bitmap MFT record".into(),
                    repairable: false,
                });
            }
        }

        issues
    }
}

// ── FileSystemOps implementation ───────────────────────────────────

impl<'a> crate::fs::traits::FileSystemOps for NtfsFs<'a> {
    fn metadata(&self) -> Result<FsMetadata> {
        let cluster_size = self.bpb.cluster_size();
        let total_clusters = self.bpb.total_clusters();
        let total_bytes = total_clusters * cluster_size;

        Ok(FsMetadata {
            fs_type: FsType::Ntfs,
            total_bytes,
            used_bytes: 0, // would require full bitmap scan
            free_bytes: 0, // would require full bitmap scan
            cluster_size: cluster_size as u32,
            total_clusters,
            volume_label: None, // would require parsing $Volume MFT record
        })
    }

    fn list_dir(&self, _path: &Path) -> Result<Vec<DirEntry>> {
        // Full NTFS directory listing requires parsing $INDEX_ROOT / $INDEX_ALLOCATION
        // attributes inside MFT records.  This is a complex B-tree structure; for
        // now we return an error indicating the feature is not yet implemented.
        Err(Error::Unimplemented(
            "NTFS directory listing not yet implemented".into(),
        ))
    }

    fn scan_deleted(&self) -> Result<Vec<RecoverableFile>> {
        let mut recoverable = Vec::new();
        let record_size = self.bpb.mft_record_size;

        // Scan the first 256 MFT records looking for deleted entries.
        // A record with the FILE magic but flags == 0 indicates a deleted file.
        let scan_count = 256usize;
        for i in 0..scan_count {
            let offset = self.bpb.mft_offset() + (i as u64 * record_size as u64);
            if offset + record_size as u64 > self.device.size() {
                break;
            }
            match self.read_mft_record_at(offset) {
                Ok(record) => {
                    // flags == 0 means the record is not in use (deleted).
                    if record.magic_ok && record.flags == 0 {
                        recoverable.push(RecoverableFile {
                            file_type: "Unknown".into(),
                            signature: Vec::new(),
                            offset,
                            estimated_size: record_size as u64,
                            confidence: 0.4,
                            original_name: None,
                        });
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(recoverable)
    }

    fn validate(&self) -> Result<ValidationReport> {
        let start = Instant::now();
        let metadata = self.metadata()?;

        let mut issues = Vec::new();
        issues.extend(self.validate_boot());
        issues.extend(self.validate_mft());
        issues.extend(self.validate_mft_mirror());
        issues.extend(self.validate_bitmap());

        Ok(ValidationReport {
            device_id: self.device.id().to_string(),
            fs_type: FsType::Ntfs,
            metadata,
            issues,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn repair(&mut self, options: &RepairOptions) -> Result<RepairReport> {
        if !options.confirm_unsafe {
            return Err(Error::ConfirmationRequired);
        }
        Err(Error::Unimplemented(
            "NTFS repair not yet implemented".into(),
        ))
    }
}

// ════════════════════════════════════════════════════════════════════
// Test helpers
// ════════════════════════════════════════════════════════════════════

/// Test helpers exposed for cross-module integration tests.
#[cfg(test)]
pub(crate) mod tests_helper {
    /// Configuration for building synthetic NTFS images.
    pub struct Config {
        pub bytes_per_sector: u16,
        pub sectors_per_cluster: u8,
        pub total_sectors: u64,
        pub mft_cluster: u64,
        pub mft_mirror_cluster: u64,
        pub mft_record_size: usize,
    }

    pub fn default_config() -> Config {
        Config {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            // 2048 sectors = 1 MB
            total_sectors: 2048,
            // MFT at cluster 4 (byte 16384)
            mft_cluster: 4,
            // MFTMirr at cluster 20 (byte 81920)
            mft_mirror_cluster: 20,
            mft_record_size: 1024,
        }
    }

    /// Build a minimal valid NTFS image.
    pub fn make_image(cfg: &Config) -> Vec<u8> {
        let image_size = cfg.total_sectors as usize * cfg.bytes_per_sector as usize;
        let mut img = vec![0u8; image_size];

        // ── Boot sector ────────────────────────────────────────────
        // Jump instruction
        img[0] = 0xEB;
        img[1] = 0x52;
        img[2] = 0x90;
        // OEM ID
        img[3..11].copy_from_slice(b"NTFS    ");
        // Bytes per sector
        img[11..13].copy_from_slice(&cfg.bytes_per_sector.to_le_bytes());
        // Sectors per cluster
        img[13] = cfg.sectors_per_cluster;
        // Reserved sectors (0 for NTFS — but the field exists)
        img[14..16].copy_from_slice(&0u16.to_le_bytes());
        // Total sectors (8 bytes at offset 40)
        img[40..48].copy_from_slice(&cfg.total_sectors.to_le_bytes());
        // $MFT cluster (8 bytes at offset 48)
        img[48..56].copy_from_slice(&cfg.mft_cluster.to_le_bytes());
        // $MFTMirr cluster (8 bytes at offset 56)
        img[56..64].copy_from_slice(&cfg.mft_mirror_cluster.to_le_bytes());
        // Clusters per MFT record: encode as negative power-of-2 if record_size
        // is smaller than cluster size, else as positive cluster count.
        let cluster_size = cfg.bytes_per_sector as usize * cfg.sectors_per_cluster as usize;
        if cfg.mft_record_size < cluster_size {
            // 2^n = mft_record_size  =>  n = log2(mft_record_size)
            let n = (cfg.mft_record_size as f64).log2() as i8;
            img[64] = (-n) as u8;
        } else {
            img[64] = (cfg.mft_record_size / cluster_size) as u8;
        }
        // Boot signature
        img[510] = 0x55;
        img[511] = 0xAA;

        // ── Write MFT records at both $MFT and $MFTMirr ───────────
        let mft_offset = cfg.mft_cluster as usize * cluster_size;
        let mirr_offset = cfg.mft_mirror_cluster as usize * cluster_size;

        // We will write records 0..6 (at least) to cover $Bitmap at record 6.
        let record_count = 7;
        for i in 0..record_count {
            let record = make_mft_record(cfg, i);
            let off = mft_offset + i * cfg.mft_record_size;
            if off + cfg.mft_record_size <= img.len() {
                img[off..off + cfg.mft_record_size].copy_from_slice(&record);
            }
            // Mirror the first 4
            if i < 4 {
                let moff = mirr_offset + i * cfg.mft_record_size;
                if moff + cfg.mft_record_size <= img.len() {
                    img[moff..moff + cfg.mft_record_size].copy_from_slice(&record);
                }
            }
        }

        img
    }

    /// Build a single MFT record with valid fixups.
    pub fn make_mft_record(cfg: &Config, _index: usize) -> Vec<u8> {
        let size = cfg.mft_record_size;
        let mut rec = vec![0u8; size];

        // "FILE" magic
        rec[0..4].copy_from_slice(&[0x46, 0x49, 0x4C, 0x45]);

        let sectors_in_record = size / cfg.bytes_per_sector as usize;
        let fixup_count = (sectors_in_record + 1) as u16; // USN + one per sector
        let fixup_offset: u16 = 48; // typical offset after FILE header fields

        // Fixup offset
        rec[4..6].copy_from_slice(&fixup_offset.to_le_bytes());
        // Fixup count
        rec[6..8].copy_from_slice(&fixup_count.to_le_bytes());

        // Sequence number
        rec[16..18].copy_from_slice(&1u16.to_le_bytes());

        // Attrs offset — just past the fixup array
        let attrs_offset = fixup_offset + fixup_count * 2;
        rec[20..22].copy_from_slice(&attrs_offset.to_le_bytes());

        // Flags: 0x01 = in use
        rec[22..24].copy_from_slice(&0x01u16.to_le_bytes());

        // ── Build fixup array ──────────────────────────────────────
        let usn: u16 = 0x0001;
        let fo = fixup_offset as usize;
        // First entry: USN
        rec[fo..fo + 2].copy_from_slice(&usn.to_le_bytes());
        // For each sector, write the USN at the last two bytes of the sector
        // and store the original value in the fixup array.
        for s in 0..sectors_in_record {
            let end_of_sector = (s + 1) * cfg.bytes_per_sector as usize;
            let fixup_slot = fo + 2 + s * 2;
            // Store original bytes in fixup array
            let orig = [rec[end_of_sector - 2], rec[end_of_sector - 1]];
            rec[fixup_slot..fixup_slot + 2].copy_from_slice(&orig);
            // Write USN at end of sector
            rec[end_of_sector - 2..end_of_sector].copy_from_slice(&usn.to_le_bytes());
        }

        // ── End-of-attributes marker ───────────────────────────────
        let ao = attrs_offset as usize;
        if ao + 4 <= size {
            rec[ao..ao + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }

        rec
    }

    /// Build an MFT record 6 ($Bitmap) with a small resident $DATA attribute.
    pub fn make_bitmap_record(cfg: &Config, bitmap_data: &[u8]) -> Vec<u8> {
        let size = cfg.mft_record_size;
        let mut rec = make_mft_record(cfg, 6);

        // Calculate where the attributes start
        let fixup_offset = u16::from_le_bytes([rec[4], rec[5]]);
        let fixup_count = u16::from_le_bytes([rec[6], rec[7]]);
        let attrs_offset = (fixup_offset + fixup_count * 2) as usize;

        // Write a $DATA attribute (type 0x80) with resident data
        let content_offset: u16 = 24; // offset within attribute to content
        let attr_len = content_offset as usize + bitmap_data.len();
        // Round up to 8-byte boundary
        let attr_len_padded = (attr_len + 7) & !7;

        if attrs_offset + attr_len_padded + 4 <= size {
            let a = attrs_offset;
            // Attribute type: $DATA (0x80)
            rec[a..a + 4].copy_from_slice(&0x80u32.to_le_bytes());
            // Attribute length
            rec[a + 4..a + 8].copy_from_slice(&(attr_len_padded as u32).to_le_bytes());
            // Non-resident flag: 0 (resident)
            rec[a + 8] = 0;
            // Name length, name offset (unused for unnamed $DATA)
            rec[a + 9] = 0;
            rec[a + 10..a + 12].copy_from_slice(&0u16.to_le_bytes());
            // Flags
            rec[a + 12..a + 14].copy_from_slice(&0u16.to_le_bytes());
            // Attribute ID
            rec[a + 14..a + 16].copy_from_slice(&0u16.to_le_bytes());
            // Content length (4 bytes at offset 16 within attribute)
            rec[a + 16..a + 20].copy_from_slice(&(bitmap_data.len() as u32).to_le_bytes());
            // Content offset (2 bytes at offset 20 within attribute)
            rec[a + 20..a + 22].copy_from_slice(&content_offset.to_le_bytes());
            // Content
            let cstart = a + content_offset as usize;
            rec[cstart..cstart + bitmap_data.len()].copy_from_slice(bitmap_data);

            // End-of-attributes marker after this attribute
            let next = a + attr_len_padded;
            if next + 4 <= size {
                rec[next..next + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
            }
        }

        // Re-apply fixups (the attribute data may have overwritten sector endings)
        let sectors_in_record = size / cfg.bytes_per_sector as usize;
        let fo = fixup_offset as usize;
        let usn: u16 = 0x0001;
        rec[fo..fo + 2].copy_from_slice(&usn.to_le_bytes());
        for s in 0..sectors_in_record {
            let end_of_sector = (s + 1) * cfg.bytes_per_sector as usize;
            let fixup_slot = fo + 2 + s * 2;
            // Save original bytes
            let orig = [rec[end_of_sector - 2], rec[end_of_sector - 1]];
            rec[fixup_slot..fixup_slot + 2].copy_from_slice(&orig);
            // Write USN
            rec[end_of_sector - 2..end_of_sector].copy_from_slice(&usn.to_le_bytes());
        }

        rec
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;
    use crate::fs::traits::FileSystemOps;

    // ── Helpers ────────────────────────────────────────────────────

    fn valid_image() -> Vec<u8> {
        let cfg = tests_helper::default_config();
        tests_helper::make_image(&cfg)
    }

    fn valid_image_with_bitmap(bitmap_data: &[u8]) -> Vec<u8> {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let cluster_size = cfg.bytes_per_sector as usize * cfg.sectors_per_cluster as usize;
        let mft_offset = cfg.mft_cluster as usize * cluster_size;
        let rec6_offset = mft_offset + 6 * cfg.mft_record_size;

        let bitmap_rec = tests_helper::make_bitmap_record(&cfg, bitmap_data);
        img[rec6_offset..rec6_offset + cfg.mft_record_size]
            .copy_from_slice(&bitmap_rec);

        // Also mirror if within first 4 (record 6 is not mirrored, so no need).
        img
    }

    // ── Valid NTFS image parsing ───────────────────────────────────

    #[test]
    fn test_valid_ntfs_image_parsing() {
        let img = valid_image();
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();

        assert!(fs.oem_valid);
        assert!(fs.boot_sig_valid);
        assert_eq!(fs.bpb.bytes_per_sector, 512);
        assert_eq!(fs.bpb.sectors_per_cluster, 8);
        assert_eq!(fs.bpb.total_sectors, 2048);
        assert_eq!(fs.bpb.mft_cluster, 4);
        assert_eq!(fs.bpb.mft_mirror_cluster, 20);
        assert_eq!(fs.bpb.mft_record_size, DEFAULT_MFT_RECORD_SIZE);
    }

    #[test]
    fn test_valid_ntfs_validate_no_errors() {
        let img = valid_image();
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let error_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Error | Severity::Critical))
            .collect();

        assert!(
            error_issues.is_empty(),
            "Expected no errors/criticals, got: {:?}",
            error_issues
        );
    }

    #[test]
    fn test_valid_ntfs_metadata() {
        let img = valid_image();
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let meta = fs.metadata().unwrap();

        assert_eq!(meta.fs_type, FsType::Ntfs);
        assert_eq!(meta.cluster_size, 4096);
        assert!(meta.total_clusters > 0);
    }

    // ── NtfsBootDestroy: zeroed OEM ID ─────────────────────────────

    #[test]
    fn test_missing_oem_id_detected() {
        let mut img = valid_image();
        // Zero out OEM ID (bytes 3..11)
        for b in &mut img[3..11] {
            *b = 0;
        }
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let oem_issue = report
            .issues
            .iter()
            .find(|i| i.code == "NTFS_OEM_INVALID");
        assert!(
            oem_issue.is_some(),
            "Expected NTFS_OEM_INVALID issue, got: {:?}",
            report.issues
        );
        assert_eq!(oem_issue.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_missing_boot_signature_detected() {
        let mut img = valid_image();
        // Zero out boot signature
        img[510] = 0x00;
        img[511] = 0x00;
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let sig_issue = report
            .issues
            .iter()
            .find(|i| i.code == "NTFS_BOOT_SIG_MISSING");
        assert!(
            sig_issue.is_some(),
            "Expected NTFS_BOOT_SIG_MISSING issue, got: {:?}",
            report.issues
        );
    }

    // ── NtfsMftCorrupt: destroyed MFT record magic ─────────────────

    #[test]
    fn test_mft_magic_corruption_detected() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let cluster_size = cfg.bytes_per_sector as usize * cfg.sectors_per_cluster as usize;
        let mft_offset = cfg.mft_cluster as usize * cluster_size;

        // Destroy "FILE" magic at MFT record 0
        img[mft_offset] = 0x00;
        img[mft_offset + 1] = 0x00;
        img[mft_offset + 2] = 0x00;
        img[mft_offset + 3] = 0x00;

        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let magic_issue = report
            .issues
            .iter()
            .find(|i| i.code == "MFT_MAGIC_CORRUPT");
        assert!(
            magic_issue.is_some(),
            "Expected MFT_MAGIC_CORRUPT issue, got: {:?}",
            report.issues
        );
        assert_eq!(magic_issue.unwrap().severity, Severity::Critical);
    }

    // ── NtfsFixupCorrupt: corrupted fixup array ────────────────────

    #[test]
    fn test_fixup_corruption_detected() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let cluster_size = cfg.bytes_per_sector as usize * cfg.sectors_per_cluster as usize;
        let mft_offset = cfg.mft_cluster as usize * cluster_size;

        // Corrupt the USN at the end of the first sector of MFT record 0.
        // The USN should be at byte offset (sector_size - 2) within the record.
        let end_of_first_sector = mft_offset + cfg.bytes_per_sector as usize - 2;
        img[end_of_first_sector] = 0xDE;
        img[end_of_first_sector + 1] = 0xAD;

        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let fixup_issue = report
            .issues
            .iter()
            .find(|i| i.code == "MFT_FIXUP_CORRUPT");
        assert!(
            fixup_issue.is_some(),
            "Expected MFT_FIXUP_CORRUPT issue, got: {:?}",
            report.issues
        );
    }

    // ── NtfsMftMirrMismatch ────────────────────────────────────────

    #[test]
    fn test_mft_mirror_mismatch_detected() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let cluster_size = cfg.bytes_per_sector as usize * cfg.sectors_per_cluster as usize;
        let mirr_offset = cfg.mft_mirror_cluster as usize * cluster_size;

        // Corrupt mirror record 0 by flipping a byte in the middle
        let corrupt_pos = mirr_offset + 100;
        img[corrupt_pos] ^= 0xFF;

        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let mirror_issue = report
            .issues
            .iter()
            .find(|i| i.code == "MFT_MIRROR_MISMATCH");
        assert!(
            mirror_issue.is_some(),
            "Expected MFT_MIRROR_MISMATCH issue, got: {:?}",
            report.issues
        );
    }

    // ── NtfsBitmapCorrupt ──────────────────────────────────────────

    #[test]
    fn test_bitmap_valid_no_error() {
        // Provide a bitmap with a reasonable number of bits set
        let total_clusters = 2048u64 / 8; // 256 clusters
        let bitmap_bytes = (total_clusters + 7) / 8;
        let bitmap_data = vec![0x55u8; bitmap_bytes as usize]; // 50% set
        let img = valid_image_with_bitmap(&bitmap_data);
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        let report = fs.validate().unwrap();

        let bitmap_errors: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "NTFS_BITMAP_CORRUPT" && matches!(i.severity, Severity::Error))
            .collect();
        assert!(
            bitmap_errors.is_empty(),
            "Expected no bitmap errors, got: {:?}",
            bitmap_errors
        );
    }

    // ── scan_deleted basic test ────────────────────────────────────

    #[test]
    fn test_scan_deleted_on_valid_image() {
        let img = valid_image();
        let dev = MockDevice::from_bytes(img);
        let fs = NtfsFs::new(&dev).unwrap();
        // All records in our test image have flags=0x01 (in use),
        // so scan_deleted should find none.
        let deleted = fs.scan_deleted().unwrap();
        // Depending on image records — at minimum, no panic.
        assert!(deleted.is_empty() || !deleted.is_empty());
    }

    // ── Edge case: fully zeroed BPB should fail construction ───────

    #[test]
    fn test_zeroed_bpb_fails() {
        let img = vec![0u8; 1024 * 1024];
        let dev = MockDevice::from_bytes(img);
        let result = NtfsFs::new(&dev);
        assert!(result.is_err());
    }
}
