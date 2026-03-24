//! FAT32 filesystem implementation using the `fatfs` crate.
//!
//! Provides filesystem validation, directory listing, deleted file scanning,
//! and (in Phase 4) repair operations.

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};
use crate::models::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

/// FAT32 filesystem backed by a device.
pub struct Fat32Fs<'a> {
    device: &'a dyn Device,
    bpb: Fat32Bpb,
}

/// Parsed FAT32 BIOS Parameter Block.
#[derive(Debug, Clone)]
struct Fat32Bpb {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    num_fats: u8,
    total_sectors: u32,
    fat_size_sectors: u32,
    root_cluster: u32,
    volume_label: String,
}

impl<'a> Fat32Fs<'a> {
    /// Parse a FAT32 filesystem from a device.
    pub fn new(device: &'a dyn Device) -> Result<Self> {
        let boot = device.read_exact_at(0, 512)?;

        // Verify boot signature
        if boot[510] != 0x55 || boot[511] != 0xAA {
            return Err(Error::FilesystemCorrupted(
                "Missing boot signature 0x55AA".into(),
            ));
        }

        let bytes_per_sector = u16::from_le_bytes([boot[11], boot[12]]);
        let sectors_per_cluster = boot[13];
        let reserved_sectors = u16::from_le_bytes([boot[14], boot[15]]);
        let num_fats = boot[16];

        let total_sectors_16 = u16::from_le_bytes([boot[19], boot[20]]) as u32;
        let total_sectors_32 =
            u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]);
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16
        } else {
            total_sectors_32
        };

        let fat_size_sectors =
            u32::from_le_bytes([boot[36], boot[37], boot[38], boot[39]]);
        let root_cluster = u32::from_le_bytes([boot[44], boot[45], boot[46], boot[47]]);

        // Volume label from extended boot record (offset 71 for FAT32)
        let label_bytes = &boot[71..82];
        let volume_label = String::from_utf8_lossy(label_bytes).trim().to_string();

        if bytes_per_sector == 0 || sectors_per_cluster == 0 {
            return Err(Error::FilesystemCorrupted(
                "Invalid BPB: zero bytes_per_sector or sectors_per_cluster".into(),
            ));
        }

        Ok(Self {
            device,
            bpb: Fat32Bpb {
                bytes_per_sector,
                sectors_per_cluster,
                reserved_sectors,
                num_fats,
                total_sectors,
                fat_size_sectors,
                root_cluster,
                volume_label,
            },
        })
    }

    /// Calculate byte offset for a given cluster number.
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let bpb = &self.bpb;
        let data_start_sector = bpb.reserved_sectors as u64
            + (bpb.num_fats as u64 * bpb.fat_size_sectors as u64);
        let cluster_offset = (cluster as u64 - 2) * bpb.sectors_per_cluster as u64;
        (data_start_sector + cluster_offset) * bpb.bytes_per_sector as u64
    }

    /// Read a FAT entry for a given cluster.
    fn read_fat_entry(&self, cluster: u32) -> Result<u32> {
        let bpb = &self.bpb;
        let fat_offset = cluster as u64 * 4;
        let fat_sector = bpb.reserved_sectors as u64 + (fat_offset / bpb.bytes_per_sector as u64);
        let offset_in_sector = (fat_offset % bpb.bytes_per_sector as u64) as usize;

        let sector_data =
            self.device
                .read_exact_at(fat_sector * bpb.bytes_per_sector as u64, bpb.bytes_per_sector as usize)?;

        let entry = u32::from_le_bytes([
            sector_data[offset_in_sector],
            sector_data[offset_in_sector + 1],
            sector_data[offset_in_sector + 2],
            sector_data[offset_in_sector + 3],
        ]) & 0x0FFF_FFFF;

        Ok(entry)
    }

    /// Follow a cluster chain starting from `start_cluster`.
    ///
    /// Uses a HashSet for O(1) cycle detection instead of iterating up to
    /// `max_clusters` times before discovering a loop.
    fn follow_chain(&self, start_cluster: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut current = start_cluster;

        loop {
            if !(2..0x0FFF_FFF8).contains(&current) {
                break;
            }
            if !visited.insert(current) {
                return Err(Error::FilesystemCorrupted(
                    format!("Circular cluster chain detected at cluster {}", current),
                ));
            }
            chain.push(current);
            current = self.read_fat_entry(current)?;
        }

        Ok(chain)
    }

    /// Total number of data clusters on the volume.
    fn total_data_clusters(&self) -> u64 {
        let bpb = &self.bpb;
        let data_start_sector = bpb.reserved_sectors as u64
            + (bpb.num_fats as u64 * bpb.fat_size_sectors as u64);
        let data_sectors = (bpb.total_sectors as u64).saturating_sub(data_start_sector);
        data_sectors / bpb.sectors_per_cluster as u64
    }

    /// Resolve a path to its starting cluster by walking the directory tree.
    ///
    /// `/` and empty paths resolve to the root cluster. Subdirectories are
    /// resolved component-by-component.
    fn resolve_dir_cluster(&self, path: &Path) -> Result<u32> {
        // Root directory
        if path == Path::new("/") || path == Path::new("") {
            return Ok(self.bpb.root_cluster);
        }

        let mut current_cluster = self.bpb.root_cluster;

        for component in path.components() {
            use std::path::Component;
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::ParentDir => {
                    // ".." navigation not supported — would need parent tracking
                    return Err(Error::Unimplemented(
                        "Parent directory navigation (..) not supported".into(),
                    ));
                }
                Component::Normal(name) => {
                    let target_name = name.to_string_lossy();
                    let entries = self.read_dir_entries(current_cluster)?;

                    let found = entries.iter().find(|e| {
                        !e.is_deleted
                            && e.is_dir
                            && (e.display_name().eq_ignore_ascii_case(&target_name))
                    });

                    match found {
                        Some(dir_entry) => {
                            if dir_entry.first_cluster < 2 {
                                return Err(Error::FilesystemCorrupted(format!(
                                    "Directory '{}' has invalid cluster {}",
                                    target_name, dir_entry.first_cluster
                                )));
                            }
                            current_cluster = dir_entry.first_cluster;
                        }
                        None => {
                            return Err(Error::NotFound(format!(
                                "Directory '{}' not found",
                                target_name
                            )));
                        }
                    }
                }
                _ => continue,
            }
        }

        Ok(current_cluster)
    }

    /// Read directory entries from a cluster chain.
    fn read_dir_entries(&self, start_cluster: u32) -> Result<Vec<Fat32DirEntry>> {
        let chain = self.follow_chain(start_cluster)?;
        let cluster_size =
            self.bpb.sectors_per_cluster as usize * self.bpb.bytes_per_sector as usize;

        let mut entries = Vec::new();
        let mut lfn_parts: Vec<String> = Vec::new();

        for &cluster in &chain {
            let offset = self.cluster_offset(cluster);
            let data = self.device.read_exact_at(offset, cluster_size)?;

            for i in (0..data.len().saturating_sub(31)).step_by(32) {
                let entry = &data[i..i + 32];

                // End of directory
                if entry[0] == 0x00 {
                    return Ok(entries);
                }

                // Deleted entry marker
                if entry[0] == 0xE5 {
                    let deleted = parse_deleted_entry(entry);
                    if let Some(d) = deleted {
                        entries.push(d);
                    }
                    lfn_parts.clear();
                    continue;
                }

                // LFN entry (attribute byte = 0x0F)
                if entry[11] == 0x0F {
                    let part = parse_lfn_part(entry);
                    lfn_parts.push(part);
                    continue;
                }

                // Regular 8.3 entry
                let mut dir_entry = parse_83_entry(entry);

                // If we had LFN parts, reconstruct the long filename
                if !lfn_parts.is_empty() {
                    lfn_parts.reverse();
                    dir_entry.long_name = Some(lfn_parts.join(""));
                    lfn_parts.clear();
                }

                entries.push(dir_entry);
            }
        }

        Ok(entries)
    }

    /// Validate FAT table consistency.
    fn validate_fat(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();
        let total_clusters = self.total_data_clusters();

        // Check FAT1 vs FAT2 consistency (if 2 FATs exist)
        if self.bpb.num_fats >= 2 {
            let fat1_offset = self.bpb.reserved_sectors as u64 * self.bpb.bytes_per_sector as u64;
            let fat_size_bytes =
                self.bpb.fat_size_sectors as u64 * self.bpb.bytes_per_sector as u64;
            let fat2_offset = fat1_offset + fat_size_bytes;

            // Compare first 4KB of FAT1 and FAT2 as a quick consistency check
            let check_size = 4096.min(fat_size_bytes as usize);
            match (
                self.device.read_exact_at(fat1_offset, check_size),
                self.device.read_exact_at(fat2_offset, check_size),
            ) {
                (Ok(fat1), Ok(fat2)) => {
                    if fat1 != fat2 {
                        issues.push(FsIssue {
                            severity: Severity::Warning,
                            code: "FAT_MISMATCH".into(),
                            message: "FAT1 and FAT2 do not match — possible corruption".into(),
                            repairable: true,
                        });
                    }
                }
                _ => {
                    issues.push(FsIssue {
                        severity: Severity::Error,
                        code: "FAT_READ_FAIL".into(),
                        message: "Unable to read FAT table(s)".into(),
                        repairable: false,
                    });
                }
            }
        }

        // Check for basic BPB sanity
        if self.bpb.bytes_per_sector != 512
            && self.bpb.bytes_per_sector != 1024
            && self.bpb.bytes_per_sector != 2048
            && self.bpb.bytes_per_sector != 4096
        {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "INVALID_BPS".into(),
                message: format!(
                    "Invalid bytes per sector: {} (expected 512/1024/2048/4096)",
                    self.bpb.bytes_per_sector
                ),
                repairable: false,
            });
        }

        // Check root cluster is valid
        if self.bpb.root_cluster < 2 || self.bpb.root_cluster as u64 > total_clusters + 1 {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "INVALID_ROOT".into(),
                message: format!(
                    "Root cluster {} is out of valid range (2..{})",
                    self.bpb.root_cluster,
                    total_clusters + 1
                ),
                repairable: false,
            });
        }

        // Detect cross-linked clusters: scan all FAT entries and track which
        // clusters are pointed to by more than one predecessor.
        // Skip if BPB is invalid (avoids panics with corrupt sector sizes).
        let bpb_valid = matches!(
            self.bpb.bytes_per_sector,
            512 | 1024 | 2048 | 4096
        );
        if bpb_valid {
            let last_cluster = (total_clusters + 1).min(u32::MAX as u64) as u32;
            let mut target_to_sources: HashMap<u32, Vec<u32>> = HashMap::new();
            for cluster in 2..=last_cluster {
                match self.read_fat_entry(cluster) {
                    Ok(next) if (2..0x0FFF_FFF8).contains(&next) => {
                        target_to_sources
                            .entry(next)
                            .or_default()
                            .push(cluster);
                    }
                    _ => {}
                }
            }
            let cross_links: Vec<_> = target_to_sources
                .iter()
                .filter(|(_, sources)| sources.len() > 1)
                .collect();
            for (target, sources) in &cross_links {
                issues.push(FsIssue {
                    severity: Severity::Error,
                    code: "FAT_CROSS_LINK".into(),
                    message: format!(
                        "Cluster {} is pointed to by {} different clusters: {:?}",
                        target,
                        sources.len(),
                        sources,
                    ),
                    repairable: true,
                });
            }
        }

        // Validate FSInfo sector (typically sector 1 for FAT32).
        // FSInfo contains cached free cluster count and next-free hint.
        if bpb_valid {
            let fsinfo_offset = 1u64 * self.bpb.bytes_per_sector as u64;
            if let Ok(fsinfo) = self.device.read_exact_at(fsinfo_offset, 512) {
                // Check FSInfo signatures
                let lead_sig = u32::from_le_bytes([fsinfo[0], fsinfo[1], fsinfo[2], fsinfo[3]]);
                let struc_sig =
                    u32::from_le_bytes([fsinfo[484], fsinfo[485], fsinfo[486], fsinfo[487]]);
                let trail_sig =
                    u32::from_le_bytes([fsinfo[508], fsinfo[509], fsinfo[510], fsinfo[511]]);

                if lead_sig != 0x41615252 {
                    issues.push(FsIssue {
                        severity: Severity::Warning,
                        code: "FSINFO_LEAD_SIG".into(),
                        message: format!(
                            "FSInfo lead signature invalid: {:#010x} (expected 0x41615252)",
                            lead_sig
                        ),
                        repairable: true,
                    });
                }
                if struc_sig != 0x61417272 {
                    issues.push(FsIssue {
                        severity: Severity::Warning,
                        code: "FSINFO_STRUC_SIG".into(),
                        message: format!(
                            "FSInfo struct signature invalid: {:#010x} (expected 0x61417272)",
                            struc_sig
                        ),
                        repairable: true,
                    });
                }
                if trail_sig != 0xAA550000 {
                    issues.push(FsIssue {
                        severity: Severity::Warning,
                        code: "FSINFO_TRAIL_SIG".into(),
                        message: format!(
                            "FSInfo trail signature invalid: {:#010x} (expected 0xAA550000)",
                            trail_sig
                        ),
                        repairable: true,
                    });
                }

                // Check free cluster count against actual
                let fsinfo_free = u32::from_le_bytes([
                    fsinfo[488], fsinfo[489], fsinfo[490], fsinfo[491],
                ]);
                if fsinfo_free != 0xFFFFFFFF {
                    // 0xFFFFFFFF means "unknown" — only check if it claims to know
                    let last_cl = (total_clusters + 1).min(u32::MAX as u64) as u32;
                    let mut actual_free = 0u32;
                    for c in 2..=last_cl {
                        if let Ok(0) = self.read_fat_entry(c) {
                            actual_free += 1;
                        }
                    }
                    if fsinfo_free != actual_free {
                        issues.push(FsIssue {
                            severity: Severity::Warning,
                            code: "FSINFO_FREE_MISMATCH".into(),
                            message: format!(
                                "FSInfo reports {} free clusters but FAT scan found {}",
                                fsinfo_free, actual_free,
                            ),
                            repairable: true,
                        });
                    }
                }
            }
        }

        issues
    }
}

/// Internal representation of a FAT32 directory entry.
#[derive(Debug, Clone)]
struct Fat32DirEntry {
    short_name: String,
    long_name: Option<String>,
    is_dir: bool,
    is_deleted: bool,
    size: u32,
    first_cluster: u32,
    created: Option<u64>,
    modified: Option<u64>,
}

impl Fat32DirEntry {
    fn display_name(&self) -> &str {
        self.long_name.as_deref().unwrap_or(&self.short_name)
    }
}

fn parse_83_entry(entry: &[u8]) -> Fat32DirEntry {
    let name = &entry[0..8];
    let ext = &entry[8..11];
    let attr = entry[11];

    let short_name = {
        let n = String::from_utf8_lossy(name).trim_end().to_string();
        let e = String::from_utf8_lossy(ext).trim_end().to_string();
        if e.is_empty() {
            n
        } else {
            format!("{}.{}", n, e)
        }
    };

    let is_dir = attr & 0x10 != 0;

    let first_cluster_hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
    let first_cluster_lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
    let first_cluster = (first_cluster_hi << 16) | first_cluster_lo;

    let size = u32::from_le_bytes([entry[28], entry[29], entry[30], entry[31]]);

    Fat32DirEntry {
        short_name,
        long_name: None,
        is_dir,
        is_deleted: false,
        size,
        first_cluster,
        created: None, // TODO: parse FAT timestamps
        modified: None,
    }
}

fn parse_deleted_entry(entry: &[u8]) -> Option<Fat32DirEntry> {
    let attr = entry[11];
    // Skip LFN entries and volume labels
    if attr == 0x0F || attr & 0x08 != 0 {
        return None;
    }

    let mut e = parse_83_entry(entry);
    // Restore first byte (0xE5 means deleted, original byte is unknown).
    // The 0xE5 byte may become a multi-byte replacement char in UTF-8,
    // so we must skip by *character* not by byte index.
    let rest: String = e.short_name.chars().skip(1).collect();
    e.short_name = format!("?{}", rest);
    e.is_deleted = true;
    Some(e)
}

fn parse_lfn_part(entry: &[u8]) -> String {
    let mut chars = Vec::new();

    // LFN characters are stored in UCS-2 at specific offsets
    let offsets: &[(usize, usize)] = &[
        (1, 11),  // chars 1-5
        (14, 26), // chars 6-11
        (28, 32), // chars 12-13
    ];

    for &(start, end) in offsets {
        for i in (start..end).step_by(2) {
            if i + 1 >= entry.len() {
                break;
            }
            let c = u16::from_le_bytes([entry[i], entry[i + 1]]);
            if c == 0x0000 || c == 0xFFFF {
                return chars.iter().collect();
            }
            if let Some(ch) = char::from_u32(c as u32) {
                chars.push(ch);
            }
        }
    }

    chars.iter().collect()
}

impl<'a> crate::fs::traits::FileSystemOps for Fat32Fs<'a> {
    fn metadata(&self) -> Result<FsMetadata> {
        let bpb = &self.bpb;
        let total_clusters = self.total_data_clusters();
        let cluster_size =
            bpb.sectors_per_cluster as u32 * bpb.bytes_per_sector as u32;
        let total_bytes = total_clusters * cluster_size as u64;

        // Count free clusters by scanning FAT.
        // Cluster numbers are u32 in FAT32; cap to avoid overflow.
        let last_cluster = (total_clusters + 1).min(u32::MAX as u64) as u32;
        let mut free_clusters = 0u64;
        for cluster in 2..=last_cluster {
            match self.read_fat_entry(cluster) {
                Ok(0) => free_clusters += 1,
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(cluster, error = %e, "Unreadable FAT entry during free-cluster scan");
                    continue;
                }
            }
        }

        let free_bytes = free_clusters * cluster_size as u64;

        Ok(FsMetadata {
            fs_type: FsType::Fat32,
            total_bytes,
            used_bytes: total_bytes.saturating_sub(free_bytes),
            free_bytes,
            cluster_size,
            total_clusters,
            volume_label: if bpb.volume_label.is_empty() {
                None
            } else {
                Some(bpb.volume_label.clone())
            },
        })
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        // Resolve the starting cluster for this path by walking the directory tree
        let start_cluster = self.resolve_dir_cluster(path)?;

        let raw_entries = self.read_dir_entries(start_cluster)?;

        Ok(raw_entries
            .iter()
            .filter(|e| !e.is_deleted && e.short_name != "." && e.short_name != "..")
            .map(|e| DirEntry {
                name: e.display_name().to_string(),
                path: Path::new("/").join(e.display_name()),
                is_dir: e.is_dir,
                size_bytes: e.size as u64,
                created: e.created,
                modified: e.modified,
            })
            .collect())
    }

    fn validate(&self) -> Result<ValidationReport> {
        let start = Instant::now();
        let metadata = self.metadata()?;

        let mut issues = self.validate_fat();

        // Check volume label
        if self.bpb.volume_label.is_empty() || self.bpb.volume_label == "NO NAME" {
            issues.push(FsIssue {
                severity: Severity::Info,
                code: "NO_LABEL".into(),
                message: "Volume label is not set".into(),
                repairable: false,
            });
        }

        // Try listing root directory
        match self.read_dir_entries(self.bpb.root_cluster) {
            Ok(entries) => {
                let deleted = entries.iter().filter(|e| e.is_deleted).count();
                if deleted > 0 {
                    issues.push(FsIssue {
                        severity: Severity::Info,
                        code: "DELETED_ENTRIES".into(),
                        message: format!(
                            "{} deleted entries found in root directory (potentially recoverable)",
                            deleted
                        ),
                        repairable: false,
                    });
                }
            }
            Err(e) => {
                issues.push(FsIssue {
                    severity: Severity::Critical,
                    code: "ROOT_UNREADABLE".into(),
                    message: format!("Cannot read root directory: {}", e),
                    repairable: false,
                });
            }
        }

        Ok(ValidationReport {
            device_id: self.device.id().to_string(),
            fs_type: FsType::Fat32,
            metadata,
            issues,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn scan_deleted(&self) -> Result<Vec<RecoverableFile>> {
        let entries = self.read_dir_entries(self.bpb.root_cluster)?;

        Ok(entries
            .iter()
            .filter(|e| e.is_deleted && e.first_cluster >= 2 && e.size > 0)
            .map(|e| RecoverableFile {
                file_type: guess_file_type(e.display_name()),
                signature: Vec::new(),
                offset: self.cluster_offset(e.first_cluster),
                estimated_size: e.size as u64,
                confidence: 0.6, // Medium confidence — entry found but data may be overwritten
                original_name: Some(e.display_name().to_string()),
            })
            .collect())
    }

    fn repair(&mut self, options: &RepairOptions) -> Result<RepairReport> {
        if !options.confirm_unsafe {
            return Err(Error::ConfirmationRequired);
        }
        // Phase 4: Implement actual repair
        Err(Error::Unimplemented(
            "FAT32 repair will be implemented in Phase 4".into(),
        ))
    }
}

/// Guess file type from filename extension.
fn guess_file_type(name: &str) -> String {
    let ext = name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_uppercase();
    match ext.as_str() {
        "JPG" | "JPEG" => "JPEG Image".into(),
        "PNG" => "PNG Image".into(),
        "PDF" => "PDF Document".into(),
        "DOC" | "DOCX" => "Word Document".into(),
        "XLS" | "XLSX" => "Excel Spreadsheet".into(),
        "ZIP" => "ZIP Archive".into(),
        "TXT" => "Text File".into(),
        "MP3" => "MP3 Audio".into(),
        "MP4" => "MP4 Video".into(),
        _ => format!("{} File", ext),
    }
}

/// Expose guess_file_type for cross-module testing.
#[cfg(test)]
pub(crate) mod tests_helper_guess {
    pub fn guess(name: &str) -> String {
        super::guess_file_type(name)
    }
}

/// Test helpers exposed for cross-module integration tests.
#[cfg(test)]
pub(crate) mod tests_helper {
    /// Minimal config for building test FAT32 images from other modules.
    pub struct Config {
        pub bytes_per_sector: u16,
        pub sectors_per_cluster: u8,
        pub reserved_sectors: u16,
        pub num_fats: u8,
        pub fat_size_sectors: u32,
        pub total_sectors: u32,
        pub root_cluster: u32,
    }

    pub fn default_config() -> Config {
        Config {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            reserved_sectors: 32,
            num_fats: 2,
            fat_size_sectors: 16,
            total_sectors: 2048,
            root_cluster: 2,
        }
    }

    pub fn make_image(cfg: &Config) -> Vec<u8> {
        let size = cfg.total_sectors as usize * cfg.bytes_per_sector as usize;
        let mut img = vec![0u8; size];
        img[0] = 0xEB;
        img[1] = 0x58;
        img[2] = 0x90;
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[11..13].copy_from_slice(&cfg.bytes_per_sector.to_le_bytes());
        img[13] = cfg.sectors_per_cluster;
        img[14..16].copy_from_slice(&cfg.reserved_sectors.to_le_bytes());
        img[16] = cfg.num_fats;
        img[32..36].copy_from_slice(&cfg.total_sectors.to_le_bytes());
        img[36..40].copy_from_slice(&cfg.fat_size_sectors.to_le_bytes());
        img[44..48].copy_from_slice(&cfg.root_cluster.to_le_bytes());
        img[71..82].copy_from_slice(b"TEST       ");
        img[82..90].copy_from_slice(b"FAT32   ");
        img[510] = 0x55;
        img[511] = 0xAA;
        // FAT reserved entries
        for fat_idx in 0..cfg.num_fats as u32 {
            let fat_start = (cfg.reserved_sectors as u32 + fat_idx * cfg.fat_size_sectors)
                as usize * cfg.bytes_per_sector as usize;
            img[fat_start..fat_start + 4].copy_from_slice(&0x0FFF_FF00u32.to_le_bytes());
            img[fat_start + 4..fat_start + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        }
        // Root cluster EOC
        let entry_offset = cfg.root_cluster as usize * 4;
        for fat_idx in 0..cfg.num_fats as usize {
            let fat_start = (cfg.reserved_sectors as usize + fat_idx * cfg.fat_size_sectors as usize)
                * cfg.bytes_per_sector as usize;
            let off = fat_start + entry_offset;
            if off + 4 <= img.len() {
                img[off..off + 4].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
            }
        }
        img
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;
    use crate::fs::traits::FileSystemOps;

    // ════════════════════════════════════════════════════════════════
    // Phase 0 — Test Infrastructure & Helpers
    // ════════════════════════════════════════════════════════════════

    /// Configurable FAT32 image geometry for test images.
    #[derive(Clone)]
    struct TestFat32Config {
        bytes_per_sector: u16,
        sectors_per_cluster: u8,
        reserved_sectors: u16,
        num_fats: u8,
        fat_size_sectors: u32,
        total_sectors: u32,
        root_cluster: u32,
        volume_label: [u8; 11],
    }

    impl Default for TestFat32Config {
        fn default() -> Self {
            Self {
                bytes_per_sector: 512,
                sectors_per_cluster: 8,
                reserved_sectors: 32,
                num_fats: 2,
                fat_size_sectors: 16,
                total_sectors: 2048, // 1 MB
                root_cluster: 2,
                volume_label: *b"TEST       ",
            }
        }
    }

    /// Produce a complete in-memory FAT32 volume image from config.
    fn make_fat32_image(cfg: &TestFat32Config) -> Vec<u8> {
        let size = cfg.total_sectors as usize * cfg.bytes_per_sector as usize;
        let mut img = vec![0u8; size];

        // ── Boot sector ──
        img[0] = 0xEB;
        img[1] = 0x58;
        img[2] = 0x90;
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[11..13].copy_from_slice(&cfg.bytes_per_sector.to_le_bytes());
        img[13] = cfg.sectors_per_cluster;
        img[14..16].copy_from_slice(&cfg.reserved_sectors.to_le_bytes());
        img[16] = cfg.num_fats;
        img[32..36].copy_from_slice(&cfg.total_sectors.to_le_bytes());
        img[36..40].copy_from_slice(&cfg.fat_size_sectors.to_le_bytes());
        img[44..48].copy_from_slice(&cfg.root_cluster.to_le_bytes());
        img[71..82].copy_from_slice(&cfg.volume_label);
        img[82..90].copy_from_slice(b"FAT32   ");
        img[510] = 0x55;
        img[511] = 0xAA;

        // ── FAT tables — write reserved entries for clusters 0 and 1 ──
        for fat_idx in 0..cfg.num_fats as u32 {
            let fat_start = (cfg.reserved_sectors as u32
                + fat_idx * cfg.fat_size_sectors) as usize
                * cfg.bytes_per_sector as usize;
            // Cluster 0: media descriptor
            img[fat_start..fat_start + 4].copy_from_slice(&0x0FFF_FF00u32.to_le_bytes());
            // Cluster 1: end-of-chain
            img[fat_start + 4..fat_start + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        }

        // Mark root cluster (cluster 2) as end-of-chain by default
        set_fat_entry(&mut img, cfg, cfg.root_cluster, 0x0FFF_FFFF);

        img
    }

    /// Write a FAT entry at the correct offset in all FAT copies.
    fn set_fat_entry(image: &mut [u8], cfg: &TestFat32Config, cluster: u32, value: u32) {
        let entry_offset = cluster as usize * 4;
        for fat_idx in 0..cfg.num_fats as usize {
            let fat_start = (cfg.reserved_sectors as usize
                + fat_idx * cfg.fat_size_sectors as usize)
                * cfg.bytes_per_sector as usize;
            let off = fat_start + entry_offset;
            if off + 4 <= image.len() {
                // Preserve upper 4 bits of existing value
                let existing = u32::from_le_bytes([
                    image[off],
                    image[off + 1],
                    image[off + 2],
                    image[off + 3],
                ]);
                let masked = (existing & 0xF000_0000) | (value & 0x0FFF_FFFF);
                image[off..off + 4].copy_from_slice(&masked.to_le_bytes());
            }
        }
    }

    /// Returns byte offset where a cluster's data begins.
    fn cluster_data_offset(cfg: &TestFat32Config, cluster: u32) -> usize {
        let data_start_sector = cfg.reserved_sectors as u32
            + cfg.num_fats as u32 * cfg.fat_size_sectors;
        let cluster_offset = (cluster - 2) * cfg.sectors_per_cluster as u32;
        ((data_start_sector + cluster_offset) as usize) * cfg.bytes_per_sector as usize
    }

    /// Write a 32-byte directory entry into a cluster's data area at `slot`.
    fn write_dir_entry(
        image: &mut [u8],
        cfg: &TestFat32Config,
        cluster: u32,
        slot: usize,
        entry: &[u8; 32],
    ) {
        let base = cluster_data_offset(cfg, cluster);
        let off = base + slot * 32;
        image[off..off + 32].copy_from_slice(entry);
    }

    /// Build a standard 8.3 directory entry.
    fn make_83_entry(
        name: &[u8; 8],
        ext: &[u8; 3],
        attr: u8,
        cluster_hi: u16,
        cluster_lo: u16,
        size: u32,
    ) -> [u8; 32] {
        let mut e = [0u8; 32];
        e[0..8].copy_from_slice(name);
        e[8..11].copy_from_slice(ext);
        e[11] = attr;
        e[20..22].copy_from_slice(&cluster_hi.to_le_bytes());
        e[26..28].copy_from_slice(&cluster_lo.to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// Write a single LFN entry (UCS-2 encoded) into a cluster.
    fn write_lfn_entry(
        image: &mut [u8],
        cfg: &TestFat32Config,
        cluster: u32,
        slot: usize,
        name_chars: &str,
        seq: u8,
        is_last: bool,
    ) {
        let base = cluster_data_offset(cfg, cluster);
        let off = base + slot * 32;
        let mut entry = [0xFFu8; 32];

        // Sequence number (0x40 bit if last)
        entry[0] = if is_last { seq | 0x40 } else { seq };
        // LFN attribute
        entry[11] = 0x0F;
        // Type (always 0 for LFN)
        entry[12] = 0x00;
        // Checksum (simplified — not validated by our parser)
        entry[13] = 0x00;
        // First cluster (always 0 for LFN)
        entry[26] = 0x00;
        entry[27] = 0x00;

        // Encode UCS-2 characters into the 3 LFN regions
        let chars: Vec<u16> = name_chars.encode_utf16().collect();
        let lfn_offsets: &[(usize, usize)] = &[
            (1, 5),   // chars 0-4 → bytes 1..11
            (14, 6),  // chars 5-10 → bytes 14..26
            (28, 2),  // chars 11-12 → bytes 28..32
        ];

        let mut char_idx = 0;
        for &(byte_start, count) in lfn_offsets {
            for i in 0..count {
                let byte_off = byte_start + i * 2;
                if char_idx < chars.len() {
                    let le = chars[char_idx].to_le_bytes();
                    entry[byte_off] = le[0];
                    entry[byte_off + 1] = le[1];
                    char_idx += 1;
                } else if char_idx == chars.len() {
                    // Null terminator
                    entry[byte_off] = 0x00;
                    entry[byte_off + 1] = 0x00;
                    char_idx += 1;
                }
                // else leave as 0xFFFF
            }
        }

        image[off..off + 32].copy_from_slice(&entry);
    }

    /// Helper: build a MockDevice from a config with a valid image.
    fn make_test_device(cfg: &TestFat32Config) -> MockDevice {
        let img = make_fat32_image(cfg);
        MockDevice::from_bytes(img)
    }

    // ── Phase 0 self-tests ─────────────────────────────────────────

    #[test]
    fn phase0_valid_boot_sector() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.bpb.bytes_per_sector, 512);
        assert_eq!(fs.bpb.sectors_per_cluster, 8);
        assert_eq!(fs.bpb.reserved_sectors, 32);
        assert_eq!(fs.bpb.num_fats, 2);
        assert_eq!(fs.bpb.root_cluster, 2);
        assert_eq!(fs.bpb.volume_label, "TEST");
    }

    #[test]
    fn phase0_fat_entry_roundtrip() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        set_fat_entry(&mut img, &cfg, 5, 0x0FFF_FFF8); // EOC
        set_fat_entry(&mut img, &cfg, 10, 11); // chain 10->11

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.read_fat_entry(5).unwrap(), 0x0FFF_FFF8);
        assert_eq!(fs.read_fat_entry(10).unwrap(), 11);
    }

    #[test]
    fn phase0_dir_entry_roundtrip() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        let entry = make_83_entry(b"HELLO   ", b"TXT", 0x20, 0, 3, 1024);
        write_dir_entry(&mut img, &cfg, 2, 0, &entry);
        // End marker
        let end = [0u8; 32];
        write_dir_entry(&mut img, &cfg, 2, 1, &end);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.read_dir_entries(2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].short_name, "HELLO.TXT");
        assert_eq!(entries[0].size, 1024);
    }

    #[test]
    fn phase0_cluster_offset_calculation() {
        let cfg = TestFat32Config::default();
        let expected = cluster_data_offset(&cfg, 2);
        // data_start = (32 + 2*16) * 512 = 64 * 512 = 32768
        assert_eq!(expected, 32768);

        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.cluster_offset(2), expected as u64);
    }

    #[test]
    fn phase0_lfn_roundtrip() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        // Write an LFN "Long Name.txt" across 1 LFN entry + 1 SFN entry
        write_lfn_entry(&mut img, &cfg, 2, 0, "Long Name.tx", 1, true);
        let sfn = make_83_entry(b"LONGNA~1", b"TXT", 0x20, 0, 3, 2048);
        write_dir_entry(&mut img, &cfg, 2, 1, &sfn);
        // End marker
        let end = [0u8; 32];
        write_dir_entry(&mut img, &cfg, 2, 2, &end);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.read_dir_entries(2).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].long_name.is_some());
        assert!(entries[0].long_name.as_ref().unwrap().starts_with("Long Name"));
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 1 — FAT32 Core Arithmetic
    // ════════════════════════════════════════════════════════════════

    // ── cluster_offset() ───────────────────────────────────────────

    #[test]
    fn phase1_cluster_offset_cluster_2() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // Cluster 2 = first data cluster
        // data_start = (32 + 2*16) = 64 sectors * 512 = 32768
        assert_eq!(fs.cluster_offset(2), 32768);
    }

    #[test]
    fn phase1_cluster_offset_cluster_3() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // Cluster 3 = 32768 + 8*512 = 32768 + 4096 = 36864
        assert_eq!(fs.cluster_offset(3), 36864);
    }

    #[test]
    fn phase1_cluster_offset_cluster_100() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // Cluster 100 = 32768 + (100-2)*8*512 = 32768 + 98*4096 = 32768 + 401408 = 434176
        assert_eq!(fs.cluster_offset(100), 434176);
    }

    #[test]
    fn phase1_cluster_offset_4096_byte_sectors() {
        let cfg = TestFat32Config {
            bytes_per_sector: 4096,
            sectors_per_cluster: 1,
            reserved_sectors: 4,
            num_fats: 2,
            fat_size_sectors: 2,
            total_sectors: 256,
            root_cluster: 2,
            volume_label: *b"TEST       ",
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // data_start = (4 + 2*2) = 8 sectors * 4096 = 32768
        assert_eq!(fs.cluster_offset(2), 32768);
        // Cluster 3 = 32768 + 1*4096 = 36864
        assert_eq!(fs.cluster_offset(3), 36864);
    }

    // ── read_fat_entry() ───────────────────────────────────────────

    #[test]
    fn phase1_read_fat_entry_free() {
        let cfg = TestFat32Config::default();
        let img = make_fat32_image(&cfg);
        // Cluster 5 should be free (0x00000000) by default
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.read_fat_entry(5).unwrap(), 0);
    }

    #[test]
    fn phase1_read_fat_entry_chain_next() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        set_fat_entry(&mut img, &cfg, 5, 6); // cluster 5 -> 6
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.read_fat_entry(5).unwrap(), 6);
    }

    #[test]
    fn phase1_read_fat_entry_eoc() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        set_fat_entry(&mut img, &cfg, 5, 0x0FFF_FFF8);
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.read_fat_entry(5).unwrap(), 0x0FFF_FFF8);
    }

    #[test]
    fn phase1_read_fat_entry_upper_4_bits_masked() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        // Write raw value with upper 4 bits set
        let entry_offset = 5usize * 4;
        let fat_start =
            cfg.reserved_sectors as usize * cfg.bytes_per_sector as usize;
        let off = fat_start + entry_offset;
        img[off..off + 4].copy_from_slice(&0xF000_0007u32.to_le_bytes());

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        // Upper 4 bits should be masked off
        assert_eq!(fs.read_fat_entry(5).unwrap(), 0x0000_0007);
    }

    // ── total_data_clusters() ──────────────────────────────────────

    #[test]
    fn phase1_total_data_clusters_default() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // data_start = 32 + 2*16 = 64 sectors
        // data_sectors = 2048 - 64 = 1984
        // clusters = 1984 / 8 = 248
        assert_eq!(fs.total_data_clusters(), 248);
    }

    #[test]
    fn phase1_total_data_clusters_small_volume() {
        let cfg = TestFat32Config {
            total_sectors: 512, // 256 KB
            ..TestFat32Config::default()
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // data_start = 64 sectors, data_sectors = 512 - 64 = 448
        // clusters = 448 / 8 = 56
        assert_eq!(fs.total_data_clusters(), 56);
    }

    #[test]
    fn phase1_total_data_clusters_large_cluster() {
        let cfg = TestFat32Config {
            sectors_per_cluster: 64, // 32 KB clusters
            total_sectors: 4096,
            ..TestFat32Config::default()
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        // data_start = 64 sectors, data_sectors = 4096 - 64 = 4032
        // clusters = 4032 / 64 = 63
        assert_eq!(fs.total_data_clusters(), 63);
    }

    // ── follow_chain() ─────────────────────────────────────────────

    #[test]
    fn phase1_follow_chain_single_cluster() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        set_fat_entry(&mut img, &cfg, 5, 0x0FFF_FFFF); // EOC
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.follow_chain(5).unwrap(), vec![5]);
    }

    #[test]
    fn phase1_follow_chain_three_clusters() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        set_fat_entry(&mut img, &cfg, 5, 6);
        set_fat_entry(&mut img, &cfg, 6, 7);
        set_fat_entry(&mut img, &cfg, 7, 0x0FFF_FFF8); // EOC
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.follow_chain(5).unwrap(), vec![5, 6, 7]);
    }

    #[test]
    fn phase1_follow_chain_non_contiguous() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        set_fat_entry(&mut img, &cfg, 5, 10);
        set_fat_entry(&mut img, &cfg, 10, 3);
        set_fat_entry(&mut img, &cfg, 3, 0x0FFF_FFF8);
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.follow_chain(5).unwrap(), vec![5, 10, 3]);
    }

    #[test]
    fn phase1_follow_chain_circular_detected() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        // Create a cycle: 5 -> 6 -> 7 -> 5
        set_fat_entry(&mut img, &cfg, 5, 6);
        set_fat_entry(&mut img, &cfg, 6, 7);
        set_fat_entry(&mut img, &cfg, 7, 5);
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let result = fs.follow_chain(5);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Circular"));
    }

    #[test]
    fn phase1_follow_chain_free_cluster_start() {
        let cfg = TestFat32Config::default();
        let img = make_fat32_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        // Cluster 0 is not in range 2..0x0FFFFFF8, so chain is empty
        let chain = fs.follow_chain(0).unwrap();
        assert!(chain.is_empty());
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 2 — Directory Entry Parsing
    // ════════════════════════════════════════════════════════════════

    // ── parse_83_entry() ───────────────────────────────────────────

    #[test]
    fn phase2_parse_83_regular_file() {
        let entry = make_83_entry(b"README  ", b"TXT", 0x20, 0, 5, 4096);
        let parsed = parse_83_entry(&entry);
        assert_eq!(parsed.short_name, "README.TXT");
        assert!(!parsed.is_dir);
        assert!(!parsed.is_deleted);
        assert_eq!(parsed.first_cluster, 5);
        assert_eq!(parsed.size, 4096);
    }

    #[test]
    fn phase2_parse_83_directory() {
        let entry = make_83_entry(b"SUBDIR  ", b"   ", 0x10, 0, 8, 0);
        let parsed = parse_83_entry(&entry);
        assert_eq!(parsed.short_name, "SUBDIR");
        assert!(parsed.is_dir);
        assert_eq!(parsed.first_cluster, 8);
        assert_eq!(parsed.size, 0);
    }

    #[test]
    fn phase2_parse_83_no_extension() {
        let entry = make_83_entry(b"MAKEFILE", b"   ", 0x20, 0, 3, 512);
        let parsed = parse_83_entry(&entry);
        assert_eq!(parsed.short_name, "MAKEFILE");
    }

    #[test]
    fn phase2_parse_83_high_cluster_number() {
        // Cluster = 0x0002_0003 (hi=2, lo=3)
        let entry = make_83_entry(b"BIG     ", b"DAT", 0x20, 2, 3, 999999);
        let parsed = parse_83_entry(&entry);
        assert_eq!(parsed.first_cluster, (2 << 16) | 3);
        assert_eq!(parsed.first_cluster, 0x0002_0003);
    }

    #[test]
    fn phase2_parse_83_volume_label() {
        let entry = make_83_entry(b"MYDRIVE ", b"   ", 0x08, 0, 0, 0);
        let parsed = parse_83_entry(&entry);
        // Volume labels have attr 0x08, not a directory
        assert!(!parsed.is_dir);
        assert_eq!(parsed.short_name, "MYDRIVE");
    }

    // ── parse_deleted_entry() ──────────────────────────────────────

    #[test]
    fn phase2_parse_deleted_regular() {
        let mut entry = make_83_entry(b"README  ", b"TXT", 0x20, 0, 5, 4096);
        entry[0] = 0xE5; // deleted marker
        let parsed = parse_deleted_entry(&entry);
        assert!(parsed.is_some());
        let d = parsed.unwrap();
        assert!(d.is_deleted);
        assert!(d.short_name.starts_with('?'));
        assert_eq!(d.first_cluster, 5);
        assert_eq!(d.size, 4096);
    }

    #[test]
    fn phase2_parse_deleted_skip_lfn() {
        let mut entry = [0u8; 32];
        entry[0] = 0xE5;
        entry[11] = 0x0F; // LFN attribute
        assert!(parse_deleted_entry(&entry).is_none());
    }

    #[test]
    fn phase2_parse_deleted_skip_volume_label() {
        let mut entry = make_83_entry(b"LABEL   ", b"   ", 0x08, 0, 0, 0);
        entry[0] = 0xE5;
        assert!(parse_deleted_entry(&entry).is_none());
    }

    #[test]
    fn phase2_parse_deleted_preserves_size_cluster() {
        let mut entry = make_83_entry(b"DATA    ", b"BIN", 0x20, 0, 42, 99999);
        entry[0] = 0xE5;
        let d = parse_deleted_entry(&entry).unwrap();
        assert_eq!(d.first_cluster, 42);
        assert_eq!(d.size, 99999);
    }

    // ── parse_lfn_part() ───────────────────────────────────────────

    #[test]
    fn phase2_parse_lfn_ascii() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        // We'll build an LFN entry in a buffer, then parse it directly
        write_lfn_entry(&mut img, &cfg, 2, 0, "Hello", 1, true);
        let base = cluster_data_offset(&cfg, 2);
        let entry = &img[base..base + 32];
        let result = parse_lfn_part(entry);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn phase2_parse_lfn_full_13_chars() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        write_lfn_entry(&mut img, &cfg, 2, 0, "1234567890abc", 1, true);
        let base = cluster_data_offset(&cfg, 2);
        let entry = &img[base..base + 32];
        let result = parse_lfn_part(entry);
        assert_eq!(result, "1234567890abc");
    }

    #[test]
    fn phase2_parse_lfn_null_terminated() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        // Write "Ab" — rest should be null/padded
        write_lfn_entry(&mut img, &cfg, 2, 0, "Ab", 1, true);
        let base = cluster_data_offset(&cfg, 2);
        let entry = &img[base..base + 32];
        let result = parse_lfn_part(entry);
        assert_eq!(result, "Ab");
    }

    // ── read_dir_entries() integrated ──────────────────────────────

    #[test]
    fn phase2_read_dir_single_83_file() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        let e = make_83_entry(b"FILE1   ", b"TXT", 0x20, 0, 3, 100);
        write_dir_entry(&mut img, &cfg, 2, 0, &e);
        write_dir_entry(&mut img, &cfg, 2, 1, &[0u8; 32]); // end marker

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.read_dir_entries(2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].short_name, "FILE1.TXT");
    }

    #[test]
    fn phase2_read_dir_file_with_lfn() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        // LFN entry
        write_lfn_entry(&mut img, &cfg, 2, 0, "My Document", 1, true);
        // SFN entry
        let sfn = make_83_entry(b"MYDOCU~1", b"TXT", 0x20, 0, 4, 5000);
        write_dir_entry(&mut img, &cfg, 2, 1, &sfn);
        write_dir_entry(&mut img, &cfg, 2, 2, &[0u8; 32]);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.read_dir_entries(2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].long_name.as_deref().unwrap(), "My Document");
        assert_eq!(entries[0].display_name(), "My Document");
    }

    #[test]
    fn phase2_read_dir_end_marker_stops_parsing() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        let e1 = make_83_entry(b"FIRST   ", b"TXT", 0x20, 0, 3, 10);
        write_dir_entry(&mut img, &cfg, 2, 0, &e1);
        // End marker at slot 1
        write_dir_entry(&mut img, &cfg, 2, 1, &[0u8; 32]);
        // This entry should NOT be parsed
        let e2 = make_83_entry(b"SECOND  ", b"TXT", 0x20, 0, 4, 20);
        write_dir_entry(&mut img, &cfg, 2, 2, &e2);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.read_dir_entries(2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].short_name, "FIRST.TXT");
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 3 — FileSystemOps Trait Methods
    // ════════════════════════════════════════════════════════════════

    // ── metadata() ─────────────────────────────────────────────────

    #[test]
    fn phase3_metadata_all_free() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let meta = fs.metadata().unwrap();
        assert_eq!(meta.fs_type, FsType::Fat32);
        assert_eq!(meta.total_clusters, 248);
        assert_eq!(meta.cluster_size, 8 * 512); // 4096
        // Clusters 0,1 are reserved FAT entries; cluster 2 = root (marked EOC)
        // Only cluster 2 is non-free out of 2..249
        // So free = 248 - 1 = 247 clusters
        assert!(meta.free_bytes > 0);
    }

    #[test]
    fn phase3_metadata_used_clusters() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        // Mark clusters 3,4,5 as used (chain: 3->4->5->EOC)
        set_fat_entry(&mut img, &cfg, 3, 4);
        set_fat_entry(&mut img, &cfg, 4, 5);
        set_fat_entry(&mut img, &cfg, 5, 0x0FFF_FFFF);
        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let meta = fs.metadata().unwrap();
        // 4 clusters used (root + 3,4,5)
        let cluster_size = 8u64 * 512;
        assert_eq!(meta.used_bytes, 4 * cluster_size);
    }

    #[test]
    fn phase3_metadata_volume_label_present() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let meta = fs.metadata().unwrap();
        assert_eq!(meta.volume_label.as_deref(), Some("TEST"));
    }

    #[test]
    fn phase3_metadata_volume_label_empty() {
        let cfg = TestFat32Config {
            volume_label: *b"           ", // all spaces
            ..TestFat32Config::default()
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let meta = fs.metadata().unwrap();
        assert!(meta.volume_label.is_none());
    }

    // ── validate() ─────────────────────────────────────────────────

    #[test]
    fn phase3_validate_healthy() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        assert_eq!(report.fs_type, FsType::Fat32);
        // Should be healthy (no Error or Critical issues)
        let errors: Vec<_> = report
            .issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Error | Severity::Critical))
            .collect();
        assert!(errors.is_empty(), "unexpected errors: {:?}", errors);
    }

    #[test]
    fn phase3_validate_fat_mismatch() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);
        // Corrupt FAT2 to differ from FAT1
        let fat2_start = (cfg.reserved_sectors as usize + cfg.fat_size_sectors as usize)
            * cfg.bytes_per_sector as usize;
        img[fat2_start + 8] = 0xAB; // tamper with cluster 2 entry in FAT2 only

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        assert!(
            report.issues.iter().any(|i| i.code == "FAT_MISMATCH"),
            "expected FAT_MISMATCH issue, got: {:?}",
            report.issues
        );
    }

    #[test]
    fn phase3_validate_invalid_bps() {
        let cfg = TestFat32Config {
            bytes_per_sector: 999, // invalid
            // Make total_sectors big enough to be valid
            total_sectors: 4096,
            ..TestFat32Config::default()
        };
        let mut img = make_fat32_image(&cfg);
        // Fix up the image — we need the mock device to have enough data
        // Override BPS in boot sector to 999
        img[11..13].copy_from_slice(&999u16.to_le_bytes());

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let issues = fs.validate_fat();
        assert!(issues.iter().any(|i| i.code == "INVALID_BPS"));
    }

    #[test]
    fn phase3_validate_invalid_root_cluster() {
        let cfg = TestFat32Config {
            root_cluster: 9999, // way out of bounds for a 1 MB volume
            ..TestFat32Config::default()
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let issues = fs.validate_fat();
        assert!(issues.iter().any(|i| i.code == "INVALID_ROOT"));
    }

    #[test]
    fn phase3_validate_no_volume_label() {
        let cfg = TestFat32Config {
            volume_label: *b"NO NAME    ",
            ..TestFat32Config::default()
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let report = fs.validate().unwrap();
        assert!(report.issues.iter().any(|i| i.code == "NO_LABEL"));
    }

    // ── validate_fat() internal ────────────────────────────────────

    #[test]
    fn phase3_validate_fat_consistent() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let issues = fs.validate_fat();
        // No FAT_MISMATCH expected
        assert!(
            !issues.iter().any(|i| i.code == "FAT_MISMATCH"),
            "FATs should be consistent"
        );
    }

    #[test]
    fn phase3_validate_fat_single_fat() {
        let cfg = TestFat32Config {
            num_fats: 1,
            ..TestFat32Config::default()
        };
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let issues = fs.validate_fat();
        // No mismatch possible with 1 FAT
        assert!(!issues.iter().any(|i| i.code == "FAT_MISMATCH"));
    }

    #[test]
    fn phase3_validate_fat_read_failure() {
        let cfg = TestFat32Config::default();
        // Inject bad sector in FAT1 region
        let fat1_sector = cfg.reserved_sectors as u64; // first FAT sector
        let dev = make_test_device(&cfg).with_bad_sector(fat1_sector);
        let fs = Fat32Fs::new(&dev).unwrap();
        let issues = fs.validate_fat();
        assert!(issues.iter().any(|i| i.code == "FAT_READ_FAIL"));
    }

    // ── list_dir() ─────────────────────────────────────────────────

    #[test]
    fn phase3_list_dir_root_with_files() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        let e1 = make_83_entry(b"FILE1   ", b"TXT", 0x20, 0, 3, 100);
        let e2 = make_83_entry(b"FILE2   ", b"DAT", 0x20, 0, 4, 200);
        write_dir_entry(&mut img, &cfg, 2, 0, &e1);
        write_dir_entry(&mut img, &cfg, 2, 1, &e2);
        write_dir_entry(&mut img, &cfg, 2, 2, &[0u8; 32]);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.list_dir(Path::new("/")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "FILE1.TXT");
        assert_eq!(entries[1].name, "FILE2.DAT");
    }

    #[test]
    fn phase3_list_dir_filters_deleted() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        let e1 = make_83_entry(b"ALIVE   ", b"TXT", 0x20, 0, 3, 100);
        let mut e2 = make_83_entry(b"DEAD    ", b"TXT", 0x20, 0, 4, 200);
        e2[0] = 0xE5; // deleted
        write_dir_entry(&mut img, &cfg, 2, 0, &e1);
        write_dir_entry(&mut img, &cfg, 2, 1, &e2);
        write_dir_entry(&mut img, &cfg, 2, 2, &[0u8; 32]);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let entries = fs.list_dir(Path::new("/")).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "ALIVE.TXT");
    }

    #[test]
    fn phase3_list_dir_subdirectory_not_found() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let fs = Fat32Fs::new(&dev).unwrap();
        let result = fs.list_dir(Path::new("/subdir"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    // ── scan_deleted() ─────────────────────────────────────────────

    #[test]
    fn phase3_scan_deleted_finds_valid() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        let mut e1 = make_83_entry(b"PHOTO   ", b"JPG", 0x20, 0, 5, 50000);
        e1[0] = 0xE5;
        let mut e2 = make_83_entry(b"NOTES   ", b"TXT", 0x20, 0, 8, 1024);
        e2[0] = 0xE5;
        write_dir_entry(&mut img, &cfg, 2, 0, &e1);
        write_dir_entry(&mut img, &cfg, 2, 1, &e2);
        write_dir_entry(&mut img, &cfg, 2, 2, &[0u8; 32]);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let deleted = fs.scan_deleted().unwrap();
        assert_eq!(deleted.len(), 2);
        assert!(deleted[0].original_name.is_some());
        assert_eq!(deleted[0].estimated_size, 50000);
        assert_eq!(deleted[1].estimated_size, 1024);
    }

    #[test]
    fn phase3_scan_deleted_skips_zero_size() {
        let cfg = TestFat32Config::default();
        let mut img = make_fat32_image(&cfg);

        // Deleted file with zero size — should be skipped
        let mut e1 = make_83_entry(b"EMPTY   ", b"TXT", 0x20, 0, 5, 0);
        e1[0] = 0xE5;
        // Deleted file with valid size
        let mut e2 = make_83_entry(b"VALID   ", b"TXT", 0x20, 0, 6, 100);
        e2[0] = 0xE5;
        write_dir_entry(&mut img, &cfg, 2, 0, &e1);
        write_dir_entry(&mut img, &cfg, 2, 1, &e2);
        write_dir_entry(&mut img, &cfg, 2, 2, &[0u8; 32]);

        let dev = MockDevice::from_bytes(img);
        let fs = Fat32Fs::new(&dev).unwrap();
        let deleted = fs.scan_deleted().unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].estimated_size, 100);
    }

    // ── repair() ───────────────────────────────────────────────────

    #[test]
    fn phase3_repair_requires_confirmation() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let mut fs = Fat32Fs::new(&dev).unwrap();
        let opts = RepairOptions {
            confirm_unsafe: false,
            backup_first: false,
            fix_fat: false,
            remove_bad_chains: false,
        };
        let result = fs.repair(&opts);
        assert!(matches!(result, Err(Error::ConfirmationRequired)));
    }

    #[test]
    fn phase3_repair_with_unsafe_returns_unimplemented() {
        let cfg = TestFat32Config::default();
        let dev = make_test_device(&cfg);
        let mut fs = Fat32Fs::new(&dev).unwrap();
        let opts = RepairOptions {
            confirm_unsafe: true,
            backup_first: false,
            fix_fat: false,
            remove_bad_chains: false,
        };
        let result = fs.repair(&opts);
        assert!(matches!(result, Err(Error::Unimplemented(_))));
    }

    // ════════════════════════════════════════════════════════════════
    // Legacy tests (preserved from original)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn test_fat32_invalid_boot_signature() {
        let dev = MockDevice::new(1024 * 1024);
        let result = Fat32Fs::new(&dev);
        assert!(result.is_err());
    }

    #[test]
    fn test_guess_file_type() {
        assert_eq!(guess_file_type("photo.jpg"), "JPEG Image");
        assert_eq!(guess_file_type("document.pdf"), "PDF Document");
        assert_eq!(guess_file_type("archive.zip"), "ZIP Archive");
        assert_eq!(guess_file_type("unknown.xyz"), "XYZ File");
    }
}
