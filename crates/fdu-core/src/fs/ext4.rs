//! Ext2/3/4 filesystem implementation for the Flash Drive UnCorruptor.
//!
//! Parses and validates ext-family filesystems, detecting all 7 Corrosion
//! corruption techniques:
//!
//! - **ExtSuperblockZero**: zeroed superblock magic
//! - **ExtSuperblockMangle**: corrupted superblock fields
//! - **ExtGroupDescCorrupt**: corrupted group descriptors
//! - **ExtBitmapDesync**: flipped bits in block bitmap
//! - **ExtJournalDirty**: journal in dirty state
//! - **ExtInodeCorrupt**: corrupted inode structures
//! - **ExtBackupSuperMismatch**: backup superblock mismatch

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};
use crate::models::*;
use std::path::Path;
use std::time::Instant;

// ── Constants ──────────────────────────────────────────────────────

/// Superblock always lives at byte offset 1024, regardless of block size.
const SUPERBLOCK_OFFSET: u64 = 1024;

/// Superblock is exactly 1024 bytes on disk.
const SUPERBLOCK_SIZE: usize = 1024;

/// Ext2/3/4 magic number (little-endian at superblock offset 56).
const EXT_MAGIC: u16 = 0xEF53;

/// Journal inode number (always inode 8 in ext3/4).
const JOURNAL_INODE: u32 = 8;

/// JBD2 journal superblock magic (big-endian).
const JOURNAL_MAGIC: u32 = 0xC03B3998;

// Feature compat flags
const COMPAT_HAS_JOURNAL: u32 = 0x0004;

// Feature incompat flags
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_FLEX_BG: u32 = 0x0200;

// Filesystem state values
const EXT_VALID_FS: u16 = 0x0001;
const EXT_ERROR_FS: u16 = 0x0002;

// ── Superblock ─────────────────────────────────────────────────────

/// Parsed ext2/3/4 superblock.
#[derive(Debug, Clone)]
struct ExtSuperblock {
    inodes_count: u32,
    blocks_count: u64,
    free_blocks_count: u64,
    free_inodes_count: u32,
    first_data_block: u32,
    log_block_size: u32,
    blocks_per_group: u32,
    inodes_per_group: u32,
    magic: u16,
    state: u16,
    inode_size: u16,
    feature_compat: u32,
    feature_incompat: u32,
    feature_ro_compat: u32,
    block_group_nr: u16,
    /// Volume label (up to 16 bytes, null-terminated).
    volume_name: String,
}

impl ExtSuperblock {
    /// Parse a superblock from a 1024-byte buffer.
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < SUPERBLOCK_SIZE {
            return Err(Error::FilesystemCorrupted(
                "Superblock buffer too small".into(),
            ));
        }

        let magic = u16::from_le_bytes([buf[56], buf[57]]);
        let state = u16::from_le_bytes([buf[58], buf[59]]);
        let inode_size = u16::from_le_bytes([buf[88], buf[89]]);

        let inodes_count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let blocks_count_lo = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let free_blocks_lo = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        let free_inodes_count = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let first_data_block = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        let log_block_size = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        let blocks_per_group = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let inodes_per_group = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);

        let feature_compat = u32::from_le_bytes([buf[92], buf[93], buf[94], buf[95]]);
        let feature_incompat = u32::from_le_bytes([buf[96], buf[97], buf[98], buf[99]]);
        let feature_ro_compat = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);

        let block_group_nr = u16::from_le_bytes([buf[104 + 22], buf[104 + 23]]);

        // Volume name at offset 120, 16 bytes, null-terminated
        let name_bytes = &buf[120..136];
        let volume_name = {
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        };

        // Handle 64-bit block counts if the INCOMPAT_64BIT flag is set
        let blocks_count;
        let free_blocks_count;
        if feature_incompat & INCOMPAT_64BIT != 0 {
            let blocks_count_hi = u32::from_le_bytes([buf[336], buf[337], buf[338], buf[339]]);
            let free_blocks_hi = u32::from_le_bytes([buf[340], buf[341], buf[342], buf[343]]);
            blocks_count = (blocks_count_hi as u64) << 32 | blocks_count_lo as u64;
            free_blocks_count = (free_blocks_hi as u64) << 32 | free_blocks_lo as u64;
        } else {
            blocks_count = blocks_count_lo as u64;
            free_blocks_count = free_blocks_lo as u64;
        }

        Ok(Self {
            inodes_count,
            blocks_count,
            free_blocks_count,
            free_inodes_count,
            first_data_block,
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            magic,
            state,
            inode_size: if inode_size == 0 { 128 } else { inode_size },
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            block_group_nr,
            volume_name,
        })
    }

    /// Block size in bytes: 1024 << log_block_size.
    fn block_size(&self) -> u64 {
        1024u64 << self.log_block_size
    }

    /// Number of block groups on the filesystem.
    fn group_count(&self) -> u32 {
        if self.blocks_per_group == 0 {
            return 0;
        }
        ((self.blocks_count + self.blocks_per_group as u64 - 1) / self.blocks_per_group as u64)
            as u32
    }

    /// Detect whether this is ext2, ext3, or ext4 based on feature flags.
    fn detect_fs_type(&self) -> FsType {
        let has_journal = self.feature_compat & COMPAT_HAS_JOURNAL != 0;
        let has_extents = self.feature_incompat & INCOMPAT_EXTENTS != 0;
        let has_flex_bg = self.feature_incompat & INCOMPAT_FLEX_BG != 0;
        let has_64bit = self.feature_incompat & INCOMPAT_64BIT != 0;

        if has_extents || has_flex_bg || has_64bit {
            FsType::Ext4
        } else if has_journal {
            FsType::Ext3
        } else {
            FsType::Ext2
        }
    }
}

// ── Group Descriptor ───────────────────────────────────────────────

/// Parsed block group descriptor (32-byte classic format).
#[derive(Debug, Clone)]
struct GroupDescriptor {
    block_bitmap: u64,
    inode_bitmap: u64,
    inode_table: u64,
    free_blocks_count: u32,
    free_inodes_count: u32,
}

impl GroupDescriptor {
    /// Parse a single group descriptor from a buffer slice (at least 32 bytes).
    fn parse(buf: &[u8], has_64bit: bool) -> Result<Self> {
        if buf.len() < 32 {
            return Err(Error::FilesystemCorrupted(
                "Group descriptor buffer too small".into(),
            ));
        }

        let block_bitmap_lo = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let inode_bitmap_lo = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let inode_table_lo = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let free_blocks_lo = u16::from_le_bytes([buf[12], buf[13]]);
        let free_inodes_lo = u16::from_le_bytes([buf[14], buf[15]]);

        let (block_bitmap, inode_bitmap, inode_table, free_blocks_count, free_inodes_count);

        if has_64bit && buf.len() >= 64 {
            let block_bitmap_hi = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);
            let inode_bitmap_hi = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
            let inode_table_hi = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]);
            let free_blocks_hi = u16::from_le_bytes([buf[44], buf[45]]);
            let free_inodes_hi = u16::from_le_bytes([buf[46], buf[47]]);

            block_bitmap = (block_bitmap_hi as u64) << 32 | block_bitmap_lo as u64;
            inode_bitmap = (inode_bitmap_hi as u64) << 32 | inode_bitmap_lo as u64;
            inode_table = (inode_table_hi as u64) << 32 | inode_table_lo as u64;
            free_blocks_count = (free_blocks_hi as u32) << 16 | free_blocks_lo as u32;
            free_inodes_count = (free_inodes_hi as u32) << 16 | free_inodes_lo as u32;
        } else {
            block_bitmap = block_bitmap_lo as u64;
            inode_bitmap = inode_bitmap_lo as u64;
            inode_table = inode_table_lo as u64;
            free_blocks_count = free_blocks_lo as u32;
            free_inodes_count = free_inodes_lo as u32;
        }

        Ok(Self {
            block_bitmap,
            inode_bitmap,
            inode_table,
            free_blocks_count,
            free_inodes_count,
        })
    }
}

// ── Inode ──────────────────────────────────────────────────────────

/// Parsed inode structure (key fields only).
#[derive(Debug, Clone)]
struct ExtInode {
    mode: u16,
    size: u64,
    links_count: u16,
    blocks: u32,
    flags: u32,
}

impl ExtInode {
    /// Parse an inode from a buffer (at least inode_size bytes).
    fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 128 {
            return Err(Error::FilesystemCorrupted(
                "Inode buffer too small".into(),
            ));
        }

        let mode = u16::from_le_bytes([buf[0], buf[1]]);
        let size_lo = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let links_count = u16::from_le_bytes([buf[26], buf[27]]);
        let blocks = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let flags = u32::from_le_bytes([buf[32], buf[33], buf[34], buf[35]]);

        // For regular files, size can be 64-bit (high 32 bits at offset 108)
        let size_hi = if buf.len() >= 112 {
            u32::from_le_bytes([buf[108], buf[109], buf[110], buf[111]])
        } else {
            0
        };
        let size = (size_hi as u64) << 32 | size_lo as u64;

        Ok(Self {
            mode,
            size,
            links_count,
            blocks,
            flags,
        })
    }

    /// Check whether this inode looks sane.
    fn is_sane(&self) -> bool {
        // An all-zero inode is unused (valid)
        if self.mode == 0 && self.size == 0 && self.links_count == 0 {
            return true;
        }

        // Mode should have a valid file type in the top 4 bits
        let file_type = self.mode >> 12;
        let valid_types = [0x1, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC]; // FIFO, char, dir, block, reg, symlink, socket
        if !valid_types.contains(&file_type) {
            return false;
        }

        // Link count should not be impossibly high
        if self.links_count > 65000 {
            return false;
        }

        true
    }
}

// ── Ext Filesystem ─────────────────────────────────────────────────

/// Ext2/3/4 filesystem backed by a device.
pub struct ExtFs<'a> {
    device: &'a dyn Device,
    sb: ExtSuperblock,
}

impl<'a> ExtFs<'a> {
    /// Parse an ext2/3/4 filesystem from a device.
    pub fn new(device: &'a dyn Device) -> Result<Self> {
        let sb_buf = device.read_exact_at(SUPERBLOCK_OFFSET, SUPERBLOCK_SIZE)?;
        let sb = ExtSuperblock::parse(&sb_buf)?;

        if sb.magic != EXT_MAGIC {
            return Err(Error::FilesystemCorrupted(format!(
                "Invalid ext superblock magic: {:#06x} (expected {:#06x})",
                sb.magic, EXT_MAGIC
            )));
        }

        // Basic sanity checks
        if sb.block_size() == 0 || sb.block_size() > 64 * 1024 {
            return Err(Error::FilesystemCorrupted(format!(
                "Invalid block size: {} (log_block_size={})",
                sb.block_size(),
                sb.log_block_size
            )));
        }

        if sb.blocks_per_group == 0 || sb.inodes_per_group == 0 {
            return Err(Error::FilesystemCorrupted(
                "Invalid superblock: zero blocks_per_group or inodes_per_group".into(),
            ));
        }

        Ok(Self { device, sb })
    }

    /// Byte offset of the group descriptor table.
    ///
    /// The GDT starts at the block immediately after the superblock. When
    /// block_size == 1024 the superblock occupies block 1 (bytes 1024..2047)
    /// so the GDT begins at block 2 (byte 2048). For larger block sizes the
    /// superblock fits inside block 0, so the GDT starts at block 1.
    fn gdt_offset(&self) -> u64 {
        let bs = self.sb.block_size();
        if bs == 1024 {
            // Superblock is in block 1; GDT starts at block 2
            2 * bs
        } else {
            // Superblock fits in block 0; GDT starts at block 1
            bs
        }
    }

    /// Size of a single group descriptor entry on disk.
    fn gd_size(&self) -> usize {
        if self.sb.feature_incompat & INCOMPAT_64BIT != 0 {
            64
        } else {
            32
        }
    }

    /// Read and parse all group descriptors.
    fn read_group_descriptors(&self) -> Result<Vec<GroupDescriptor>> {
        let group_count = self.sb.group_count();
        if group_count == 0 {
            return Ok(Vec::new());
        }

        let gd_size = self.gd_size();
        let total_size = group_count as usize * gd_size;
        let gdt_offset = self.gdt_offset();
        let has_64bit = self.sb.feature_incompat & INCOMPAT_64BIT != 0;

        let buf = self.device.read_exact_at(gdt_offset, total_size)?;

        let mut descriptors = Vec::with_capacity(group_count as usize);
        for i in 0..group_count as usize {
            let start = i * gd_size;
            let end = start + gd_size;
            let gd = GroupDescriptor::parse(&buf[start..end], has_64bit)?;
            descriptors.push(gd);
        }

        Ok(descriptors)
    }

    /// Validate the superblock fields for sanity.
    fn validate_superblock(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();
        let sb = &self.sb;

        // Check magic
        if sb.magic != EXT_MAGIC {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "SUPERBLOCK_MAGIC_INVALID".into(),
                message: format!(
                    "Superblock magic {:#06x} does not match expected {:#06x}",
                    sb.magic, EXT_MAGIC
                ),
                repairable: true,
            });
        }

        // Check block size is a valid power of two
        let bs = sb.block_size();
        if bs < 1024 || bs > 65536 || !bs.is_power_of_two() {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: format!(
                    "Invalid block size {} (log_block_size={})",
                    bs, sb.log_block_size
                ),
                repairable: false,
            });
        }

        // Check blocks_per_group > 0
        if sb.blocks_per_group == 0 {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: "blocks_per_group is zero".into(),
                repairable: false,
            });
        }

        // Check inodes_per_group > 0
        if sb.inodes_per_group == 0 {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: "inodes_per_group is zero".into(),
                repairable: false,
            });
        }

        // Check free blocks does not exceed total blocks
        if sb.free_blocks_count > sb.blocks_count {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: format!(
                    "Free blocks ({}) exceeds total blocks ({})",
                    sb.free_blocks_count, sb.blocks_count
                ),
                repairable: true,
            });
        }

        // Check free inodes does not exceed total inodes
        if sb.free_inodes_count > sb.inodes_count {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: format!(
                    "Free inodes ({}) exceeds total inodes ({})",
                    sb.free_inodes_count, sb.inodes_count
                ),
                repairable: true,
            });
        }

        // Check filesystem state
        if sb.state == EXT_ERROR_FS {
            issues.push(FsIssue {
                severity: Severity::Warning,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: "Filesystem state indicates errors were detected".into(),
                repairable: true,
            });
        }

        // Check inode size is sane
        if sb.inode_size < 128 || !sb.inode_size.is_power_of_two() {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "SUPERBLOCK_FIELD_INVALID".into(),
                message: format!("Invalid inode size: {}", sb.inode_size),
                repairable: false,
            });
        }

        issues
    }

    /// Validate group descriptors — check that pointers are within device bounds.
    fn validate_group_descriptors(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();
        let device_blocks = self.sb.blocks_count;

        let descriptors = match self.read_group_descriptors() {
            Ok(d) => d,
            Err(e) => {
                issues.push(FsIssue {
                    severity: Severity::Critical,
                    code: "GROUP_DESC_CORRUPT".into(),
                    message: format!("Failed to read group descriptors: {}", e),
                    repairable: false,
                });
                return issues;
            }
        };

        for (i, gd) in descriptors.iter().enumerate() {
            // Block bitmap must be within device
            if gd.block_bitmap >= device_blocks {
                issues.push(FsIssue {
                    severity: Severity::Error,
                    code: "GROUP_DESC_CORRUPT".into(),
                    message: format!(
                        "Group {} block_bitmap ({}) beyond device bounds ({})",
                        i, gd.block_bitmap, device_blocks
                    ),
                    repairable: false,
                });
            }

            // Inode bitmap must be within device
            if gd.inode_bitmap >= device_blocks {
                issues.push(FsIssue {
                    severity: Severity::Error,
                    code: "GROUP_DESC_CORRUPT".into(),
                    message: format!(
                        "Group {} inode_bitmap ({}) beyond device bounds ({})",
                        i, gd.inode_bitmap, device_blocks
                    ),
                    repairable: false,
                });
            }

            // Inode table must be within device
            if gd.inode_table >= device_blocks {
                issues.push(FsIssue {
                    severity: Severity::Error,
                    code: "GROUP_DESC_CORRUPT".into(),
                    message: format!(
                        "Group {} inode_table ({}) beyond device bounds ({})",
                        i, gd.inode_table, device_blocks
                    ),
                    repairable: false,
                });
            }

            // Free blocks count should not exceed blocks_per_group
            if gd.free_blocks_count > self.sb.blocks_per_group {
                issues.push(FsIssue {
                    severity: Severity::Warning,
                    code: "GROUP_DESC_CORRUPT".into(),
                    message: format!(
                        "Group {} free_blocks_count ({}) exceeds blocks_per_group ({})",
                        i, gd.free_blocks_count, self.sb.blocks_per_group
                    ),
                    repairable: true,
                });
            }

            // Free inodes count should not exceed inodes_per_group
            if gd.free_inodes_count > self.sb.inodes_per_group {
                issues.push(FsIssue {
                    severity: Severity::Warning,
                    code: "GROUP_DESC_CORRUPT".into(),
                    message: format!(
                        "Group {} free_inodes_count ({}) exceeds inodes_per_group ({})",
                        i, gd.free_inodes_count, self.sb.inodes_per_group
                    ),
                    repairable: true,
                });
            }
        }

        issues
    }

    /// Validate block bitmaps — check that free counts match actual free bits.
    fn validate_bitmaps(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        let descriptors = match self.read_group_descriptors() {
            Ok(d) => d,
            Err(_) => return issues, // Already reported in validate_group_descriptors
        };

        let bs = self.sb.block_size();

        for (i, gd) in descriptors.iter().enumerate() {
            let bitmap_offset = gd.block_bitmap * bs;

            // Read exactly one block for the bitmap
            let bitmap = match self.device.read_exact_at(bitmap_offset, bs as usize) {
                Ok(b) => b,
                Err(_) => continue, // Skip unreadable bitmaps
            };

            // Count free bits (0 = free) in the bitmap up to blocks_per_group
            let bits_to_check = self.sb.blocks_per_group as usize;
            let mut free_count = 0u32;
            for bit_idx in 0..bits_to_check {
                let byte_idx = bit_idx / 8;
                let bit_pos = bit_idx % 8;
                if byte_idx >= bitmap.len() {
                    break;
                }
                if bitmap[byte_idx] & (1 << bit_pos) == 0 {
                    free_count += 1;
                }
            }

            if free_count != gd.free_blocks_count {
                issues.push(FsIssue {
                    severity: Severity::Warning,
                    code: "BITMAP_MISMATCH".into(),
                    message: format!(
                        "Group {} block bitmap: counted {} free but descriptor says {}",
                        i, free_count, gd.free_blocks_count
                    ),
                    repairable: true,
                });
            }
        }

        issues
    }

    /// Validate a sample of inodes for structural sanity.
    fn validate_inodes(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        let descriptors = match self.read_group_descriptors() {
            Ok(d) => d,
            Err(_) => return issues,
        };

        let inode_size = self.sb.inode_size as usize;
        let bs = self.sb.block_size();

        // Sample the first group's inode table (first 16 inodes or fewer)
        if let Some(gd) = descriptors.first() {
            let inode_table_offset = gd.inode_table * bs;
            let sample_count = 16.min(self.sb.inodes_per_group as usize);
            let read_size = sample_count * inode_size;

            let buf = match self.device.read_exact_at(inode_table_offset, read_size) {
                Ok(b) => b,
                Err(_) => return issues,
            };

            for idx in 0..sample_count {
                let start = idx * inode_size;
                let end = start + inode_size.min(buf.len() - start);
                if end - start < 128 {
                    continue;
                }

                let inode = match ExtInode::parse(&buf[start..end]) {
                    Ok(i) => i,
                    Err(_) => {
                        issues.push(FsIssue {
                            severity: Severity::Error,
                            code: "INODE_CORRUPT".into(),
                            message: format!("Inode {} could not be parsed", idx + 1),
                            repairable: false,
                        });
                        continue;
                    }
                };

                if !inode.is_sane() {
                    issues.push(FsIssue {
                        severity: Severity::Error,
                        code: "INODE_CORRUPT".into(),
                        message: format!(
                            "Inode {} has invalid fields: mode={:#06x}, links={}, size={}",
                            idx + 1,
                            inode.mode,
                            inode.links_count,
                            inode.size
                        ),
                        repairable: false,
                    });
                }
            }
        }

        issues
    }

    /// Detect journal state (ext3/4 only).
    ///
    /// Reads the journal inode (inode 8) to find the journal's location,
    /// then reads the journal superblock and checks for dirty state.
    fn validate_journal(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();

        // Only check journal on ext3/4
        if self.sb.feature_compat & COMPAT_HAS_JOURNAL == 0 {
            return issues;
        }

        let descriptors = match self.read_group_descriptors() {
            Ok(d) => d,
            Err(_) => return issues,
        };

        let inode_size = self.sb.inode_size as usize;
        let bs = self.sb.block_size();

        // Journal inode (8) is in group 0, at position 7 (0-indexed) in the
        // inode table (inode numbers are 1-based).
        if let Some(gd) = descriptors.first() {
            let journal_inode_offset =
                gd.inode_table * bs + (JOURNAL_INODE as u64 - 1) * inode_size as u64;

            let inode_buf = match self.device.read_exact_at(journal_inode_offset, inode_size) {
                Ok(b) => b,
                Err(_) => {
                    issues.push(FsIssue {
                        severity: Severity::Warning,
                        code: "JOURNAL_DIRTY".into(),
                        message: "Could not read journal inode".into(),
                        repairable: false,
                    });
                    return issues;
                }
            };

            // Extract first direct block pointer from inode (offset 40 in the
            // inode, 4 bytes, little-endian) to locate the journal superblock.
            if inode_buf.len() >= 44 {
                let journal_block =
                    u32::from_le_bytes([inode_buf[40], inode_buf[41], inode_buf[42], inode_buf[43]]);

                if journal_block > 0 {
                    let journal_sb_offset = journal_block as u64 * bs;

                    if let Ok(jbuf) = self.device.read_exact_at(journal_sb_offset, bs as usize) {
                        // Journal magic is stored big-endian at offset 0
                        if jbuf.len() >= 4 {
                            let jmagic = u32::from_be_bytes([jbuf[0], jbuf[1], jbuf[2], jbuf[3]]);
                            if jmagic != JOURNAL_MAGIC {
                                issues.push(FsIssue {
                                    severity: Severity::Warning,
                                    code: "JOURNAL_DIRTY".into(),
                                    message: format!(
                                        "Journal magic {:#010x} does not match expected {:#010x}",
                                        jmagic, JOURNAL_MAGIC
                                    ),
                                    repairable: true,
                                });
                            }
                        }

                        // Check journal sequence/flags for dirty state.
                        // Bytes 28-31 (big-endian): journal flags.
                        // If sequence at offset 16 != sequence at offset 20, journal is dirty.
                        if jbuf.len() >= 24 {
                            let seq_start =
                                u32::from_be_bytes([jbuf[16], jbuf[17], jbuf[18], jbuf[19]]);
                            let seq_end =
                                u32::from_be_bytes([jbuf[20], jbuf[21], jbuf[22], jbuf[23]]);
                            if seq_start != seq_end {
                                issues.push(FsIssue {
                                    severity: Severity::Warning,
                                    code: "JOURNAL_DIRTY".into(),
                                    message: format!(
                                        "Journal has uncommitted transactions (seq {} != {})",
                                        seq_start, seq_end
                                    ),
                                    repairable: true,
                                });
                            }
                        }
                    }
                }
            }
        }

        issues
    }

    /// Compare the primary superblock with the first backup superblock.
    ///
    /// The first backup lives at the start of group 1 (block `blocks_per_group`
    /// for 1k blocks, or `blocks_per_group` for larger blocks).
    fn validate_backup_superblock(&self) -> Vec<FsIssue> {
        let mut issues = Vec::new();
        let bs = self.sb.block_size();

        // Backup superblock is at the first block of group 1
        let backup_block = self.sb.blocks_per_group as u64 + self.sb.first_data_block as u64;
        let backup_offset = backup_block * bs;

        let backup_buf = match self.device.read_exact_at(backup_offset, SUPERBLOCK_SIZE) {
            Ok(b) => b,
            Err(_) => {
                // Device may be too small for a backup superblock (single group)
                return issues;
            }
        };

        let backup = match ExtSuperblock::parse(&backup_buf) {
            Ok(sb) => sb,
            Err(_) => {
                issues.push(FsIssue {
                    severity: Severity::Error,
                    code: "BACKUP_SUPER_MISMATCH".into(),
                    message: "Backup superblock could not be parsed".into(),
                    repairable: true,
                });
                return issues;
            }
        };

        // Compare key fields
        if backup.magic != EXT_MAGIC {
            issues.push(FsIssue {
                severity: Severity::Critical,
                code: "BACKUP_SUPER_MISMATCH".into(),
                message: format!(
                    "Backup superblock magic {:#06x} does not match expected {:#06x}",
                    backup.magic, EXT_MAGIC
                ),
                repairable: true,
            });
        }

        if backup.blocks_count != self.sb.blocks_count {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "BACKUP_SUPER_MISMATCH".into(),
                message: format!(
                    "Backup blocks_count ({}) differs from primary ({})",
                    backup.blocks_count, self.sb.blocks_count
                ),
                repairable: true,
            });
        }

        if backup.inodes_count != self.sb.inodes_count {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "BACKUP_SUPER_MISMATCH".into(),
                message: format!(
                    "Backup inodes_count ({}) differs from primary ({})",
                    backup.inodes_count, self.sb.inodes_count
                ),
                repairable: true,
            });
        }

        if backup.blocks_per_group != self.sb.blocks_per_group {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "BACKUP_SUPER_MISMATCH".into(),
                message: format!(
                    "Backup blocks_per_group ({}) differs from primary ({})",
                    backup.blocks_per_group, self.sb.blocks_per_group
                ),
                repairable: true,
            });
        }

        if backup.inodes_per_group != self.sb.inodes_per_group {
            issues.push(FsIssue {
                severity: Severity::Error,
                code: "BACKUP_SUPER_MISMATCH".into(),
                message: format!(
                    "Backup inodes_per_group ({}) differs from primary ({})",
                    backup.inodes_per_group, self.sb.inodes_per_group
                ),
                repairable: true,
            });
        }

        issues
    }

    /// Read a directory block and extract directory entries.
    ///
    /// Ext directory entries are variable-length:
    ///   - inode (4 bytes)
    ///   - rec_len (2 bytes)
    ///   - name_len (1 byte)
    ///   - file_type (1 byte, if INCOMPAT_FILETYPE)
    ///   - name (name_len bytes)
    fn read_dir_block(&self, block: u64) -> Result<Vec<DirEntry>> {
        let bs = self.sb.block_size() as usize;
        let data = self.device.read_exact_at(block * self.sb.block_size(), bs)?;
        let has_filetype = self.sb.feature_incompat & INCOMPAT_FILETYPE != 0;

        let mut entries = Vec::new();
        let mut pos = 0usize;

        while pos + 8 <= data.len() {
            let inode = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let rec_len =
                u16::from_le_bytes([data[pos + 4], data[pos + 5]]) as usize;
            let name_len = data[pos + 6] as usize;
            let file_type_byte = if has_filetype { data[pos + 7] } else { 0 };

            if rec_len == 0 {
                break; // Avoid infinite loop
            }

            if inode != 0 && name_len > 0 && pos + 8 + name_len <= data.len() {
                let name = String::from_utf8_lossy(&data[pos + 8..pos + 8 + name_len]).to_string();

                // file_type: 1=regular, 2=directory, 7=symlink, etc.
                let is_dir = file_type_byte == 2;

                if name != "." && name != ".." {
                    entries.push(DirEntry {
                        name: name.clone(),
                        path: Path::new("/").join(&name),
                        is_dir,
                        size_bytes: 0, // Size requires reading the inode
                        created: None,
                        modified: None,
                    });
                }
            }

            pos += rec_len;
        }

        Ok(entries)
    }
}

// ── FileSystemOps Implementation ───────────────────────────────────

impl<'a> crate::fs::traits::FileSystemOps for ExtFs<'a> {
    fn metadata(&self) -> Result<FsMetadata> {
        let sb = &self.sb;
        let bs = sb.block_size();
        let total_bytes = sb.blocks_count * bs;
        let free_bytes = sb.free_blocks_count * bs;
        let used_bytes = total_bytes.saturating_sub(free_bytes);

        Ok(FsMetadata {
            fs_type: sb.detect_fs_type(),
            total_bytes,
            used_bytes,
            free_bytes,
            cluster_size: bs as u32,
            total_clusters: sb.blocks_count,
            volume_label: if sb.volume_name.is_empty() {
                None
            } else {
                Some(sb.volume_name.clone())
            },
        })
    }

    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntry>> {
        // For root directory, read the root inode (inode 2)
        if path == Path::new("/") || path == Path::new("") {
            let descriptors = self.read_group_descriptors()?;
            let gd = descriptors.first().ok_or_else(|| {
                Error::FilesystemCorrupted("No group descriptors found".into())
            })?;

            let bs = self.sb.block_size();
            let inode_size = self.sb.inode_size as usize;

            // Root inode is inode 2 (1-indexed), so offset 1 in the table
            let root_inode_offset = gd.inode_table * bs + inode_size as u64;
            let inode_buf = self.device.read_exact_at(root_inode_offset, inode_size)?;

            if inode_buf.len() < 44 {
                return Err(Error::FilesystemCorrupted(
                    "Root inode too small".into(),
                ));
            }

            // Get the first direct block pointer (offset 40 in the inode)
            let first_block = u32::from_le_bytes([
                inode_buf[40],
                inode_buf[41],
                inode_buf[42],
                inode_buf[43],
            ]);

            if first_block == 0 {
                return Ok(Vec::new());
            }

            return self.read_dir_block(first_block as u64);
        }

        Err(Error::Unimplemented(
            "Subdirectory listing not yet implemented for ext filesystems".into(),
        ))
    }

    fn validate(&self) -> Result<ValidationReport> {
        let start = Instant::now();
        let metadata = self.metadata()?;

        let mut issues = Vec::new();
        issues.extend(self.validate_superblock());
        issues.extend(self.validate_group_descriptors());
        issues.extend(self.validate_bitmaps());
        issues.extend(self.validate_inodes());
        issues.extend(self.validate_journal());
        issues.extend(self.validate_backup_superblock());

        Ok(ValidationReport {
            device_id: self.device.id().to_string(),
            fs_type: self.sb.detect_fs_type(),
            metadata,
            issues,
            scan_duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    fn scan_deleted(&self) -> Result<Vec<RecoverableFile>> {
        // Scan inode table for deleted inodes (mode != 0, links_count == 0,
        // dtime != 0). This is a simplified approach that checks group 0.
        let mut recoverable = Vec::new();

        let descriptors = self.read_group_descriptors()?;
        let inode_size = self.sb.inode_size as usize;
        let bs = self.sb.block_size();

        if let Some(gd) = descriptors.first() {
            let inode_table_offset = gd.inode_table * bs;
            let sample_count = 64.min(self.sb.inodes_per_group as usize);
            let read_size = sample_count * inode_size;

            let buf = match self.device.read_exact_at(inode_table_offset, read_size) {
                Ok(b) => b,
                Err(_) => return Ok(recoverable),
            };

            for idx in 0..sample_count {
                let start = idx * inode_size;
                if start + 128 > buf.len() {
                    break;
                }

                let inode = match ExtInode::parse(&buf[start..start + inode_size.min(buf.len() - start)]) {
                    Ok(i) => i,
                    Err(_) => continue,
                };

                // Deleted inode: has a valid file mode but zero link count and nonzero size
                let file_type = inode.mode >> 12;
                if file_type == 0x8 && inode.links_count == 0 && inode.size > 0 {
                    recoverable.push(RecoverableFile {
                        file_type: "Unknown".into(),
                        signature: Vec::new(),
                        offset: inode_table_offset + start as u64,
                        estimated_size: inode.size,
                        confidence: 0.4,
                        original_name: None,
                    });
                }
            }
        }

        Ok(recoverable)
    }

    fn repair(&mut self, options: &RepairOptions) -> Result<RepairReport> {
        if !options.confirm_unsafe {
            return Err(Error::ConfirmationRequired);
        }
        Err(Error::Unimplemented(
            "Ext filesystem repair not yet implemented".into(),
        ))
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests_helper {
    /// Configuration for building a minimal ext4 test image.
    pub struct Ext4Config {
        /// Total size in bytes (must be large enough for at least 2 groups).
        pub total_size: usize,
        pub block_size: u32,
        pub blocks_per_group: u32,
        pub inodes_per_group: u32,
        pub inode_size: u16,
    }

    pub fn default_config() -> Ext4Config {
        // 2 MB image, 1024-byte blocks, 1024 blocks/group = 2 groups
        Ext4Config {
            total_size: 2 * 1024 * 1024,
            block_size: 1024,
            blocks_per_group: 1024,
            inodes_per_group: 128,
            inode_size: 256,
        }
    }

    /// Build a minimal ext4 image with valid superblock, group descriptors,
    /// block bitmaps, inode table, and a backup superblock.
    pub fn make_image(cfg: &Ext4Config) -> Vec<u8> {
        let mut img = vec![0u8; cfg.total_size];
        let log_block_size = match cfg.block_size {
            1024 => 0u32,
            2048 => 1,
            4096 => 2,
            _ => 0,
        };

        let total_blocks = cfg.total_size as u64 / cfg.block_size as u64;
        let group_count =
            ((total_blocks + cfg.blocks_per_group as u64 - 1) / cfg.blocks_per_group as u64) as u32;

        // For 1024-byte blocks: first_data_block = 1, superblock at byte 1024
        let first_data_block: u32 = if cfg.block_size == 1024 { 1 } else { 0 };

        // Write primary superblock at offset 1024
        write_superblock(
            &mut img,
            1024,
            cfg,
            log_block_size,
            total_blocks,
            first_data_block,
        );

        // GDT starts at block after superblock
        let gdt_block = if cfg.block_size == 1024 { 2u64 } else { 1u64 };
        let gdt_offset = gdt_block * cfg.block_size as u64;

        // For each group, set up group descriptor, block bitmap, and inode table
        for g in 0..group_count {
            let group_start_block = first_data_block as u64 + g as u64 * cfg.blocks_per_group as u64;

            // Block bitmap: place after GDT (simple layout for group 0)
            // For group 0: bitmap at block (gdt_block + 1)
            // For group 1: bitmap at block (group_start_block + 1) — after backup SB + GDT
            let bitmap_block;
            let inode_bitmap_block;
            let inode_table_block;

            if g == 0 {
                // Group 0: GDT at block 2 (1k blocks), so bitmap at block 3
                bitmap_block = gdt_block + 1;
                inode_bitmap_block = bitmap_block + 1;
                inode_table_block = inode_bitmap_block + 1;
            } else {
                // Group 1+: backup superblock at group_start_block, then GDT, then bitmap
                bitmap_block = group_start_block + 2;
                inode_bitmap_block = bitmap_block + 1;
                inode_table_block = inode_bitmap_block + 1;
            }

            // Write group descriptor
            let gd_offset = gdt_offset as usize + g as usize * 32;
            if gd_offset + 32 <= img.len() {
                // block_bitmap
                write_le32(&mut img, gd_offset, bitmap_block as u32);
                // inode_bitmap
                write_le32(&mut img, gd_offset + 4, inode_bitmap_block as u32);
                // inode_table
                write_le32(&mut img, gd_offset + 8, inode_table_block as u32);
                // free_blocks_count (u16)
                let free_blocks = cfg.blocks_per_group.min(1024) as u16;
                write_le16(&mut img, gd_offset + 12, free_blocks);
                // free_inodes_count (u16)
                write_le16(&mut img, gd_offset + 14, cfg.inodes_per_group as u16);
            }

            // Initialize block bitmap — mark all as free (0 bits)
            // Already zeroed, which means "all free"
            // But set the count to match: count 0-bits in blocks_per_group bits
            // Since bitmap is all zeros, free_count == blocks_per_group
        }

        // Write backup superblock at start of group 1
        let backup_block = cfg.blocks_per_group as u64 + first_data_block as u64;
        let backup_offset = backup_block * cfg.block_size as u64;
        if backup_offset as usize + 1024 <= img.len() {
            write_superblock(
                &mut img,
                backup_offset as usize,
                cfg,
                log_block_size,
                total_blocks,
                first_data_block,
            );
        }

        // Write a valid root inode (inode 2) in group 0's inode table
        // inode_table is at inode_table_block for group 0
        let inode_table_block = gdt_block + 3; // bitmap + inode_bitmap + 1
        let inode_table_offset = inode_table_block * cfg.block_size as u64;
        let root_inode_offset = inode_table_offset as usize + cfg.inode_size as usize; // inode 2, 0-indexed = 1
        if root_inode_offset + 128 <= img.len() {
            // mode: directory (0x4000) + rwxr-xr-x (0o755)
            write_le16(&mut img, root_inode_offset, 0x41ED);
            // links_count at offset 26
            write_le16(&mut img, root_inode_offset + 26, 2);
        }

        img
    }

    fn write_superblock(
        img: &mut [u8],
        offset: usize,
        cfg: &Ext4Config,
        log_block_size: u32,
        total_blocks: u64,
        first_data_block: u32,
    ) {
        if offset + 1024 > img.len() {
            return;
        }

        let total_inodes = cfg.inodes_per_group
            * ((total_blocks + cfg.blocks_per_group as u64 - 1) / cfg.blocks_per_group as u64)
                as u32;

        // s_inodes_count (offset 0)
        write_le32(img, offset, total_inodes);
        // s_blocks_count_lo (offset 4)
        write_le32(img, offset + 4, total_blocks as u32);
        // s_free_blocks_count_lo (offset 12)
        write_le32(img, offset + 12, (total_blocks - 10) as u32);
        // s_free_inodes_count (offset 16)
        write_le32(img, offset + 16, total_inodes - 2);
        // s_first_data_block (offset 20)
        write_le32(img, offset + 20, first_data_block);
        // s_log_block_size (offset 24)
        write_le32(img, offset + 24, log_block_size);
        // s_blocks_per_group (offset 32)
        write_le32(img, offset + 32, cfg.blocks_per_group);
        // s_inodes_per_group (offset 40)
        write_le32(img, offset + 40, cfg.inodes_per_group);
        // s_magic (offset 56)
        write_le16(img, offset + 56, 0xEF53);
        // s_state (offset 58)
        write_le16(img, offset + 58, 0x0001); // EXT_VALID_FS
        // s_inode_size (offset 88)
        write_le16(img, offset + 88, cfg.inode_size);
        // s_feature_compat (offset 92) — has_journal
        write_le32(img, offset + 92, 0x0004);
        // s_feature_incompat (offset 96) — FILETYPE | EXTENTS
        write_le32(img, offset + 96, 0x0042);
        // s_feature_ro_compat (offset 100)
        write_le32(img, offset + 100, 0);
        // Volume name at offset 120 — "test_ext4"
        let label = b"test_ext4";
        img[offset + 120..offset + 120 + label.len()].copy_from_slice(label);
    }

    fn write_le32(buf: &mut [u8], offset: usize, val: u32) {
        let bytes = val.to_le_bytes();
        buf[offset..offset + 4].copy_from_slice(&bytes);
    }

    fn write_le16(buf: &mut [u8], offset: usize, val: u16) {
        let bytes = val.to_le_bytes();
        buf[offset..offset + 2].copy_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;
    use crate::fs::traits::FileSystemOps;

    // ════════════════════════════════════════════════════════════════
    // Valid ext4 image parsing
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn valid_ext4_parse_and_metadata() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).expect("Should parse valid ext4 image");

        let meta = fs.metadata().expect("Should return metadata");
        assert_eq!(meta.fs_type, FsType::Ext4);
        assert_eq!(meta.cluster_size, 1024);
        assert!(meta.total_bytes > 0);
        assert!(meta.volume_label.as_deref() == Some("test_ext4"));
    }

    #[test]
    fn valid_ext4_validate_no_critical_issues() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).expect("Should parse valid ext4 image");

        let report = fs.validate().expect("Validation should succeed");
        let critical = report
            .issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Critical | Severity::Error))
            .filter(|i| {
                i.code == "SUPERBLOCK_MAGIC_INVALID"
                    || i.code == "SUPERBLOCK_FIELD_INVALID"
                    || i.code == "GROUP_DESC_CORRUPT"
                    || i.code == "INODE_CORRUPT"
            })
            .collect::<Vec<_>>();
        assert!(
            critical.is_empty(),
            "Valid image should have no critical structural issues, got: {:?}",
            critical
        );
    }

    #[test]
    fn valid_ext4_detect_fs_type() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        // Our test image sets EXTENTS (0x0040) + FILETYPE (0x0002) = ext4
        assert_eq!(fs.sb.detect_fs_type(), FsType::Ext4);
    }

    #[test]
    fn valid_ext4_list_root_dir() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        // Root dir listing should succeed (may be empty)
        let result = fs.list_dir(Path::new("/"));
        assert!(result.is_ok());
    }

    #[test]
    fn valid_ext4_scan_deleted() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        let deleted = fs.scan_deleted().expect("scan_deleted should succeed");
        // Fresh image has no deleted files
        assert!(deleted.is_empty());
    }

    // ════════════════════════════════════════════════════════════════
    // ExtSuperblockZero — zeroed superblock magic
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn zeroed_superblock_rejected() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        // Zero out the magic bytes at superblock offset 56-57 (absolute 1024+56)
        img[1024 + 56] = 0x00;
        img[1024 + 57] = 0x00;

        let dev = MockDevice::from_bytes(img);
        let result = ExtFs::new(&dev);
        assert!(result.is_err(), "Zeroed magic should cause parse failure");
    }

    #[test]
    fn zeroed_superblock_detected_by_validate() {
        // Build an image where the magic is wrong but we construct ExtFs
        // manually to test validate() detection.
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        // Parse first, then corrupt the magic (validate re-reads from sb struct)
        let dev = MockDevice::from_bytes(img.clone());
        let mut fs = ExtFs::new(&dev).unwrap();

        // Mutate the in-memory superblock to simulate a zeroed magic
        fs.sb.magic = 0x0000;

        let report = fs.validate().unwrap();
        let magic_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "SUPERBLOCK_MAGIC_INVALID")
            .collect();
        assert!(
            !magic_issues.is_empty(),
            "Should detect zeroed superblock magic"
        );
    }

    // ════════════════════════════════════════════════════════════════
    // ExtSuperblockMangle — corrupted superblock fields
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn mangled_blocks_per_group_detected() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        // Corrupt blocks_per_group (offset 32-35 from superblock start = 1024+32)
        // Set to zero
        img[1024 + 32] = 0;
        img[1024 + 33] = 0;
        img[1024 + 34] = 0;
        img[1024 + 35] = 0;

        let dev = MockDevice::from_bytes(img);
        let result = ExtFs::new(&dev);
        assert!(
            result.is_err(),
            "Zero blocks_per_group should cause parse failure"
        );
    }

    #[test]
    fn mangled_free_blocks_exceeds_total() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let mut fs = ExtFs::new(&dev).unwrap();

        // Set free_blocks higher than total
        fs.sb.free_blocks_count = fs.sb.blocks_count + 1000;

        let report = fs.validate().unwrap();
        let field_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "SUPERBLOCK_FIELD_INVALID")
            .collect();
        assert!(
            !field_issues.is_empty(),
            "Should detect free_blocks > total_blocks"
        );
    }

    #[test]
    fn mangled_free_inodes_exceeds_total() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let mut fs = ExtFs::new(&dev).unwrap();

        fs.sb.free_inodes_count = fs.sb.inodes_count + 500;

        let report = fs.validate().unwrap();
        let field_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "SUPERBLOCK_FIELD_INVALID")
            .collect();
        assert!(
            !field_issues.is_empty(),
            "Should detect free_inodes > total_inodes"
        );
    }

    #[test]
    fn mangled_inode_size_detected() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let mut fs = ExtFs::new(&dev).unwrap();

        // Set inode size to non-power-of-two
        fs.sb.inode_size = 100;

        let report = fs.validate().unwrap();
        let field_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "SUPERBLOCK_FIELD_INVALID" && i.message.contains("inode size"))
            .collect();
        assert!(
            !field_issues.is_empty(),
            "Should detect invalid inode size"
        );
    }

    // ════════════════════════════════════════════════════════════════
    // ExtBackupSuperMismatch — backup superblock mismatch
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn backup_superblock_magic_mismatch() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        // Backup superblock is at block (blocks_per_group + first_data_block)
        // For 1k blocks: first_data_block=1, so backup at block 1025 = byte 1025*1024
        let backup_offset = (cfg.blocks_per_group as usize + 1) * cfg.block_size as usize;

        // Corrupt the backup magic (offset 56-57 within the backup superblock)
        if backup_offset + 1024 <= img.len() {
            img[backup_offset + 56] = 0xDE;
            img[backup_offset + 57] = 0xAD;
        }

        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap(); // Primary is still valid

        let report = fs.validate().unwrap();
        let backup_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "BACKUP_SUPER_MISMATCH")
            .collect();
        assert!(
            !backup_issues.is_empty(),
            "Should detect backup superblock magic mismatch"
        );
    }

    #[test]
    fn backup_superblock_blocks_count_mismatch() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let backup_offset = (cfg.blocks_per_group as usize + 1) * cfg.block_size as usize;

        // Corrupt the backup blocks_count (offset 4-7 within the backup superblock)
        if backup_offset + 1024 <= img.len() {
            img[backup_offset + 4] = 0xFF;
            img[backup_offset + 5] = 0xFF;
            img[backup_offset + 6] = 0x00;
            img[backup_offset + 7] = 0x00;
        }

        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        let report = fs.validate().unwrap();
        let backup_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "BACKUP_SUPER_MISMATCH" && i.message.contains("blocks_count"))
            .collect();
        assert!(
            !backup_issues.is_empty(),
            "Should detect backup blocks_count mismatch"
        );
    }

    // ════════════════════════════════════════════════════════════════
    // ExtGroupDescCorrupt — corrupted group descriptors
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn group_desc_block_bitmap_out_of_bounds() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        // GDT is at block 2 (byte 2048 for 1k blocks)
        // Group 0 descriptor starts at byte 2048
        // block_bitmap is at offset 0-3 in the descriptor
        let gdt_offset = 2 * cfg.block_size as usize;

        // Set block_bitmap to an impossibly large value
        let bad_val = 0xFFFFFFFFu32;
        let bytes = bad_val.to_le_bytes();
        img[gdt_offset..gdt_offset + 4].copy_from_slice(&bytes);

        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        let report = fs.validate().unwrap();
        let gd_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "GROUP_DESC_CORRUPT" && i.message.contains("block_bitmap"))
            .collect();
        assert!(
            !gd_issues.is_empty(),
            "Should detect group descriptor block_bitmap out of bounds"
        );
    }

    #[test]
    fn group_desc_inode_table_out_of_bounds() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let gdt_offset = 2 * cfg.block_size as usize;

        // Set inode_table (offset 8-11) to impossibly large value
        let bad_val = 0xFFFFFFFFu32;
        let bytes = bad_val.to_le_bytes();
        img[gdt_offset + 8..gdt_offset + 12].copy_from_slice(&bytes);

        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        let report = fs.validate().unwrap();
        let gd_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| i.code == "GROUP_DESC_CORRUPT" && i.message.contains("inode_table"))
            .collect();
        assert!(
            !gd_issues.is_empty(),
            "Should detect group descriptor inode_table out of bounds"
        );
    }

    #[test]
    fn group_desc_free_blocks_exceeds_per_group() {
        let cfg = tests_helper::default_config();
        let mut img = tests_helper::make_image(&cfg);

        let gdt_offset = 2 * cfg.block_size as usize;

        // Set free_blocks_count (offset 12-13, u16) to exceed blocks_per_group
        let bad_count = (cfg.blocks_per_group + 100) as u16;
        let bytes = bad_count.to_le_bytes();
        img[gdt_offset + 12..gdt_offset + 14].copy_from_slice(&bytes);

        let dev = MockDevice::from_bytes(img);
        let fs = ExtFs::new(&dev).unwrap();

        let report = fs.validate().unwrap();
        let gd_issues: Vec<_> = report
            .issues
            .iter()
            .filter(|i| {
                i.code == "GROUP_DESC_CORRUPT" && i.message.contains("free_blocks_count")
            })
            .collect();
        assert!(
            !gd_issues.is_empty(),
            "Should detect group descriptor free_blocks exceeding blocks_per_group"
        );
    }

    // ════════════════════════════════════════════════════════════════
    // Filesystem type detection
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn detect_ext2_no_journal_no_extents() {
        let mut sb = ExtSuperblock {
            inodes_count: 100,
            blocks_count: 1000,
            free_blocks_count: 500,
            free_inodes_count: 50,
            first_data_block: 1,
            log_block_size: 0,
            blocks_per_group: 1024,
            inodes_per_group: 128,
            magic: EXT_MAGIC,
            state: EXT_VALID_FS,
            inode_size: 128,
            feature_compat: 0,
            feature_incompat: INCOMPAT_FILETYPE,
            feature_ro_compat: 0,
            block_group_nr: 0,
            volume_name: String::new(),
        };

        assert_eq!(sb.detect_fs_type(), FsType::Ext2);

        // Add journal -> ext3
        sb.feature_compat = COMPAT_HAS_JOURNAL;
        assert_eq!(sb.detect_fs_type(), FsType::Ext3);

        // Add extents -> ext4
        sb.feature_incompat |= INCOMPAT_EXTENTS;
        assert_eq!(sb.detect_fs_type(), FsType::Ext4);
    }

    // ════════════════════════════════════════════════════════════════
    // Superblock parsing edge cases
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn superblock_parse_too_small_buffer() {
        let buf = vec![0u8; 512]; // Too small
        let result = ExtSuperblock::parse(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn inode_sanity_checks() {
        // Valid regular file inode
        let valid = ExtInode {
            mode: 0x8180, // regular file, rw-------
            size: 4096,
            links_count: 1,
            blocks: 8,
            flags: 0,
        };
        assert!(valid.is_sane());

        // Valid directory inode
        let dir = ExtInode {
            mode: 0x41ED, // directory, rwxr-xr-x
            size: 1024,
            links_count: 2,
            blocks: 2,
            flags: 0,
        };
        assert!(dir.is_sane());

        // Unused (all zeros) — valid
        let unused = ExtInode {
            mode: 0,
            size: 0,
            links_count: 0,
            blocks: 0,
            flags: 0,
        };
        assert!(unused.is_sane());

        // Invalid file type bits
        let bad_type = ExtInode {
            mode: 0x3000, // invalid type
            size: 100,
            links_count: 1,
            blocks: 1,
            flags: 0,
        };
        assert!(!bad_type.is_sane());

        // Impossibly high link count
        let bad_links = ExtInode {
            mode: 0x8180,
            size: 100,
            links_count: 65001,
            blocks: 1,
            flags: 0,
        };
        assert!(!bad_links.is_sane());
    }

    #[test]
    fn repair_requires_confirmation() {
        let cfg = tests_helper::default_config();
        let img = tests_helper::make_image(&cfg);
        let dev = MockDevice::from_bytes(img);
        let mut fs = ExtFs::new(&dev).unwrap();

        let opts = RepairOptions {
            confirm_unsafe: false,
            backup_first: false,
            fix_fat: false,
            remove_bad_chains: false,
        };
        let result = fs.repair(&opts);
        assert!(matches!(result, Err(Error::ConfirmationRequired)));
    }
}
