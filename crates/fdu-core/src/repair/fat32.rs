//! FAT32 repair operations for the Flash Drive UnCorruptor.
//!
//! Implements concrete repairs for FAT32 corruption, including techniques
//! used by the Corrosion attack framework: boot signature wiping, FAT
//! desynchronisation, orphan/circular/cross-linked cluster chains, and
//! FSInfo invalidation.

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};
use crate::models::{RepairOptions, RepairReport};
use std::collections::{HashMap, HashSet};

// ── FAT32 constants ────────────────────────────────────────────────────

const BOOT_SIG_OFFSET: u64 = 510;
const BOOT_SIG: [u8; 2] = [0x55, 0xAA];
const FAT_EOC: u32 = 0x0FFF_FFFF;
const FAT_FREE: u32 = 0x0000_0000;
const FSINFO_LEAD_SIG: u32 = 0x4161_5252;
const FSINFO_STRUC_SIG: u32 = 0x6141_7272;
const FSINFO_TRAIL_SIG: u32 = 0xAA55_0000;

// ── BPB (re-exported for repair callers) ───────────────────────────────

/// Parsed FAT32 BIOS Parameter Block — the subset of fields needed for
/// repair operations.
#[derive(Debug, Clone)]
pub struct Fat32Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub fat_size_sectors: u32,
    pub root_cluster: u32,
    pub total_sectors_32: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
}

impl Fat32Bpb {
    /// Parse the BPB from a device by reading sector 0.
    pub fn parse(device: &dyn Device) -> Result<Self> {
        let boot = device.read_exact_at(0, 512)?;
        Ok(Self {
            bytes_per_sector: u16::from_le_bytes([boot[11], boot[12]]),
            sectors_per_cluster: boot[13],
            reserved_sectors: u16::from_le_bytes([boot[14], boot[15]]),
            num_fats: boot[16],
            fat_size_sectors: u32::from_le_bytes([boot[36], boot[37], boot[38], boot[39]]),
            root_cluster: u32::from_le_bytes([boot[44], boot[45], boot[46], boot[47]]),
            total_sectors_32: u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]),
            fs_info_sector: u16::from_le_bytes([boot[48], boot[49]]),
            backup_boot_sector: u16::from_le_bytes([boot[50], boot[51]]),
        })
    }

    /// Byte offset of the start of FAT `fat_index` (0-based).
    fn fat_offset(&self, fat_index: u32) -> u64 {
        (self.reserved_sectors as u64 + fat_index as u64 * self.fat_size_sectors as u64)
            * self.bytes_per_sector as u64
    }

    /// Size of a single FAT in bytes.
    fn fat_size_bytes(&self) -> u64 {
        self.fat_size_sectors as u64 * self.bytes_per_sector as u64
    }

    /// Total number of data clusters on the volume.
    fn total_data_clusters(&self) -> u32 {
        let data_start_sector = self.reserved_sectors as u64
            + self.num_fats as u64 * self.fat_size_sectors as u64;
        let data_sectors = (self.total_sectors_32 as u64).saturating_sub(data_start_sector);
        (data_sectors / self.sectors_per_cluster as u64) as u32
    }

    /// Byte offset where cluster `cluster` begins on the data region.
    fn cluster_offset(&self, cluster: u32) -> u64 {
        let data_start_sector = self.reserved_sectors as u64
            + self.num_fats as u64 * self.fat_size_sectors as u64;
        let cluster_offset_sectors = (cluster as u64 - 2) * self.sectors_per_cluster as u64;
        (data_start_sector + cluster_offset_sectors) * self.bytes_per_sector as u64
    }

    /// Cluster size in bytes.
    fn cluster_size(&self) -> usize {
        self.sectors_per_cluster as usize * self.bytes_per_sector as usize
    }
}

// ── Helpers: FAT entry I/O ─────────────────────────────────────────────

/// Read the FAT entry for `cluster` from FAT1.
pub fn read_fat_entry(device: &dyn Device, bpb: &Fat32Bpb, cluster: u32) -> Result<u32> {
    let fat_start = bpb.fat_offset(0);
    let entry_offset = fat_start + cluster as u64 * 4;
    let data = device.read_exact_at(entry_offset, 4)?;
    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    Ok(raw & 0x0FFF_FFFF)
}

/// Write a FAT entry for `cluster` into *all* FATs on the volume.
pub fn write_fat_entry(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
    cluster: u32,
    value: u32,
) -> Result<()> {
    // Preserve the upper 4 bits of the existing entry.
    let fat_start = bpb.fat_offset(0);
    let entry_offset_in_fat = cluster as u64 * 4;
    let existing = device.read_exact_at(fat_start + entry_offset_in_fat, 4)?;
    let old = u32::from_le_bytes([existing[0], existing[1], existing[2], existing[3]]);
    let new_val = (old & 0xF000_0000) | (value & 0x0FFF_FFFF);
    let bytes = new_val.to_le_bytes();

    for fat_idx in 0..bpb.num_fats as u32 {
        let offset = bpb.fat_offset(fat_idx) + entry_offset_in_fat;
        device.write_at(offset, &bytes)?;
    }
    Ok(())
}

// ── 1. Boot signature repair ──────────────────────────────────────────

/// Repair a missing or invalid 0x55AA boot signature at bytes 510-511
/// of sector 0.  Tries the backup boot sector first; falls back to a
/// direct write.
pub fn repair_boot_signature(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();

    let boot = device.read_exact_at(0, 512)?;
    if boot[510] == 0x55 && boot[511] == 0xAA {
        return Ok(fixes); // already valid
    }

    // Try restoring from backup boot sector.
    let backup_offset = bpb.backup_boot_sector as u64 * bpb.bytes_per_sector as u64;
    if bpb.backup_boot_sector > 0 && backup_offset + 512 <= device.size() {
        let backup = device.read_exact_at(backup_offset, 512)?;
        if backup[510] == 0x55 && backup[511] == 0xAA {
            device.write_at(0, &backup)?;
            fixes.push(format!(
                "Restored boot sector from backup (sector {})",
                bpb.backup_boot_sector
            ));
            return Ok(fixes);
        }
    }

    // Backup also bad — write signature directly.
    device.write_at(BOOT_SIG_OFFSET, &BOOT_SIG)?;
    fixes.push("Wrote boot signature 0x55AA directly to sector 0".into());
    Ok(fixes)
}

// ── 2. FAT desync repair ──────────────────────────────────────────────

/// Compare FAT1 and FAT2. If they differ, copy FAT1 over FAT2 (FAT1 is
/// authoritative).
pub fn repair_fat_desync(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();

    if bpb.num_fats < 2 {
        return Ok(fixes);
    }

    let fat1_start = bpb.fat_offset(0);
    let fat2_start = bpb.fat_offset(1);
    let fat_bytes = bpb.fat_size_bytes() as usize;

    // Compare in 4 KiB chunks to avoid huge allocations on real devices.
    let chunk = 4096usize;
    let mut mismatched = false;
    let mut offset = 0usize;

    while offset < fat_bytes {
        let len = chunk.min(fat_bytes - offset);
        let f1 = device.read_exact_at(fat1_start + offset as u64, len)?;
        let f2 = device.read_exact_at(fat2_start + offset as u64, len)?;
        if f1 != f2 {
            mismatched = true;
            break;
        }
        offset += len;
    }

    if !mismatched {
        return Ok(fixes);
    }

    // Copy FAT1 -> FAT2 in chunks.
    offset = 0;
    while offset < fat_bytes {
        let len = chunk.min(fat_bytes - offset);
        let data = device.read_exact_at(fat1_start + offset as u64, len)?;
        device.write_at(fat2_start + offset as u64, &data)?;
        offset += len;
    }

    fixes.push(format!(
        "Copied FAT1 to FAT2 ({} bytes) to resynchronise FAT tables",
        fat_bytes
    ));
    Ok(fixes)
}

// ── 3. Orphan chain repair ────────────────────────────────────────────

/// Scan all FAT entries for allocated clusters that are not the start of
/// any chain reachable from a directory entry.  Mark orphans as free.
pub fn repair_orphan_chains(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();
    let max_cluster = bpb.total_data_clusters() + 2;

    // Build set of all clusters reachable from the root directory tree.
    let reachable = collect_reachable_clusters(device, bpb, max_cluster)?;

    // Walk FAT and free anything allocated but not reachable.
    let mut freed = 0u32;
    for cluster in 2..max_cluster {
        let entry = read_fat_entry(device, bpb, cluster)?;
        if entry != FAT_FREE && entry < 0x0FFF_FFF8 && !reachable.contains(&cluster) {
            // Check that it is also not referenced as a *continuation* in
            // a reachable chain (i.e. it is truly orphaned).
            write_fat_entry(device, bpb, cluster, FAT_FREE)?;
            freed += 1;
        }
    }

    if freed > 0 {
        fixes.push(format!("Freed {} orphan cluster(s)", freed));
    }
    Ok(fixes)
}

/// Walk the directory tree starting at root and collect every cluster
/// that belongs to a live chain.
fn collect_reachable_clusters(
    device: &dyn Device,
    bpb: &Fat32Bpb,
    max_cluster: u32,
) -> Result<HashSet<u32>> {
    let mut reachable = HashSet::new();
    let mut dir_queue: Vec<u32> = vec![bpb.root_cluster];

    while let Some(dir_start) = dir_queue.pop() {
        // Follow the directory's own cluster chain.
        let dir_chain = follow_chain(device, bpb, dir_start, max_cluster)?;
        for &c in &dir_chain {
            reachable.insert(c);
        }

        // Parse directory entries in each cluster of the chain.
        let cluster_size = bpb.cluster_size();
        for &cluster in &dir_chain {
            let offset = bpb.cluster_offset(cluster);
            let data = device.read_exact_at(offset, cluster_size)?;

            for i in (0..data.len()).step_by(32) {
                if i + 32 > data.len() {
                    break;
                }
                let entry = &data[i..i + 32];
                if entry[0] == 0x00 {
                    break; // end of directory
                }
                if entry[0] == 0xE5 || entry[11] == 0x0F {
                    continue; // deleted or LFN
                }

                let first_cluster_lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let first_cluster_hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let first_cluster = (first_cluster_hi << 16) | first_cluster_lo;

                if first_cluster < 2 || first_cluster >= max_cluster {
                    continue;
                }

                let chain = follow_chain(device, bpb, first_cluster, max_cluster)?;
                for &c in &chain {
                    reachable.insert(c);
                }

                // If it is a subdirectory (and not . or ..), queue it.
                let attr = entry[11];
                let is_dir = attr & 0x10 != 0;
                let name = &entry[0..11];
                let is_dot = name[0] == b'.' || (name[0] == b'.' && name[1] == b'.');
                if is_dir && !is_dot {
                    dir_queue.push(first_cluster);
                }
            }
        }
    }
    Ok(reachable)
}

/// Follow a cluster chain with cycle detection.  Returns the chain, or
/// stops when a cycle is found (returning the chain up to the cycle
/// point without error — callers that need to *detect* the cycle use
/// `detect_cycle` instead).
fn follow_chain(
    device: &dyn Device,
    bpb: &Fat32Bpb,
    start: u32,
    max_cluster: u32,
) -> Result<Vec<u32>> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut current = start;

    loop {
        if current < 2 || current >= 0x0FFF_FFF8 || current >= max_cluster {
            break;
        }
        if !visited.insert(current) {
            break; // cycle — stop without error
        }
        chain.push(current);
        current = read_fat_entry(device, bpb, current)?;
    }
    Ok(chain)
}

// ── 4. Circular chain repair ──────────────────────────────────────────

/// Walk all cluster chains reachable from the root directory.  When a
/// cycle is detected (a cluster is visited twice), break it by writing
/// EOC at the point just before the revisit.
pub fn repair_circular_chains(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();
    let max_cluster = bpb.total_data_clusters() + 2;

    // Collect every chain-start from directory entries.
    let chain_starts = collect_chain_starts(device, bpb, max_cluster)?;

    for start in chain_starts {
        let mut visited = HashSet::new();
        let mut current = start;
        let mut prev: Option<u32> = None;

        loop {
            if current < 2 || current >= 0x0FFF_FFF8 || current >= max_cluster {
                break;
            }
            if !visited.insert(current) {
                // Cycle detected — `prev` points to a cluster whose FAT
                // entry leads back into the already-visited set.
                if let Some(p) = prev {
                    write_fat_entry(device, bpb, p, FAT_EOC)?;
                    fixes.push(format!(
                        "Broke circular chain: wrote EOC at cluster {} (was pointing to {})",
                        p, current
                    ));
                }
                break;
            }
            let next = read_fat_entry(device, bpb, current)?;
            prev = Some(current);
            current = next;
        }
    }

    Ok(fixes)
}

/// Collect every first-cluster value referenced by directory entries in
/// the directory tree.
fn collect_chain_starts(
    device: &dyn Device,
    bpb: &Fat32Bpb,
    max_cluster: u32,
) -> Result<Vec<u32>> {
    let mut starts = Vec::new();
    let mut dir_queue: Vec<u32> = vec![bpb.root_cluster];
    starts.push(bpb.root_cluster);
    let mut visited_dirs = HashSet::new();

    while let Some(dir_start) = dir_queue.pop() {
        if !visited_dirs.insert(dir_start) {
            continue;
        }
        let dir_chain = follow_chain(device, bpb, dir_start, max_cluster)?;
        let cluster_size = bpb.cluster_size();

        for &cluster in &dir_chain {
            let offset = bpb.cluster_offset(cluster);
            let data = device.read_exact_at(offset, cluster_size)?;

            for i in (0..data.len()).step_by(32) {
                if i + 32 > data.len() {
                    break;
                }
                let entry = &data[i..i + 32];
                if entry[0] == 0x00 {
                    break;
                }
                if entry[0] == 0xE5 || entry[11] == 0x0F {
                    continue;
                }

                let first_cluster_lo = u16::from_le_bytes([entry[26], entry[27]]) as u32;
                let first_cluster_hi = u16::from_le_bytes([entry[20], entry[21]]) as u32;
                let first_cluster = (first_cluster_hi << 16) | first_cluster_lo;

                if first_cluster < 2 || first_cluster >= max_cluster {
                    continue;
                }

                starts.push(first_cluster);

                let attr = entry[11];
                let is_dir = attr & 0x10 != 0;
                let name = &entry[0..11];
                let is_dot = name[0] == b'.' || (name[0] == b'.' && name[1] == b'.');
                if is_dir && !is_dot {
                    dir_queue.push(first_cluster);
                }
            }
        }
    }
    Ok(starts)
}

// ── 5. Cross-link repair ──────────────────────────────────────────────

/// Build a reverse map (cluster -> list of parent clusters whose FAT
/// entry points to it).  If any cluster has more than one parent, the
/// duplicate references are overwritten with EOC.
pub fn repair_cross_links(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();
    let max_cluster = bpb.total_data_clusters() + 2;

    // Build reverse map: child -> vec of parents.
    let mut parents: HashMap<u32, Vec<u32>> = HashMap::new();

    for cluster in 2..max_cluster {
        let entry = read_fat_entry(device, bpb, cluster)?;
        if entry >= 2 && entry < 0x0FFF_FFF8 && entry < max_cluster {
            parents.entry(entry).or_default().push(cluster);
        }
    }

    for (child, parent_list) in &parents {
        if parent_list.len() > 1 {
            // Keep the first parent, mark the rest as EOC.
            for &dup_parent in &parent_list[1..] {
                write_fat_entry(device, bpb, dup_parent, FAT_EOC)?;
                fixes.push(format!(
                    "Resolved cross-link: cluster {} had {} parents; \
                     wrote EOC at cluster {} (duplicate reference to {})",
                    child,
                    parent_list.len(),
                    dup_parent,
                    child,
                ));
            }
        }
    }

    Ok(fixes)
}

// ── 6. FSInfo repair ──────────────────────────────────────────────────

/// Read the FSInfo sector, recalculate the free cluster count by scanning
/// the FAT, and write corrected values back.
pub fn repair_fsinfo(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();
    let fsinfo_offset = bpb.fs_info_sector as u64 * bpb.bytes_per_sector as u64;

    if bpb.fs_info_sector == 0 {
        return Ok(fixes);
    }

    let mut fsinfo = device.read_exact_at(fsinfo_offset, 512)?;

    // Validate / fix signatures.
    let lead_sig = u32::from_le_bytes([fsinfo[0], fsinfo[1], fsinfo[2], fsinfo[3]]);
    let struc_sig = u32::from_le_bytes([fsinfo[484], fsinfo[485], fsinfo[486], fsinfo[487]]);
    let trail_sig = u32::from_le_bytes([fsinfo[508], fsinfo[509], fsinfo[510], fsinfo[511]]);

    if lead_sig != FSINFO_LEAD_SIG {
        fsinfo[0..4].copy_from_slice(&FSINFO_LEAD_SIG.to_le_bytes());
        fixes.push("Corrected FSInfo lead signature".into());
    }
    if struc_sig != FSINFO_STRUC_SIG {
        fsinfo[484..488].copy_from_slice(&FSINFO_STRUC_SIG.to_le_bytes());
        fixes.push("Corrected FSInfo structure signature".into());
    }
    if trail_sig != FSINFO_TRAIL_SIG {
        fsinfo[508..512].copy_from_slice(&FSINFO_TRAIL_SIG.to_le_bytes());
        fixes.push("Corrected FSInfo trail signature".into());
    }

    // Recalculate free cluster count.
    let max_cluster = bpb.total_data_clusters() + 2;
    let mut free_count: u32 = 0;
    let mut first_free: u32 = 0xFFFF_FFFF;

    for cluster in 2..max_cluster {
        let entry = read_fat_entry(device, bpb, cluster)?;
        if entry == FAT_FREE {
            free_count += 1;
            if first_free == 0xFFFF_FFFF {
                first_free = cluster;
            }
        }
    }

    let stored_free =
        u32::from_le_bytes([fsinfo[488], fsinfo[489], fsinfo[490], fsinfo[491]]);
    let stored_next =
        u32::from_le_bytes([fsinfo[492], fsinfo[493], fsinfo[494], fsinfo[495]]);

    if stored_free != free_count {
        fsinfo[488..492].copy_from_slice(&free_count.to_le_bytes());
        fixes.push(format!(
            "Updated FSInfo free cluster count: {} -> {}",
            stored_free, free_count
        ));
    }

    if stored_next != first_free {
        fsinfo[492..496].copy_from_slice(&first_free.to_le_bytes());
        fixes.push(format!(
            "Updated FSInfo next free cluster hint: {} -> {}",
            stored_next, first_free
        ));
    }

    if !fixes.is_empty() {
        device.write_at(fsinfo_offset, &fsinfo)?;
    }
    Ok(fixes)
}

// ── 7. Backup boot sector repair ──────────────────────────────────────

/// Copy the primary boot sector (sector 0) to the backup location
/// (typically sector 6).
pub fn repair_backup_boot(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
) -> Result<Vec<String>> {
    let mut fixes = Vec::new();

    if bpb.backup_boot_sector == 0 {
        return Ok(fixes);
    }

    let boot = device.read_exact_at(0, 512)?;
    let backup_offset = bpb.backup_boot_sector as u64 * bpb.bytes_per_sector as u64;
    device.write_at(backup_offset, &boot)?;
    fixes.push(format!(
        "Copied primary boot sector to backup sector {}",
        bpb.backup_boot_sector
    ));
    Ok(fixes)
}

// ── 8. Run all repairs ────────────────────────────────────────────────

/// Run all applicable FAT32 repairs in a safe order and collect results
/// into a `RepairReport`.
pub fn run_all_repairs(
    device: &mut dyn Device,
    bpb: &Fat32Bpb,
    options: &RepairOptions,
) -> Result<RepairReport> {
    if !options.confirm_unsafe {
        return Err(Error::ConfirmationRequired);
    }

    let mut all_fixes: Vec<String> = Vec::new();

    // 1. Boot signature (always — it is non-destructive).
    let f = repair_boot_signature(device, bpb)?;
    all_fixes.extend(f);

    // 2. Backup boot sector.
    let f = repair_backup_boot(device, bpb)?;
    all_fixes.extend(f);

    // 3. FAT desync.
    if options.fix_fat {
        let f = repair_fat_desync(device, bpb)?;
        all_fixes.extend(f);
    }

    // 4. Circular chains.
    if options.remove_bad_chains {
        let f = repair_circular_chains(device, bpb)?;
        all_fixes.extend(f);
    }

    // 5. Cross-links.
    if options.fix_fat {
        let f = repair_cross_links(device, bpb)?;
        all_fixes.extend(f);
    }

    // 6. Orphan chains (after fixing cycles and cross-links).
    if options.remove_bad_chains {
        let f = repair_orphan_chains(device, bpb)?;
        all_fixes.extend(f);
    }

    // 7. FSInfo (last — counts depend on FAT being clean).
    if options.fix_fat {
        let f = repair_fsinfo(device, bpb)?;
        all_fixes.extend(f);
    }

    let errors_fixed = all_fixes.len();
    Ok(RepairReport {
        device_id: device.id().to_string(),
        fixes_applied: all_fixes,
        errors_fixed,
        bytes_written: 0, // not tracked per-byte in this implementation
        backup_path: None,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    // ── Test image builder ─────────────────────────────────────────────

    /// Build a minimal FAT32 disk image suitable for repair tests.
    fn make_test_image() -> (Vec<u8>, Fat32Bpb) {
        let bytes_per_sector: u16 = 512;
        let sectors_per_cluster: u8 = 1; // keep it tiny
        let reserved_sectors: u16 = 32;
        let num_fats: u8 = 2;
        let fat_size_sectors: u32 = 8;
        let root_cluster: u32 = 2;
        let total_sectors: u32 = 256; // 128 KiB
        let fs_info_sector: u16 = 1;
        let backup_boot_sector: u16 = 6;

        let size = total_sectors as usize * bytes_per_sector as usize;
        let mut img = vec![0u8; size];

        // ── Boot sector (sector 0) ──
        img[0] = 0xEB;
        img[1] = 0x58;
        img[2] = 0x90;
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        img[13] = sectors_per_cluster;
        img[14..16].copy_from_slice(&reserved_sectors.to_le_bytes());
        img[16] = num_fats;
        img[32..36].copy_from_slice(&total_sectors.to_le_bytes());
        img[36..40].copy_from_slice(&fat_size_sectors.to_le_bytes());
        img[44..48].copy_from_slice(&root_cluster.to_le_bytes());
        img[48..50].copy_from_slice(&fs_info_sector.to_le_bytes());
        img[50..52].copy_from_slice(&backup_boot_sector.to_le_bytes());
        img[71..82].copy_from_slice(b"TEST       ");
        img[82..90].copy_from_slice(b"FAT32   ");
        img[510] = 0x55;
        img[511] = 0xAA;

        // ── Backup boot sector (sector 6) ──
        let backup_off = backup_boot_sector as usize * bytes_per_sector as usize;
        let boot_copy: Vec<u8> = img[0..512].to_vec();
        img[backup_off..backup_off + 512].copy_from_slice(&boot_copy);

        // ── FSInfo sector (sector 1) ──
        let fsinfo_off = fs_info_sector as usize * bytes_per_sector as usize;
        img[fsinfo_off..fsinfo_off + 4].copy_from_slice(&FSINFO_LEAD_SIG.to_le_bytes());
        img[fsinfo_off + 484..fsinfo_off + 488]
            .copy_from_slice(&FSINFO_STRUC_SIG.to_le_bytes());
        img[fsinfo_off + 508..fsinfo_off + 512]
            .copy_from_slice(&FSINFO_TRAIL_SIG.to_le_bytes());
        // free count + next free (will be recalculated)
        img[fsinfo_off + 488..fsinfo_off + 492].copy_from_slice(&0u32.to_le_bytes());
        img[fsinfo_off + 492..fsinfo_off + 496]
            .copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        // ── FAT tables ──
        for fat_idx in 0..num_fats as u32 {
            let fat_start = (reserved_sectors as u32 + fat_idx * fat_size_sectors) as usize
                * bytes_per_sector as usize;
            // Reserved entries: FAT[0] and FAT[1]
            img[fat_start..fat_start + 4].copy_from_slice(&0x0FFF_FF00u32.to_le_bytes());
            img[fat_start + 4..fat_start + 8]
                .copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
            // Root cluster (cluster 2) = EOC
            let root_off = fat_start + root_cluster as usize * 4;
            img[root_off..root_off + 4].copy_from_slice(&FAT_EOC.to_le_bytes());
        }

        // Root directory cluster — empty (all zeros already).

        let bpb = Fat32Bpb {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            fat_size_sectors,
            root_cluster,
            total_sectors_32: total_sectors,
            fs_info_sector,
            backup_boot_sector,
        };

        (img, bpb)
    }

    /// Set a FAT entry directly in the image buffer (for both FATs).
    fn set_fat_entry(img: &mut [u8], bpb: &Fat32Bpb, cluster: u32, value: u32) {
        for fat_idx in 0..bpb.num_fats as u32 {
            let fat_start = (bpb.reserved_sectors as u64
                + fat_idx as u64 * bpb.fat_size_sectors as u64)
                * bpb.bytes_per_sector as u64;
            let off = fat_start as usize + cluster as usize * 4;
            img[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// Read a FAT entry directly from the image buffer (FAT1).
    fn get_fat_entry(img: &[u8], bpb: &Fat32Bpb, cluster: u32) -> u32 {
        let fat_start =
            bpb.reserved_sectors as usize * bpb.bytes_per_sector as usize;
        let off = fat_start + cluster as usize * 4;
        u32::from_le_bytes([img[off], img[off + 1], img[off + 2], img[off + 3]])
            & 0x0FFF_FFFF
    }

    // ── Test: boot signature repair from backup ────────────────────────

    #[test]
    fn test_boot_signature_repair_from_backup() {
        let (mut img, bpb) = make_test_image();
        // Corrupt the boot signature.
        img[510] = 0x00;
        img[511] = 0x00;

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_boot_signature(&mut dev, &bpb).unwrap();

        assert!(!fixes.is_empty());
        assert!(fixes[0].contains("backup"));

        // Verify signature restored.
        let data = dev.data();
        assert_eq!(data[510], 0x55);
        assert_eq!(data[511], 0xAA);
    }

    #[test]
    fn test_boot_signature_repair_direct_write() {
        let (mut img, bpb) = make_test_image();
        // Corrupt both primary and backup.
        img[510] = 0x00;
        img[511] = 0x00;
        let backup_off = bpb.backup_boot_sector as usize * bpb.bytes_per_sector as usize;
        img[backup_off + 510] = 0x00;
        img[backup_off + 511] = 0x00;

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_boot_signature(&mut dev, &bpb).unwrap();

        assert!(!fixes.is_empty());
        assert!(fixes[0].contains("directly"));

        let data = dev.data();
        assert_eq!(data[510], 0x55);
        assert_eq!(data[511], 0xAA);
    }

    // ── Test: FAT desync repair ────────────────────────────────────────

    #[test]
    fn test_fat_desync_repair() {
        let (mut img, bpb) = make_test_image();

        // Make FAT2 differ by zeroing its first few bytes.
        let fat2_start = bpb.fat_offset(1) as usize;
        img[fat2_start] = 0x00;
        img[fat2_start + 1] = 0x00;
        img[fat2_start + 2] = 0x00;
        img[fat2_start + 3] = 0x00;

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_fat_desync(&mut dev, &bpb).unwrap();

        assert!(!fixes.is_empty());
        assert!(fixes[0].contains("FAT1 to FAT2"));

        // Verify FAT1 == FAT2 now.
        let data = dev.data();
        let fat1_start = bpb.fat_offset(0) as usize;
        let fat2_start = bpb.fat_offset(1) as usize;
        let fat_bytes = bpb.fat_size_bytes() as usize;
        assert_eq!(
            &data[fat1_start..fat1_start + fat_bytes],
            &data[fat2_start..fat2_start + fat_bytes]
        );
    }

    #[test]
    fn test_fat_desync_no_op_when_synced() {
        let (img, bpb) = make_test_image();
        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_fat_desync(&mut dev, &bpb).unwrap();
        assert!(fixes.is_empty());
    }

    // ── Test: FSInfo recalculation ─────────────────────────────────────

    #[test]
    fn test_fsinfo_recalculation() {
        let (mut img, bpb) = make_test_image();

        // Allocate a few clusters so the free count changes.
        set_fat_entry(&mut img, &bpb, 3, FAT_EOC);
        set_fat_entry(&mut img, &bpb, 4, FAT_EOC);

        // Set a wrong free count in FSInfo.
        let fsinfo_off = bpb.fs_info_sector as usize * bpb.bytes_per_sector as usize;
        img[fsinfo_off + 488..fsinfo_off + 492].copy_from_slice(&999u32.to_le_bytes());

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_fsinfo(&mut dev, &bpb).unwrap();

        assert!(fixes.iter().any(|f| f.contains("free cluster count")));

        // The recalculated count should exclude clusters 0,1 (reserved),
        // 2 (root-EOC), 3, and 4 (allocated).
        let data = dev.data();
        let stored_free = u32::from_le_bytes([
            data[fsinfo_off + 488],
            data[fsinfo_off + 489],
            data[fsinfo_off + 490],
            data[fsinfo_off + 491],
        ]);

        let max_cluster = bpb.total_data_clusters() + 2;
        // Clusters 2, 3, 4 are allocated, everything from 5..max is free.
        let expected_free = max_cluster - 5; // clusters 5 .. max_cluster-1
        assert_eq!(stored_free, expected_free);
    }

    // ── Test: circular chain breaking ──────────────────────────────────

    #[test]
    fn test_circular_chain_breaking() {
        let (mut img, bpb) = make_test_image();

        // Create a file starting at cluster 3, with chain: 3 -> 4 -> 5 -> 3 (cycle).
        set_fat_entry(&mut img, &bpb, 3, 4);
        set_fat_entry(&mut img, &bpb, 4, 5);
        set_fat_entry(&mut img, &bpb, 5, 3); // cycle back to 3

        // Add a directory entry in the root cluster pointing to cluster 3.
        let root_off = bpb.cluster_offset(bpb.root_cluster) as usize;
        // Minimal 8.3 entry: "FILE    TXT", attr=0x20, first cluster = 3
        let mut entry = [0x20u8; 32]; // spaces
        entry[0..8].copy_from_slice(b"FILE    ");
        entry[8..11].copy_from_slice(b"TXT");
        entry[11] = 0x20; // archive attribute
        entry[20..22].copy_from_slice(&0u16.to_le_bytes()); // cluster hi
        entry[26..28].copy_from_slice(&3u16.to_le_bytes()); // cluster lo
        img[root_off..root_off + 32].copy_from_slice(&entry);

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_circular_chains(&mut dev, &bpb).unwrap();

        assert!(!fixes.is_empty());
        assert!(fixes[0].contains("circular"));

        // Verify the cycle is broken — one of the entries should now be EOC.
        let e3 = get_fat_entry(dev.data(), &bpb, 3);
        let e4 = get_fat_entry(dev.data(), &bpb, 4);
        let e5 = get_fat_entry(dev.data(), &bpb, 5);

        // The chain should terminate somewhere.
        let has_eoc = e3 == (FAT_EOC & 0x0FFF_FFFF)
            || e4 == (FAT_EOC & 0x0FFF_FFFF)
            || e5 == (FAT_EOC & 0x0FFF_FFFF);
        assert!(has_eoc, "Expected at least one EOC, got: 3={:#x}, 4={:#x}, 5={:#x}", e3, e4, e5);
    }

    // ── Test: cross-link detection and repair ──────────────────────────

    #[test]
    fn test_cross_link_repair() {
        let (mut img, bpb) = make_test_image();

        // Two chains that both point to cluster 6:
        //   chain A: 3 -> 6 -> EOC
        //   chain B: 4 -> 5 -> 6 (cross-link!)
        set_fat_entry(&mut img, &bpb, 3, 6);
        set_fat_entry(&mut img, &bpb, 4, 5);
        set_fat_entry(&mut img, &bpb, 5, 6); // <-- duplicate reference to 6
        set_fat_entry(&mut img, &bpb, 6, FAT_EOC);

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_cross_links(&mut dev, &bpb).unwrap();

        assert!(!fixes.is_empty());
        assert!(fixes[0].contains("cross-link"));

        // After repair, cluster 6 should have exactly one parent.
        let e3 = get_fat_entry(dev.data(), &bpb, 3);
        let e5 = get_fat_entry(dev.data(), &bpb, 5);

        // One of them should still point to 6, the other should be EOC.
        let pointing_to_6 = [e3, e5].iter().filter(|&&v| v == 6).count();
        let eoc_count = [e3, e5]
            .iter()
            .filter(|&&v| v == (FAT_EOC & 0x0FFF_FFFF))
            .count();
        assert_eq!(pointing_to_6, 1, "Exactly one parent should still reference cluster 6");
        assert_eq!(eoc_count, 1, "The duplicate parent should now be EOC");
    }

    // ── Test: run_all_repairs requires confirmation ────────────────────

    #[test]
    fn test_run_all_requires_confirmation() {
        let (img, bpb) = make_test_image();
        let mut dev = MockDevice::from_bytes(img);
        let opts = RepairOptions {
            confirm_unsafe: false,
            backup_first: false,
            fix_fat: true,
            remove_bad_chains: true,
        };
        let result = run_all_repairs(&mut dev, &bpb, &opts);
        assert!(result.is_err());
    }

    // ── Test: backup boot sector copy ──────────────────────────────────

    #[test]
    fn test_backup_boot_copy() {
        let (mut img, bpb) = make_test_image();
        // Corrupt backup.
        let backup_off = bpb.backup_boot_sector as usize * bpb.bytes_per_sector as usize;
        img[backup_off..backup_off + 512].fill(0x00);

        let mut dev = MockDevice::from_bytes(img);
        let fixes = repair_backup_boot(&mut dev, &bpb).unwrap();

        assert!(!fixes.is_empty());

        let data = dev.data();
        assert_eq!(
            &data[0..512],
            &data[backup_off..backup_off + 512],
            "Backup should be an exact copy of sector 0"
        );
    }
}
