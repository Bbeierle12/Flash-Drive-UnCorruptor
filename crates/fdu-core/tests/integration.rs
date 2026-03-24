//! Cross-module integration tests for fdu-core.
//!
//! These tests exercise the public API across multiple modules,
//! verifying that device → filesystem → diagnostics → recovery
//! all work together correctly.

use fdu_core::device::traits::{Device, DeviceExt};
use fdu_core::device::MockDevice;
use fdu_core::diagnostics::scan_bad_sectors;
use fdu_core::fs::detect_filesystem;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::FileSystemOps;
use fdu_core::models::FsType;
use fdu_core::recovery::scan_signatures;
use std::path::Path;

/// Build a minimal but complete FAT32 image for integration testing.
fn make_fat32_image() -> Vec<u8> {
    let bps: u16 = 512;
    let spc: u8 = 8;
    let reserved: u16 = 32;
    let num_fats: u8 = 2;
    let fat_size: u32 = 16;
    let total_sectors: u32 = 2048; // 1 MB

    let size = total_sectors as usize * bps as usize;
    let mut img = vec![0u8; size];

    // Boot sector
    img[0] = 0xEB;
    img[1] = 0x58;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"MSDOS5.0");
    img[11..13].copy_from_slice(&bps.to_le_bytes());
    img[13] = spc;
    img[14..16].copy_from_slice(&reserved.to_le_bytes());
    img[16] = num_fats;
    img[32..36].copy_from_slice(&total_sectors.to_le_bytes());
    img[36..40].copy_from_slice(&fat_size.to_le_bytes());
    let root_cluster: u32 = 2;
    img[44..48].copy_from_slice(&root_cluster.to_le_bytes()); // root cluster
    img[71..82].copy_from_slice(b"INTTEST    ");
    img[82..90].copy_from_slice(b"FAT32   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT tables — reserved entries
    for fat_idx in 0..num_fats as u32 {
        let fat_start = (reserved as u32 + fat_idx * fat_size) as usize * bps as usize;
        img[fat_start..fat_start + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes()); // cluster 0: media descriptor
        img[fat_start + 4..fat_start + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes()); // cluster 1: EOC marker
        // Root cluster = end of chain
        let root_off = fat_start + root_cluster as usize * 4;
        img[root_off..root_off + 4].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    }

    img
}

/// Write a FAT entry in both FAT copies.
fn set_fat_entry(img: &mut [u8], cluster: u32, value: u32) {
    let bps = 512usize;
    let reserved = 32usize;
    let fat_size = 16usize;
    let offset = cluster as usize * 4;
    for fat_idx in 0..2usize {
        let fat_start = (reserved + fat_idx * fat_size) * bps;
        let off = fat_start + offset;
        img[off..off + 4].copy_from_slice(&(value & 0x0FFF_FFFF).to_le_bytes());
    }
}

/// Write an 8.3 dir entry at a slot in a cluster's data area.
fn write_dir_entry(img: &mut [u8], cluster: u32, slot: usize, entry: &[u8; 32]) {
    let data_start = (32 + 2 * 16) * 512; // reserved + 2 FATs
    let cluster_off = data_start + (cluster as usize - 2) * 8 * 512;
    let off = cluster_off + slot * 32;
    img[off..off + 32].copy_from_slice(entry);
}

fn make_83_entry(
    name: &[u8; 8],
    ext: &[u8; 3],
    attr: u8,
    cluster: u32,
    size: u32,
) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..8].copy_from_slice(name);
    e[8..11].copy_from_slice(ext);
    e[11] = attr;
    e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

// ════════════════════════════════════════════════════════════════════
// Phase 6 — Integration Tests
// ════════════════════════════════════════════════════════════════════

#[test]
fn phase6_full_fat32_workflow() {
    let mut img = make_fat32_image();

    // Add a file and a deleted file
    let file_entry = make_83_entry(b"HELLO   ", b"TXT", 0x20, 3, 512);
    set_fat_entry(&mut img, 3, 0x0FFF_FFFF);
    let mut deleted = make_83_entry(b"REMOVED ", b"DAT", 0x20, 4, 1024);
    deleted[0] = 0xE5;
    set_fat_entry(&mut img, 4, 0x0FFF_FFFF);
    write_dir_entry(&mut img, 2, 0, &file_entry);
    write_dir_entry(&mut img, 2, 1, &deleted);
    write_dir_entry(&mut img, 2, 2, &[0u8; 32]);

    let dev = MockDevice::from_bytes(img);

    // Step 1: detect
    let fs_type = detect_filesystem(&dev).unwrap();
    assert_eq!(fs_type, FsType::Fat32);

    // Step 2: parse
    let fs = Fat32Fs::new(&dev).unwrap();

    // Step 3: metadata
    let meta = fs.metadata().unwrap();
    assert_eq!(meta.fs_type, FsType::Fat32);
    assert!(meta.total_clusters > 0);

    // Step 4: list
    let entries = fs.list_dir(Path::new("/")).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "HELLO.TXT");

    // Step 5: scan_deleted
    let deleted_files = fs.scan_deleted().unwrap();
    assert_eq!(deleted_files.len(), 1);

    // Step 6: validate
    let report = fs.validate().unwrap();
    assert_eq!(report.fs_type, FsType::Fat32);
}

#[test]
fn phase6_corrupted_fat32_graceful_degradation() {
    let mut img = make_fat32_image();
    // Corrupt FAT2 to differ from FAT1
    let fat2_start = (32 + 16) * 512; // reserved + fat1
    img[fat2_start + 8] = 0xDE;

    let dev = MockDevice::from_bytes(img);
    let fs = Fat32Fs::new(&dev).unwrap();
    let report = fs.validate().unwrap();
    assert!(report.issues.iter().any(|i| i.code == "FAT_MISMATCH"));
}

#[test]
fn phase6_deleted_scan_plus_signature_carving() {
    let mut img = make_fat32_image();

    // Add a deleted JPEG file entry
    let mut jpeg_entry = make_83_entry(b"PHOTO   ", b"JPG", 0x20, 3, 2000);
    jpeg_entry[0] = 0xE5;
    set_fat_entry(&mut img, 3, 0x0FFF_FFFF);
    write_dir_entry(&mut img, 2, 0, &jpeg_entry);
    write_dir_entry(&mut img, 2, 1, &[0u8; 32]);

    // Also plant a JPEG signature in the data area of cluster 3
    let cluster3_offset = (32 + 2 * 16) * 512 + 8 * 512;
    img[cluster3_offset] = 0xFF;
    img[cluster3_offset + 1] = 0xD8;
    img[cluster3_offset + 2] = 0xFF;

    let dev = MockDevice::from_bytes(img);

    // FAT32 deleted scan
    let fs = Fat32Fs::new(&dev).unwrap();
    let deleted = fs.scan_deleted().unwrap();
    assert!(!deleted.is_empty());

    // Signature carving
    let carved = scan_signatures(&dev, &["jpg".to_string()], None).unwrap();
    assert!(!carved.is_empty());
}

#[test]
fn phase6_bad_sectors_detected_by_diagnostics_and_validation() {
    let img = make_fat32_image();
    // Inject bad sector in FAT1 region
    let fat_sector = 32u64; // first FAT sector
    let dev = MockDevice::from_bytes(img).with_bad_sector(fat_sector);

    // Diagnostics should find the bad sector
    let diag = scan_bad_sectors(&dev, None).unwrap();
    assert!(diag.bad_sectors.contains(&fat_sector));

    // Validation should report FAT_READ_FAIL
    let fs = Fat32Fs::new(&dev).unwrap();
    let report = fs.validate().unwrap();
    assert!(report.issues.iter().any(|i| i.code == "FAT_READ_FAIL"));
}

#[test]
fn phase6_empty_root_directory() {
    let img = make_fat32_image();
    // Root directory cluster is all zeros (end marker at slot 0)
    let dev = MockDevice::from_bytes(img);
    let fs = Fat32Fs::new(&dev).unwrap();
    let entries = fs.list_dir(Path::new("/")).unwrap();
    assert!(entries.is_empty());
}

#[test]
fn phase6_full_cluster_chain_data_read() {
    let mut img = make_fat32_image();

    // Create a 3-cluster chain: 3 -> 4 -> 5 -> EOC
    set_fat_entry(&mut img, 3, 4);
    set_fat_entry(&mut img, 4, 5);
    set_fat_entry(&mut img, 5, 0x0FFF_FFFF);

    // Add a file pointing to this chain
    let file_entry = make_83_entry(b"BIG     ", b"DAT", 0x20, 3, 12288);
    write_dir_entry(&mut img, 2, 0, &file_entry);
    write_dir_entry(&mut img, 2, 1, &[0u8; 32]);

    let dev = MockDevice::from_bytes(img);
    let fs = Fat32Fs::new(&dev).unwrap();

    let entries = fs.list_dir(Path::new("/")).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size_bytes, 12288);
}

#[test]
fn phase6_mock_device_as_trait_object() {
    let dev = MockDevice::new(4096);
    let boxed: Box<dyn Device> = Box::new(dev);
    assert_eq!(boxed.size(), 4096);
    assert_eq!(boxed.sector_size(), 512);
}

#[test]
fn phase6_device_ext_through_trait_object() {
    let mut dev = MockDevice::new(4096);
    dev.set_data(512, &[0xBB; 512]);
    let boxed: Box<dyn Device> = Box::new(dev);
    let sector = boxed.read_sector(1).unwrap();
    assert!(sector.iter().all(|&b| b == 0xBB));
    assert_eq!(boxed.sector_count(), 8);
}

#[test]
fn phase6_bad_sector_scan_and_carving_coexistence() {
    let mut dev = MockDevice::new(512 * 100);
    // Plant a JPEG at sector 10
    dev.set_data(10 * 512, &[0xFF, 0xD8, 0xFF]);
    // Bad sector at sector 50 (far from JPEG)
    let dev = dev.with_bad_sector(50);

    // Bad sector scan should find the bad sector
    let diag = scan_bad_sectors(&dev, None).unwrap();
    assert!(diag.bad_sectors.contains(&50));

    // Carving may find signatures before the bad sector, or fail when it
    // hits one.  The key point: both functions can operate on the same device
    // without interfering.  We explicitly verify the result instead of
    // discarding it.
    let carving_result = scan_signatures(&dev, &[], None);
    // Either Ok (found some or none before the bad sector) or Err (hit bad sector)
    // — both are acceptable in this scenario.
    match &carving_result {
        Ok(files) => assert!(files.len() <= 1, "Should find at most the planted JPEG"),
        Err(_) => { /* bad-sector read error is acceptable */ }
    }
}

#[test]
fn phase6_large_device_smoke_test() {
    // 10,000 sectors = ~5 MB
    let dev = MockDevice::new(512 * 10_000);
    assert_eq!(dev.sector_count(), 10_000);
    assert_eq!(dev.size(), 512 * 10_000);

    // Should be able to read first and last sectors
    let first = dev.read_sector(0).unwrap();
    assert_eq!(first.len(), 512);
    let last = dev.read_sector(9999).unwrap();
    assert_eq!(last.len(), 512);
}
