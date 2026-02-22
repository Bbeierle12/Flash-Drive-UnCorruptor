//! Disk layout threat detectors.
//!
//! Each function examines a [`DiskLayout`] for a specific anomaly and returns
//! zero or more [`Finding`]s.

use crate::layout::{DiskLayout, PartitionScheme};
use fdu_models::{Evidence, Finding, Severity};

/// Run all disk threat detectors.
pub fn run_all(layout: &DiskLayout) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_overlapping_partitions(layout));
    findings.extend(detect_suspicious_gaps(layout));
    findings.extend(detect_type_mismatch(layout));
    findings.extend(detect_hybrid_mismatch(layout));
    findings
}

/// Overlapping partitions → Critical.
///
/// Two partitions whose LBA ranges overlap is always a sign of corruption
/// or deliberate manipulation.
fn detect_overlapping_partitions(layout: &DiskLayout) -> Vec<Finding> {
    let mut findings = Vec::new();
    let parts = &layout.partitions;

    for i in 0..parts.len() {
        for j in (i + 1)..parts.len() {
            let a = &parts[i];
            let b = &parts[j];

            // Check for overlap: a.start <= b.end && b.start <= a.end
            if a.start_lba <= b.end_lba && b.start_lba <= a.end_lba {
                findings.push(
                    Finding::new(
                        "disk.overlapping_partitions",
                        Severity::Critical,
                        "Overlapping partitions detected",
                        format!(
                            "Partition {} ({}, LBA {}-{}) overlaps with partition {} ({}, LBA {}-{}). \
                             This indicates corruption or deliberate partition table manipulation.",
                            a.index, a.type_label, a.start_lba, a.end_lba,
                            b.index, b.type_label, b.start_lba, b.end_lba,
                        ),
                    )
                    .with_evidence(Evidence::Metric {
                        key: "overlap_sectors".into(),
                        value: overlap_size(
                            a.start_lba,
                            a.end_lba,
                            b.start_lba,
                            b.end_lba,
                        ) as f64,
                    })
                    .with_remediation(
                        "Do not mount this device. The partition table may have been \
                         tampered with to hide data or cause filesystem damage.",
                    ),
                );
            }
        }
    }

    findings
}

/// Suspiciously large unallocated gap (> 10% of disk) → Medium.
fn detect_suspicious_gaps(layout: &DiskLayout) -> Vec<Finding> {
    let mut findings = Vec::new();
    let threshold = layout.total_sectors / 10; // 10% of disk

    for &(start, end) in &layout.unallocated_regions {
        let gap_sectors = end - start + 1;
        if gap_sectors > threshold && threshold > 0 {
            let gap_bytes = gap_sectors * layout.sector_size as u64;
            let pct = (gap_sectors as f64 / layout.total_sectors as f64) * 100.0;

            findings.push(
                Finding::new(
                    "disk.suspicious_gap",
                    Severity::Medium,
                    "Large unallocated disk region",
                    format!(
                        "Unallocated region at LBA {}-{} spans {} sectors ({:.1}% of disk, \
                         {} bytes). This could hide a partition or contain residual data.",
                        start,
                        end,
                        gap_sectors,
                        pct,
                        gap_bytes,
                    ),
                )
                .with_evidence(Evidence::Metric {
                    key: "gap_percentage".into(),
                    value: pct,
                }),
            );
        }
    }

    findings
}

/// Partition type doesn't match detected filesystem → Medium.
fn detect_type_mismatch(layout: &DiskLayout) -> Vec<Finding> {
    let mut findings = Vec::new();

    for part in &layout.partitions {
        if let Some(fs) = part.fs_type {
            let expected = match fs {
                fdu_core::models::FsType::Fat32 => {
                    vec!["0x0B", "0x0C", "0x1B", "0x1C"]
                }
                fdu_core::models::FsType::Fat16 => {
                    vec!["0x04", "0x06", "0x0E", "0x14", "0x16", "0x1E"]
                }
                fdu_core::models::FsType::Fat12 => vec!["0x01"],
                fdu_core::models::FsType::Ntfs => vec!["0x07"],
                fdu_core::models::FsType::Ext4 | fdu_core::models::FsType::Ext3 | fdu_core::models::FsType::Ext2 => {
                    vec!["0x83"]
                }
                _ => continue,
            };

            // Only check MBR-style type IDs (hex byte format)
            if part.type_id.starts_with("0x") && !expected.contains(&part.type_id.as_str()) {
                findings.push(
                    Finding::new(
                        "disk.type_mismatch",
                        Severity::Medium,
                        "Partition type mismatch",
                        format!(
                            "Partition {} has type {} ({}) but contains a {} filesystem. \
                             This mismatch may indicate the partition was re-formatted \
                             without updating the partition table, or deliberate disguise.",
                            part.index, part.type_id, part.type_label, fs,
                        ),
                    )
                    .with_evidence(Evidence::Text(format!(
                        "Expected type IDs for {}: {:?}",
                        fs, expected
                    ))),
                );
            }
        }
    }

    findings
}

/// MBR + GPT hybrid with potential mismatch → Low.
fn detect_hybrid_mismatch(layout: &DiskLayout) -> Vec<Finding> {
    if layout.scheme == PartitionScheme::Hybrid {
        vec![Finding::new(
            "disk.hybrid_partition_table",
            Severity::Low,
            "Hybrid MBR/GPT partition table",
            "This device has both MBR and GPT partition tables. While this is \
             sometimes legitimate (protective MBR), it can also be used to present \
             different partition views to different operating systems, potentially \
             hiding partitions.",
        )]
    } else {
        vec![]
    }
}

/// Calculate the number of overlapping sectors between two LBA ranges.
fn overlap_size(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> u64 {
    let start = a_start.max(b_start);
    let end = a_end.min(b_end);
    if end >= start {
        end - start + 1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{PartitionFlags, PartitionInfo};

    fn make_partition(index: u8, start: u64, end: u64) -> PartitionInfo {
        PartitionInfo {
            index,
            type_id: "0x0C".into(),
            type_label: "FAT32 (LBA)".into(),
            label: None,
            start_lba: start,
            end_lba: end,
            size_bytes: (end - start + 1) * 512,
            fs_type: Some(fdu_core::models::FsType::Fat32),
            flags: PartitionFlags::default(),
        }
    }

    #[test]
    fn detect_overlap() {
        let layout = DiskLayout {
            scheme: PartitionScheme::Mbr,
            partitions: vec![
                make_partition(0, 100, 200),
                make_partition(1, 150, 300), // overlaps with first
            ],
            unallocated_regions: vec![],
            total_sectors: 1000,
            sector_size: 512,
        };

        let findings = detect_overlapping_partitions(&layout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn no_overlap() {
        let layout = DiskLayout {
            scheme: PartitionScheme::Mbr,
            partitions: vec![
                make_partition(0, 100, 200),
                make_partition(1, 300, 400),
            ],
            unallocated_regions: vec![],
            total_sectors: 1000,
            sector_size: 512,
        };

        let findings = detect_overlapping_partitions(&layout);
        assert!(findings.is_empty());
    }

    #[test]
    fn suspicious_gap_detected() {
        let layout = DiskLayout {
            scheme: PartitionScheme::Mbr,
            partitions: vec![make_partition(0, 100, 200)],
            unallocated_regions: vec![(300, 800)], // 50% of disk!
            total_sectors: 1000,
            sector_size: 512,
        };

        let findings = detect_suspicious_gaps(&layout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn small_gap_ignored() {
        let layout = DiskLayout {
            scheme: PartitionScheme::Mbr,
            partitions: vec![make_partition(0, 100, 900)],
            unallocated_regions: vec![(901, 999)], // 10% exactly — not >10%
            total_sectors: 1000,
            sector_size: 512,
        };

        let findings = detect_suspicious_gaps(&layout);
        assert!(findings.is_empty());
    }

    #[test]
    fn type_mismatch_detected() {
        let mut part = make_partition(0, 100, 200);
        part.type_id = "0x83".into(); // Linux type, but fs_type is FAT32
        part.type_label = "Linux".into();

        let layout = DiskLayout {
            scheme: PartitionScheme::Mbr,
            partitions: vec![part],
            unallocated_regions: vec![],
            total_sectors: 1000,
            sector_size: 512,
        };

        let findings = detect_type_mismatch(&layout);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.contains("mismatch"));
    }

    #[test]
    fn hybrid_detected() {
        let layout = DiskLayout {
            scheme: PartitionScheme::Hybrid,
            partitions: vec![],
            unallocated_regions: vec![],
            total_sectors: 1000,
            sector_size: 512,
        };

        let findings = detect_hybrid_mismatch(&layout);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Low);
    }

    #[test]
    fn overlap_size_calculation() {
        assert_eq!(overlap_size(100, 200, 150, 300), 51);
        assert_eq!(overlap_size(100, 200, 201, 300), 0);
        assert_eq!(overlap_size(100, 200, 100, 200), 101); // identical
    }
}
