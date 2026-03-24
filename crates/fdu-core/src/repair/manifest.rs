//! Loading and verification of Corrosion corruption manifests.
//!
//! Corrosion is a companion tool that corrupts drive images in controlled ways
//! and records every mutation in a JSON manifest. FDU loads these manifests to
//! verify repair quality against the Corrosion spec (section 8.2).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::device::traits::{Device, DeviceExt};
use crate::errors::{Error, Result};

// ── Manifest data model ──────────────────────────────────────────────

/// Top-level Corrosion manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrosionManifest {
    /// Manifest schema version (e.g. "1.0").
    pub version: String,

    /// RFC 3339 timestamp of when corruption was performed.
    pub timestamp: String,

    /// Optional random seed used by Corrosion for reproducibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,

    /// Path to the corrupted disk image.
    pub image_path: String,

    /// SHA-256 hash of the original (clean) image, prefixed with `sha256:`.
    pub clean_hash: String,

    /// SHA-256 hash of the corrupted image, prefixed with `sha256:`.
    pub corrupted_hash: String,

    /// What kind of target was corrupted (e.g. `"disk_image"`).
    pub target_type: String,

    /// Filesystem type of the image.
    pub fs_type: String,

    /// Corruption scenario name.
    pub scenario: String,

    /// Ordered list of corruption actions that were applied.
    pub actions: Vec<CorruptionAction>,

    /// Aggregate statistics about the corruption run.
    pub stats: CorruptionStats,
}

/// A single corruption action recorded by Corrosion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionAction {
    /// Name of the corruption technique (e.g. `"bit_flip"`, `"zero_fill"`).
    pub technique: String,

    /// How hard this mutation is expected to be to repair.
    pub difficulty: Difficulty,

    /// Where on disk the corruption was applied.
    pub target: CorruptionTarget,

    /// Human-readable description of what was done.
    pub description: String,

    /// Original bytes before corruption.
    pub original: Vec<u8>,

    /// Bytes written by Corrosion (the corrupted version).
    pub corrupted: Vec<u8>,
}

/// Location on disk targeted by a corruption action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionTarget {
    /// Logical Block Address of the target sector.
    pub lba: u64,

    /// Byte offset from the start of the image.
    pub byte_offset: u64,

    /// Length of the corrupted region in bytes.
    pub length: usize,

    /// Filesystem structure that was targeted (e.g. `"Boot Sector"`, `"FAT1"`).
    pub fs_structure: String,
}

/// Aggregate statistics recorded in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorruptionStats {
    /// Total number of discrete mutations applied.
    pub total_mutations: u64,

    /// Total number of bytes that were overwritten.
    pub bytes_corrupted: u64,

    /// Mutation count keyed by technique name.
    #[serde(default)]
    pub by_mode: HashMap<String, u64>,

    /// Mutation count keyed by difficulty level.
    #[serde(default)]
    pub by_difficulty: HashMap<String, u64>,
}

/// Difficulty rating assigned to a corruption action by Corrosion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Difficulty {
    Easy,
    Medium,
    Hard,
    Impossible,
}

// ── Manifest loading ─────────────────────────────────────────────────

/// Load and parse a Corrosion manifest from a JSON file on disk.
pub fn load_manifest(path: &Path) -> Result<CorrosionManifest> {
    let data = std::fs::read_to_string(path).map_err(|e| Error::IoGeneral(e))?;
    let manifest: CorrosionManifest =
        serde_json::from_str(&data).map_err(|e| Error::RecoveryFailed(format!("Invalid Corrosion manifest: {e}")))?;
    Ok(manifest)
}

// ── Verification verdicts and scoring (Corrosion spec 8.2) ───────────

/// Verdict for a single corruption action after repair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// The bytes at this location match the original — repair succeeded.
    FullyRepaired,

    /// The bytes differ from both original and corrupted — partial fix.
    PartiallyRepaired,

    /// The bytes still match the corrupted version — not repaired.
    NotRepaired,

    /// An `Impossible`-difficulty action was left as-is, which is correct.
    CorrectlyUnrecoverable,

    /// An `Impossible`-difficulty action was "repaired" to match the original,
    /// which means the tool fabricated data — a false positive.
    FalsePositive,
}

impl Verdict {
    /// Numeric score for this verdict per Corrosion spec 8.2.
    pub fn score(self) -> f64 {
        match self {
            Verdict::FullyRepaired => 1.0,
            Verdict::PartiallyRepaired => 0.5,
            Verdict::CorrectlyUnrecoverable => 1.0,
            Verdict::NotRepaired => 0.0,
            Verdict::FalsePositive => -0.5,
        }
    }
}

/// Per-action verdict entry inside a [`VerificationReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionVerdict {
    /// Index of the action in the manifest's `actions` array.
    pub action_index: usize,

    /// The technique that was used for corruption.
    pub technique: String,

    /// Difficulty of the action.
    pub difficulty: Difficulty,

    /// What filesystem structure was targeted.
    pub fs_structure: String,

    /// The verdict after comparing repaired bytes.
    pub verdict: Verdict,
}

/// Summary statistics inside a [`VerificationReport`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub fully_repaired: usize,
    pub partially_repaired: usize,
    pub not_repaired: usize,
    pub correctly_unrecoverable: usize,
    pub false_positive: usize,
    pub total: usize,
}

/// Complete report produced by [`verify_repair`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Per-action verdicts, one entry per action in the manifest.
    pub per_action: Vec<ActionVerdict>,

    /// Overall quality score in the range `[-0.5, 1.0]`.
    ///
    /// Computed as `sum(verdict_scores) / total_actions`.
    pub overall_score: f64,

    /// Summary counts by verdict category.
    pub summary: VerificationSummary,
}

// ── Repair verification ──────────────────────────────────────────────

/// Verify a repaired device against a Corrosion manifest.
///
/// For each action in the manifest the function reads the corresponding bytes
/// from `device` and compares them to the original and corrupted byte vectors
/// recorded in the manifest, then assigns a [`Verdict`].
///
/// # Errors
///
/// Returns an error if any device read fails (e.g. out-of-bounds).
pub fn verify_repair(
    device: &dyn Device,
    manifest: &CorrosionManifest,
) -> Result<VerificationReport> {
    let mut per_action = Vec::with_capacity(manifest.actions.len());
    let mut summary = VerificationSummary::default();

    for (idx, action) in manifest.actions.iter().enumerate() {
        let offset = action.target.byte_offset;
        let len = action.target.length;

        let actual = device.read_exact_at(offset, len)?;

        let verdict = classify(&actual, &action.original, &action.corrupted, action.difficulty);

        match verdict {
            Verdict::FullyRepaired => summary.fully_repaired += 1,
            Verdict::PartiallyRepaired => summary.partially_repaired += 1,
            Verdict::NotRepaired => summary.not_repaired += 1,
            Verdict::CorrectlyUnrecoverable => summary.correctly_unrecoverable += 1,
            Verdict::FalsePositive => summary.false_positive += 1,
        }

        per_action.push(ActionVerdict {
            action_index: idx,
            technique: action.technique.clone(),
            difficulty: action.difficulty,
            fs_structure: action.target.fs_structure.clone(),
            verdict,
        });
    }

    summary.total = manifest.actions.len();

    let overall_score = if summary.total == 0 {
        1.0
    } else {
        let sum: f64 = per_action.iter().map(|a| a.verdict.score()).sum();
        sum / summary.total as f64
    };

    Ok(VerificationReport {
        per_action,
        overall_score,
        summary,
    })
}

/// Classify the repair result for a single action.
fn classify(actual: &[u8], original: &[u8], corrupted: &[u8], difficulty: Difficulty) -> Verdict {
    let matches_original = actual == original;
    let matches_corrupted = actual == corrupted;

    match difficulty {
        Difficulty::Impossible => {
            if matches_original {
                // Tool claims to have repaired something that cannot be repaired
                // — it must have fabricated the data.
                Verdict::FalsePositive
            } else if matches_corrupted {
                Verdict::CorrectlyUnrecoverable
            } else {
                // Modified but not back to original — still a partial attempt
                Verdict::PartiallyRepaired
            }
        }
        _ => {
            if matches_original {
                Verdict::FullyRepaired
            } else if matches_corrupted {
                Verdict::NotRepaired
            } else {
                Verdict::PartiallyRepaired
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    /// Helper: build a minimal valid manifest JSON string.
    fn sample_manifest_json() -> String {
        r#"{
            "version": "1.0",
            "timestamp": "2026-01-15T10:30:00Z",
            "seed": "42",
            "image_path": "/tmp/test.img",
            "clean_hash": "sha256:aabbccdd",
            "corrupted_hash": "sha256:11223344",
            "target_type": "disk_image",
            "fs_type": "fat32",
            "scenario": "boot_sector_wipe",
            "actions": [
                {
                    "technique": "zero_fill",
                    "difficulty": "Easy",
                    "target": {
                        "lba": 0,
                        "byte_offset": 0,
                        "length": 4,
                        "fs_structure": "Boot Sector"
                    },
                    "description": "Zeroed the first 4 bytes of the boot sector",
                    "original": [235, 88, 144, 77],
                    "corrupted": [0, 0, 0, 0]
                },
                {
                    "technique": "entropy_inject",
                    "difficulty": "Impossible",
                    "target": {
                        "lba": 100,
                        "byte_offset": 51200,
                        "length": 3,
                        "fs_structure": "Data Region"
                    },
                    "description": "Replaced data region bytes with random noise",
                    "original": [170, 187, 204],
                    "corrupted": [17, 34, 51]
                }
            ],
            "stats": {
                "total_mutations": 2,
                "bytes_corrupted": 7,
                "by_mode": {"zero_fill": 1, "entropy_inject": 1},
                "by_difficulty": {"Easy": 1, "Impossible": 1}
            }
        }"#
        .to_string()
    }

    /// Parse the sample JSON and re-serialize to verify round-trip fidelity.
    #[test]
    fn manifest_deserialization_roundtrip() {
        let json = sample_manifest_json();
        let manifest: CorrosionManifest = serde_json::from_str(&json).unwrap();

        assert_eq!(manifest.version, "1.0");
        assert_eq!(manifest.fs_type, "fat32");
        assert_eq!(manifest.actions.len(), 2);
        assert_eq!(manifest.actions[0].difficulty, Difficulty::Easy);
        assert_eq!(manifest.actions[1].difficulty, Difficulty::Impossible);
        assert_eq!(manifest.actions[0].original, vec![235, 88, 144, 77]);
        assert_eq!(manifest.actions[0].corrupted, vec![0, 0, 0, 0]);
        assert_eq!(manifest.stats.total_mutations, 2);
        assert_eq!(manifest.stats.bytes_corrupted, 7);
        assert_eq!(manifest.stats.by_mode.get("zero_fill"), Some(&1));

        // Re-serialize and re-parse to confirm round-trip stability.
        let reserialized = serde_json::to_string(&manifest).unwrap();
        let manifest2: CorrosionManifest = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(manifest2.version, manifest.version);
        assert_eq!(manifest2.actions.len(), manifest.actions.len());
        assert_eq!(
            manifest2.actions[0].target.byte_offset,
            manifest.actions[0].target.byte_offset
        );
    }

    /// Verify that seed can be omitted (it is optional).
    #[test]
    fn manifest_optional_seed() {
        let json = sample_manifest_json().replace(r#""seed": "42","#, "");
        let manifest: CorrosionManifest = serde_json::from_str(&json).unwrap();
        assert!(manifest.seed.is_none());
    }

    // ── Verdict scoring ──────────────────────────────────────────────

    #[test]
    fn verdict_scores_match_spec() {
        assert_eq!(Verdict::FullyRepaired.score(), 1.0);
        assert_eq!(Verdict::PartiallyRepaired.score(), 0.5);
        assert_eq!(Verdict::CorrectlyUnrecoverable.score(), 1.0);
        assert_eq!(Verdict::NotRepaired.score(), 0.0);
        assert_eq!(Verdict::FalsePositive.score(), -0.5);
    }

    #[test]
    fn overall_score_all_fully_repaired() {
        // 3 actions, all FullyRepaired => score = 3.0 / 3 = 1.0
        let report = VerificationReport {
            per_action: vec![
                action_verdict(Verdict::FullyRepaired),
                action_verdict(Verdict::FullyRepaired),
                action_verdict(Verdict::FullyRepaired),
            ],
            overall_score: 1.0,
            summary: VerificationSummary {
                fully_repaired: 3,
                total: 3,
                ..Default::default()
            },
        };
        let sum: f64 = report.per_action.iter().map(|a| a.verdict.score()).sum();
        let score = sum / report.summary.total as f64;
        assert!((score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn overall_score_mixed() {
        // FullyRepaired(1.0) + NotRepaired(0.0) + PartiallyRepaired(0.5) = 1.5 / 3 = 0.5
        let sum = Verdict::FullyRepaired.score()
            + Verdict::NotRepaired.score()
            + Verdict::PartiallyRepaired.score();
        let score = sum / 3.0;
        assert!((score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn overall_score_with_false_positive() {
        // FullyRepaired(1.0) + FalsePositive(-0.5) = 0.5 / 2 = 0.25
        let sum = Verdict::FullyRepaired.score() + Verdict::FalsePositive.score();
        let score = sum / 2.0;
        assert!((score - 0.25).abs() < f64::EPSILON);
    }

    // ── verify_repair integration ────────────────────────────────────

    #[test]
    fn fully_repaired_detection() {
        let manifest = make_test_manifest(vec![make_action(
            Difficulty::Easy,
            0,
            vec![0xAA, 0xBB],
            vec![0x00, 0x00],
        )]);

        // Device contains the original bytes => FullyRepaired
        let mut data = vec![0u8; 1024];
        data[0] = 0xAA;
        data[1] = 0xBB;
        let device = MockDevice::from_bytes(data);

        let report = verify_repair(&device, &manifest).unwrap();
        assert_eq!(report.per_action.len(), 1);
        assert_eq!(report.per_action[0].verdict, Verdict::FullyRepaired);
        assert!((report.overall_score - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.summary.fully_repaired, 1);
    }

    #[test]
    fn not_repaired_detection() {
        let manifest = make_test_manifest(vec![make_action(
            Difficulty::Easy,
            0,
            vec![0xAA, 0xBB],
            vec![0x00, 0x00],
        )]);

        // Device still has corrupted bytes => NotRepaired
        let device = MockDevice::from_bytes(vec![0u8; 1024]);

        let report = verify_repair(&device, &manifest).unwrap();
        assert_eq!(report.per_action[0].verdict, Verdict::NotRepaired);
        assert!((report.overall_score - 0.0).abs() < f64::EPSILON);
        assert_eq!(report.summary.not_repaired, 1);
    }

    #[test]
    fn partially_repaired_detection() {
        let manifest = make_test_manifest(vec![make_action(
            Difficulty::Medium,
            0,
            vec![0xAA, 0xBB],
            vec![0x00, 0x00],
        )]);

        // Device has bytes that differ from both original and corrupted.
        let mut data = vec![0u8; 1024];
        data[0] = 0xFF;
        data[1] = 0xFF;
        let device = MockDevice::from_bytes(data);

        let report = verify_repair(&device, &manifest).unwrap();
        assert_eq!(report.per_action[0].verdict, Verdict::PartiallyRepaired);
        assert!((report.overall_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn correctly_unrecoverable_for_impossible() {
        let manifest = make_test_manifest(vec![make_action(
            Difficulty::Impossible,
            0,
            vec![0xAA, 0xBB],
            vec![0x00, 0x00],
        )]);

        // Device still has corrupted bytes AND difficulty is Impossible
        // => CorrectlyUnrecoverable
        let device = MockDevice::from_bytes(vec![0u8; 1024]);

        let report = verify_repair(&device, &manifest).unwrap();
        assert_eq!(report.per_action[0].verdict, Verdict::CorrectlyUnrecoverable);
        assert!((report.overall_score - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.summary.correctly_unrecoverable, 1);
    }

    #[test]
    fn false_positive_for_impossible() {
        let manifest = make_test_manifest(vec![make_action(
            Difficulty::Impossible,
            0,
            vec![0xAA, 0xBB],
            vec![0x00, 0x00],
        )]);

        // Device has the *original* bytes for an Impossible action
        // => FalsePositive (tool fabricated data)
        let mut data = vec![0u8; 1024];
        data[0] = 0xAA;
        data[1] = 0xBB;
        let device = MockDevice::from_bytes(data);

        let report = verify_repair(&device, &manifest).unwrap();
        assert_eq!(report.per_action[0].verdict, Verdict::FalsePositive);
        assert!((report.overall_score - (-0.5)).abs() < f64::EPSILON);
        assert_eq!(report.summary.false_positive, 1);
    }

    #[test]
    fn multi_action_mixed_report() {
        let manifest = make_test_manifest(vec![
            // Action 0 at offset 0: Easy, original=[0xAA], corrupted=[0x00]
            make_action(Difficulty::Easy, 0, vec![0xAA], vec![0x00]),
            // Action 1 at offset 100: Impossible, original=[0xBB], corrupted=[0x11]
            make_action(Difficulty::Impossible, 100, vec![0xBB], vec![0x11]),
        ]);

        let mut data = vec![0u8; 1024];
        // Action 0: repaired to original
        data[0] = 0xAA;
        // Action 1: left as corrupted (correct for Impossible)
        data[100] = 0x11;
        let device = MockDevice::from_bytes(data);

        let report = verify_repair(&device, &manifest).unwrap();
        assert_eq!(report.per_action[0].verdict, Verdict::FullyRepaired);
        assert_eq!(report.per_action[1].verdict, Verdict::CorrectlyUnrecoverable);
        // (1.0 + 1.0) / 2 = 1.0
        assert!((report.overall_score - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.summary.fully_repaired, 1);
        assert_eq!(report.summary.correctly_unrecoverable, 1);
        assert_eq!(report.summary.total, 2);
    }

    #[test]
    fn empty_manifest_scores_perfectly() {
        let manifest = make_test_manifest(vec![]);
        let device = MockDevice::new(1024);

        let report = verify_repair(&device, &manifest).unwrap();
        assert!(report.per_action.is_empty());
        assert!((report.overall_score - 1.0).abs() < f64::EPSILON);
        assert_eq!(report.summary.total, 0);
    }

    // ── Test helpers ─────────────────────────────────────────────────

    fn action_verdict(verdict: Verdict) -> ActionVerdict {
        ActionVerdict {
            action_index: 0,
            technique: "test".into(),
            difficulty: Difficulty::Easy,
            fs_structure: "Test".into(),
            verdict,
        }
    }

    fn make_action(
        difficulty: Difficulty,
        byte_offset: u64,
        original: Vec<u8>,
        corrupted: Vec<u8>,
    ) -> CorruptionAction {
        let length = original.len();
        CorruptionAction {
            technique: "test_technique".into(),
            difficulty,
            target: CorruptionTarget {
                lba: byte_offset / 512,
                byte_offset,
                length,
                fs_structure: "Test Structure".into(),
            },
            description: "test action".into(),
            original,
            corrupted,
        }
    }

    fn make_test_manifest(actions: Vec<CorruptionAction>) -> CorrosionManifest {
        CorrosionManifest {
            version: "1.0".into(),
            timestamp: "2026-01-15T10:30:00Z".into(),
            seed: None,
            image_path: "/tmp/test.img".into(),
            clean_hash: "sha256:0000".into(),
            corrupted_hash: "sha256:1111".into(),
            target_type: "disk_image".into(),
            fs_type: "fat32".into(),
            scenario: "test".into(),
            stats: CorruptionStats {
                total_mutations: actions.len() as u64,
                bytes_corrupted: actions.iter().map(|a| a.target.length as u64).sum(),
                by_mode: HashMap::new(),
                by_difficulty: HashMap::new(),
            },
            actions,
        }
    }
}
