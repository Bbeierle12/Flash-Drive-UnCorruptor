//! Extraction and quarantine types — policies, manifests, extracted files.

use crate::threat::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use uuid::Uuid;

/// Policy controlling which files pass through quarantine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtractionPolicy {
    /// Only files that pass all security checks.
    VerifiedOnly,
    /// Include files with low-risk suspicious indicators.
    IncludeSuspicious,
    /// Extract everything for forensic analysis — no filtering.
    ForensicFull,
}

impl fmt::Display for ExtractionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtractionPolicy::VerifiedOnly => write!(f, "verified-only"),
            ExtractionPolicy::IncludeSuspicious => write!(f, "include-suspicious"),
            ExtractionPolicy::ForensicFull => write!(f, "forensic-full"),
        }
    }
}

impl ExtractionPolicy {
    /// Parse from a CLI-friendly string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "verified-only" | "verified" => Some(Self::VerifiedOnly),
            "include-suspicious" | "suspicious" => Some(Self::IncludeSuspicious),
            "forensic-full" | "forensic" | "full" => Some(Self::ForensicFull),
            _ => None,
        }
    }

    /// Whether a file at the given threat level should be extracted under this policy.
    pub fn allows(&self, threat_level: Severity) -> bool {
        match self {
            ExtractionPolicy::VerifiedOnly => threat_level <= Severity::Info,
            ExtractionPolicy::IncludeSuspicious => threat_level <= Severity::Low,
            ExtractionPolicy::ForensicFull => true,
        }
    }
}

/// Manifest describing all files staged through quarantine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionManifest {
    /// All extracted files.
    pub files: Vec<ExtractedFile>,
    /// Root of the quarantine staging area.
    pub quarantine_path: PathBuf,
    /// Policy used for this extraction.
    pub policy: ExtractionPolicy,
    /// SHA-256 hashes keyed by output path (for integrity verification).
    pub integrity_hashes: HashMap<PathBuf, String>,
}

impl ExtractionManifest {
    /// Total bytes across all extracted files.
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size_bytes).sum()
    }

    /// Count of files that had any associated findings.
    pub fn flagged_count(&self) -> usize {
        self.files.iter().filter(|f| !f.findings.is_empty()).count()
    }
}

/// A single file that was extracted through the quarantine process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFile {
    /// Original path on the source device.
    pub original_path: String,
    /// Path in the quarantine staging area.
    pub quarantine_path: PathBuf,
    /// SHA-256 hash of the extracted content.
    pub sha256: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Assessed threat level for this file.
    pub threat_level: Severity,
    /// IDs of findings associated with this file.
    pub findings: Vec<Uuid>,
}

/// Progress update during extraction (passed to progress callback).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionProgress {
    /// How many files have been processed so far.
    pub files_processed: usize,
    /// Total files to process.
    pub files_total: usize,
    /// Bytes transferred so far.
    pub bytes_transferred: u64,
    /// Current file being processed.
    pub current_file: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_allows() {
        assert!(ExtractionPolicy::VerifiedOnly.allows(Severity::Info));
        assert!(!ExtractionPolicy::VerifiedOnly.allows(Severity::Low));

        assert!(ExtractionPolicy::IncludeSuspicious.allows(Severity::Low));
        assert!(!ExtractionPolicy::IncludeSuspicious.allows(Severity::Medium));

        assert!(ExtractionPolicy::ForensicFull.allows(Severity::Critical));
    }

    #[test]
    fn policy_parse() {
        assert_eq!(
            ExtractionPolicy::from_str_loose("verified-only"),
            Some(ExtractionPolicy::VerifiedOnly)
        );
        assert_eq!(
            ExtractionPolicy::from_str_loose("forensic_full"),
            Some(ExtractionPolicy::ForensicFull)
        );
        assert_eq!(ExtractionPolicy::from_str_loose("garbage"), None);
    }

    #[test]
    fn manifest_metrics() {
        let manifest = ExtractionManifest {
            files: vec![
                ExtractedFile {
                    original_path: "/file1.txt".into(),
                    quarantine_path: PathBuf::from("/tmp/q/file1.txt"),
                    sha256: "abc".into(),
                    size_bytes: 1000,
                    threat_level: Severity::Info,
                    findings: vec![],
                },
                ExtractedFile {
                    original_path: "/file2.exe".into(),
                    quarantine_path: PathBuf::from("/tmp/q/file2.exe"),
                    sha256: "def".into(),
                    size_bytes: 2000,
                    threat_level: Severity::Medium,
                    findings: vec![Uuid::new_v4()],
                },
            ],
            quarantine_path: PathBuf::from("/tmp/q"),
            policy: ExtractionPolicy::ForensicFull,
            integrity_hashes: HashMap::new(),
        };

        assert_eq!(manifest.total_bytes(), 3000);
        assert_eq!(manifest.flagged_count(), 1);
    }

    #[test]
    fn serialization_roundtrip() {
        let mut hashes = HashMap::new();
        hashes.insert(PathBuf::from("/out/file.txt"), "abc123".to_string());
        let manifest = ExtractionManifest {
            files: vec![ExtractedFile {
                original_path: "/file.txt".into(),
                quarantine_path: PathBuf::from("/tmp/q/file.txt"),
                sha256: "abc123".into(),
                size_bytes: 42,
                threat_level: Severity::Info,
                findings: vec![],
            }],
            quarantine_path: PathBuf::from("/tmp/q"),
            policy: ExtractionPolicy::VerifiedOnly,
            integrity_hashes: hashes,
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let m2: ExtractionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.policy, manifest.policy);
        assert_eq!(m2.quarantine_path, manifest.quarantine_path);
        assert_eq!(m2.files.len(), manifest.files.len());
        assert_eq!(m2.files[0].sha256, manifest.files[0].sha256);
        assert_eq!(m2.files[0].size_bytes, manifest.files[0].size_bytes);
        assert_eq!(m2.integrity_hashes.len(), manifest.integrity_hashes.len());
    }
}
