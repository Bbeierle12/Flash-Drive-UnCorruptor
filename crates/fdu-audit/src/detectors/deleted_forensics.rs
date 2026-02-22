//! Deleted file forensics detector — wraps `fdu_core::fs::scan_deleted()`.
//!
//! Scans for deleted files that might indicate an attempt to hide evidence
//! or deliver malware.

use crate::detector::{Detector, Phase, ScanContext};
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::FsType;
use fdu_models::{Evidence, Finding, Severity};

pub struct DeletedForensicsDetector;

impl Detector for DeletedForensicsDetector {
    fn name(&self) -> &str {
        "Deleted File Forensics Detector"
    }

    fn phase(&self) -> Phase {
        Phase::Forensics
    }

    fn detect(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let fs_type = match detect_filesystem(ctx.device) {
            Ok(ft) => ft,
            Err(_) => return Ok(vec![]),
        };

        match fs_type {
            FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
                self.scan_fat_deleted(ctx)
            }
            _ => Ok(vec![]),
        }
    }
}

impl DeletedForensicsDetector {
    fn scan_fat_deleted(
        &self,
        ctx: &ScanContext,
    ) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let fs = match Fat32Fs::new(ctx.device) {
            Ok(fs) => fs,
            Err(_) => return Ok(vec![]),
        };

        let deleted = match fs.scan_deleted() {
            Ok(files) => files,
            Err(_) => return Ok(vec![]),
        };

        if deleted.is_empty() {
            return Ok(vec![]);
        }

        let mut findings = Vec::new();

        // Summarize deleted files found
        let total = deleted.len();
        let suspicious_exts: Vec<_> = deleted
            .iter()
            .filter(|f| {
                let ft = f.file_type.to_lowercase();
                ft.contains("exe")
                    || ft.contains("bat")
                    || ft.contains("script")
                    || ft.contains("dll")
            })
            .collect();

        if !suspicious_exts.is_empty() {
            findings.push(
                Finding::new(
                    "forensics.deleted_executables",
                    Severity::Medium,
                    "Deleted executable files found",
                    format!(
                        "Found {} deleted files, {} of which appear to be executables \
                         or scripts. Deleted executables on removable media may indicate \
                         an attempt to hide a malware delivery payload.",
                        total,
                        suspicious_exts.len(),
                    ),
                )
                .with_evidence(Evidence::Metric {
                    key: "deleted_executable_count".into(),
                    value: suspicious_exts.len() as f64,
                }),
            );
        }

        if total > 50 {
            findings.push(
                Finding::new(
                    "forensics.high_deleted_count",
                    Severity::Low,
                    "Large number of deleted files",
                    format!(
                        "Found {} deleted files. A high count of deleted files may \
                         warrant forensic analysis to understand the device's history.",
                        total,
                    ),
                )
                .with_evidence(Evidence::Metric {
                    key: "deleted_file_count".into(),
                    value: total as f64,
                }),
            );
        }

        Ok(findings)
    }
}
