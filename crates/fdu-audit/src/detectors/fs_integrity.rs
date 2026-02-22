//! Filesystem integrity detector — wraps `fdu_core::fs::validate()`.
//!
//! Translates `FsIssue` items from fdu-core into security `Finding`s.

use crate::detector::{Detector, Phase, ScanContext};
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::FsType;
use fdu_models::{Evidence, Finding, Severity};

pub struct FsIntegrityDetector;

impl Detector for FsIntegrityDetector {
    fn name(&self) -> &str {
        "Filesystem Integrity Detector"
    }

    fn phase(&self) -> Phase {
        Phase::Filesystem
    }

    fn detect(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let fs_type = match detect_filesystem(ctx.device) {
            Ok(ft) => ft,
            Err(_) => return Ok(vec![]),
        };

        match fs_type {
            FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
                self.check_fat(ctx)
            }
            _ => Ok(vec![]),
        }
    }
}

impl FsIntegrityDetector {
    fn check_fat(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let fs = match Fat32Fs::new(ctx.device) {
            Ok(fs) => fs,
            Err(e) => {
                return Ok(vec![Finding::new(
                    "fs.parse_failed",
                    Severity::High,
                    "Filesystem parsing failed",
                    format!(
                        "Could not parse FAT filesystem: {}. This may indicate severe \
                         corruption or a filesystem crafted to exploit parser vulnerabilities.",
                        e
                    ),
                )]);
            }
        };

        let report = match fs.validate() {
            Ok(r) => r,
            Err(e) => {
                return Ok(vec![Finding::new(
                    "fs.validation_failed",
                    Severity::High,
                    "Filesystem validation failed",
                    format!("Validation error: {}", e),
                )]);
            }
        };

        // Translate each FsIssue into a security Finding
        let findings = report
            .issues
            .iter()
            .map(|issue| {
                let severity = match issue.severity {
                    fdu_core::models::Severity::Info => Severity::Info,
                    fdu_core::models::Severity::Warning => Severity::Low,
                    fdu_core::models::Severity::Error => Severity::Medium,
                    fdu_core::models::Severity::Critical => Severity::High,
                };

                Finding::new(
                    format!("fs.integrity.{}", issue.code),
                    severity,
                    format!("Filesystem issue: {}", issue.code),
                    issue.message.clone(),
                )
                .with_evidence(Evidence::Text(format!(
                    "Repairable: {}",
                    if issue.repairable { "yes" } else { "no" }
                )))
            })
            .collect();

        Ok(findings)
    }
}
