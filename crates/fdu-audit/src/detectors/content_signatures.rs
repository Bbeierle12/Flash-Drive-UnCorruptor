//! Content signature detector — scans for known malware/suspicious file signatures.
//!
//! Uses the existing `fdu_core::recovery::carving::scan_signatures` to find files,
//! then checks for suspicious content patterns (PE executables, shell scripts,
//! autorun.inf, etc.).

use crate::detector::{Detector, Phase, ScanContext};
use fdu_core::device::traits::DeviceExt;
use fdu_models::{Evidence, Finding, Severity};

pub struct ContentSignatureDetector;

/// Suspicious content patterns to scan for.
struct SuspiciousPattern {
    name: &'static str,
    magic: &'static [u8],
    severity: Severity,
    description: &'static str,
}

const SUSPICIOUS_PATTERNS: &[SuspiciousPattern] = &[
    SuspiciousPattern {
        name: "Windows PE executable",
        magic: b"MZ",
        severity: Severity::Medium,
        description: "Windows executable found on removable media. May be legitimate \
                      or a malware payload.",
    },
    SuspiciousPattern {
        name: "ELF executable",
        magic: b"\x7fELF",
        severity: Severity::Medium,
        description: "Linux ELF binary found on removable media.",
    },
    SuspiciousPattern {
        name: "Shell script",
        magic: b"#!/",
        severity: Severity::Medium,
        description: "Shell script found on removable media. Scripts can execute arbitrary \
                      commands — inspect before running.",
    },
];

/// Known autorun-style patterns to scan for (all lowercase — input is
/// lowercased before comparison so we catch every casing variant).
const AUTORUN_SIGNATURES: &[&[u8]] = &[
    b"[autorun]",
    b"autorun.inf",
];

impl Detector for ContentSignatureDetector {
    fn name(&self) -> &str {
        "Content Signature Detector"
    }

    fn phase(&self) -> Phase {
        Phase::Content
    }

    fn detect(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        let mut findings = Vec::new();

        // Scan first sectors for autorun content
        findings.extend(scan_for_autorun(ctx));

        // Scan for suspicious file signatures in the first few MB
        findings.extend(scan_for_executables(ctx));

        Ok(findings)
    }
}

/// Scan first sectors of each partition for autorun.inf content.
fn scan_for_autorun(ctx: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut found_patterns = std::collections::HashSet::new();

    // Scan first 16MB for autorun patterns — autorun.inf can appear anywhere
    // in the first partition, not just the first few sectors.
    let scan_size = ctx.device.size().min(16 * 1024 * 1024) as usize;
    let chunk_size = 64 * 1024; // 64KB chunks

    let mut offset = 0u64;
    while offset < scan_size as u64 {
        let read_size = chunk_size.min(scan_size - offset as usize);
        let data = match ctx.device.read_exact_at(offset, read_size) {
            Ok(d) => d,
            Err(_) => break,
        };

        // Convert chunk to lowercase ASCII for case-insensitive matching.
        // Autorun patterns are ASCII, so byte-level lowering is correct.
        let data_lower: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();

        for pattern in AUTORUN_SIGNATURES {
            if found_patterns.contains(pattern) {
                continue;
            }
            if let Some(pos) = find_subsequence(&data_lower, pattern) {
                found_patterns.insert(pattern);
                findings.push(
                    Finding::new(
                        "content.autorun",
                        Severity::High,
                        "Autorun file detected",
                        "An autorun.inf or similar auto-execution trigger was found. \
                         This is a classic malware distribution vector on USB devices.",
                    )
                    .with_evidence(Evidence::Bytes {
                        offset: offset + pos as u64,
                        data: data[pos..data.len().min(pos + 64)].to_vec(),
                        label: "Autorun content".into(),
                    })
                    .with_remediation(
                        "Do not allow this device to auto-mount. Inspect the autorun.inf \
                         content before proceeding.",
                    ),
                );
            }
        }

        offset += read_size as u64;
    }

    findings
}

/// Scan for executable file signatures.
fn scan_for_executables(ctx: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Scan first 16MB for executable signatures
    let scan_size = ctx.device.size().min(16 * 1024 * 1024) as usize;
    let chunk_size = 64 * 1024;

    let mut offset = 0u64;
    let mut found_types = std::collections::HashSet::new();

    while offset < scan_size as u64 {
        let read_size = chunk_size.min(scan_size - offset as usize);
        let data = match ctx.device.read_exact_at(offset, read_size) {
            Ok(d) => d,
            Err(_) => break,
        };

        for pattern in SUSPICIOUS_PATTERNS {
            if found_types.contains(pattern.name) {
                continue;
            }
            if find_subsequence(&data, pattern.magic).is_some() {
                found_types.insert(pattern.name);
                findings.push(Finding::new(
                    format!("content.suspicious.{}", pattern.name.to_lowercase().replace(' ', "_")),
                    pattern.severity,
                    format!("{} found", pattern.name),
                    pattern.description,
                ));
            }
        }

        offset += read_size as u64;
    }

    findings
}

/// Find a byte subsequence in a haystack.
///
/// Returns `None` for empty needles — an empty pattern is not a meaningful
/// match and would cause false positives if a signature were accidentally
/// cleared.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_subsequence_works() {
        let data = b"hello world [autorun] test";
        assert!(find_subsequence(data, b"[autorun]").is_some());
        assert!(find_subsequence(data, b"notfound").is_none());
    }

    #[test]
    fn find_subsequence_empty() {
        // Empty needle should NOT match — it would cause false positives
        assert!(find_subsequence(b"hello", b"").is_none());
        assert!(find_subsequence(b"", b"x").is_none());
    }
}
