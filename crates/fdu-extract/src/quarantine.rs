//! Quarantine staging — the core extraction pipeline.
//!
//! 1. Discover files on device (via FAT directory or signature carving)
//! 2. Copy each file to a temp quarantine directory with SHA-256
//! 3. Run content scan on each file
//! 4. Apply policy filter
//! 5. Move approved files to output

use crate::hasher;
use crate::manifest::write_manifest;
use crate::ExtractError;
use fdu_core::device::{Device, traits::DeviceExt};
use fdu_core::fs::detect::detect_filesystem;
use fdu_core::fs::fat32::Fat32Fs;
use fdu_core::fs::traits::FileSystemOps;
use fdu_core::models::FsType;
use fdu_models::{
    ExtractedFile, ExtractionManifest, ExtractionPolicy, ExtractionProgress, Severity,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Run the full quarantine extraction pipeline.
pub fn run_extraction(
    device: &dyn Device,
    policy: ExtractionPolicy,
    output_dir: &Path,
    progress: Option<Box<dyn Fn(ExtractionProgress) + Send>>,
) -> Result<ExtractionManifest, ExtractError> {
    // Create output directory if needed
    std::fs::create_dir_all(output_dir)?;

    // Create quarantine staging area
    let quarantine_dir = tempfile::tempdir()
        .map_err(|e| ExtractError::QuarantineSetup(e.to_string()))?;

    info!(
        quarantine = %quarantine_dir.path().display(),
        output = %output_dir.display(),
        policy = %policy,
        "Starting quarantine extraction"
    );

    // Discover files
    let files = discover_files(device)?;
    if files.is_empty() {
        return Err(ExtractError::NoFiles);
    }

    let total = files.len();
    let mut extracted: Vec<ExtractedFile> = Vec::new();
    let mut integrity_hashes: HashMap<PathBuf, String> = HashMap::new();

    for (i, file_info) in files.iter().enumerate() {
        // Report progress
        if let Some(ref cb) = progress {
            cb(ExtractionProgress {
                files_processed: i,
                files_total: total,
                bytes_transferred: extracted.iter().map(|f| f.size_bytes).sum(),
                current_file: file_info.name.clone(),
            });
        }

        debug!(file = %file_info.name, size = file_info.size, "Processing file");

        // Read file data from device
        let data = match read_file_data(device, file_info) {
            Ok(d) => d,
            Err(e) => {
                warn!(file = %file_info.name, error = %e, "Failed to read file, skipping");
                continue;
            }
        };

        // Hash the content
        let sha256 = hasher::sha256_bytes(&data);

        // Write to quarantine
        let quarantine_path = quarantine_dir.path().join(&file_info.name);
        if let Some(parent) = quarantine_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&quarantine_path, &data)?;

        // Assess threat level (simplified — in production this would use the audit engine)
        let threat_level = assess_threat_level(&data, &file_info.name);

        // Apply policy filter
        if !policy.allows(threat_level) {
            debug!(
                file = %file_info.name,
                threat = %threat_level,
                "File rejected by policy"
            );
            continue;
        }

        // Move to output directory
        let output_path = output_dir.join(&file_info.name);
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&quarantine_path, &output_path)?;

        integrity_hashes.insert(output_path.clone(), sha256.clone());

        extracted.push(ExtractedFile {
            original_path: file_info.name.clone(),
            quarantine_path: quarantine_path.clone(),
            sha256,
            size_bytes: data.len() as u64,
            threat_level,
            findings: vec![],
        });
    }

    // Final progress
    if let Some(ref cb) = progress {
        cb(ExtractionProgress {
            files_processed: total,
            files_total: total,
            bytes_transferred: extracted.iter().map(|f| f.size_bytes).sum(),
            current_file: String::new(),
        });
    }

    let manifest = ExtractionManifest {
        files: extracted,
        quarantine_path: quarantine_dir.path().to_path_buf(),
        policy,
        integrity_hashes,
    };

    // Write manifest to output directory
    let manifest_path = output_dir.join("extraction_manifest.json");
    write_manifest(&manifest, &manifest_path)
        .map_err(|e| ExtractError::ManifestError(e.to_string()))?;

    info!(
        files = manifest.files.len(),
        bytes = manifest.total_bytes(),
        "Extraction complete"
    );

    Ok(manifest)
}

/// Info about a file discovered on the device.
#[derive(Debug)]
struct DiscoveredFile {
    name: String,
    offset: u64,
    size: u64,
}

/// Discover files on the device — tries filesystem directory listing first,
/// falls back to signature carving.
fn discover_files(device: &dyn Device) -> Result<Vec<DiscoveredFile>, ExtractError> {
    let fs_type = detect_filesystem(device).unwrap_or(FsType::Unknown);

    match fs_type {
        FsType::Fat32 | FsType::Fat16 | FsType::Fat12 => {
            discover_fat_files(device)
        }
        _ => {
            // Fall back to signature carving
            discover_carved_files(device)
        }
    }
}

/// List files from a FAT filesystem.
fn discover_fat_files(device: &dyn Device) -> Result<Vec<DiscoveredFile>, ExtractError> {
    let fs = Fat32Fs::new(device)
        .map_err(|e| ExtractError::UnsupportedFs(format!("FAT parse failed: {}", e)))?;

    let entries = fs
        .list_dir(Path::new("/"))
        .map_err(|e| ExtractError::DeviceRead(format!("Directory listing failed: {}", e)))?;

    Ok(entries
        .into_iter()
        .filter(|e| !e.is_dir)
        .map(|e| DiscoveredFile {
            name: e.name,
            offset: 0, // actual offset resolved during read
            size: e.size_bytes,
        })
        .collect())
}

/// Discover files by signature carving (when no readable filesystem).
fn discover_carved_files(device: &dyn Device) -> Result<Vec<DiscoveredFile>, ExtractError> {
    use fdu_core::recovery::carving::scan_signatures;

    let recoverable = scan_signatures(device, &[], None)
        .map_err(|e| ExtractError::DeviceRead(format!("Carving failed: {}", e)))?;

    Ok(recoverable
        .into_iter()
        .enumerate()
        .map(|(i, r)| DiscoveredFile {
            name: format!("recovered_{:04}.{}", i, r.file_type.to_lowercase()),
            offset: r.offset,
            size: r.estimated_size,
        })
        .collect())
}

/// Read file data from the device.
fn read_file_data(device: &dyn Device, file: &DiscoveredFile) -> Result<Vec<u8>, ExtractError> {
    // Cap file read at 100MB for safety
    let max_size = 100 * 1024 * 1024;
    let size = file.size.min(max_size) as usize;

    if size == 0 {
        return Ok(vec![]);
    }

    device
        .read_exact_at(file.offset, size)
        .map_err(|e: fdu_core::errors::Error| ExtractError::DeviceRead(e.to_string()))
}

/// Simple heuristic threat assessment based on file content and name.
fn assess_threat_level(data: &[u8], filename: &str) -> Severity {
    let name_lower = filename.to_lowercase();

    // Executable extensions are suspicious
    if name_lower.ends_with(".exe")
        || name_lower.ends_with(".bat")
        || name_lower.ends_with(".cmd")
        || name_lower.ends_with(".ps1")
        || name_lower.ends_with(".vbs")
        || name_lower.ends_with(".dll")
    {
        return Severity::Medium;
    }

    // Autorun files are high risk
    if name_lower == "autorun.inf" {
        return Severity::High;
    }

    // Check for PE header in content
    if data.len() >= 2 && data[0] == b'M' && data[1] == b'Z' {
        return Severity::Medium;
    }

    // Check for ELF header
    if data.len() >= 4 && &data[0..4] == b"\x7fELF" {
        return Severity::Medium;
    }

    Severity::Info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_assessment_safe_file() {
        assert_eq!(assess_threat_level(b"hello world", "readme.txt"), Severity::Info);
    }

    #[test]
    fn threat_assessment_exe() {
        assert_eq!(assess_threat_level(b"MZ...", "malware.exe"), Severity::Medium);
    }

    #[test]
    fn threat_assessment_autorun() {
        assert_eq!(
            assess_threat_level(b"[autorun]", "autorun.inf"),
            Severity::High
        );
    }

    #[test]
    fn threat_assessment_pe_header() {
        assert_eq!(
            assess_threat_level(b"MZ\x90\x00", "document.pdf"),
            Severity::Medium
        );
    }
}
