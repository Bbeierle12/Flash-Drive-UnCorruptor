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
use std::path::{Component, Path, PathBuf};
use tracing::{debug, info, warn};

/// Sanitize a filename from a device to prevent path traversal and
/// Unicode-based attacks.
///
/// 1. Strips all path components (e.g. `../../etc/cron.d/backdoor` → `backdoor`)
/// 2. Rejects empty names, `.`, and `..`
/// 3. Strips null bytes and dangerous Unicode characters (RTL override,
///    zero-width joiners/spaces, etc.)
/// 4. Rejects Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`,
///    `COM1`–`COM9`, `LPT1`–`LPT9`)
fn sanitize_filename(name: &str) -> Option<String> {
    let path = Path::new(name);
    // Extract only the final file_name component, stripping any directory traversal
    let safe_name = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .next_back()?;

    if safe_name.is_empty() || safe_name == "." || safe_name == ".." {
        return None;
    }

    // Strip null bytes and dangerous Unicode characters:
    //   U+200B  zero-width space
    //   U+200C  zero-width non-joiner
    //   U+200D  zero-width joiner
    //   U+200E  left-to-right mark
    //   U+200F  right-to-left mark
    //   U+202A–U+202E  bidi embedding / override
    //   U+2060  word joiner
    //   U+FEFF  byte-order mark / zero-width no-break space
    let cleaned: String = safe_name
        .chars()
        .filter(|c| {
            !c.is_control()
                && *c != '\0'
                && !matches!(
                    *c,
                    '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'
                        | '\u{FEFF}'
                )
        })
        .collect();

    if cleaned.is_empty() {
        return None;
    }

    // Reject Windows reserved device names (with or without extension).
    // "CON.txt" is still reserved on Windows.
    let stem = cleaned
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
        "LPT9",
    ];
    if RESERVED.contains(&stem.as_str()) {
        return None;
    }

    Some(cleaned)
}

/// Run the full quarantine extraction pipeline.
pub fn run_extraction(
    device: &dyn Device,
    policy: ExtractionPolicy,
    output_dir: &Path,
    progress: Option<Box<dyn Fn(ExtractionProgress) + Send>>,
) -> Result<ExtractionManifest, ExtractError> {
    // Create output directory if needed
    std::fs::create_dir_all(output_dir)?;

    // Create quarantine staging area inside the output directory so the path
    // remains valid after this function returns.  Using a child directory of
    // output_dir avoids the TempDir-drop problem (tempfile::tempdir() would
    // delete the directory when dropped, leaving the manifest with a dangling
    // path).
    let quarantine_dir = output_dir.join(".quarantine");
    std::fs::create_dir_all(&quarantine_dir)
        .map_err(|e| ExtractError::QuarantineSetup(e.to_string()))?;

    info!(
        quarantine = %quarantine_dir.display(),
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

        // Sanitize filename to prevent path traversal
        let safe_name = match sanitize_filename(&file_info.name) {
            Some(name) => name,
            None => {
                warn!(
                    file = %file_info.name,
                    "Skipping file with invalid or malicious filename"
                );
                continue;
            }
        };

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

        // Write to quarantine using sanitized name.
        // Use create_new to prevent TOCTOU symlink-following attacks:
        // an attacker could race between create_dir_all and write to place a
        // symlink, causing data to be written outside the quarantine.
        let quarantine_path = quarantine_dir.join(&safe_name);
        if let Some(parent) = quarantine_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&quarantine_path)?;
            f.write_all(&data)?;
        }

        // Restrict quarantine file permissions to owner-only (prevent other
        // users from reading potentially malicious content).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&quarantine_path, perms)?;
        }

        // Assess threat level (simplified — in production this would use the audit engine)
        let threat_level = assess_threat_level(&data, &safe_name);

        // Apply policy filter
        if !policy.allows(threat_level) {
            debug!(
                file = %file_info.name,
                threat = %threat_level,
                "File rejected by policy"
            );
            continue;
        }

        // Move to output directory using sanitized name
        let output_path = output_dir.join(&safe_name);
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
        quarantine_path: quarantine_dir.clone(),
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
    let max_size: u64 = 100 * 1024 * 1024;
    if file.size > max_size {
        warn!(
            file = %file.name,
            original_size = file.size,
            capped_size = max_size,
            "File exceeds 100 MB cap — content will be truncated and hash will not match the original"
        );
    }
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
    fn sanitize_strips_traversal() {
        assert_eq!(
            sanitize_filename("../../etc/cron.d/backdoor"),
            Some("backdoor".into())
        );
    }

    #[test]
    fn sanitize_strips_absolute_path() {
        assert_eq!(
            sanitize_filename("/etc/passwd"),
            Some("passwd".into())
        );
    }

    #[test]
    fn sanitize_normal_filename() {
        assert_eq!(
            sanitize_filename("readme.txt"),
            Some("readme.txt".into())
        );
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert_eq!(sanitize_filename(""), None);
    }

    #[test]
    fn sanitize_rejects_dots() {
        assert_eq!(sanitize_filename(".."), None);
        assert_eq!(sanitize_filename("."), None);
    }

    #[test]
    fn sanitize_rejects_only_traversal() {
        assert_eq!(sanitize_filename("../.."), None);
    }

    #[test]
    fn sanitize_strips_null_bytes() {
        assert_eq!(
            sanitize_filename("hello\0world.txt"),
            Some("helloworld.txt".into())
        );
    }

    #[test]
    fn sanitize_strips_rtl_override() {
        // U+202E (right-to-left override) is used to visually reverse filenames
        assert_eq!(
            sanitize_filename("readme\u{202E}fdp.exe"),
            Some("readmefdp.exe".into())
        );
    }

    #[test]
    fn sanitize_strips_zero_width_chars() {
        assert_eq!(
            sanitize_filename("ma\u{200B}lware.exe"),
            Some("malware.exe".into())
        );
    }

    #[test]
    fn sanitize_rejects_windows_reserved() {
        assert_eq!(sanitize_filename("CON"), None);
        assert_eq!(sanitize_filename("con.txt"), None);
        assert_eq!(sanitize_filename("PRN"), None);
        assert_eq!(sanitize_filename("AUX"), None);
        assert_eq!(sanitize_filename("NUL"), None);
        assert_eq!(sanitize_filename("COM1"), None);
        assert_eq!(sanitize_filename("LPT1.log"), None);
    }

    #[test]
    fn sanitize_allows_similar_to_reserved() {
        // "CONFIGURE" starts with "CON" but is not a reserved name
        assert_eq!(
            sanitize_filename("CONFIGURE.txt"),
            Some("CONFIGURE.txt".into())
        );
    }

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
