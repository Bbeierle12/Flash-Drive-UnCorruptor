//! Core data models shared across all fdu-core modules.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

// ── Filesystem Types ────────────────────────────────────────────────

/// Recognized filesystem types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FsType {
    Fat12,
    Fat16,
    Fat32,
    ExFat,
    Ntfs,
    Ext2,
    Ext3,
    Ext4,
    HfsPlus,
    Apfs,
    Unknown,
}

impl fmt::Display for FsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsType::Fat12 => write!(f, "FAT12"),
            FsType::Fat16 => write!(f, "FAT16"),
            FsType::Fat32 => write!(f, "FAT32"),
            FsType::ExFat => write!(f, "exFAT"),
            FsType::Ntfs => write!(f, "NTFS"),
            FsType::Ext2 => write!(f, "ext2"),
            FsType::Ext3 => write!(f, "ext3"),
            FsType::Ext4 => write!(f, "ext4"),
            FsType::HfsPlus => write!(f, "HFS+"),
            FsType::Apfs => write!(f, "APFS"),
            FsType::Unknown => write!(f, "Unknown"),
        }
    }
}

// ── Device Info ─────────────────────────────────────────────────────

/// Information about a detected storage device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// System identifier (e.g., "/dev/sda1", "\\.\PhysicalDrive1")
    pub id: String,
    /// Human-readable name / model string
    pub name: String,
    /// Total size in bytes
    pub size_bytes: u64,
    /// Detected filesystem type
    pub fs_type: Option<FsType>,
    /// Whether this is a removable device
    pub is_removable: bool,
    /// Mount point, if mounted
    pub mount_point: Option<PathBuf>,
    /// Whether we can read from this device
    pub is_readable: bool,
}

impl DeviceInfo {
    /// Human-readable size string (e.g., "32.0 GB")
    pub fn size_display(&self) -> String {
        format_bytes(self.size_bytes)
    }
}

// ── Filesystem Metadata ─────────────────────────────────────────────

/// Metadata about a mounted/parsed filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsMetadata {
    pub fs_type: FsType,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub cluster_size: u32,
    pub total_clusters: u64,
    pub volume_label: Option<String>,
}

// ── Directory Entry ─────────────────────────────────────────────────

/// A file or directory entry within a filesystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size_bytes: u64,
    pub created: Option<u64>,
    pub modified: Option<u64>,
}

// ── Validation / Scan Results ───────────────────────────────────────

/// Severity of a filesystem issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Warning => write!(f, "WARN"),
            Severity::Error => write!(f, "ERROR"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single issue found during filesystem validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsIssue {
    pub severity: Severity,
    pub code: String,
    pub message: String,
    /// Whether this issue can be automatically repaired
    pub repairable: bool,
}

/// Results of a filesystem validation scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub device_id: String,
    pub fs_type: FsType,
    pub metadata: FsMetadata,
    pub issues: Vec<FsIssue>,
    pub scan_duration_ms: u64,
}

impl ValidationReport {
    pub fn is_healthy(&self) -> bool {
        !self
            .issues
            .iter()
            .any(|i| matches!(i.severity, Severity::Error | Severity::Critical))
    }

    pub fn error_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Error | Severity::Critical))
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Warning))
            .count()
    }
}

// ── Diagnostics ─────────────────────────────────────────────────────

/// Results of a drive health diagnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub device_id: String,
    pub total_sectors: u64,
    pub bad_sectors: Vec<u64>,
    pub read_speed_mbps: Option<f64>,
    pub write_speed_mbps: Option<f64>,
    pub scan_duration_ms: u64,
}

impl DiagnosticReport {
    pub fn bad_sector_count(&self) -> usize {
        self.bad_sectors.len()
    }

    pub fn health_score(&self) -> f64 {
        if self.total_sectors == 0 {
            return 0.0;
        }
        let bad_ratio = self.bad_sectors.len() as f64 / self.total_sectors as f64;
        (1.0 - bad_ratio) * 100.0
    }
}

// ── Recovery ────────────────────────────────────────────────────────

/// A file detected during recovery scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverableFile {
    /// Detected file type (e.g., "JPEG", "PDF")
    pub file_type: String,
    /// Magic bytes signature used for detection
    pub signature: Vec<u8>,
    /// Offset on device where file starts
    pub offset: u64,
    /// Estimated file size in bytes
    pub estimated_size: u64,
    /// Confidence score 0.0–1.0
    pub confidence: f64,
    /// Original filename if recoverable from directory entry
    pub original_name: Option<String>,
}

/// Strategy for file recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    /// Scan for known file signatures (magic bytes)
    SignatureCarving,
    /// Scan orphaned clusters via FAT/allocation table
    ClusterScan,
    /// Both strategies combined
    Both,
}

/// Options for a recovery operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryOptions {
    pub strategy: RecoveryStrategy,
    pub output_dir: PathBuf,
    /// Only recover these file types (empty = all)
    pub file_types: Vec<String>,
    /// Max file size to recover (0 = unlimited)
    pub max_file_size: u64,
}

/// Result of a recovery operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub device_id: String,
    pub files_found: usize,
    pub files_recovered: usize,
    pub bytes_recovered: u64,
    pub recovered_files: Vec<RecoveredFile>,
    pub scan_duration_ms: u64,
}

/// A successfully recovered file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    pub output_path: PathBuf,
    pub file_type: String,
    pub size_bytes: u64,
    pub confidence: f64,
}

// ── Repair ──────────────────────────────────────────────────────────

/// Options for a repair operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairOptions {
    /// User has explicitly confirmed destructive operation
    pub confirm_unsafe: bool,
    /// Create a backup of critical structures before repair
    pub backup_first: bool,
    /// Rebuild the FAT table
    pub fix_fat: bool,
    /// Remove bad cluster chains
    pub remove_bad_chains: bool,
}

/// Result of a repair operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairReport {
    pub device_id: String,
    pub fixes_applied: Vec<String>,
    pub errors_fixed: usize,
    pub bytes_written: u64,
    pub backup_path: Option<PathBuf>,
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Format a byte count into human-readable form.
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
        assert_eq!(format_bytes(32_000_000_000), "29.8 GB");
    }

    #[test]
    fn test_fs_type_display() {
        assert_eq!(FsType::Fat32.to_string(), "FAT32");
        assert_eq!(FsType::Ntfs.to_string(), "NTFS");
        assert_eq!(FsType::Ext4.to_string(), "ext4");
        assert_eq!(FsType::HfsPlus.to_string(), "HFS+");
    }

    #[test]
    fn test_validation_report_healthy() {
        let report = ValidationReport {
            device_id: "test".into(),
            fs_type: FsType::Fat32,
            metadata: FsMetadata {
                fs_type: FsType::Fat32,
                total_bytes: 1_000_000,
                used_bytes: 500_000,
                free_bytes: 500_000,
                cluster_size: 4096,
                total_clusters: 244,
                volume_label: None,
            },
            issues: vec![FsIssue {
                severity: Severity::Info,
                code: "INFO001".into(),
                message: "Volume label not set".into(),
                repairable: false,
            }],
            scan_duration_ms: 100,
        };
        assert!(report.is_healthy());
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn test_diagnostic_health_score() {
        let report = DiagnosticReport {
            device_id: "test".into(),
            total_sectors: 1000,
            bad_sectors: vec![10, 20, 30],
            read_speed_mbps: Some(25.0),
            write_speed_mbps: None,
            scan_duration_ms: 500,
        };
        assert!((report.health_score() - 99.7).abs() < 0.1);
        assert_eq!(report.bad_sector_count(), 3);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let info = DeviceInfo {
            id: "/dev/sda1".into(),
            name: "USB Flash Drive".into(),
            size_bytes: 32_000_000_000,
            fs_type: Some(FsType::Fat32),
            is_removable: true,
            mount_point: Some(PathBuf::from("/mnt/usb")),
            is_readable: true,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: DeviceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "/dev/sda1");
        assert_eq!(deserialized.size_display(), "29.8 GB");
    }
}
