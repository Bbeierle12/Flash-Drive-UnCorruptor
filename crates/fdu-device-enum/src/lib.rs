//! Cross-platform removable device enumeration.
//!
//! Discovers USB flash drives, SD cards, and other removable storage
//! connected to the system.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
pub mod linux;

/// Information about a detected removable storage device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnumeratedDevice {
    /// Block device path (e.g., "/dev/sdb1")
    pub device_path: String,
    /// Parent device path (e.g., "/dev/sdb")
    pub parent_device: Option<String>,
    /// Human-readable model/vendor name
    pub model: String,
    /// Vendor string
    pub vendor: String,
    /// Size in bytes
    pub size_bytes: u64,
    /// Whether it's removable
    pub is_removable: bool,
    /// Current mount point (if mounted)
    pub mount_point: Option<PathBuf>,
    /// Transport type (usb, ata, etc.)
    pub transport: Option<String>,
    /// Logical sector size in bytes (from sysfs, typically 512 or 4096).
    #[serde(default = "default_sector_size")]
    pub sector_size: u32,
}

fn default_sector_size() -> u32 {
    512
}

/// Enumerate all removable storage devices on the system.
pub fn enumerate_devices() -> Result<Vec<EnumeratedDevice>, EnumError> {
    #[cfg(target_os = "linux")]
    return linux::enumerate();

    #[cfg(not(target_os = "linux"))]
    return Err(EnumError::UnsupportedPlatform(
        std::env::consts::OS.to_string(),
    ));
}

/// Errors during device enumeration.
#[derive(thiserror::Error, Debug)]
pub enum EnumError {
    #[error("I/O error during enumeration: {0}")]
    Io(#[from] std::io::Error),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Failed to parse system info: {0}")]
    ParseError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════
    // Phase 8 — Device Enumeration Tests
    // ════════════════════════════════════════════════════════════════

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn phase8_enumerate_returns_unsupported_on_non_linux() {
        let result = enumerate_devices();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, EnumError::UnsupportedPlatform(_)));
    }

    #[test]
    fn phase8_unsupported_platform_display() {
        let err = EnumError::UnsupportedPlatform("windows".into());
        let msg = format!("{}", err);
        assert!(msg.contains("Platform not supported"));
        assert!(msg.contains("windows"));
    }

    #[test]
    fn phase8_io_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err = EnumError::Io(io_err);
        let msg = format!("{}", err);
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("file gone"));
    }

    #[test]
    fn phase8_parse_error_display() {
        let err = EnumError::ParseError("bad sysfs format".into());
        let msg = format!("{}", err);
        assert!(msg.contains("parse system info"));
        assert!(msg.contains("bad sysfs format"));
    }
}
