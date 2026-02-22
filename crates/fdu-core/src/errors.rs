//! Error types for fdu-core operations.

use std::path::PathBuf;

/// Core error type for all fdu-core operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Device not found: {0}")]
    DeviceNotFound(String),

    #[error("Device busy or locked: {0}")]
    DeviceBusy(String),

    #[error("Permission denied — this operation requires elevated privileges (sudo/admin)")]
    PermissionDenied,

    #[error("Unsupported filesystem: {0}")]
    UnsupportedFilesystem(String),

    #[error("Filesystem detection failed: could not identify filesystem on device")]
    DetectionFailed,

    #[error("Filesystem corrupted: {0}")]
    FilesystemCorrupted(String),

    #[error("I/O error at offset {offset:#x}: {source}")]
    Io {
        offset: u64,
        #[source]
        source: std::io::Error,
    },

    #[error("I/O error: {0}")]
    IoGeneral(#[from] std::io::Error),

    #[error("Bad sector detected at offset {offset:#x} (sector {sector})")]
    BadSector { offset: u64, sector: u64 },

    #[error("Recovery failed: {0}")]
    RecoveryFailed(String),

    #[error("Repair requires explicit confirmation — use --unsafe flag")]
    ConfirmationRequired,

    #[error("Operation not yet implemented: {0}")]
    Unimplemented(String),

    #[error("Invalid path: {0}")]
    InvalidPath(PathBuf),

    #[error("Read beyond device bounds: offset {offset:#x}, requested {requested} bytes, device size {device_size}")]
    OutOfBounds {
        offset: u64,
        requested: usize,
        device_size: u64,
    },
}

/// Convenience type alias for Results using our Error type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════════════════════════
    // Phase 4 — Error Display
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn phase4_display_device_not_found() {
        let e = Error::DeviceNotFound("/dev/sdb1".into());
        let msg = format!("{}", e);
        assert!(msg.contains("Device not found"));
        assert!(msg.contains("/dev/sdb1"));
    }

    #[test]
    fn phase4_display_permission_denied() {
        let e = Error::PermissionDenied;
        let msg = format!("{}", e);
        assert!(msg.contains("Permission denied"));
        assert!(msg.contains("elevated privileges"));
    }

    #[test]
    fn phase4_display_out_of_bounds() {
        let e = Error::OutOfBounds {
            offset: 0x1000,
            requested: 512,
            device_size: 0x800,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("0x1000"));
        assert!(msg.contains("512"));
    }

    #[test]
    fn phase4_display_bad_sector() {
        let e = Error::BadSector {
            offset: 0x2000,
            sector: 16,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("Bad sector"));
        assert!(msg.contains("0x2000"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn phase4_display_confirmation_required() {
        let e = Error::ConfirmationRequired;
        let msg = format!("{}", e);
        assert!(msg.contains("--unsafe"));
    }

    #[test]
    fn phase4_display_filesystem_corrupted() {
        let e = Error::FilesystemCorrupted("missing FAT".into());
        let msg = format!("{}", e);
        assert!(msg.contains("corrupted"));
        assert!(msg.contains("missing FAT"));
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 4 — Error Propagation
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn phase4_fat32_new_bad_sector_at_0() {
        use crate::device::MockDevice;
        use crate::fs::fat32::Fat32Fs;

        let dev = MockDevice::new(1024 * 1024).with_bad_sector(0);
        let result = Fat32Fs::new(&dev);
        assert!(result.is_err());
    }

    #[test]
    fn phase4_follow_chain_bad_fat_sector() {
        use crate::device::MockDevice;
        use crate::fs::fat32::Fat32Fs;
        use crate::fs::traits::FileSystemOps;
        use std::path::Path;

        // Build a valid image, then inject a bad sector in the FAT region.
        // list_dir("/") → read_dir_entries → follow_chain → read_fat_entry
        // which reads from the FAT region. If that sector is bad, we get an error.
        let cfg = crate::fs::fat32::tests_helper::default_config();
        let img = crate::fs::fat32::tests_helper::make_image(&cfg);
        let fat_sector = cfg.reserved_sectors as u64;
        let dev = MockDevice::from_bytes(img).with_bad_sector(fat_sector);
        let fs = Fat32Fs::new(&dev).unwrap();
        // The root cluster's FAT entry is in the bad sector region
        let result = fs.list_dir(Path::new("/"));
        assert!(result.is_err());
    }

    #[test]
    fn phase4_scan_signatures_bad_sector() {
        use crate::device::MockDevice;
        use crate::recovery::carving::scan_signatures;

        let dev = MockDevice::new(512 * 100).with_bad_sector(5);
        let result = scan_signatures(&dev, &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn phase4_bad_sector_scanner_non_io_error() {
        use crate::device::MockDevice;
        use crate::diagnostics::bad_sectors::scan_bad_sectors;

        // A healthy device should complete without error
        let dev = MockDevice::new(512 * 10);
        let result = scan_bad_sectors(&dev, None);
        assert!(result.is_ok());
        assert!(result.unwrap().bad_sectors.is_empty());
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 4 — DeviceExt edge cases
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn phase4_device_ext_zero_length_read() {
        use crate::device::MockDevice;
        use crate::device::traits::DeviceExt;

        let dev = MockDevice::new(4096);
        let result = dev.read_exact_at(0, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn phase4_device_ext_read_at_exact_boundary() {
        use crate::device::MockDevice;
        use crate::device::traits::DeviceExt;

        let dev = MockDevice::new(1024);
        // Read exactly at end — should fail because offset=1024 is past the data
        let result = dev.read_exact_at(1024, 1);
        assert!(result.is_err());
    }
}
