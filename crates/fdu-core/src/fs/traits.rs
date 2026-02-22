//! FileSystem trait — the core abstraction for interacting with filesystems.

use crate::errors::Result;
use crate::models::*;
use std::path::Path;

/// Operations that can be performed on a detected filesystem.
///
/// All implementations should be safe to call on corrupted filesystems —
/// they should return errors rather than panicking.
pub trait FileSystemOps: Send + Sync {
    /// Get filesystem metadata (size, cluster info, label, etc.)
    fn metadata(&self) -> Result<FsMetadata>;

    /// List entries in a directory.
    fn list_dir(&self, path: &Path) -> Result<Vec<DirEntry>>;

    /// Validate the filesystem integrity and return a report of issues.
    fn validate(&self) -> Result<ValidationReport>;

    /// Scan for deleted/recoverable files.
    fn scan_deleted(&self) -> Result<Vec<RecoverableFile>>;

    /// Attempt to repair filesystem issues.
    ///
    /// Will return `Error::ConfirmationRequired` if `options.confirm_unsafe` is false.
    fn repair(&mut self, options: &RepairOptions) -> Result<RepairReport>;
}
