//! # fdu-extract
//!
//! Quarantine-based safe file extraction.
//!
//! Files are never written directly to the output directory.  Instead:
//!
//! 1. A temporary quarantine staging area is created
//! 2. Files are read from the device and written to quarantine with SHA-256 hashes
//! 3. Each file is scanned for threats
//! 4. Files that pass the [`ExtractionPolicy`] are moved to the output directory
//! 5. An [`ExtractionManifest`] is written to document everything

pub mod hasher;
pub mod manifest;
pub mod quarantine;

use fdu_core::device::Device;
use fdu_models::{ExtractionManifest, ExtractionPolicy, ExtractionProgress};
use std::path::Path;

/// Extract files from a device through the quarantine pipeline.
///
/// # Arguments
/// * `device` — the source device to extract files from
/// * `policy` — which files to allow through quarantine
/// * `output_dir` — final destination for approved files
/// * `progress` — optional callback for extraction progress
pub fn extract(
    device: &dyn Device,
    policy: ExtractionPolicy,
    output_dir: &Path,
    progress: Option<Box<dyn Fn(ExtractionProgress) + Send>>,
) -> Result<ExtractionManifest, ExtractError> {
    quarantine::run_extraction(device, policy, output_dir, progress)
}

/// Errors from the extraction process.
#[derive(thiserror::Error, Debug)]
pub enum ExtractError {
    #[error("Device read failed: {0}")]
    DeviceRead(String),

    #[error("Quarantine directory creation failed: {0}")]
    QuarantineSetup(String),

    #[error("File write failed: {0}")]
    FileWrite(#[from] std::io::Error),

    #[error("Filesystem not supported for extraction: {0}")]
    UnsupportedFs(String),

    #[error("No files found on device")]
    NoFiles,

    #[error("Manifest serialization failed: {0}")]
    ManifestError(String),
}

impl From<fdu_core::errors::Error> for ExtractError {
    fn from(e: fdu_core::errors::Error) -> Self {
        ExtractError::DeviceRead(e.to_string())
    }
}
