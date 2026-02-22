//! # fdu-disk
//!
//! Partition table analysis without mounting.
//!
//! Parses MBR and GPT partition tables via the [`Device`](fdu_core::device::Device)
//! trait, builds a unified [`DiskLayout`], and runs threat detectors to find
//! hidden partitions, overlapping entries, suspicious gaps, and type mismatches.

pub mod detectors;
pub mod gpt;
pub mod layout;
pub mod mbr;

use fdu_core::device::Device;
use fdu_models::Finding;
use layout::DiskLayout;

/// Errors specific to disk analysis.
#[derive(thiserror::Error, Debug)]
pub enum DiskError {
    #[error("Failed to read from device: {0}")]
    DeviceRead(String),

    #[error("Invalid MBR: {0}")]
    InvalidMbr(String),

    #[error("Invalid GPT: {0}")]
    InvalidGpt(String),

    #[error("Device too small for partition table analysis")]
    DeviceTooSmall,
}

impl From<fdu_core::errors::Error> for DiskError {
    fn from(e: fdu_core::errors::Error) -> Self {
        DiskError::DeviceRead(e.to_string())
    }
}

/// Analyze the partition layout of a device.
///
/// Reads the first sectors to determine the partitioning scheme (MBR, GPT,
/// hybrid, or none), then parses partition entries.
pub fn analyze_partitions(device: &dyn Device) -> Result<DiskLayout, DiskError> {
    layout::analyze(device)
}

/// Run all disk threat detectors against a parsed layout.
pub fn detect_disk_threats(layout: &DiskLayout) -> Vec<Finding> {
    detectors::run_all(layout)
}
