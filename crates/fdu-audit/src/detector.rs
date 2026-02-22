//! The [`Detector`] trait and supporting types.

use fdu_core::device::Device;
use fdu_core::models::FsMetadata;
use fdu_disk::layout::DiskLayout;
use fdu_models::{Finding, UsbFingerprint};
use std::fmt;

use crate::config::AuditConfig;

/// Scan phase — determines execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    Usb = 0,
    Disk = 1,
    Filesystem = 2,
    Content = 3,
    Forensics = 4,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase::Usb => write!(f, "USB"),
            Phase::Disk => write!(f, "Disk"),
            Phase::Filesystem => write!(f, "Filesystem"),
            Phase::Content => write!(f, "Content"),
            Phase::Forensics => write!(f, "Forensics"),
        }
    }
}

/// Context passed to each detector — provides access to device data and
/// results from prior phases.
pub struct ScanContext<'a> {
    /// The raw block device being scanned.
    pub device: &'a dyn Device,
    /// USB fingerprint (populated after USB phase).
    pub usb_fingerprint: Option<&'a UsbFingerprint>,
    /// Parsed disk layout (populated after Disk phase).
    pub disk_layout: Option<&'a DiskLayout>,
    /// Filesystem metadata (populated after Filesystem phase).
    pub fs_metadata: Option<&'a FsMetadata>,
    /// Audit configuration.
    pub config: &'a AuditConfig,
}

/// A pluggable security detector.
///
/// Detectors are stateless — they examine the [`ScanContext`] and return
/// findings.  The engine handles ordering, filtering, and aggregation.
pub trait Detector: Send + Sync {
    /// Human-readable name (e.g., "BadUSB Detector").
    fn name(&self) -> &str;

    /// Which scan phase this detector belongs to.
    fn phase(&self) -> Phase;

    /// Run the detector and return any findings.
    fn detect(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>>;
}
