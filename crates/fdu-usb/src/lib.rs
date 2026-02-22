//! # fdu-usb
//!
//! USB descriptor interrogation and BadUSB detection.
//!
//! This crate reads USB descriptors **without mounting** the device, then runs
//! heuristics to detect BadUSB attacks and other descriptor anomalies.
//!
//! ## Architecture
//!
//! - [`enumerate`] — discover connected USB devices via `nusb`
//! - [`interrogate`] — read descriptors and build a [`UsbFingerprint`]
//! - [`detectors`] — heuristic checks that produce [`Finding`]s
//! - [`vid_pid_db`] — embedded database of known-bad vendor/product IDs

pub mod detectors;
pub mod enumerate;
pub mod interrogate;
pub mod vid_pid_db;

use fdu_models::{Finding, UsbFingerprint};

/// Enumerate all connected USB devices and return their fingerprints.
///
/// Filters to mass-storage and suspicious device classes by default.
pub fn enumerate_usb_devices() -> Result<Vec<UsbFingerprint>, UsbError> {
    enumerate::list_usb_devices()
}

/// Run all BadUSB and descriptor anomaly detectors against a fingerprint.
pub fn detect_badusb(fingerprint: &UsbFingerprint) -> Vec<Finding> {
    detectors::run_all(fingerprint)
}

/// Errors specific to USB interrogation.
#[derive(thiserror::Error, Debug)]
pub enum UsbError {
    #[error("USB enumeration failed: {0}")]
    EnumerationFailed(String),

    #[error("Failed to open USB device: {0}")]
    DeviceOpenFailed(String),

    #[error("Failed to read USB descriptors: {0}")]
    DescriptorReadFailed(String),

    #[error("USB I/O error: {0}")]
    Io(#[from] std::io::Error),
}
