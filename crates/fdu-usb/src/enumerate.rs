//! USB device enumeration via nusb.

use crate::interrogate::build_fingerprint;
use crate::UsbError;
use fdu_models::UsbFingerprint;
use nusb::MaybeFuture;
use tracing::{debug, warn};

/// List all USB devices, returning fingerprints for each.
///
/// This uses `nusb::list_devices()` to discover connected USB hardware,
/// then reads descriptors from each device to build fingerprints.
pub fn list_usb_devices() -> Result<Vec<UsbFingerprint>, UsbError> {
    let device_list = nusb::list_devices()
        .wait()
        .map_err(|e| UsbError::EnumerationFailed(e.to_string()))?;

    let mut fingerprints = Vec::new();

    for info in device_list {
        debug!(
            vid = info.vendor_id(),
            pid = info.product_id(),
            "Discovered USB device"
        );

        match build_fingerprint(&info) {
            Ok(fp) => fingerprints.push(fp),
            Err(e) => {
                warn!(
                    vid = info.vendor_id(),
                    pid = info.product_id(),
                    error = %e,
                    "Failed to build fingerprint, skipping"
                );
            }
        }
    }

    Ok(fingerprints)
}

/// List only USB devices that present as mass storage or have suspicious
/// interface classes (HID on a storage-looking device, etc.).
pub fn list_suspicious_devices() -> Result<Vec<UsbFingerprint>, UsbError> {
    let all = list_usb_devices()?;
    Ok(all
        .into_iter()
        .filter(|fp| {
            fp.is_mass_storage()
                || fp.has_hid_interface()
                || fp.is_composite()
        })
        .collect())
}
