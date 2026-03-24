//! USB device enumeration via nusb.

use crate::interrogate::build_fingerprint;
use crate::UsbError;
use fdu_models::UsbFingerprint;
use nusb::MaybeFuture;
use std::sync::mpsc;
use std::time::Duration;
use tracing::{debug, warn};

/// Timeout for USB subsystem enumeration (5 seconds).
const USB_ENUM_TIMEOUT: Duration = Duration::from_secs(5);

/// List all USB devices, returning fingerprints for each.
///
/// This uses `nusb::list_devices()` to discover connected USB hardware,
/// then reads descriptors from each device to build fingerprints.
/// A timeout is enforced to avoid hanging on broken USB subsystems.
pub fn list_usb_devices() -> Result<Vec<UsbFingerprint>, UsbError> {
    // Run enumeration in a separate thread with a channel-based timeout
    // to avoid hanging indefinitely on broken USB subsystems.
    //
    // NOTE: If the timeout fires, the background thread continues to live
    // until `nusb::list_devices().wait()` returns (we cannot cancel a
    // blocked syscall from Rust).  The thread is detached and will be
    // cleaned up when the process exits; in pathological cases (repeated
    // timeouts) threads may accumulate.  A future improvement would be to
    // keep a static handle and reuse it.
    let (tx, rx) = mpsc::channel();

    std::thread::Builder::new()
        .name("fdu-usb-enum".into())
        .spawn(move || {
            let result = nusb::list_devices()
                .wait()
                .map_err(|e| UsbError::EnumerationFailed(e.to_string()));
            // If the receiver has been dropped (timeout), this send silently fails.
            let _ = tx.send(result);
        })
        .map_err(|e| UsbError::EnumerationFailed(format!("Failed to spawn USB enum thread: {}", e)))?;

    let device_list = rx
        .recv_timeout(USB_ENUM_TIMEOUT)
        .map_err(|_| {
            UsbError::EnumerationFailed(format!(
                "USB enumeration timed out after {}s",
                USB_ENUM_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e: UsbError| e)?;

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
