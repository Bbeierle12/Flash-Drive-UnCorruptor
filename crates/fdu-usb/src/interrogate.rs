//! USB descriptor interrogation — read device/config/interface descriptors
//! and build a [`UsbFingerprint`].

use crate::UsbError;
use fdu_models::UsbFingerprint;
use nusb::MaybeFuture;
use tracing::debug;

/// Build a [`UsbFingerprint`] from a `nusb::DeviceInfo` (enumeration-level data).
///
/// This extracts everything available from the device info without needing to
/// open the device.  For deeper interrogation (reading raw descriptor bytes),
/// use [`interrogate_opened`].
pub fn build_fingerprint(info: &nusb::DeviceInfo) -> Result<UsbFingerprint, UsbError> {
    let interface_classes: Vec<u8> = info
        .interfaces()
        .map(|iface| iface.class())
        .collect();

    debug!(
        vid = info.vendor_id(),
        pid = info.product_id(),
        class = info.class(),
        interfaces = ?interface_classes,
        "Building USB fingerprint"
    );

    Ok(UsbFingerprint {
        vendor_id: info.vendor_id(),
        product_id: info.product_id(),
        manufacturer: info.manufacturer_string().map(|s| s.to_string()),
        product: info.product_string().map(|s| s.to_string()),
        serial: info.serial_number().map(|s| s.to_string()),
        device_class: info.class(),
        interface_classes,
        bcd_device: info.device_version(),
        descriptors_raw: Vec::new(), // filled by interrogate_opened if needed
    })
}

/// Interrogate an opened USB device to read raw descriptor bytes.
///
/// This provides the full descriptor data for deep analysis and fuzzing.
/// Requires the device to be opened (which may need permissions).
pub fn interrogate_opened(info: &nusb::DeviceInfo) -> Result<UsbFingerprint, UsbError> {
    let mut fp = build_fingerprint(info)?;

    // Open the device to read raw descriptor bytes (blocking).
    // This requires device permissions and may fail — non-fatal.
    match info.open().wait() {
        Ok(device) => {
            if let Ok(cfg) = device.active_configuration() {
                // Collect descriptor headers (length + type byte pairs)
                let mut raw: Vec<u8> = Vec::new();
                for desc in cfg.descriptors() {
                    raw.push(desc.descriptor_len() as u8);
                    raw.push(desc.descriptor_type());
                }
                fp.descriptors_raw = raw;
            }
            debug!(
                raw_len = fp.descriptors_raw.len(),
                "Read raw descriptor bytes"
            );
        }
        Err(e) => {
            // Non-fatal: we still have the basic fingerprint
            debug!(error = %e, "Could not open device for raw descriptors");
        }
    }

    Ok(fp)
}
