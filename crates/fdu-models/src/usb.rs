//! USB-specific types — fingerprints, descriptors, class codes.

use serde::{Deserialize, Serialize};
use std::fmt;

/// USB class codes relevant to security analysis.
pub mod class {
    /// Human Interface Device (keyboard, mouse) — key BadUSB vector.
    pub const HID: u8 = 0x03;
    /// Mass Storage.
    pub const MASS_STORAGE: u8 = 0x08;
    /// Hub.
    pub const HUB: u8 = 0x09;
    /// Wireless Controller.
    pub const WIRELESS: u8 = 0xE0;
    /// Vendor-specific.
    pub const VENDOR_SPECIFIC: u8 = 0xFF;
}

/// A fingerprint of a USB device's identity — extracted from descriptors
/// *without mounting* the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsbFingerprint {
    /// USB Vendor ID.
    pub vendor_id: u16,
    /// USB Product ID.
    pub product_id: u16,
    /// Manufacturer string descriptor, if available.
    pub manufacturer: Option<String>,
    /// Product string descriptor, if available.
    pub product: Option<String>,
    /// Serial number string descriptor, if available.
    pub serial: Option<String>,
    /// Device class code from device descriptor.
    pub device_class: u8,
    /// Interface class codes (one per interface).
    pub interface_classes: Vec<u8>,
    /// BCD-encoded device version.
    pub bcd_device: u16,
    /// Raw descriptor bytes (for deep analysis / fuzzing).
    pub descriptors_raw: Vec<u8>,
}

impl UsbFingerprint {
    /// Does this device claim to be a mass storage device?
    pub fn is_mass_storage(&self) -> bool {
        self.device_class == class::MASS_STORAGE
            || self.interface_classes.contains(&class::MASS_STORAGE)
    }

    /// Does this device expose an HID interface?
    pub fn has_hid_interface(&self) -> bool {
        self.device_class == class::HID || self.interface_classes.contains(&class::HID)
    }

    /// Is this a composite device (multiple interface classes)?
    pub fn is_composite(&self) -> bool {
        let unique: std::collections::HashSet<_> = self.interface_classes.iter().collect();
        unique.len() > 1
    }

    /// Format the VID:PID pair.
    pub fn vid_pid(&self) -> String {
        format!("{:04x}:{:04x}", self.vendor_id, self.product_id)
    }
}

impl fmt::Display for UsbFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "USB [{vid_pid}] {mfg} {prod}",
            vid_pid = self.vid_pid(),
            mfg = self.manufacturer.as_deref().unwrap_or("(unknown)"),
            prod = self.product.as_deref().unwrap_or("(unknown)"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fingerprint() -> UsbFingerprint {
        UsbFingerprint {
            vendor_id: 0x0781,
            product_id: 0x5567,
            manufacturer: Some("SanDisk".into()),
            product: Some("Cruzer Blade".into()),
            serial: Some("ABC123".into()),
            device_class: 0x00,
            interface_classes: vec![class::MASS_STORAGE],
            bcd_device: 0x0100,
            descriptors_raw: vec![],
        }
    }

    #[test]
    fn mass_storage_detection() {
        let fp = sample_fingerprint();
        assert!(fp.is_mass_storage());
        assert!(!fp.has_hid_interface());
    }

    #[test]
    fn hid_detection() {
        let mut fp = sample_fingerprint();
        fp.interface_classes = vec![class::MASS_STORAGE, class::HID];
        assert!(fp.has_hid_interface());
        assert!(fp.is_composite());
    }

    #[test]
    fn vid_pid_format() {
        let fp = sample_fingerprint();
        assert_eq!(fp.vid_pid(), "0781:5567");
    }

    #[test]
    fn display() {
        let fp = sample_fingerprint();
        let s = format!("{}", fp);
        assert!(s.contains("0781:5567"));
        assert!(s.contains("SanDisk"));
    }

    #[test]
    fn serialization_roundtrip() {
        let fp = sample_fingerprint();
        let json = serde_json::to_string(&fp).unwrap();
        let fp2: UsbFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp.vendor_id, fp2.vendor_id);
        assert_eq!(fp.product_id, fp2.product_id);
    }
}
