//! USB BadUSB detector — wraps `fdu_usb::detect_badusb`.

use crate::detector::{Detector, Phase, ScanContext};
use fdu_models::Finding;

pub struct UsbBadUsbDetector;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditConfig;
    use fdu_core::device::MockDevice;

    #[test]
    fn phase_is_usb() {
        assert_eq!(UsbBadUsbDetector.phase(), Phase::Usb);
    }

    #[test]
    fn no_fingerprint_returns_empty() {
        let dev = MockDevice::new(1024 * 1024);
        let cfg = AuditConfig::default();
        let ctx = ScanContext {
            device: &dev,
            usb_fingerprint: None,
            disk_layout: None,
            fs_metadata: None,
            config: &cfg,
        };
        let findings = UsbBadUsbDetector.detect(&ctx).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn clean_fingerprint_returns_empty() {
        let dev = MockDevice::new(1024 * 1024);
        let cfg = AuditConfig::default();
        let clean_fp = fdu_models::UsbFingerprint {
            vendor_id: 0x0781,
            product_id: 0x5567,
            manufacturer: Some("SanDisk".into()),
            product: Some("Cruzer".into()),
            serial: Some("SN123".into()),
            device_class: 0x00,
            interface_classes: vec![fdu_models::usb::class::MASS_STORAGE],
            bcd_device: 0x0100,
            descriptors_raw: vec![],
        };
        let ctx = ScanContext {
            device: &dev,
            usb_fingerprint: Some(&clean_fp),
            disk_layout: None,
            fs_metadata: None,
            config: &cfg,
        };
        let findings = UsbBadUsbDetector.detect(&ctx).unwrap();
        assert!(
            findings.iter().all(|f| f.severity < fdu_models::Severity::High),
            "Clean USB should not have high findings"
        );
    }

    #[test]
    fn known_bad_vid_pid_detected() {
        let dev = MockDevice::new(1024 * 1024);
        let cfg = AuditConfig::default();
        let bad_fp = fdu_models::UsbFingerprint {
            vendor_id: 0x16C0,
            product_id: 0x0486, // Teensy
            manufacturer: None,
            product: None,
            serial: None,
            device_class: 0x00,
            interface_classes: vec![fdu_models::usb::class::MASS_STORAGE, fdu_models::usb::class::HID],
            bcd_device: 0x0100,
            descriptors_raw: vec![],
        };
        let ctx = ScanContext {
            device: &dev,
            usb_fingerprint: Some(&bad_fp),
            disk_layout: None,
            fs_metadata: None,
            config: &cfg,
        };
        let findings = UsbBadUsbDetector.detect(&ctx).unwrap();
        assert!(!findings.is_empty(), "Known-bad device should produce findings");
        assert!(
            findings.iter().any(|f| f.severity == fdu_models::Severity::Critical),
            "Should have Critical finding for known-bad VID:PID"
        );
    }
}

impl Detector for UsbBadUsbDetector {
    fn name(&self) -> &str {
        "USB BadUSB Detector"
    }

    fn phase(&self) -> Phase {
        Phase::Usb
    }

    fn detect(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        match ctx.usb_fingerprint {
            Some(fp) => Ok(fdu_usb::detect_badusb(fp)),
            None => Ok(vec![]),
        }
    }
}
