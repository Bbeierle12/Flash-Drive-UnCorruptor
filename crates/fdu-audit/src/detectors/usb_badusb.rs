//! USB BadUSB detector — wraps `fdu_usb::detect_badusb`.

use crate::detector::{Detector, Phase, ScanContext};
use fdu_models::Finding;

pub struct UsbBadUsbDetector;

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
