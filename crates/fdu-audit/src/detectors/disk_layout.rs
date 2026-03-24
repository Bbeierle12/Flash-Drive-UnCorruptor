//! Disk layout detector — wraps `fdu_disk::detect_disk_threats`.

use crate::detector::{Detector, Phase, ScanContext};
use fdu_models::Finding;

pub struct DiskLayoutDetector;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditConfig;
    use fdu_core::device::MockDevice;

    #[test]
    fn phase_is_disk() {
        assert_eq!(DiskLayoutDetector.phase(), Phase::Disk);
    }

    #[test]
    fn no_layout_returns_empty() {
        let dev = MockDevice::new(1024 * 1024);
        let cfg = AuditConfig::default();
        let ctx = ScanContext {
            device: &dev,
            usb_fingerprint: None,
            disk_layout: None,
            fs_metadata: None,
            config: &cfg,
        };
        let findings = DiskLayoutDetector.detect(&ctx).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_layout_returns_empty() {
        let dev = MockDevice::new(1024 * 1024);
        let cfg = AuditConfig::default();
        let layout = fdu_disk::layout::DiskLayout {
            scheme: fdu_disk::layout::PartitionScheme::None,
            partitions: vec![],
            unallocated_regions: vec![],
            total_sectors: 2048,
            sector_size: 512,
        };
        let ctx = ScanContext {
            device: &dev,
            usb_fingerprint: None,
            disk_layout: Some(&layout),
            fs_metadata: None,
            config: &cfg,
        };
        let findings = DiskLayoutDetector.detect(&ctx).unwrap();
        assert!(findings.is_empty());
    }
}

impl Detector for DiskLayoutDetector {
    fn name(&self) -> &str {
        "Disk Layout Detector"
    }

    fn phase(&self) -> Phase {
        Phase::Disk
    }

    fn detect(&self, ctx: &ScanContext) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
        match ctx.disk_layout {
            Some(layout) => Ok(fdu_disk::detect_disk_threats(layout)),
            None => Ok(vec![]),
        }
    }
}
