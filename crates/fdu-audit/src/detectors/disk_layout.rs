//! Disk layout detector — wraps `fdu_disk::detect_disk_threats`.

use crate::detector::{Detector, Phase, ScanContext};
use fdu_models::Finding;

pub struct DiskLayoutDetector;

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
