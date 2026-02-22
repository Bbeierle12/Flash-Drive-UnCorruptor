//! The [`AuditEngine`] — orchestrates the full scan pipeline.

use crate::config::AuditConfig;
use crate::detector::{Detector, Phase, ScanContext};
use crate::detectors;
use fdu_core::device::Device;
use fdu_disk::layout::DiskLayout;
use fdu_models::{AuditEvent, AuditEventType, Finding, ThreatReport, UsbFingerprint};
use std::time::Instant;
use tracing::{debug, info, warn};

/// The main audit engine.
///
/// Register detectors (or use `register_defaults()`), then call `scan()` to
/// run the full pipeline.
pub struct AuditEngine {
    detectors: Vec<Box<dyn Detector>>,
    config: AuditConfig,
    event_callback: Option<Box<dyn Fn(AuditEvent) + Send + Sync>>,
}

impl AuditEngine {
    /// Create a new engine with the given config.
    pub fn new(config: AuditConfig) -> Self {
        Self {
            detectors: Vec::new(),
            config,
            event_callback: None,
        }
    }

    /// Register a custom detector.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    /// Register all built-in detectors.
    pub fn register_defaults(&mut self) {
        self.register(Box::new(detectors::usb_badusb::UsbBadUsbDetector));
        self.register(Box::new(detectors::disk_layout::DiskLayoutDetector));
        self.register(Box::new(detectors::fs_integrity::FsIntegrityDetector));
        self.register(Box::new(
            detectors::content_signatures::ContentSignatureDetector,
        ));
        self.register(Box::new(
            detectors::deleted_forensics::DeletedForensicsDetector,
        ));
    }

    /// Set a callback to receive audit events during the scan.
    pub fn on_event(&mut self, cb: impl Fn(AuditEvent) + Send + Sync + 'static) {
        self.event_callback = Some(Box::new(cb));
    }

    /// Run the full audit pipeline on a device.
    ///
    /// If a USB fingerprint is provided, it's used for USB-phase detectors.
    /// Otherwise, the USB phase is skipped.
    pub fn scan(
        &self,
        device: &dyn Device,
        usb: Option<&UsbFingerprint>,
    ) -> Result<ThreatReport, AuditError> {
        let start = Instant::now();

        self.emit(AuditEvent::new(
            AuditEventType::ScanStarted,
            device.id(),
            "Full security audit started",
        ));

        info!(device_id = device.id(), "Starting security audit");

        // --- Disk analysis (if not skipped) ---
        let disk_layout: Option<DiskLayout> = if self.config.should_run_phase(Phase::Disk) {
            match fdu_disk::analyze_partitions(device) {
                Ok(layout) => {
                    debug!(scheme = ?layout.scheme, partitions = layout.partitions.len(), "Disk analysis complete");
                    Some(layout)
                }
                Err(e) => {
                    warn!(error = %e, "Disk analysis failed, continuing without layout");
                    None
                }
            }
        } else {
            None
        };

        // --- Filesystem metadata (if not skipped) ---
        let fs_metadata = if self.config.should_run_phase(Phase::Filesystem) {
            Self::try_get_fs_metadata(device)
        } else {
            None
        };

        // --- Run all detectors by phase order ---
        let mut all_findings: Vec<Finding> = Vec::new();
        let mut phases: Vec<Phase> = self.detectors.iter().map(|d| d.phase()).collect();
        phases.sort();
        phases.dedup();

        for phase in phases {
            if !self.config.should_run_phase(phase) {
                debug!(phase = %phase, "Skipping phase");
                continue;
            }

            debug!(phase = %phase, "Running detectors");

            for detector in self.detectors.iter().filter(|d| d.phase() == phase) {
                let ctx = ScanContext {
                    device,
                    usb_fingerprint: usb,
                    disk_layout: disk_layout.as_ref(),
                    fs_metadata: fs_metadata.as_ref(),
                    config: &self.config,
                };

                match detector.detect(&ctx) {
                    Ok(findings) => {
                        for finding in &findings {
                            if finding.severity >= self.config.min_severity {
                                self.emit(AuditEvent::new(
                                    AuditEventType::ThreatDetected,
                                    device.id(),
                                    format!("[{}] {}", finding.severity, finding.title),
                                ));
                            }
                        }
                        let filtered: Vec<_> = findings
                            .into_iter()
                            .filter(|f| f.severity >= self.config.min_severity)
                            .collect();
                        all_findings.extend(filtered);
                    }
                    Err(e) => {
                        warn!(
                            detector = detector.name(),
                            error = %e,
                            "Detector failed, skipping"
                        );
                    }
                }
            }
        }

        let elapsed = start.elapsed();
        let report = ThreatReport::from_findings(device.id(), all_findings, elapsed);

        self.emit(AuditEvent::new(
            AuditEventType::ScanCompleted,
            device.id(),
            format!(
                "Audit complete: {} findings, risk={}, safe_to_mount={}",
                report.findings.len(),
                report.overall_risk,
                report.safe_to_mount,
            ),
        ));

        info!(
            device_id = device.id(),
            findings = report.findings.len(),
            risk = %report.overall_risk,
            duration_ms = elapsed.as_millis() as u64,
            "Audit complete"
        );

        Ok(report)
    }

    fn emit(&self, event: AuditEvent) {
        if let Some(cb) = &self.event_callback {
            cb(event);
        }
    }

    /// Try to get filesystem metadata from the device.
    fn try_get_fs_metadata(device: &dyn Device) -> Option<fdu_core::models::FsMetadata> {
        use fdu_core::fs::detect::detect_filesystem;
        use fdu_core::fs::fat32::Fat32Fs;
        use fdu_core::fs::traits::FileSystemOps;
        use fdu_core::models::FsType;

        match detect_filesystem(device) {
            Ok(FsType::Fat32 | FsType::Fat16 | FsType::Fat12) => {
                Fat32Fs::new(device).ok().and_then(|fs| fs.metadata().ok())
            }
            _ => None,
        }
    }
}

/// Audit engine errors.
#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("Device access failed: {0}")]
    DeviceError(String),

    #[error("Scan timed out after {0:?}")]
    Timeout(std::time::Duration),
}

#[cfg(test)]
mod tests {
    use super::*;
    use fdu_core::device::MockDevice;

    #[test]
    fn engine_with_no_detectors() {
        let engine = AuditEngine::new(AuditConfig::default());
        let device = MockDevice::new(1024 * 1024);
        let report = engine.scan(&device, None).unwrap();
        assert!(report.findings.is_empty());
        assert!(report.safe_to_mount);
    }

    #[test]
    fn engine_with_defaults_on_clean_device() {
        let mut engine = AuditEngine::new(AuditConfig::default());
        engine.register_defaults();

        let device = MockDevice::new(1024 * 1024);
        let report = engine.scan(&device, None).unwrap();
        // Clean device should have no high-severity findings
        assert!(
            report.findings.iter().all(|f| f.severity < fdu_models::Severity::High),
            "Clean device should not have high-severity findings"
        );
    }

    #[test]
    fn engine_receives_events() {
        use std::sync::{Arc, Mutex};

        let events = Arc::new(Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let mut engine = AuditEngine::new(AuditConfig::quick());
        engine.on_event(move |evt| {
            events_clone.lock().unwrap().push(evt);
        });

        let device = MockDevice::new(1024 * 1024);
        engine.scan(&device, None).unwrap();

        let captured = events.lock().unwrap();
        assert!(captured.iter().any(|e| e.event_type == AuditEventType::ScanStarted));
        assert!(captured.iter().any(|e| e.event_type == AuditEventType::ScanCompleted));
    }

    #[test]
    fn engine_skips_phases() {
        let mut config = AuditConfig::default();
        config.skip_phases.push(Phase::Disk);
        config.skip_phases.push(Phase::Filesystem);
        config.enable_content_scan = false;
        config.enable_forensics = false;

        let mut engine = AuditEngine::new(config);
        engine.register_defaults();

        let device = MockDevice::new(1024 * 1024);
        let report = engine.scan(&device, None).unwrap();
        // With all phases skipped, should have no findings
        assert!(report.findings.is_empty());
    }

    #[test]
    fn engine_with_badusb_fingerprint() {
        let mut engine = AuditEngine::new(AuditConfig::quick());
        engine.register_defaults();

        let device = MockDevice::new(1024 * 1024);
        let bad_usb = UsbFingerprint {
            vendor_id: 0x16C0,
            product_id: 0x0486, // Teensy — known bad
            manufacturer: None,
            product: None,
            serial: None,
            device_class: 0x00,
            interface_classes: vec![fdu_models::usb::class::MASS_STORAGE, fdu_models::usb::class::HID],
            bcd_device: 0x0100,
            descriptors_raw: vec![],
        };

        let report = engine.scan(&device, Some(&bad_usb)).unwrap();
        assert!(!report.safe_to_mount);
        assert!(report.findings.iter().any(|f| f.severity == fdu_models::Severity::Critical));
    }
}
