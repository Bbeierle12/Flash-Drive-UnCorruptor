//! BadUSB heuristic detectors.
//!
//! Each function examines a [`UsbFingerprint`] for a specific anomaly pattern
//! and returns zero or more [`Finding`]s.

use crate::vid_pid_db;
use fdu_models::usb::class;
use fdu_models::{Evidence, Finding, Severity, UsbFingerprint};

/// Run all BadUSB detectors against a fingerprint.
pub fn run_all(fp: &UsbFingerprint) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(detect_hid_on_storage(fp));
    findings.extend(detect_composite_device(fp));
    findings.extend(detect_descriptor_anomalies(fp));
    findings.extend(detect_known_bad_vid_pid(fp));
    findings.extend(detect_missing_serial(fp));
    findings
}

/// HID interface on a device that also claims mass storage → High.
///
/// This is the classic BadUSB attack vector: a "flash drive" that also
/// silently types keystrokes.
fn detect_hid_on_storage(fp: &UsbFingerprint) -> Vec<Finding> {
    if fp.is_mass_storage() && fp.has_hid_interface() {
        vec![Finding::new(
            "usb.hid_on_storage",
            Severity::High,
            "HID interface on mass storage device",
            format!(
                "Device {} presents both mass storage (class 0x{:02x}) and HID \
                 (class 0x{:02x}) interfaces. This is a common BadUSB attack pattern \
                 where a flash drive covertly injects keystrokes.",
                fp.vid_pid(),
                class::MASS_STORAGE,
                class::HID,
            ),
        )
        .with_evidence(Evidence::Text(format!(
            "Interface classes: {:?}",
            fp.interface_classes
        )))
        .with_remediation(
            "Do not trust this device. Disconnect it immediately and inspect \
             with a USB protocol analyzer.",
        )]
    } else {
        vec![]
    }
}

/// Multiple distinct interface classes (composite device) → Medium.
///
/// Composite devices are legitimate (e.g., keyboard + trackpad), but on a
/// device marketed as "just a flash drive," multiple classes are suspicious.
fn detect_composite_device(fp: &UsbFingerprint) -> Vec<Finding> {
    if fp.is_composite() && fp.is_mass_storage() {
        let unique: std::collections::HashSet<_> = fp.interface_classes.iter().collect();
        vec![Finding::new(
            "usb.composite_storage",
            Severity::Medium,
            "Composite device with mass storage",
            format!(
                "Device {} has {} distinct interface classes: {:?}. \
                 A standard flash drive typically has only mass storage.",
                fp.vid_pid(),
                unique.len(),
                fp.interface_classes,
            ),
        )
        .with_evidence(Evidence::Metric {
            key: "interface_class_count".into(),
            value: unique.len() as f64,
        })]
    } else {
        vec![]
    }
}

/// Descriptor length anomalies → Medium.
///
/// If raw descriptors are available, check for obviously wrong lengths.
/// Collects ALL anomalies instead of stopping at the first one.
fn detect_descriptor_anomalies(fp: &UsbFingerprint) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !fp.descriptors_raw.is_empty() {
        // Walk descriptor chain: each descriptor starts with [length, type]
        let mut offset = 0;
        let data = &fp.descriptors_raw;
        while offset < data.len() {
            if offset + 1 >= data.len() {
                findings.push(
                    Finding::new(
                        "usb.descriptor_truncated",
                        Severity::Medium,
                        "Truncated USB descriptor",
                        format!(
                            "Descriptor chain ends at offset {} with only {} byte(s) remaining. \
                             This may indicate corrupted or maliciously crafted descriptors.",
                            offset,
                            data.len() - offset,
                        ),
                    )
                    .with_evidence(Evidence::bytes(
                        offset as u64,
                        data[offset..].to_vec(),
                        "Remaining bytes",
                    )),
                );
                break;
            }

            let desc_len = data[offset] as usize;
            if desc_len < 2 {
                findings.push(
                    Finding::new(
                        "usb.descriptor_invalid_length",
                        Severity::Medium,
                        "Invalid USB descriptor length",
                        format!(
                            "Descriptor at offset {} has length {} (minimum is 2). \
                             This is structurally invalid and may indicate firmware manipulation.",
                            offset, desc_len,
                        ),
                    )
                    .with_evidence(Evidence::bytes(
                        offset as u64,
                        data[offset..data.len().min(offset + 4)].to_vec(),
                        "Descriptor header",
                    )),
                );
                // Cannot advance — break to avoid infinite loop on length=0
                break;
            }

            // Guard against reading past the buffer
            if offset + desc_len > data.len() {
                findings.push(
                    Finding::new(
                        "usb.descriptor_truncated",
                        Severity::Medium,
                        "Truncated USB descriptor",
                        format!(
                            "Descriptor at offset {} claims length {} but only {} bytes remain. \
                             This may indicate corrupted or maliciously crafted descriptors.",
                            offset, desc_len, data.len() - offset,
                        ),
                    )
                    .with_evidence(Evidence::bytes(
                        offset as u64,
                        data[offset..].to_vec(),
                        "Remaining bytes",
                    )),
                );
                break;
            }

            offset += desc_len;
        }
    }

    findings
}

/// Known-bad VID:PID match → Critical.
fn detect_known_bad_vid_pid(fp: &UsbFingerprint) -> Vec<Finding> {
    if let Some(entry) = vid_pid_db::lookup(fp.vendor_id, fp.product_id) {
        let mut finding = Finding::new(
            "usb.known_bad_vid_pid",
            Severity::Critical,
            "Known-bad USB device identified",
            format!(
                "Device {} matches a known attack tool: {}",
                fp.vid_pid(),
                entry.description,
            ),
        )
        .with_evidence(Evidence::Text(format!(
            "VID:PID {:04x}:{:04x}",
            fp.vendor_id, fp.product_id
        )))
        .with_remediation("Disconnect this device immediately. Do not mount or trust any data from it.");

        if let Some(cve) = entry.cve {
            finding = finding.with_cve(cve);
        }

        vec![finding]
    } else {
        vec![]
    }
}

/// Missing serial number on a device that should have one → Low.
///
/// Mass storage devices from reputable manufacturers almost always have serial
/// numbers.  Missing one may indicate cloned or tampered firmware.
fn detect_missing_serial(fp: &UsbFingerprint) -> Vec<Finding> {
    if fp.is_mass_storage() && fp.serial.is_none() {
        vec![Finding::new(
            "usb.missing_serial",
            Severity::Low,
            "Mass storage device without serial number",
            format!(
                "Device {} does not report a serial number. Most legitimate \
                 flash drives include one. This may indicate cloned or modified firmware.",
                fp.vid_pid(),
            ),
        )]
    } else {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_drive() -> UsbFingerprint {
        UsbFingerprint {
            vendor_id: 0x0781,
            product_id: 0x5567,
            manufacturer: Some("SanDisk".into()),
            product: Some("Cruzer Blade".into()),
            serial: Some("12345".into()),
            device_class: 0x00,
            interface_classes: vec![class::MASS_STORAGE],
            bcd_device: 0x0100,
            descriptors_raw: vec![],
        }
    }

    #[test]
    fn clean_drive_no_findings() {
        let findings = run_all(&clean_drive());
        assert!(findings.is_empty(), "Clean drive should have no findings");
    }

    #[test]
    fn hid_on_storage_detected() {
        let mut fp = clean_drive();
        fp.interface_classes = vec![class::MASS_STORAGE, class::HID];

        let findings = run_all(&fp);
        assert!(findings.iter().any(|f| f.detector == "usb.hid_on_storage"));
        assert!(findings.iter().any(|f| f.severity == Severity::High));
    }

    #[test]
    fn composite_detected() {
        let mut fp = clean_drive();
        fp.interface_classes = vec![class::MASS_STORAGE, 0x02]; // CDC

        let findings = run_all(&fp);
        assert!(findings
            .iter()
            .any(|f| f.detector == "usb.composite_storage"));
    }

    #[test]
    fn known_bad_detected() {
        let mut fp = clean_drive();
        fp.vendor_id = 0x16C0;
        fp.product_id = 0x0486; // Teensy

        let findings = run_all(&fp);
        assert!(findings
            .iter()
            .any(|f| f.detector == "usb.known_bad_vid_pid"));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn missing_serial_detected() {
        let mut fp = clean_drive();
        fp.serial = None;

        let findings = run_all(&fp);
        assert!(findings
            .iter()
            .any(|f| f.detector == "usb.missing_serial"));
        assert!(findings.iter().any(|f| f.severity == Severity::Low));
    }

    #[test]
    fn descriptor_anomaly_invalid_length() {
        let mut fp = clean_drive();
        // Descriptor with length 0 — invalid
        fp.descriptors_raw = vec![0x00, 0x04];

        let findings = run_all(&fp);
        assert!(findings
            .iter()
            .any(|f| f.detector == "usb.descriptor_invalid_length"));
    }

    #[test]
    fn descriptor_anomaly_truncated() {
        let mut fp = clean_drive();
        // Valid descriptor (len=4) followed by a single orphan byte
        fp.descriptors_raw = vec![0x04, 0x02, 0x00, 0x00, 0xFF];

        let findings = run_all(&fp);
        assert!(findings
            .iter()
            .any(|f| f.detector == "usb.descriptor_truncated"));
    }

    #[test]
    fn valid_descriptor_chain_no_anomaly() {
        let mut fp = clean_drive();
        // Two valid descriptors: [len=4, type, data, data] [len=3, type, data]
        fp.descriptors_raw = vec![0x04, 0x02, 0x00, 0x00, 0x03, 0x05, 0x01];

        let findings = run_all(&fp);
        assert!(!findings
            .iter()
            .any(|f| f.detector.starts_with("usb.descriptor_")));
    }
}
