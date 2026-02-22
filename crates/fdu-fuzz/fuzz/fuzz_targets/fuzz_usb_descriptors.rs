//! Fuzz USB descriptor parsing and BadUSB detection.
//!
//! Constructs a UsbFingerprint with random descriptor bytes and runs
//! all detectors against it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Construct a fingerprint from fuzz data
    let vendor_id = u16::from_le_bytes([data[0], data[1]]);
    let product_id = u16::from_le_bytes([data[2], data[3]]);
    let device_class = data[4];
    let num_interfaces = (data[5] as usize).min(8);
    let interface_classes: Vec<u8> = data[6..data.len().min(6 + num_interfaces)].to_vec();

    let fp = fdu_models::UsbFingerprint {
        vendor_id,
        product_id,
        manufacturer: None,
        product: None,
        serial: None,
        device_class,
        interface_classes,
        bcd_device: u16::from_le_bytes([data[6 % data.len()], data[7 % data.len()]]),
        descriptors_raw: data[8..].to_vec(),
    };

    // Run all detectors — should never panic
    let _ = fdu_usb::detect_badusb(&fp);
});
