//! Fuzz the filesystem detection logic.
//!
//! Feeds random bytes to detect_filesystem() which reads magic bytes
//! from various offsets to identify the filesystem type.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    let device = fdu_core::device::MockDevice::from_bytes(data.to_vec());
    let _ = fdu_core::fs::detect::detect_filesystem(&device);
});
