//! Fuzz the file signature carving engine.
//!
//! Feeds random bytes to scan_signatures() which searches for
//! known file magic bytes (JPEG, PNG, PDF, etc.).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let device = fdu_core::device::MockDevice::from_bytes(data.to_vec());
    let _ = fdu_core::recovery::carving::scan_signatures(&device, &[], None);
});
