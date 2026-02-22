//! Fuzz the GPT partition table parser.
//!
//! Feeds random bytes as a disk image and attempts GPT parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 3 sectors (MBR + GPT header + partition entries)
    if data.len() < 512 * 3 {
        return;
    }

    let device = fdu_core::device::MockDevice::from_bytes(data.to_vec());
    // analyze_partitions reads MBR at LBA 0, then GPT at LBA 1
    let _ = fdu_disk::analyze_partitions(&device);
});
