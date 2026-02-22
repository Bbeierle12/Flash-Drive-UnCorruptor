//! Fuzz the FAT32 BPB (BIOS Parameter Block) parser.
//!
//! Feeds random bytes as a MockDevice to Fat32Fs::new(), which parses
//! the BPB from the first sector.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    let device = fdu_core::device::MockDevice::from_bytes(data.to_vec());
    // We only care that it doesn't panic — errors are expected
    let _ = fdu_core::fs::fat32::Fat32Fs::new(&device);
});
