//! Fuzz the MBR partition table parser.
//!
//! Feeds random 512-byte sectors to the MBR parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 512 {
        return;
    }

    let _ = fdu_disk::mbr::parse_mbr(data, 512);
});
