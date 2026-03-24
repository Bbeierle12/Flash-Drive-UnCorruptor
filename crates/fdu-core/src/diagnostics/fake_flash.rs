//! Fake flash / counterfeit capacity detection.
//!
//! Detects drives that report a larger capacity than they actually have.
//! Common with counterfeit USB flash drives that internally wrap LBA
//! addresses, causing data written past the real capacity to overwrite
//! earlier data (or return stale reads).
//!
//! Corrosion attack handled: FakeFlashWrap

use crate::device::traits::{Device, DeviceExt};
use crate::errors;
use serde::{Deserialize, Serialize};

/// Result of a fake-flash capacity test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeFlashResult {
    /// Device identifier.
    pub device_id: String,
    /// Reported device size in bytes.
    pub reported_size: u64,
    /// Estimated real capacity (0 if test was read-only).
    pub estimated_real_size: u64,
    /// Whether the device appears to be counterfeit.
    pub is_fake: bool,
    /// Offsets where wrap-around was detected.
    pub wrap_offsets: Vec<u64>,
    /// Description of findings.
    pub description: String,
}

/// Probe for fake flash by reading data at strategic offsets and checking
/// for wrap-around patterns.
///
/// This is a **read-only** heuristic check. It reads data at power-of-2
/// offsets and checks whether different regions return identical data
/// (which suggests LBA wrap-around). For a definitive test, a write-read
/// verification would be needed (destructive).
///
/// The read-only approach works when the drive already has data and the
/// fake controller wraps reads as well as writes.
pub fn detect_fake_flash(
    device: &dyn Device,
    progress_cb: Option<Box<dyn Fn(u64, u64) + Send>>,
) -> errors::Result<FakeFlashResult> {
    let reported_size = device.size();
    let sector_size = device.sector_size() as u64;

    if reported_size < sector_size * 2 {
        return Ok(FakeFlashResult {
            device_id: device.id().to_string(),
            reported_size,
            estimated_real_size: reported_size,
            is_fake: false,
            wrap_offsets: vec![],
            description: "Device too small to test".into(),
        });
    }

    // Read the first sector as our reference pattern
    let reference = device.read_exact_at(0, sector_size as usize)?;

    // Check at power-of-2 byte offsets from the device start.
    // If a distant offset returns the same data as offset 0, it may be
    // wrapping around.
    let mut probe_offsets = Vec::new();
    let mut offset = 1024 * 1024; // Start at 1 MB
    while offset < reported_size {
        probe_offsets.push(offset);
        offset *= 2;
    }
    // Also check near the end
    if reported_size > sector_size {
        probe_offsets.push(reported_size - sector_size);
    }

    let total_probes = probe_offsets.len() as u64;
    let mut wrap_offsets = Vec::new();
    let mut last_good_offset = 0u64;

    for (i, &probe_offset) in probe_offsets.iter().enumerate() {
        if let Some(ref cb) = progress_cb {
            cb(i as u64, total_probes);
        }

        let probe_data = match device.read_exact_at(probe_offset, sector_size as usize) {
            Ok(d) => d,
            Err(_) => {
                // Can't read this offset — might be past real capacity
                wrap_offsets.push(probe_offset);
                continue;
            }
        };

        // Check if this sector is identical to sector 0.
        // On a real drive with data, distant sectors should differ from sector 0.
        // On a fake drive, wrapped reads return the same physical sector.
        if probe_data == reference && probe_offset > 0 {
            // Could be a coincidence if both are zeroed — check for that
            let all_zero = reference.iter().all(|&b| b == 0);
            if !all_zero {
                wrap_offsets.push(probe_offset);
            }
        } else {
            last_good_offset = probe_offset;
        }
    }

    let is_fake = !wrap_offsets.is_empty();
    let estimated_real_size = if is_fake {
        // Estimate: smallest wrap offset is approximately the real capacity
        wrap_offsets.iter().copied().min().unwrap_or(reported_size)
    } else {
        reported_size
    };

    let description = if is_fake {
        format!(
            "FAKE FLASH DETECTED: Device reports {} bytes but wraps at ~{} bytes. \
             {} probe offsets showed wrap-around.",
            reported_size,
            estimated_real_size,
            wrap_offsets.len(),
        )
    } else {
        format!(
            "Device capacity appears genuine ({} bytes). {} offsets probed, last verified at {}.",
            reported_size,
            probe_offsets.len(),
            last_good_offset,
        )
    };

    Ok(FakeFlashResult {
        device_id: device.id().to_string(),
        reported_size,
        estimated_real_size,
        is_fake,
        wrap_offsets,
        description,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    #[test]
    fn genuine_device_passes() {
        // A device with different data at different offsets is genuine
        let mut dev = MockDevice::new(1024 * 1024 * 4); // 4 MB
        // Write distinct patterns at key offsets
        dev.set_data(0, b"FIRST_SECTOR_DATA_UNIQUE_PATTERN!");
        dev.set_data(1024 * 1024, b"ONE_MEGABYTE_OFFSET_DIFFERENT!__");
        dev.set_data(2 * 1024 * 1024, b"TWO_MEGABYTE_OFFSET_ALSO_DIFF!_");

        let result = detect_fake_flash(&dev, None).unwrap();
        assert!(!result.is_fake, "Genuine device falsely flagged as fake");
    }

    #[test]
    fn zeroed_device_not_flagged() {
        // All-zero device should not be flagged (common for new drives)
        let dev = MockDevice::new(1024 * 1024 * 4);
        let result = detect_fake_flash(&dev, None).unwrap();
        assert!(!result.is_fake, "All-zero device should not be flagged");
    }

    #[test]
    fn tiny_device_skipped() {
        let dev = MockDevice::new(512);
        let result = detect_fake_flash(&dev, None).unwrap();
        assert!(!result.is_fake);
        assert!(result.description.contains("too small"));
    }

    #[test]
    fn simulated_wrap_detected() {
        // Simulate a 4MB device that wraps at 1MB: data at 1MB, 2MB, 3MB
        // returns the same as data at 0
        let mut dev = MockDevice::new(4 * 1024 * 1024);
        let pattern = b"WRAP_TEST_PATTERN_SECTOR_ZERO!__";
        // Write the same pattern at offset 0 and at 1MB, 2MB
        dev.set_data(0, pattern);
        dev.set_data(1024 * 1024, pattern);
        dev.set_data(2 * 1024 * 1024, pattern);

        let result = detect_fake_flash(&dev, None).unwrap();
        assert!(result.is_fake, "Wrap-around device should be detected as fake");
        assert!(!result.wrap_offsets.is_empty());
    }
}
