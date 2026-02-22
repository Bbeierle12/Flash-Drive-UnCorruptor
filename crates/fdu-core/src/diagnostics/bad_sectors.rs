//! Bad sector detection by attempting to read every sector on the device.

use crate::device::traits::Device;
use crate::errors;
use crate::models::DiagnosticReport;
use std::time::Instant;

/// Callback for reporting scan progress.
pub type ProgressCallback = Box<dyn Fn(u64, u64) + Send>;

/// Scan a device for bad (unreadable) sectors.
///
/// Reads every sector and records which ones fail. This can be slow
/// on large drives — use `progress_cb` for progress updates.
pub fn scan_bad_sectors(
    device: &dyn Device,
    progress_cb: Option<ProgressCallback>,
) -> errors::Result<DiagnosticReport> {
    let start = Instant::now();
    let sector_size = device.sector_size() as usize;
    let total_sectors = device.size() / sector_size as u64;

    let mut bad_sectors = Vec::new();
    let mut buf = vec![0u8; sector_size];

    // Read speed measurement
    let speed_start = Instant::now();
    let mut bytes_read = 0u64;

    for sector in 0..total_sectors {
        let offset = sector * sector_size as u64;

        match device.read_at(offset, &mut buf) {
            Ok(n) => {
                bytes_read += n as u64;
            }
            Err(errors::Error::BadSector { .. }) => {
                bad_sectors.push(sector);
            }
            Err(errors::Error::Io { .. }) => {
                bad_sectors.push(sector);
            }
            Err(e) => return Err(e),
        }

        // Report progress every 1000 sectors
        if sector % 1000 == 0 {
            if let Some(ref cb) = progress_cb {
                cb(sector, total_sectors);
            }
        }
    }

    let elapsed_secs = speed_start.elapsed().as_secs_f64();
    let read_speed_mbps = if elapsed_secs > 0.0 {
        Some((bytes_read as f64 / 1_048_576.0) / elapsed_secs)
    } else {
        None
    };

    Ok(DiagnosticReport {
        device_id: device.id().to_string(),
        total_sectors,
        bad_sectors,
        read_speed_mbps,
        write_speed_mbps: None, // Write speed test requires writable device
        scan_duration_ms: start.elapsed().as_millis() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    #[test]
    fn test_scan_healthy_device() {
        let dev = MockDevice::new(512 * 100); // 100 sectors
        let report = scan_bad_sectors(&dev, None).unwrap();
        assert_eq!(report.total_sectors, 100);
        assert!(report.bad_sectors.is_empty());
        assert!(report.health_score() > 99.9);
    }

    #[test]
    fn test_scan_with_bad_sectors() {
        let dev = MockDevice::new(512 * 100)
            .with_bad_sector(10)
            .with_bad_sector(50)
            .with_bad_sector(99);

        let report = scan_bad_sectors(&dev, None).unwrap();
        assert_eq!(report.bad_sector_count(), 3);
        assert!(report.bad_sectors.contains(&10));
        assert!(report.bad_sectors.contains(&50));
        assert!(report.bad_sectors.contains(&99));
    }

    #[test]
    fn test_progress_callback() {
        use std::sync::{Arc, Mutex};

        let progress_calls = Arc::new(Mutex::new(Vec::new()));
        let progress_clone = progress_calls.clone();

        let cb: ProgressCallback = Box::new(move |current, total| {
            progress_clone.lock().unwrap().push((current, total));
        });

        let dev = MockDevice::new(512 * 5000); // 5000 sectors
        let _report = scan_bad_sectors(&dev, Some(cb)).unwrap();

        let calls = progress_calls.lock().unwrap();
        assert!(!calls.is_empty());
        // First call should be at sector 0
        assert_eq!(calls[0].0, 0);
    }
}
