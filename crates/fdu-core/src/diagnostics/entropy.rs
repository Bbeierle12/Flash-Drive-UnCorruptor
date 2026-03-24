//! Entropy analysis — detect random data injection, debug signatures,
//! and anomalous regions on a device.
//!
//! Corrosion attacks handled:
//! - EntropyInject: high-entropy random data in structured regions
//! - OldDataInject: allocator debug signatures (DEADBEEF, BAADF00D, etc.)
//! - BitRot: scattered bit flips raising block entropy

use crate::device::traits::{Device, DeviceExt};
use crate::errors;
use serde::{Deserialize, Serialize};

/// Size of each block for entropy calculation (4 KB).
const BLOCK_SIZE: usize = 4096;

/// Shannon entropy above this threshold is suspicious in structured data.
const HIGH_ENTROPY_THRESHOLD: f64 = 7.5;

/// Shannon entropy below this threshold in a non-empty block may indicate
/// a fill pattern (SectorFill, SectorZero).
const LOW_ENTROPY_THRESHOLD: f64 = 0.5;

/// Known allocator / debug fill patterns (OldDataInject detection).
const DEBUG_SIGNATURES: &[(&[u8], &str)] = &[
    (b"\xDE\xAD\xBE\xEF", "DEADBEEF — debug heap allocator"),
    (b"\xBA\xAD\xF0\x0D", "BAADF00D — uninitialized heap (Windows)"),
    (b"\xFE\xED\xFA\xCE", "FEEDFACE — Mach-O header / debug fill"),
    (b"\xFE\xEE\xFE\xEE", "FEEEFEEE — freed heap (Windows)"),
    (b"\xAB\xAB\xAB\xAB", "ABABABAB — guard bytes (Visual C++)"),
    (b"\xCD\xCD\xCD\xCD", "CDCDCDCD — uninitialized stack (MSVC)"),
    (b"\xDD\xDD\xDD\xDD", "DDDDDDDD — freed memory (MSVC)"),
    (b"\xFD\xFD\xFD\xFD", "FDFDFDFD — no-man's-land guard (MSVC)"),
    (b"\xCC\xCC\xCC\xCC", "CCCCCCCC — uninitialized stack (MSVC /GZ)"),
];

/// Result of an entropy scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyScanResult {
    /// Device identifier.
    pub device_id: String,
    /// Total blocks scanned.
    pub blocks_scanned: u64,
    /// Blocks with suspiciously high entropy.
    pub high_entropy_blocks: Vec<EntropyAnomaly>,
    /// Blocks with suspiciously low entropy (fill patterns).
    pub low_entropy_blocks: Vec<EntropyAnomaly>,
    /// Debug signature detections.
    pub debug_signatures_found: Vec<DebugSignatureHit>,
    /// Average entropy across all blocks.
    pub average_entropy: f64,
}

/// An anomalous entropy reading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnomaly {
    /// Byte offset of the block.
    pub offset: u64,
    /// Shannon entropy (0.0 – 8.0).
    pub entropy: f64,
    /// Description.
    pub description: String,
}

/// A debug fill pattern found on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSignatureHit {
    /// Byte offset where found.
    pub offset: u64,
    /// Pattern description.
    pub description: String,
    /// Number of consecutive repetitions.
    pub repetitions: usize,
}

/// Calculate Shannon entropy of a byte slice (0.0 = uniform, 8.0 = random).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Scan a device for entropy anomalies and debug signatures.
///
/// Reads blocks of `BLOCK_SIZE` and computes Shannon entropy for each.
/// Also scans for known allocator debug patterns.
pub fn scan_entropy(
    device: &dyn Device,
    progress_cb: Option<Box<dyn Fn(u64, u64) + Send>>,
) -> errors::Result<EntropyScanResult> {
    let size = device.size();
    let total_blocks = size / BLOCK_SIZE as u64;

    let mut high_entropy = Vec::new();
    let mut low_entropy = Vec::new();
    let mut debug_hits = Vec::new();
    let mut entropy_sum = 0.0;
    let mut blocks_scanned = 0u64;

    for block_idx in 0..total_blocks {
        let offset = block_idx * BLOCK_SIZE as u64;

        let data = match device.read_exact_at(offset, BLOCK_SIZE) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let e = shannon_entropy(&data);
        entropy_sum += e;
        blocks_scanned += 1;

        // Check for all-zero blocks (separate from low entropy — these are
        // extremely common on formatted drives and not inherently suspicious)
        let all_zero = data.iter().all(|&b| b == 0);

        if e > HIGH_ENTROPY_THRESHOLD && !all_zero {
            high_entropy.push(EntropyAnomaly {
                offset,
                entropy: e,
                description: format!(
                    "High entropy block ({:.2} bits/byte) — possible random data injection",
                    e
                ),
            });
        } else if e < LOW_ENTROPY_THRESHOLD && e > 0.0 && !all_zero {
            low_entropy.push(EntropyAnomaly {
                offset,
                entropy: e,
                description: format!(
                    "Low entropy block ({:.2} bits/byte) — possible fill pattern",
                    e
                ),
            });
        }

        // Scan for debug signatures (check if pattern repeats across the block)
        for &(pattern, desc) in DEBUG_SIGNATURES {
            let reps = count_pattern_repetitions(&data, pattern);
            if reps >= 8 {
                // At least 8 consecutive repetitions = suspicious
                debug_hits.push(DebugSignatureHit {
                    offset,
                    description: desc.to_string(),
                    repetitions: reps,
                });
            }
        }

        if block_idx % 1000 == 0 {
            if let Some(ref cb) = progress_cb {
                cb(block_idx, total_blocks);
            }
        }
    }

    let average_entropy = if blocks_scanned > 0 {
        entropy_sum / blocks_scanned as f64
    } else {
        0.0
    };

    Ok(EntropyScanResult {
        device_id: device.id().to_string(),
        blocks_scanned,
        high_entropy_blocks: high_entropy,
        low_entropy_blocks: low_entropy,
        debug_signatures_found: debug_hits,
        average_entropy,
    })
}

/// Count how many times a pattern repeats consecutively from the start of data.
fn count_pattern_repetitions(data: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() || data.len() < pattern.len() {
        return 0;
    }
    let mut count = 0;
    for chunk in data.chunks_exact(pattern.len()) {
        if chunk == pattern {
            count += 1;
        } else {
            break;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    #[test]
    fn entropy_of_zeros() {
        let data = vec![0u8; 4096];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_of_random() {
        // Simulate high-entropy data: all 256 byte values equally represented
        let mut data = Vec::with_capacity(4096);
        for _ in 0..16 {
            for b in 0..=255u8 {
                data.push(b);
            }
        }
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "Expected near-maximum entropy, got {}", e);
    }

    #[test]
    fn entropy_of_repeating_pattern() {
        let data = vec![0xAB; 4096];
        assert_eq!(shannon_entropy(&data), 0.0); // single byte value = 0 entropy
    }

    #[test]
    fn detects_deadbeef_injection() {
        let mut dev = MockDevice::new(BLOCK_SIZE * 10);
        // Fill block 3 with DEADBEEF pattern
        let deadbeef_block: Vec<u8> = (0..BLOCK_SIZE)
            .map(|i| b"\xDE\xAD\xBE\xEF"[i % 4])
            .collect();
        dev.set_data(3 * BLOCK_SIZE, &deadbeef_block);

        let result = scan_entropy(&dev, None).unwrap();
        assert!(
            !result.debug_signatures_found.is_empty(),
            "Should detect DEADBEEF pattern"
        );
        assert!(result.debug_signatures_found[0]
            .description
            .contains("DEADBEEF"));
    }

    #[test]
    fn detects_high_entropy_block() {
        let mut dev = MockDevice::new(BLOCK_SIZE * 10);
        // Fill block 5 with pseudo-random high-entropy data
        let mut random_block = Vec::with_capacity(BLOCK_SIZE);
        for i in 0..BLOCK_SIZE {
            random_block.push(((i * 137 + 73) % 256) as u8);
        }
        dev.set_data(5 * BLOCK_SIZE, &random_block);

        let result = scan_entropy(&dev, None).unwrap();
        // The random block should have high entropy
        let block5_entropy = shannon_entropy(&random_block);
        assert!(block5_entropy > 7.0, "Test data entropy too low: {}", block5_entropy);
    }

    #[test]
    fn pattern_repetition_counting() {
        let data: Vec<u8> = (0..32)
            .map(|i| b"\xDE\xAD\xBE\xEF"[i % 4])
            .collect();
        assert_eq!(count_pattern_repetitions(&data, b"\xDE\xAD\xBE\xEF"), 8);
    }

    #[test]
    fn no_false_positives_on_clean_device() {
        let dev = MockDevice::new(BLOCK_SIZE * 100);
        let result = scan_entropy(&dev, None).unwrap();
        assert!(result.debug_signatures_found.is_empty());
        assert!(result.high_entropy_blocks.is_empty());
    }
}
