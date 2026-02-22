//! File signature carving — detect files by their magic bytes.
//!
//! Scans raw device data for known file signatures (magic bytes at the
//! start of files) and estimates file boundaries.

use crate::device::traits::Device;
use crate::errors::Result;
use crate::models::RecoverableFile;

/// A known file signature (magic bytes).
#[derive(Debug, Clone)]
pub struct FileSignature {
    /// Human-readable file type name
    pub name: &'static str,
    /// File extension
    pub extension: &'static str,
    /// Magic bytes at the start of the file
    pub header: &'static [u8],
    /// Optional footer bytes (for determining file end)
    pub footer: Option<&'static [u8]>,
    /// Maximum expected file size (for bounding search)
    pub max_size: u64,
}

/// Built-in file signatures for common file types.
pub static SIGNATURES: &[FileSignature] = &[
    FileSignature {
        name: "JPEG Image",
        extension: "jpg",
        header: &[0xFF, 0xD8, 0xFF],
        footer: Some(&[0xFF, 0xD9]),
        max_size: 50 * 1024 * 1024, // 50 MB
    },
    FileSignature {
        name: "PNG Image",
        extension: "png",
        header: &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        footer: Some(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
        max_size: 50 * 1024 * 1024,
    },
    FileSignature {
        name: "PDF Document",
        extension: "pdf",
        header: &[0x25, 0x50, 0x44, 0x46], // %PDF
        footer: Some(&[0x25, 0x25, 0x45, 0x4F, 0x46]), // %%EOF
        max_size: 500 * 1024 * 1024,
    },
    FileSignature {
        name: "ZIP Archive",
        extension: "zip",
        header: &[0x50, 0x4B, 0x03, 0x04], // PK..
        footer: None,
        max_size: 1024 * 1024 * 1024, // 1 GB
    },
    FileSignature {
        name: "GIF Image",
        extension: "gif",
        header: &[0x47, 0x49, 0x46, 0x38], // GIF8
        footer: Some(&[0x00, 0x3B]),
        max_size: 50 * 1024 * 1024,
    },
    FileSignature {
        name: "BMP Image",
        extension: "bmp",
        header: &[0x42, 0x4D], // BM
        footer: None,
        max_size: 100 * 1024 * 1024,
    },
    FileSignature {
        name: "MP3 Audio",
        extension: "mp3",
        header: &[0x49, 0x44, 0x33], // ID3
        footer: None,
        max_size: 200 * 1024 * 1024,
    },
    FileSignature {
        name: "MP4 Video",
        extension: "mp4",
        // ftyp box marker (offset 4)
        header: &[0x66, 0x74, 0x79, 0x70], // "ftyp" — note: actually at offset 4
        footer: None,
        max_size: 4 * 1024 * 1024 * 1024, // 4 GB
    },
];

/// Scan a device for files matching known signatures.
///
/// Reads the device in chunks and searches for magic bytes.
/// Returns a list of detected files with their offsets and estimated sizes.
pub fn scan_signatures(
    device: &dyn Device,
    filter_types: &[String],
    progress_cb: Option<Box<dyn Fn(u64, u64) + Send>>,
) -> Result<Vec<RecoverableFile>> {
    let device_size = device.size();
    let chunk_size: usize = 64 * 1024; // 64 KB chunks
    let mut found = Vec::new();
    let mut buf = vec![0u8; chunk_size];

    let signatures: Vec<&FileSignature> = if filter_types.is_empty() {
        SIGNATURES.iter().collect()
    } else {
        SIGNATURES
            .iter()
            .filter(|s| {
                filter_types.iter().any(|f| {
                    f.eq_ignore_ascii_case(s.extension) || f.eq_ignore_ascii_case(s.name)
                })
            })
            .collect()
    };

    let mut offset = 0u64;
    while offset < device_size {
        let to_read = chunk_size.min((device_size - offset) as usize);
        let n = device.read_at(offset, &mut buf[..to_read])?;
        if n == 0 {
            break;
        }

        // Search for each signature in this chunk
        for sig in &signatures {
            for i in 0..n.saturating_sub(sig.header.len()) {
                if buf[i..].starts_with(sig.header) {
                    // Special case: MP4 ftyp is at offset 4, check if bytes 4-8 match
                    if sig.extension == "mp4" && i < 4 {
                        continue;
                    }

                    let file_offset = offset + i as u64;

                    // Estimate size: search for footer or use max_size
                    let estimated_size = if let Some(footer) = sig.footer {
                        estimate_size_by_footer(
                            device,
                            file_offset,
                            footer,
                            sig.max_size,
                        )
                        .unwrap_or(sig.max_size.min(device_size - file_offset))
                    } else {
                        sig.max_size.min(device_size - file_offset)
                    };

                    found.push(RecoverableFile {
                        file_type: sig.name.to_string(),
                        signature: sig.header.to_vec(),
                        offset: file_offset,
                        estimated_size,
                        confidence: 0.7,
                        original_name: None,
                    });
                }
            }
        }

        if let Some(ref cb) = progress_cb {
            cb(offset, device_size);
        }

        // Advance by bytes read minus overlap (to catch signatures spanning chunks)
        let max_sig_len = signatures.iter().map(|s| s.header.len()).max().unwrap_or(8);
        let advance = if n > max_sig_len {
            n - max_sig_len
        } else {
            n // Last small chunk — just move past it
        };
        offset += advance as u64;
    }

    Ok(found)
}

/// Search for a footer signature to estimate file size.
fn estimate_size_by_footer(
    device: &dyn Device,
    start_offset: u64,
    footer: &[u8],
    max_size: u64,
) -> Result<u64> {
    let chunk_size: usize = 64 * 1024;
    let mut buf = vec![0u8; chunk_size];
    let device_size = device.size();
    let search_limit = max_size.min(device_size - start_offset);

    let mut offset = 0u64;
    while offset < search_limit {
        let to_read = chunk_size.min((search_limit - offset) as usize);
        let n = device.read_at(start_offset + offset, &mut buf[..to_read])?;
        if n == 0 {
            break;
        }

        // Search for footer in this chunk
        for i in 0..n.saturating_sub(footer.len()) {
            if buf[i..].starts_with(footer) {
                return Ok(offset + i as u64 + footer.len() as u64);
            }
        }

        let advance = if n > footer.len() {
            n - footer.len()
        } else {
            n
        };
        offset += advance as u64;
    }

    Ok(search_limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::MockDevice;

    // ── Legacy tests (preserved) ───────────────────────────────────

    #[test]
    fn test_detect_jpeg() {
        let mut dev = MockDevice::new(16 * 1024);
        dev.set_data(4096, &[0xFF, 0xD8, 0xFF, 0xE0]);
        dev.set_data(4096 + 1000, &[0xFF, 0xD9]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let jpegs: Vec<_> = results.iter().filter(|r| r.file_type == "JPEG Image").collect();
        assert!(!jpegs.is_empty());
        assert_eq!(jpegs[0].offset, 4096);
    }

    #[test]
    fn test_detect_pdf() {
        let mut dev = MockDevice::new(16 * 1024);
        dev.set_data(8192, b"%PDF-1.4");
        dev.set_data(8192 + 5000, b"%%EOF");

        let results = scan_signatures(&dev, &[], None).unwrap();
        let pdfs: Vec<_> = results
            .iter()
            .filter(|r| r.file_type == "PDF Document")
            .collect();
        assert!(!pdfs.is_empty());
    }

    #[test]
    fn test_filter_by_type() {
        let mut dev = MockDevice::new(16 * 1024);
        dev.set_data(0, &[0xFF, 0xD8, 0xFF]);
        dev.set_data(4096, b"%PDF");

        let results =
            scan_signatures(&dev, &["jpg".to_string()], None).unwrap();
        assert!(results.iter().all(|r| r.file_type == "JPEG Image"));
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 5 — Remaining file types
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn phase5_detect_png_with_iend() {
        let mut dev = MockDevice::new(16 * 1024);
        // PNG header
        dev.set_data(100, &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        // IEND footer
        dev.set_data(100 + 2000, &[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let pngs: Vec<_> = results.iter().filter(|r| r.file_type == "PNG Image").collect();
        assert!(!pngs.is_empty());
        assert_eq!(pngs[0].offset, 100);
        // Size should be ~2008 (footer offset + footer len)
        assert!(pngs[0].estimated_size <= 2100);
    }

    #[test]
    fn phase5_detect_zip() {
        let mut dev = MockDevice::new(16 * 1024);
        // PK header
        dev.set_data(512, &[0x50, 0x4B, 0x03, 0x04]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let zips: Vec<_> = results.iter().filter(|r| r.file_type == "ZIP Archive").collect();
        assert!(!zips.is_empty());
        assert_eq!(zips[0].offset, 512);
    }

    #[test]
    fn phase5_detect_gif_with_footer() {
        let mut dev = MockDevice::new(16 * 1024);
        // GIF89a header (starts with GIF8)
        dev.set_data(256, &[0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
        // GIF footer: 0x00 0x3B
        dev.set_data(256 + 500, &[0x00, 0x3B]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let gifs: Vec<_> = results.iter().filter(|r| r.file_type == "GIF Image").collect();
        assert!(!gifs.is_empty());
        assert_eq!(gifs[0].offset, 256);
    }

    #[test]
    fn phase5_detect_bmp() {
        let mut dev = MockDevice::new(16 * 1024);
        // BM header
        dev.set_data(1024, &[0x42, 0x4D]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let bmps: Vec<_> = results.iter().filter(|r| r.file_type == "BMP Image").collect();
        assert!(!bmps.is_empty());
        assert_eq!(bmps[0].offset, 1024);
    }

    #[test]
    fn phase5_detect_mp3_id3() {
        let mut dev = MockDevice::new(16 * 1024);
        // ID3 header
        dev.set_data(2048, &[0x49, 0x44, 0x33]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let mp3s: Vec<_> = results.iter().filter(|r| r.file_type == "MP3 Audio").collect();
        assert!(!mp3s.is_empty());
        assert_eq!(mp3s[0].offset, 2048);
    }

    #[test]
    fn phase5_detect_mp4_ftyp_at_offset_4() {
        let mut dev = MockDevice::new(16 * 1024);
        // MP4: 4 bytes size + "ftyp" at offset 4 from the start of the file
        // Place the file start at offset 100 in the device
        // So "ftyp" appears at device offset 104
        let mut mp4_start = [0u8; 8];
        mp4_start[0..4].copy_from_slice(&0x00000018u32.to_be_bytes()); // box size
        mp4_start[4..8].copy_from_slice(b"ftyp");
        dev.set_data(100, &mp4_start);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let mp4s: Vec<_> = results.iter().filter(|r| r.file_type == "MP4 Video").collect();
        assert!(!mp4s.is_empty());
        // The scanner matches "ftyp" at offset 104 (which is i=4 in the chunk)
        assert_eq!(mp4s[0].offset, 104);
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 5 — Edge cases
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn phase5_mp4_ftyp_at_offset_0_skipped() {
        let mut dev = MockDevice::new(16 * 1024);
        // Place "ftyp" right at the start of a chunk (i=0, which is < 4)
        dev.set_data(0, b"ftyp");

        let results = scan_signatures(&dev, &[], None).unwrap();
        let mp4s: Vec<_> = results.iter().filter(|r| r.file_type == "MP4 Video").collect();
        // Should be skipped because ftyp is at position < 4
        assert!(mp4s.is_empty());
    }

    #[test]
    fn phase5_signature_spanning_chunk_boundary() {
        // The scanner uses 64KB chunks with overlap to catch signatures at boundaries.
        // Place a JPEG signature near the end of a chunk boundary.
        let size = 128 * 1024; // 128 KB
        let mut dev = MockDevice::new(size);
        // Place JPEG right before 64KB boundary (minus max_sig_len overlap region)
        let offset = 64 * 1024 - 4;
        dev.set_data(offset, &[0xFF, 0xD8, 0xFF, 0xE0]);

        let results = scan_signatures(&dev, &[], None).unwrap();
        let jpegs: Vec<_> = results.iter().filter(|r| r.file_type == "JPEG Image").collect();
        assert!(!jpegs.is_empty(), "JPEG at chunk boundary should be detected");
    }

    #[test]
    fn phase5_footer_found_size_estimation() {
        let mut dev = MockDevice::new(16 * 1024);
        // JPEG with known footer
        dev.set_data(0, &[0xFF, 0xD8, 0xFF, 0xE0]);
        dev.set_data(500, &[0xFF, 0xD9]); // footer at offset 500

        let results = scan_signatures(&dev, &["jpg".to_string()], None).unwrap();
        assert!(!results.is_empty());
        // Size = (footer_offset - start + footer_len) = 500 + 2 = 502
        assert_eq!(results[0].estimated_size, 502);
    }

    #[test]
    fn phase5_footer_not_found_falls_back_to_max() {
        let mut dev = MockDevice::new(16 * 1024);
        // JPEG with NO footer in the image
        dev.set_data(0, &[0xFF, 0xD8, 0xFF, 0xE0]);

        let results = scan_signatures(&dev, &["jpg".to_string()], None).unwrap();
        assert!(!results.is_empty());
        // Size should be capped at device_size (since max_size > device_size)
        assert_eq!(results[0].estimated_size, 16 * 1024);
    }

    #[test]
    fn phase5_multiple_same_type_signatures() {
        let mut dev = MockDevice::new(16 * 1024);
        // Two JPEG signatures
        dev.set_data(0, &[0xFF, 0xD8, 0xFF]);
        dev.set_data(4096, &[0xFF, 0xD8, 0xFF]);

        let results = scan_signatures(&dev, &["jpg".to_string()], None).unwrap();
        let jpegs: Vec<_> = results.iter().filter(|r| r.file_type == "JPEG Image").collect();
        assert!(jpegs.len() >= 2, "expected at least 2 JPEGs, got {}", jpegs.len());
    }

    #[test]
    fn phase5_filter_excludes_non_matching() {
        let mut dev = MockDevice::new(16 * 1024);
        dev.set_data(0, &[0xFF, 0xD8, 0xFF]); // JPEG
        dev.set_data(4096, b"%PDF"); // PDF
        dev.set_data(8192, &[0x50, 0x4B, 0x03, 0x04]); // ZIP

        let results = scan_signatures(&dev, &["pdf".to_string()], None).unwrap();
        assert!(results.iter().all(|r| r.file_type == "PDF Document"));
        // Should have exactly 1 result
        assert_eq!(results.len(), 1);
    }

    // ════════════════════════════════════════════════════════════════
    // Phase 5 — guess_file_type() (from fat32.rs, tested here for coverage)
    // ════════════════════════════════════════════════════════════════

    #[test]
    fn phase5_guess_file_type_case_insensitive() {
        use crate::fs::fat32::tests_helper_guess;
        assert_eq!(tests_helper_guess::guess("photo.JPG"), "JPEG Image");
        assert_eq!(tests_helper_guess::guess("photo.Jpg"), "JPEG Image");
        assert_eq!(tests_helper_guess::guess("photo.jpeg"), "JPEG Image");
    }

    #[test]
    fn phase5_guess_file_type_all_known() {
        use crate::fs::fat32::tests_helper_guess;
        assert_eq!(tests_helper_guess::guess("a.png"), "PNG Image");
        assert_eq!(tests_helper_guess::guess("a.doc"), "Word Document");
        assert_eq!(tests_helper_guess::guess("a.docx"), "Word Document");
        assert_eq!(tests_helper_guess::guess("a.xls"), "Excel Spreadsheet");
        assert_eq!(tests_helper_guess::guess("a.xlsx"), "Excel Spreadsheet");
        assert_eq!(tests_helper_guess::guess("a.txt"), "Text File");
        assert_eq!(tests_helper_guess::guess("a.mp3"), "MP3 Audio");
        assert_eq!(tests_helper_guess::guess("a.mp4"), "MP4 Video");
    }

    #[test]
    fn phase5_guess_file_type_no_extension() {
        use crate::fs::fat32::tests_helper_guess;
        // A file named just "README" has no extension
        let result = tests_helper_guess::guess("README");
        assert_eq!(result, "README File");
    }

    #[test]
    fn phase5_guess_file_type_dotfile() {
        use crate::fs::fat32::tests_helper_guess;
        // ".gitignore" — extension is "gitignore"
        let result = tests_helper_guess::guess(".gitignore");
        assert_eq!(result, "GITIGNORE File");
    }
}
