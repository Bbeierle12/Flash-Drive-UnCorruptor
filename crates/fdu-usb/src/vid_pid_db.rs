//! Embedded database of known-bad USB Vendor/Product ID pairs.
//!
//! These are VID:PID combinations associated with known attack tools,
//! malicious firmware, or devices commonly used in BadUSB attacks.

/// A known-bad VID:PID entry.
#[derive(Debug, Clone, Copy)]
pub struct BadVidPid {
    pub vendor_id: u16,
    pub product_id: u16,
    pub description: &'static str,
    pub cve: Option<&'static str>,
}

/// The embedded database of known-bad VID:PID pairs.
///
/// Sources:
/// - USB Rubber Ducky (Hak5)
/// - Bash Bunny (Hak5)
/// - Malduino
/// - O.MG Cable
/// - USBNinja
/// - Various BadUSB research papers
pub static KNOWN_BAD: &[BadVidPid] = &[
    // Hak5 USB Rubber Ducky (various revisions)
    BadVidPid {
        vendor_id: 0x05AC,
        product_id: 0x0201,
        description: "Potential USB Rubber Ducky (spoofed Apple keyboard VID:PID)",
        cve: None,
    },
    // Hak5 Bash Bunny
    BadVidPid {
        vendor_id: 0x0F0D,
        product_id: 0x1100,
        description: "Potential Bash Bunny or HID-attack device",
        cve: None,
    },
    // Malduino
    BadVidPid {
        vendor_id: 0x2341,
        product_id: 0x8037,
        description: "Arduino Micro (commonly used as Malduino/BadUSB platform)",
        cve: None,
    },
    // Teensy (common BadUSB platform)
    BadVidPid {
        vendor_id: 0x16C0,
        product_id: 0x0486,
        description: "Teensy HID device (common BadUSB platform)",
        cve: None,
    },
    // ATEN/Digitus HID exploits
    BadVidPid {
        vendor_id: 0x0557,
        product_id: 0x2419,
        description: "Known BadUSB firmware exploit target",
        cve: Some("CVE-2014-3566"),
    },
    // Generic Phison controller (BadUSB research target)
    BadVidPid {
        vendor_id: 0x0D49,
        product_id: 0x7212,
        description: "Phison USB controller (BadUSB firmware vulnerability)",
        cve: None,
    },
    // O.MG Cable
    BadVidPid {
        vendor_id: 0x0525,
        product_id: 0xA4A7,
        description: "Potential O.MG Cable or similar covert HID device",
        cve: None,
    },
    // CJMCU BadUSB
    BadVidPid {
        vendor_id: 0x1B4F,
        product_id: 0x9204,
        description: "SparkFun Pro Micro (common BadUSB/keystroke injection platform)",
        cve: None,
    },
];

/// Look up a VID:PID pair in the known-bad database.
pub fn lookup(vendor_id: u16, product_id: u16) -> Option<&'static BadVidPid> {
    KNOWN_BAD
        .iter()
        .find(|entry| entry.vendor_id == vendor_id && entry.product_id == product_id)
}

/// Check if a VID:PID pair is in the known-bad database.
pub fn is_known_bad(vendor_id: u16, product_id: u16) -> bool {
    lookup(vendor_id, product_id).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_bad() {
        let entry = lookup(0x16C0, 0x0486);
        assert!(entry.is_some());
        assert!(entry.unwrap().description.contains("Teensy"));
    }

    #[test]
    fn lookup_clean_device() {
        // SanDisk Cruzer — not in the bad list
        assert!(lookup(0x0781, 0x5567).is_none());
        assert!(!is_known_bad(0x0781, 0x5567));
    }

    #[test]
    fn all_entries_have_descriptions() {
        for entry in KNOWN_BAD {
            assert!(!entry.description.is_empty());
        }
    }
}
