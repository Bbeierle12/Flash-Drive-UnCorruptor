//! # fdu-models
//!
//! Shared types for FDU's security audit pipeline.
//!
//! This crate is the vocabulary layer — it defines the data structures that flow
//! between `fdu-usb`, `fdu-disk`, `fdu-audit`, `fdu-extract`, `fdu-cli`, and
//! `fdu-web`.  It has no logic beyond serialization and a handful of helper
//! methods; keeping it thin avoids circular dependencies.

pub mod audit;
pub mod extraction;
pub mod threat;
pub mod usb;

// Re-export the most commonly used types at crate root for ergonomics.
pub use audit::{AuditEvent, AuditEventType};
pub use extraction::{ExtractionManifest, ExtractionPolicy, ExtractionProgress, ExtractedFile};
pub use threat::{Evidence, Finding, Severity, Status, ThreatReport};
pub use usb::UsbFingerprint;
