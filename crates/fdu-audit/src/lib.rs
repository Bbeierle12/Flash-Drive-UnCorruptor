//! # fdu-audit
//!
//! Security audit engine with a pluggable detector framework.
//!
//! ## Architecture
//!
//! The [`AuditEngine`] orchestrates the scan pipeline:
//!
//! 1. **USB phase** — interrogate USB descriptors, detect BadUSB
//! 2. **Disk phase** — parse partition tables, detect layout anomalies
//! 3. **Filesystem phase** — validate filesystem integrity
//! 4. **Content phase** — scan for malware signatures, suspicious files
//! 5. **Forensics phase** — recover deleted files, flag anomalies
//!
//! Each detector implements the [`Detector`] trait and returns `Vec<Finding>`.
//! The engine aggregates all findings into a [`ThreatReport`].

pub mod config;
pub mod detector;
pub mod detectors;
pub mod engine;
pub mod report;

pub use config::AuditConfig;
pub use detector::{Detector, Phase, ScanContext};
pub use engine::AuditEngine;
