//! Audit configuration.

use crate::detector::Phase;
use fdu_models::Severity;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Configuration for an audit scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Phases to skip entirely.
    pub skip_phases: Vec<Phase>,
    /// Minimum severity to include in the report (filters out lower findings).
    pub min_severity: Severity,
    /// Enable content scanning (file carving + signature matching).
    pub enable_content_scan: bool,
    /// Enable forensics (deleted file recovery analysis).
    pub enable_forensics: bool,
    /// Overall scan timeout.
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            skip_phases: Vec::new(),
            min_severity: Severity::Info,
            enable_content_scan: true,
            enable_forensics: true,
            timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

impl AuditConfig {
    /// Quick scan — skip forensics and content phases.
    pub fn quick() -> Self {
        Self {
            enable_content_scan: false,
            enable_forensics: false,
            timeout: Duration::from_secs(30),
            ..Default::default()
        }
    }

    /// Check if a phase should be executed.
    pub fn should_run_phase(&self, phase: Phase) -> bool {
        if self.skip_phases.contains(&phase) {
            return false;
        }
        match phase {
            Phase::Content => self.enable_content_scan,
            Phase::Forensics => self.enable_forensics,
            _ => true,
        }
    }
}

// Serde helper for Phase (need manual impl since it's in another module)
mod phase_serde {
    use super::Phase;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Phase {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            match self {
                Phase::Usb => s.serialize_str("usb"),
                Phase::Disk => s.serialize_str("disk"),
                Phase::Filesystem => s.serialize_str("filesystem"),
                Phase::Content => s.serialize_str("content"),
                Phase::Forensics => s.serialize_str("forensics"),
            }
        }
    }

    impl<'de> Deserialize<'de> for Phase {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let s = String::deserialize(d)?;
            match s.as_str() {
                "usb" => Ok(Phase::Usb),
                "disk" => Ok(Phase::Disk),
                "filesystem" => Ok(Phase::Filesystem),
                "content" => Ok(Phase::Content),
                "forensics" => Ok(Phase::Forensics),
                _ => Err(serde::de::Error::custom(format!("Unknown phase: {}", s))),
            }
        }
    }
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct Dur {
        secs: u64,
    }

    pub fn serialize<S: Serializer>(dur: &Duration, s: S) -> Result<S::Ok, S::Error> {
        Dur {
            secs: dur.as_secs(),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let dur = Dur::deserialize(d)?;
        Ok(Duration::from_secs(dur.secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = AuditConfig::default();
        assert!(cfg.enable_content_scan);
        assert!(cfg.enable_forensics);
        assert!(cfg.skip_phases.is_empty());
    }

    #[test]
    fn quick_config() {
        let cfg = AuditConfig::quick();
        assert!(!cfg.enable_content_scan);
        assert!(!cfg.enable_forensics);
    }

    #[test]
    fn phase_skip() {
        let mut cfg = AuditConfig::default();
        cfg.skip_phases.push(Phase::Usb);
        assert!(!cfg.should_run_phase(Phase::Usb));
        assert!(cfg.should_run_phase(Phase::Disk));
    }

    #[test]
    fn serialization_roundtrip() {
        let cfg = AuditConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let cfg2: AuditConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg.enable_content_scan, cfg2.enable_content_scan);
    }
}
