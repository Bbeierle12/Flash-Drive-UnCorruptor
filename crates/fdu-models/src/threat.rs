//! Core security types — findings, severity levels, and threat reports.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use uuid::Uuid;

/// Severity level for a security finding.
///
/// This is distinct from `fdu_core::models::Severity` which covers filesystem
/// issues (Info/Warning/Error/Critical).  The security severity adds `Low` and
/// uses CVSS-aligned terminology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Lifecycle status of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Status {
    Active,
    Mitigated,
    FalsePositive,
    Acknowledged,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Active => write!(f, "Active"),
            Status::Mitigated => write!(f, "Mitigated"),
            Status::FalsePositive => write!(f, "False Positive"),
            Status::Acknowledged => write!(f, "Acknowledged"),
        }
    }
}

/// A single security finding produced by a detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding.
    pub id: Uuid,
    /// Detector that produced this finding (e.g. "usb.descriptor_anomaly").
    pub detector: String,
    /// How severe is this finding.
    pub severity: Severity,
    /// Current lifecycle status.
    pub status: Status,
    /// Short human-readable title.
    pub title: String,
    /// Longer description of the issue.
    pub description: String,
    /// Supporting evidence.
    pub evidence: Vec<Evidence>,
    /// Suggested fix, if any.
    pub remediation: Option<String>,
    /// CVE identifier, if applicable.
    pub cve: Option<String>,
    /// When this finding was produced.
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    /// Create a new finding with sensible defaults.
    pub fn new(
        detector: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            detector: detector.into(),
            severity,
            status: Status::Active,
            title: title.into(),
            description: description.into(),
            evidence: Vec::new(),
            remediation: None,
            cve: None,
            timestamp: Utc::now(),
        }
    }

    /// Attach evidence to this finding (builder-style).
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Attach a remediation suggestion.
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Attach a CVE identifier.
    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve = Some(cve.into());
        self
    }
}

/// Maximum size for `Evidence::Bytes` data (1 MB).
const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;

/// Evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence {
    /// Raw bytes from the device (capped at 1 MB).
    Bytes {
        offset: u64,
        data: Vec<u8>,
        label: String,
    },
    /// Free-form textual evidence.
    Text(String),
    /// A numeric metric (e.g., "hidden_partition_gap_bytes": 104857600).
    Metric { key: String, value: f64 },
}

impl Evidence {
    /// Create a `Bytes` evidence variant, truncating data to 1 MB.
    pub fn bytes(offset: u64, data: Vec<u8>, label: impl Into<String>) -> Self {
        let data = if data.len() > MAX_EVIDENCE_BYTES {
            data[..MAX_EVIDENCE_BYTES].to_vec()
        } else {
            data
        };
        Evidence::Bytes {
            offset,
            data,
            label: label.into(),
        }
    }
}

/// Aggregated threat report for a device scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    /// Device identifier that was scanned.
    pub device_id: String,
    /// All findings from the scan.
    pub findings: Vec<Finding>,
    /// How long the scan took.
    #[serde(with = "duration_serde")]
    pub scan_duration: Duration,
    /// Highest severity among all findings (Info if none).
    pub overall_risk: Severity,
    /// Whether the device is considered safe to mount.
    pub safe_to_mount: bool,
}

impl ThreatReport {
    /// Build a report from a list of findings.
    pub fn from_findings(device_id: impl Into<String>, findings: Vec<Finding>, duration: Duration) -> Self {
        let overall_risk = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        let safe_to_mount = overall_risk < Severity::High;

        Self {
            device_id: device_id.into(),
            findings,
            scan_duration: duration,
            overall_risk,
            safe_to_mount,
        }
    }

    /// Number of findings at or above a given severity.
    pub fn count_at_or_above(&self, min: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= min).count()
    }
}

/// Serde support for `std::time::Duration` (serializes as fractional seconds).
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct DurationRepr {
        secs: u64,
        nanos: u32,
    }

    pub fn serialize<S: Serializer>(dur: &Duration, s: S) -> Result<S::Ok, S::Error> {
        DurationRepr {
            secs: dur.as_secs(),
            nanos: dur.subsec_nanos(),
        }
        .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let repr = DurationRepr::deserialize(d)?;
        Ok(Duration::new(repr.secs, repr.nanos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn finding_builder() {
        let f = Finding::new("test.detector", Severity::High, "Test", "A test finding")
            .with_evidence(Evidence::Text("some evidence".into()))
            .with_remediation("Unplug the device")
            .with_cve("CVE-2024-0001");

        assert_eq!(f.detector, "test.detector");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.evidence.len(), 1);
        assert!(f.remediation.is_some());
        assert!(f.cve.is_some());
    }

    #[test]
    fn threat_report_aggregation() {
        let findings = vec![
            Finding::new("a", Severity::Low, "Low", "Low finding"),
            Finding::new("b", Severity::Critical, "Crit", "Critical finding"),
            Finding::new("c", Severity::Medium, "Med", "Medium finding"),
        ];

        let report = ThreatReport::from_findings("dev0", findings, Duration::from_secs(2));
        assert_eq!(report.overall_risk, Severity::Critical);
        assert!(!report.safe_to_mount);
        assert_eq!(report.count_at_or_above(Severity::High), 1);
        assert_eq!(report.count_at_or_above(Severity::Medium), 2);
    }

    #[test]
    fn empty_report_is_safe() {
        let report = ThreatReport::from_findings("dev0", vec![], Duration::from_millis(100));
        assert_eq!(report.overall_risk, Severity::Info);
        assert!(report.safe_to_mount);
    }

    #[test]
    fn finding_serialization_roundtrip() {
        let f = Finding::new("test.det", Severity::Medium, "Title", "Desc")
            .with_evidence(Evidence::Text("proof".into()))
            .with_remediation("fix it")
            .with_cve("CVE-2024-9999");
        let json = serde_json::to_string(&f).unwrap();
        let f2: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f.id, f2.id);
        assert_eq!(f.detector, f2.detector);
        assert_eq!(f.severity, f2.severity);
        assert_eq!(f.status, f2.status);
        assert_eq!(f.title, f2.title);
        assert_eq!(f.description, f2.description);
        assert_eq!(f.evidence.len(), f2.evidence.len());
        assert_eq!(f.remediation, f2.remediation);
        assert_eq!(f.cve, f2.cve);
        assert_eq!(f.timestamp, f2.timestamp);
    }

    #[test]
    fn threat_report_serialization_roundtrip() {
        let findings = vec![
            Finding::new("a", Severity::Low, "Low", "Low finding"),
        ];
        let report = ThreatReport::from_findings("dev0", findings, Duration::from_secs(5));
        let json = serde_json::to_string(&report).unwrap();
        let report2: ThreatReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.device_id, report2.device_id);
        assert_eq!(report.scan_duration, report2.scan_duration);
        assert_eq!(report.overall_risk, report2.overall_risk);
        assert_eq!(report.safe_to_mount, report2.safe_to_mount);
        assert_eq!(report.findings.len(), report2.findings.len());
    }
}
