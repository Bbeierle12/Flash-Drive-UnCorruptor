//! Audit event types — structured logs for the scan lifecycle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A structured audit event emitted during a scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// What kind of event.
    pub event_type: AuditEventType,
    /// Device being scanned.
    pub device_id: String,
    /// Human-readable details.
    pub details: String,
}

impl AuditEvent {
    /// Create a new audit event timestamped to now.
    pub fn new(
        event_type: AuditEventType,
        device_id: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            event_type,
            device_id: device_id.into(),
            details: details.into(),
        }
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {:?} on {}: {}",
            self.timestamp.format("%H:%M:%S"),
            self.event_type,
            self.device_id,
            self.details,
        )
    }
}

/// The category of audit event.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    DeviceConnected,
    ScanStarted,
    ScanCompleted,
    ThreatDetected,
    ExtractionStarted,
    ExtractionCompleted,
    QuarantineCreated,
    UserAction(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_creation() {
        let evt = AuditEvent::new(AuditEventType::ScanStarted, "/dev/sdb1", "Full security scan");
        assert_eq!(evt.event_type, AuditEventType::ScanStarted);
        assert_eq!(evt.device_id, "/dev/sdb1");
    }

    #[test]
    fn event_display() {
        let evt = AuditEvent::new(AuditEventType::ThreatDetected, "dev0", "BadUSB found");
        let s = format!("{}", evt);
        assert!(s.contains("ThreatDetected"));
        assert!(s.contains("dev0"));
    }

    #[test]
    fn serialization_roundtrip() {
        let evt = AuditEvent::new(
            AuditEventType::UserAction("quarantine_release".into()),
            "dev0",
            "User released file",
        );
        let json = serde_json::to_string(&evt).unwrap();
        let evt2: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt.event_type, evt2.event_type);
        assert_eq!(evt.device_id, evt2.device_id);
        assert_eq!(evt.details, evt2.details);
        assert_eq!(evt.timestamp, evt2.timestamp);
    }
}
