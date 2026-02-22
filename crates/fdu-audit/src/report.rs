//! Report generation — convert a [`ThreatReport`] into various output formats.

use fdu_models::ThreatReport;

/// Format a threat report as human-readable text.
pub fn format_text(report: &ThreatReport) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "=== FDU Security Audit Report ===\n\
         Device:        {}\n\
         Overall Risk:  {}\n\
         Safe to Mount: {}\n\
         Scan Duration: {:.2}s\n\
         Findings:      {}\n",
        report.device_id,
        report.overall_risk,
        if report.safe_to_mount { "YES" } else { "NO" },
        report.scan_duration.as_secs_f64(),
        report.findings.len(),
    ));

    if report.findings.is_empty() {
        out.push_str("\nNo security issues detected.\n");
        return out;
    }

    out.push_str("\n--- Findings ---\n\n");

    for (i, finding) in report.findings.iter().enumerate() {
        out.push_str(&format!(
            "[{}] #{}: {}\n    Detector: {}\n    Status:   {}\n    {}\n",
            finding.severity,
            i + 1,
            finding.title,
            finding.detector,
            finding.status,
            finding.description,
        ));

        if let Some(ref remediation) = finding.remediation {
            out.push_str(&format!("    Remediation: {}\n", remediation));
        }

        if let Some(ref cve) = finding.cve {
            out.push_str(&format!("    CVE: {}\n", cve));
        }

        out.push('\n');
    }

    out
}

/// Format a threat report as JSON.
pub fn format_json(report: &ThreatReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fdu_models::{Finding, Severity};
    use std::time::Duration;

    #[test]
    fn text_report_empty() {
        let report = ThreatReport::from_findings("test", vec![], Duration::from_secs(1));
        let text = format_text(&report);
        assert!(text.contains("No security issues"));
        assert!(text.contains("Safe to Mount: YES"));
    }

    #[test]
    fn text_report_with_findings() {
        let findings = vec![
            Finding::new("test", Severity::High, "Bad thing", "Something bad happened")
                .with_remediation("Fix it"),
        ];
        let report = ThreatReport::from_findings("test", findings, Duration::from_secs(2));
        let text = format_text(&report);
        assert!(text.contains("HIGH"));
        assert!(text.contains("Bad thing"));
        assert!(text.contains("Fix it"));
        assert!(text.contains("Safe to Mount: NO"));
    }

    #[test]
    fn json_report() {
        let report = ThreatReport::from_findings("test", vec![], Duration::from_secs(1));
        let json = format_json(&report).unwrap();
        assert!(json.contains("\"device_id\""));
        assert!(json.contains("\"safe_to_mount\""));
    }
}
