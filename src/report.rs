//! Console rendering of preflight results.

use crate::preflight::{Report, Severity};

pub fn render(report: &Report) -> String {
    let mut out = String::new();
    for finding in &report.findings {
        let accepted = if finding.accepted { " (accepted)" } else { "" };
        out.push_str(&format!(
            "[{:<5}] {:<22} {}{accepted}\n",
            finding.severity.label(),
            finding.id,
            finding.summary
        ));
        for detail in &finding.details {
            out.push_str(&format!("{:31}- {detail}\n", ""));
        }
    }
    out.push('\n');
    out.push_str(&summary_line(report));
    out.push('\n');
    out
}

pub fn summary_line(report: &Report) -> String {
    let verdict = if report.is_blocked() { "FAIL" } else { "PASS" };
    format!(
        "Preflight {verdict}: {} pass, {} info, {} warning, {} blocking",
        report.count(Severity::Pass),
        report.count(Severity::Info),
        report.count(Severity::Warning),
        report.count(Severity::Blocking)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preflight::Finding;

    fn finding(id: &'static str, severity: Severity, details: Vec<String>) -> Finding {
        Finding {
            id,
            severity,
            summary: format!("{id} summary"),
            details,
            overridable: false,
            accepted: false,
        }
    }

    #[test]
    fn blocked_report_renders_fail_with_details() {
        let report = Report {
            findings: vec![
                finding("ELEVATION", Severity::Pass, vec![]),
                finding("HIVE_FILES", Severity::Blocking, vec!["locked".into()]),
            ],
        };
        let text = render(&report);
        assert!(text.contains("[BLOCK] HIVE_FILES"));
        assert!(text.contains("- locked"));
        assert!(text.ends_with("Preflight FAIL: 1 pass, 0 info, 0 warning, 1 blocking\n"));
    }

    #[test]
    fn warnings_alone_still_pass() {
        let report = Report {
            findings: vec![finding("ONEDRIVE", Severity::Warning, vec![])],
        };
        assert!(summary_line(&report).starts_with("Preflight PASS"));
    }
}
