//! GitHub Actions workflow command annotation formatter (`--format github`).

use sorark_ir::{Diagnostic, Severity};
use std::fmt::Write as _;

/// Formats a slice of [`Diagnostic`] items as GitHub Actions workflow annotations.
///
/// Output format for diagnostics with source span:
/// `::<error|warning|notice> file={file},line={line},col={col},title={rule_id} ({title})::{message} Remediation: {help}`
///
/// Output format for diagnostics without source span:
/// `::<error|warning|notice> title={rule_id} ({title})::{message} Remediation: {help}`
#[must_use]
pub(super) fn render_diagnostics_github(diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let cmd = match d.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "notice",
        };

        if let Some(span) = &d.span {
            let _ = writeln!(
                out,
                "::{} file={},line={},col={},title={} ({})::{} Remediation: {}",
                cmd, span.file, span.line, span.column, d.rule_id, d.title, d.message, d.help
            );
        } else {
            let _ = writeln!(
                out,
                "::{} title={} ({})::{} Remediation: {}",
                cmd, d.rule_id, d.title, d.message, d.help
            );
        }
    }
    out
}
