//! GitHub Actions workflow command formatter (`--format github`).
//!
//! Emits native GitHub Actions annotation commands:
//! `::error file={file},line={line},col={col},title={rule_id}::{message}`

use sorark_ir::Diagnostic;
use std::fmt::Write as _;

/// Renders a slice of [`Diagnostic`]s as GitHub Actions workflow annotation commands.
#[must_use]
pub(super) fn render_diagnostics_github(diagnostics: &[Diagnostic]) -> String {
    let mut out = String::new();
    for d in diagnostics {
        let level = d.severity.github_command();
        let title = escape_workflow_property(&format!("{} ({})", d.rule_id, d.title));
        let msg = escape_workflow_data(&format!("{} Remediation: {}", d.message, d.help));

        if let Some(span) = &d.span {
            let file = escape_workflow_property(&span.file);
            let _ = writeln!(
                out,
                "::{level} file={file},line={},col={},title={title}::{msg}",
                span.line, span.column
            );
        } else {
            let _ = writeln!(out, "::{level} title={title}::{msg}");
        }
    }
    out
}

/// Escapes special characters inside a GitHub Actions workflow command data payload.
fn escape_workflow_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escapes special characters inside a GitHub Actions workflow command property value.
fn escape_workflow_property(s: &str) -> String {
    escape_workflow_data(s)
        .replace(':', "%3A")
        .replace(',', "%2C")
}
