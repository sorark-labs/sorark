//! Diagnostic types, fluent builder, source spans, and built-in rule catalog.

mod builder;
mod catalog;
mod severity;
mod span;

pub use builder::{Diagnostic, DiagnosticBuilder};
pub use catalog::{RuleDescriptor, builtin_rule_catalog, find_rule_descriptor};
pub use severity::{Confidence, RuleCategory, Severity};
pub use span::SourceSpan;
