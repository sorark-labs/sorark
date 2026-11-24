//! `ARK-DIFF-006`: Breaking contract event schema change (`#[contractevent]` / `ScSpecEventV0`).

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, EventSpec, RuleCategory, Severity, SorarkConfig,
    SourceSpan,
};

/// Detects removed contract events, changed prefix topics, or mutated event topic/data fields
/// between `v1` and `v2`.
pub struct EventSchemaDiffRule;

impl DiffRule for EventSchemaDiffRule {
    fn id(&self) -> &'static str {
        "ARK-DIFF-006"
    }

    fn title(&self) -> &'static str {
        "Breaking Contract Event Schema Change (`#[contractevent]` / `EventV0`)"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::AbiCompatibility
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check_diff(
        &self,
        old: &ContractModule,
        new: &ContractModule,
        _config: &SorarkConfig,
    ) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        let new_file = new.origin.path();

        for old_ev in &old.events {
            let Some(new_ev) = new.find_event(&old_ev.name) else {
                out.push(self.build_removed_event_diagnostic(old_ev, new_file));
                continue;
            };
            self.compare_event_specs(old_ev, new_ev, &mut out);
        }

        out
    }
}

impl EventSchemaDiffRule {
    /// Emits a diagnostic when a `v1` event definition is removed in `v2`.
    fn build_removed_event_diagnostic(&self, old_ev: &EventSpec, new_file: &str) -> Diagnostic {
        Diagnostic::builder(
            self.id(),
            self.title(),
            self.category(),
            self.default_severity(),
        )
        .confidence(Confidence::High)
        .message(format!(
            "Contract event `{}` (`{}`) was removed in v2, breaking off-chain Stellar indexers subscribed to this event topic.",
            old_ev.name,
            old_ev.signature()
        ))
        .help(format!(
            "Retain event `{}` or coordinate schema migration with downstream event indexers.",
            old_ev.name
        ))
        .span(SourceSpan::new(new_file, 1, 1))
        .contract_item(old_ev.name.clone())
        .build()
    }

    /// Compares prefix topics and topic/data parameters between `old_ev` and `new_ev`.
    fn compare_event_specs(
        &self,
        old_ev: &EventSpec,
        new_ev: &EventSpec,
        out: &mut Vec<Diagnostic>,
    ) {
        if old_ev.prefix_topics != new_ev.prefix_topics || old_ev.params != new_ev.params {
            out.push(
                Diagnostic::builder(
                    self.id(),
                    self.title(),
                    self.category(),
                    self.default_severity(),
                )
                .confidence(Confidence::High)
                .message(format!(
                    "Contract event `{}` changed schema from `{}` (topics: {:?}) in v1 to `{}` (topics: {:?}) in v2.",
                    old_ev.name,
                    old_ev.signature(),
                    old_ev.prefix_topics,
                    new_ev.signature(),
                    new_ev.prefix_topics
                ))
                .help(format!(
                    "Keep `{}` topic and data field layouts immutable across minor upgrades, or introduce a versioned event struct (e.g. `{}V2`).",
                    old_ev.name, old_ev.name
                ))
                .maybe_span(SourceSpan::from_optional_file(
                    new_ev.file.as_deref(),
                    new_ev.line,
                ))
                .contract_item(old_ev.name.clone())
                .build(),
            );
        }
    }
}
