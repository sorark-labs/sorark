//! `ARK-UPG-003`: Modified or newly added `__constructor` signature in `v2` without a `migrate`
//! entrypoint.

use crate::rule::DiffRule;
use sorark_ir::{
    Confidence, ContractModule, Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan,
};

/// Detects when a `v2` contract adds or modifies `__constructor` parameters relative to `v1`
/// without providing an explicit `migrate` entrypoint.
///
/// In Soroban, `env.deployer().update_current_contract_wasm(...)` replaces the WASM bytecode
/// in-place and **never re-executes `__constructor`** on an already-deployed contract instance.
pub struct ConstructorMigrationDiffRule;

impl DiffRule for ConstructorMigrationDiffRule {
    fn id(&self) -> &'static str {
        "ARK-UPG-003"
    }

    fn title(&self) -> &'static str {
        "Modified `__constructor` Signature Without `migrate` Entrypoint Across Upgrade"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::UpgradeAuth
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
        let Some(new_ctor) = new.find_function("__constructor") else {
            return Vec::new();
        };

        let has_migrate_fn = new
            .functions
            .iter()
            .any(|f| f.name == "migrate" || f.name.starts_with("migrate_"));
        if has_migrate_fn {
            return Vec::new();
        }

        let ctor_changed = match old.find_function("__constructor") {
            None => !new_ctor.params.is_empty(),
            Some(old_ctor) => old_ctor.param_types() != new_ctor.param_types(),
        };

        if !ctor_changed {
            return Vec::new();
        }

        vec![
            Diagnostic::builder(
                self.id(),
                self.title(),
                self.category(),
                self.default_severity(),
            )
            .confidence(Confidence::High)
            .message(format!(
                "v2 modifies or introduces `__constructor({})`, but `update_current_contract_wasm` never re-runs `__constructor` on an already-deployed contract and v2 exposes no `migrate` entrypoint.",
                new_ctor.params_signature()
            ))
            .help(
                "Add an admin-authenticated `pub fn migrate(env: Env, ...)` entrypoint to initialize new v2 state keys after upgrading live contracts.",
            )
            .maybe_span(SourceSpan::from_optional_file(
                new_ctor.file.as_deref(),
                new_ctor.line,
            ))
            .contract_item("__constructor")
            .build(),
        ]
    }
}
