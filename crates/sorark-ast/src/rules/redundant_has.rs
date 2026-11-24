//! `ARK-STOR-005`: Redundant ledger read-before-read (`has(&k)` followed by `get(&k)`).

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, StorageOp, StorageOpKind};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// `ARK-STOR-005`: Detects calling `env.storage().<tier>().has(&k)` followed by
/// `env.storage().<tier>().get(&k)` on the identical key within the same function.
pub struct RedundantHasBeforeGetRule;

impl AstRule for RedundantHasBeforeGetRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-005"
    }

    fn title(&self) -> &'static str {
        "Redundant Ledger Read-Before-Read (`has` Followed by `get`)"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::ResourceBudget
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, ctx: &AstAnalysisContext, _config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for func in &ctx.functions {
            self.check_function(ctx, func, &mut out);
        }
        out
    }
}

impl RedundantHasBeforeGetRule {
    /// Scans sequential storage operations in `func` for `has(&k)` followed by `get(&k)`
    /// without an intervening write/remove on `&k`.
    fn check_function(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        out: &mut Vec<Diagnostic>,
    ) {
        let ops = &func.storage_ops;
        for (idx, op) in ops.iter().enumerate() {
            if op.kind != StorageOpKind::Has {
                continue;
            }
            let Some(has_key) = op.key_expr.as_deref() else {
                continue;
            };

            if let Some(get_op) = find_redundant_followup_get(&ops[idx + 1..], op.tier, has_key)
                && !ctx.is_suppressed(&func.file, get_op.line, self.id())
                && !ctx.is_suppressed(&func.file, op.line, self.id())
            {
                out.push(
                    Diagnostic::builder(
                        self.id(),
                        self.title(),
                        self.category(),
                        self.default_severity(),
                    )
                    .message(format!(
                        "Function `{}` calls `env.storage().{}().has({has_key})` (line {}) followed by `.get({has_key})` (line {}), performing a redundant host map lookup.",
                        func.name, op.tier, op.line, get_op.line
                    ))
                    .help(format!(
                        "Remove `.has({has_key})` and match directly on `env.storage().{}().get({has_key})` (`if let Some(val) = ...` or `.unwrap_or(...)`).",
                        op.tier
                    ))
                    .span(
                        SourceSpan::new(&func.file, get_op.line, get_op.column)
                            .with_snippet(&get_op.snippet),
                    )
                    .contract_item(&func.name)
                    .build(),
                );
            }
        }
    }
}

/// Searches subsequent operations for a `.get(key)` on the same tier before any mutation/removal of `key`.
fn find_redundant_followup_get<'a>(
    rest: &'a [StorageOp],
    tier: sorark_ir::StorageTier,
    target_key: &str,
) -> Option<&'a StorageOp> {
    for next in rest {
        if next.tier != tier || next.key_expr.as_deref() != Some(target_key) {
            continue;
        }
        match next.kind {
            StorageOpKind::Get => return Some(next),
            StorageOpKind::Set | StorageOpKind::Update | StorageOpKind::Remove => return None,
            StorageOpKind::Has | StorageOpKind::ExtendTtl => {}
        }
    }
    None
}
