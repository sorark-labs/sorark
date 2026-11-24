//! `ARK-STOR-006`: Storage read/write/TTL operation executed inside a loop (`for` / `while` / `loop`).

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, StorageOp};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// `ARK-STOR-006`: Flags Soroban storage accesses inside `for`, `while`, or `loop` bodies,
/// which risk exceeding per-transaction ledger footprint entry and host CPU budget limits.
pub struct LoopStorageAccessRule;

impl AstRule for LoopStorageAccessRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-006"
    }

    fn title(&self) -> &'static str {
        "Storage Read/Write Inside Loop (`for` / `while` / `loop`)"
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
            for op in &func.storage_ops {
                if let Some(diag) = self.check_op(ctx, func, op) {
                    out.push(diag);
                }
            }
        }
        out
    }
}

impl LoopStorageAccessRule {
    /// Emits a diagnostic if `op` occurs inside a loop and is not suppressed.
    fn check_op(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        op: &StorageOp,
    ) -> Option<Diagnostic> {
        if !op.in_loop || ctx.is_suppressed(&func.file, op.line, self.id()) {
            return None;
        }

        let key_label = op.key_expr.as_deref().unwrap_or("<entry>");
        Some(
            Diagnostic::builder(
                self.id(),
                self.title(),
                self.category(),
                self.default_severity(),
            )
            .message(format!(
                "Function `{}` accesses `env.storage().{}()` (key `{key_label}`) inside a loop body. Repeated per-iteration ledger accesses can exhaust Soroban's per-transaction read/write footprint limits.",
                func.name, op.tier
            ))
            .help(
                "Hoist shared `instance()` reads/writes outside the loop, batch updates into a bounded collection, or enforce a strict maximum iteration bound.",
            )
            .span(SourceSpan::new(&func.file, op.line, op.column).with_snippet(&op.snippet))
            .contract_item(&func.name)
            .build(),
        )
    }
}
