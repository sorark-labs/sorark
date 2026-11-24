//! `ARK-FOOT-001`: Oversized fixed-size `#[contracttype]` XDR ledger entry footprint.

use super::AstRule;
use crate::parser::AstAnalysisContext;
use sorark_ir::{
    Confidence, Diagnostic, MAINNET_LEDGER_ENTRY_MAX_BYTES, RuleCategory, Severity, SorarkConfig,
    SourceSpan, TypeRef,
};

/// `ARK-FOOT-001`: Calculates the exact Stellar XDR (`ScMap`/`ScVec`) serialized byte size
/// of fixed-size `#[contracttype]` structs and tuple structs, warning when a single struct
/// exceeds `config.struct_warn_xdr_bytes` (or emitting an error if it exceeds 64 KiB).
pub struct LargeFixedStructFootprintRule;

impl AstRule for LargeFixedStructFootprintRule {
    fn id(&self) -> &'static str {
        "ARK-FOOT-001"
    }

    fn title(&self) -> &'static str {
        "Oversized Fixed-Size `#[contracttype]` XDR Ledger Entry Footprint"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::ResourceBudget
    }

    fn default_severity(&self) -> Severity {
        Severity::Warning
    }

    fn check(&self, ctx: &AstAnalysisContext, config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();

        for s in &ctx.module.structs {
            let line = s.line.unwrap_or(1);
            let file = s.file.as_deref().unwrap_or(ctx.module.origin.path());
            if ctx.is_suppressed(file, line, self.id()) {
                continue;
            }
            let ty = TypeRef::Custom(s.name.clone());
            if let Some(xdr_bytes) = ctx.module.estimate_type_xdr_bytes(&ty)
                && xdr_bytes >= config.struct_warn_xdr_bytes
            {
                out.push(self.build_diagnostic(&s.name, xdr_bytes, file, line, config));
            }
        }

        for ts in &ctx.module.tuple_structs {
            let line = ts.line.unwrap_or(1);
            let file = ts.file.as_deref().unwrap_or(ctx.module.origin.path());
            if ctx.is_suppressed(file, line, self.id()) {
                continue;
            }
            let ty = TypeRef::Custom(ts.name.clone());
            if let Some(xdr_bytes) = ctx.module.estimate_type_xdr_bytes(&ty)
                && xdr_bytes >= config.struct_warn_xdr_bytes
            {
                out.push(self.build_diagnostic(&ts.name, xdr_bytes, file, line, config));
            }
        }

        out
    }
}

impl LargeFixedStructFootprintRule {
    fn build_diagnostic(
        &self,
        type_name: &str,
        xdr_bytes: usize,
        file: &str,
        line: usize,
        config: &SorarkConfig,
    ) -> Diagnostic {
        let severity = if xdr_bytes > MAINNET_LEDGER_ENTRY_MAX_BYTES {
            Severity::Error
        } else {
            self.default_severity()
        };
        let pct_of_ceiling = (xdr_bytes as f64 / MAINNET_LEDGER_ENTRY_MAX_BYTES as f64) * 100.0;

        Diagnostic::builder(self.id(), self.title(), self.category(), severity)
            .confidence(Confidence::High)
            .message(format!(
                "`#[contracttype]` struct `{type_name}` has an estimated on-chain XDR serialized size of {xdr_bytes} bytes ({pct_of_ceiling:.1}% of the 64 KiB Stellar Mainnet ledger entry ceiling), exceeding the warning threshold of {} bytes.",
                config.struct_warn_xdr_bytes
            ))
            .help(format!(
                "Split `{type_name}` into smaller `persistent()` ledger entries so invocations do not deserialize and pay rent for the entire {xdr_bytes}-byte structure on every read/write."
            ))
            .span(SourceSpan::new(file, line, 1))
            .contract_item(type_name)
            .build()
    }
}
