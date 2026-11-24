//! `ARK-STOR-007`: Invalid Soroban `Symbol` literal length or character set (`symbol_short!` / `Symbol::new`).

use super::AstRule;
use crate::parser::{AstAnalysisContext, ParsedFunction, SymbolLiteralCall};
use sorark_ir::{Diagnostic, RuleCategory, Severity, SorarkConfig, SourceSpan};

/// Maximum character length allowed by `soroban_sdk::symbol_short!`.
const MAX_SYMBOL_SHORT_LEN: usize = 9;

/// Maximum character length allowed by Soroban host `Symbol::new`.
const MAX_SYMBOL_NEW_LEN: usize = 32;

/// `ARK-STOR-007`: Validates `symbol_short!("...")` (1..=9 chars, `[a-zA-Z0-9_]`) and
/// `Symbol::new(&env, "...")` (<= 32 chars, `[a-zA-Z0-9_]`).
pub struct InvalidSymbolLiteralRule;

impl AstRule for InvalidSymbolLiteralRule {
    fn id(&self) -> &'static str {
        "ARK-STOR-007"
    }

    fn title(&self) -> &'static str {
        "Invalid Soroban `Symbol` Literal Length or Character Set"
    }

    fn category(&self) -> RuleCategory {
        RuleCategory::StorageSafety
    }

    fn default_severity(&self) -> Severity {
        Severity::Error
    }

    fn check(&self, ctx: &AstAnalysisContext, _config: &SorarkConfig) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for func in &ctx.functions {
            for sym in &func.symbol_literals {
                if let Some(diag) = self.check_symbol(ctx, func, sym) {
                    out.push(diag);
                }
            }
        }
        out
    }
}

impl InvalidSymbolLiteralRule {
    /// Checks a single `symbol_short!` or `Symbol::new` string literal against Soroban constraints.
    fn check_symbol(
        &self,
        ctx: &AstAnalysisContext,
        func: &ParsedFunction,
        sym: &SymbolLiteralCall,
    ) -> Option<Diagnostic> {
        if ctx.is_suppressed(&func.file, sym.line, self.id()) {
            return None;
        }

        let max_len = if sym.is_short {
            MAX_SYMBOL_SHORT_LEN
        } else {
            MAX_SYMBOL_NEW_LEN
        };
        let construct = if sym.is_short {
            "symbol_short!"
        } else {
            "Symbol::new"
        };

        let invalid_chars: Vec<char> = sym
            .value
            .chars()
            .filter(|c| !c.is_ascii_alphanumeric() && *c != '_')
            .collect();

        if sym.value.len() > max_len {
            let suggestion = if sym.is_short && sym.value.len() <= MAX_SYMBOL_NEW_LEN {
                format!(
                    "Shorten `{}` to at most 9 characters or use `Symbol::new(&env, \"{}\")` (supports up to 32 characters).",
                    sym.value, sym.value
                )
            } else {
                format!(
                    "Shorten `{}` to at most {max_len} ASCII alphanumeric/underscore characters (`[a-zA-Z0-9_]`).",
                    sym.value
                )
            };

            return Some(
                Diagnostic::builder(
                    self.id(),
                    self.title(),
                    self.category(),
                    self.default_severity(),
                )
                .message(format!(
                    "In `{}`, `{construct}(\"{}\")` has length {} characters, exceeding the Soroban `{construct}` limit of {max_len} characters.",
                    func.name,
                    sym.value,
                    sym.value.len()
                ))
                .help(suggestion)
                .span(SourceSpan::new(&func.file, sym.line, sym.column).with_snippet(&sym.snippet))
                .contract_item(&func.name)
                .build(),
            );
        }

        if !invalid_chars.is_empty() {
            return Some(
                Diagnostic::builder(
                    self.id(),
                    self.title(),
                    self.category(),
                    self.default_severity(),
                )
                .message(format!(
                    "In `{}`, `{construct}(\"{}\")` contains invalid Soroban `Symbol` character(s) `{:?}`. Soroban symbols only allow `[a-zA-Z0-9_]`.",
                    func.name, sym.value, invalid_chars
                ))
                .help(
                    "Replace hyphens, spaces, or punctuation with underscores (`_`) and ASCII alphanumeric characters (`[a-zA-Z0-9_]`), or use `String::from_str(&env, ...)` for arbitrary UTF-8 text.",
                )
                .span(SourceSpan::new(&func.file, sym.line, sym.column).with_snippet(&sym.snippet))
                .contract_item(&func.name)
                .build(),
            );
        }

        None
    }
}
