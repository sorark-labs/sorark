//! Stellar SEP-0041 Token Interface Conformance Checker (`ARK-SEP-041`).
//!
//! Verifies that a [`ContractModule`] (loaded from either Rust `.rs` source or a compiled
//! `.wasm` binary's `contractspecv0` section) implements the standard Stellar SEP-41 token
//! interface with exact parameter types and return types.

use super::{ContractModule, TypeRef};
use crate::config::SorarkConfig;
use crate::diagnostic::{Confidence, Diagnostic, RuleCategory, Severity, SourceSpan};

/// Specification of a required SEP-41 token interface function.
struct Sep41Entrypoint {
    name: &'static str,
    params: &'static [(&'static str, TypeRef)],
    return_type: TypeRef,
}

/// Returns the 10 standard Stellar SEP-41 token interface methods (`TokenInterface`).
fn required_sep41_entrypoints() -> Vec<Sep41Entrypoint> {
    vec![
        Sep41Entrypoint {
            name: "allowance",
            params: &[("from", TypeRef::Address), ("spender", TypeRef::Address)],
            return_type: TypeRef::I128,
        },
        Sep41Entrypoint {
            name: "approve",
            params: &[
                ("from", TypeRef::Address),
                ("spender", TypeRef::Address),
                ("amount", TypeRef::I128),
                ("expiration_ledger", TypeRef::U32),
            ],
            return_type: TypeRef::Void,
        },
        Sep41Entrypoint {
            name: "balance",
            params: &[("id", TypeRef::Address)],
            return_type: TypeRef::I128,
        },
        Sep41Entrypoint {
            name: "transfer",
            params: &[
                ("from", TypeRef::Address),
                ("to", TypeRef::Address),
                ("amount", TypeRef::I128),
            ],
            return_type: TypeRef::Void,
        },
        Sep41Entrypoint {
            name: "transfer_from",
            params: &[
                ("spender", TypeRef::Address),
                ("from", TypeRef::Address),
                ("to", TypeRef::Address),
                ("amount", TypeRef::I128),
            ],
            return_type: TypeRef::Void,
        },
        Sep41Entrypoint {
            name: "burn",
            params: &[("from", TypeRef::Address), ("amount", TypeRef::I128)],
            return_type: TypeRef::Void,
        },
        Sep41Entrypoint {
            name: "burn_from",
            params: &[
                ("spender", TypeRef::Address),
                ("from", TypeRef::Address),
                ("amount", TypeRef::I128),
            ],
            return_type: TypeRef::Void,
        },
        Sep41Entrypoint {
            name: "decimals",
            params: &[],
            return_type: TypeRef::U32,
        },
        Sep41Entrypoint {
            name: "name",
            params: &[],
            return_type: TypeRef::String,
        },
        Sep41Entrypoint {
            name: "symbol",
            params: &[],
            return_type: TypeRef::String,
        },
    ]
}

/// Checks a [`ContractModule`] against the Stellar SEP-41 token interface specification (`ARK-SEP-041`).
#[must_use]
pub fn check_sep41_conformance(module: &ContractModule, config: &SorarkConfig) -> Vec<Diagnostic> {
    if !config.is_rule_enabled("ARK-SEP-041") {
        return Vec::new();
    }

    let mut out = Vec::new();
    let origin_path = module.origin.path();

    for expected in required_sep41_entrypoints() {
        let expected_sig = format_sep41_signature(&expected);
        let Some(actual) = module.find_function(expected.name) else {
            out.push(
                Diagnostic::builder(
                    "ARK-SEP-041",
                    "Missing or Non-Conformant SEP-41 Token Interface Entrypoint",
                    RuleCategory::AbiCompatibility,
                    Severity::Error,
                )
                .confidence(Confidence::High)
                .message(format!(
                    "Contract `{}` is missing required Stellar SEP-41 token entrypoint `{expected_sig}`.",
                    module.name
                ))
                .help(format!(
                    "Implement `pub fn {expected_sig}` in `#[contractimpl]` (or implement `soroban_sdk::token::TokenInterface`)."
                ))
                .span(SourceSpan::new(origin_path, 1, 1))
                .contract_item(expected.name)
                .build(),
            );
            continue;
        };

        let expected_param_types: Vec<&TypeRef> = expected.params.iter().map(|(_, t)| t).collect();
        let actual_param_types = actual.param_types();

        if actual_param_types != expected_param_types || actual.return_type != expected.return_type
        {
            let actual_sig = format!(
                "{}(env: Env{}{}) -> {}",
                actual.name,
                if actual.params.is_empty() { "" } else { ", " },
                actual.params_signature(),
                actual.return_type
            );
            out.push(
                Diagnostic::builder(
                    "ARK-SEP-041",
                    "Missing or Non-Conformant SEP-41 Token Interface Entrypoint",
                    RuleCategory::AbiCompatibility,
                    Severity::Error,
                )
                .confidence(Confidence::High)
                .message(format!(
                    "Entrypoint `{}` has signature `{actual_sig}`, which does not match the SEP-41 specification `{expected_sig}`.",
                    actual.name
                ))
                .help(format!(
                    "Update `{}` to match the exact SEP-41 signature: `pub fn {expected_sig}`.",
                    actual.name
                ))
                .maybe_span(SourceSpan::from_optional_file(
                    actual.file.as_deref(),
                    actual.line,
                ))
                .contract_item(actual.name.clone())
                .build(),
            );
        }
    }

    config.apply_severity_overrides(&mut out);
    out
}

/// Formats an expected [`Sep41Entrypoint`] as an idiomatic Soroban Rust method signature.
fn format_sep41_signature(ep: &Sep41Entrypoint) -> String {
    let params_str = ep
        .params
        .iter()
        .map(|(name, ty)| format!("{name}: {ty}"))
        .collect::<Vec<_>>()
        .join(", ");
    let env_sep = if params_str.is_empty() { "" } else { ", " };
    if ep.return_type == TypeRef::Void {
        format!("{}(env: Env{env_sep}{params_str})", ep.name)
    } else {
        format!(
            "{}(env: Env{env_sep}{params_str}) -> {}",
            ep.name, ep.return_type
        )
    }
}
