//! Normalized Soroban Contract Intermediate Representation (`sorark-ir`).
//!
//! This crate defines the source-agnostic data structures shared across SORARK's
//! Rust AST analyzer (`sorark-ast`), WebAssembly SEP-0048 XDR decoder (`sorark-wasm`),
//! and upgrade compatibility diff engine (`sorark-diff`).

pub mod config;
pub mod diagnostic;
pub mod model;

pub use config::{
    ConfigError, DEFAULT_WASM_WARN_BYTES, MAINNET_LEDGER_ENTRY_MAX_BYTES, MAINNET_MAX_ENTRY_TTL,
    MAINNET_MIN_PERSISTENT_ENTRY_TTL, MAINNET_MIN_TEMP_ENTRY_TTL, RuleOverride, SorarkConfig,
};
pub use diagnostic::{
    Confidence, Diagnostic, DiagnosticBuilder, RuleCategory, RuleDescriptor, Severity, SourceSpan,
    builtin_rule_catalog, find_rule_descriptor,
};
pub use model::{
    ContractModule, EnumSpec, EnumVariantSpec, ErrorEnumSpec, EventParamSpec, EventSpec,
    FunctionParamSpec, FunctionSpec, SourceOrigin, StorageTier, StructFieldSpec, StructSpec,
    TupleStructSpec, TypeRef, UnionCaseSpec, UnionSpec, check_sep41_conformance,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_and_transitive_unbounded_type_detection_works() {
        let mut module = ContractModule::new(
            "vault",
            SourceOrigin::RustSource {
                path: "src/lib.rs".to_string(),
            },
        );

        module.structs.push(StructSpec {
            name: "UserPosition".to_string(),
            fields: vec![
                StructFieldSpec {
                    name: "owner".to_string(),
                    ty: TypeRef::Address,
                    line: Some(10),
                },
                StructFieldSpec {
                    name: "history".to_string(),
                    ty: TypeRef::Vec(Box::new(TypeRef::I128)),
                    line: Some(11),
                },
            ],
            file: None,
            line: Some(9),
        });

        module.structs.push(StructSpec {
            name: "VaultState".to_string(),
            fields: vec![StructFieldSpec {
                name: "featured_position".to_string(),
                ty: TypeRef::Custom("UserPosition".to_string()),
                line: Some(20),
            }],
            file: None,
            line: Some(19),
        });

        module.structs.push(StructSpec {
            name: "FixedConfig".to_string(),
            fields: vec![
                StructFieldSpec {
                    name: "admin".to_string(),
                    ty: TypeRef::Address,
                    line: Some(30),
                },
                StructFieldSpec {
                    name: "fee_bps".to_string(),
                    ty: TypeRef::U32,
                    line: Some(31),
                },
            ],
            file: None,
            line: Some(29),
        });

        assert!(module.is_type_transitively_unbounded(&TypeRef::Custom("VaultState".to_string())));
        let reason = module
            .unbounded_reason_chain(&TypeRef::Custom("VaultState".to_string()))
            .unwrap();
        assert!(reason.contains("VaultState"));
        assert!(reason.contains("UserPosition"));
        assert!(reason.contains("Vec<i128>"));

        assert!(
            !module.is_type_transitively_unbounded(&TypeRef::Custom("FixedConfig".to_string()))
        );
    }

    #[test]
    fn config_parses_default_template_and_rule_filters() {
        let cfg = SorarkConfig::from_toml_str(SorarkConfig::default_toml_template(), "sorark.toml")
            .unwrap();
        assert_eq!(cfg.max_entry_ttl, 3_110_400);
        assert!(cfg.is_rule_enabled("ARK-STOR-001"));
    }

    #[test]
    fn config_supports_per_rule_severity_and_enabled_overrides() {
        let toml_raw = r#"
            [rules.ARK-STOR-002]
            severity = "error"

            [rules.ARK-UPG-002]
            enabled = false
        "#;
        let cfg = SorarkConfig::from_toml_str(toml_raw, "sorark.toml").unwrap();
        assert!(!cfg.is_rule_enabled("ARK-UPG-002"));
        assert_eq!(
            cfg.effective_severity("ARK-STOR-002", Severity::Warning),
            Severity::Error
        );
        assert!(find_rule_descriptor("ARK-STOR-005").is_some());
        assert_eq!(builtin_rule_catalog().len(), 19);
    }

    #[test]
    fn sep41_conformance_checker_flags_missing_and_mistyped_token_methods() {
        let mut module = ContractModule::new(
            "partial_token",
            SourceOrigin::RustSource {
                path: "src/lib.rs".to_string(),
            },
        );
        // `balance` returning `U64` instead of required `I128`
        module.functions.push(FunctionSpec {
            name: "balance".to_string(),
            params: vec![FunctionParamSpec {
                name: "id".to_string(),
                ty: TypeRef::Address,
            }],
            return_type: TypeRef::U64,
            file: Some("src/lib.rs".to_string()),
            line: Some(15),
        });

        let diags = check_sep41_conformance(&module, &SorarkConfig::default());
        assert_eq!(diags.len(), 10);
        assert!(diags.iter().all(|d| d.rule_id == "ARK-SEP-041"));
        assert!(diags.iter().any(|d| {
            d.message
                .contains("does not match the SEP-41 specification")
        }));
    }

    #[test]
    fn diagnostic_builder_constructs_complete_finding() {
        let diag = Diagnostic::builder(
            "ARK-STOR-001",
            "Unbounded Collection",
            RuleCategory::StorageSafety,
            Severity::Error,
        )
        .message("Map in instance storage")
        .help("Move to persistent storage")
        .span(SourceSpan::new("src/lib.rs", 12, 5).with_snippet("env.storage().instance()"))
        .contract_item("init")
        .build();

        assert_eq!(diag.rule_id, "ARK-STOR-001");
        assert_eq!(diag.severity, Severity::Error);
        assert_eq!(diag.span.as_ref().unwrap().line, 12);
    }
}
