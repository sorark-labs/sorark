//! Soroban contract storage-layout (`ScVal`/`ScMap`/`ScVec`) and ABI upgrade compatibility
//! diff engine (`sorark-diff`).
//!
//! Compares two normalized [`ContractModule`](sorark_ir::ContractModule) snapshots (`v1` vs `v2`,
//! whether parsed from Rust source or decoded from `.wasm` `contractspecv0` sections) to detect
//! state-corrupting storage mutations and breaking interface changes prior to calling
//! `update_current_contract_wasm`.

pub mod report;
pub mod rule;
pub mod rules;

pub use report::{DiffReport, compare_contract_modules};
pub use rule::{DiffRule, default_diff_rules};
pub use rules::{
    ConstructorMigrationDiffRule, EnumAndUnionLayoutDiffRule, ErrorEnumDiffRule,
    EventSchemaDiffRule, FunctionAbiDiffRule, ProtocolVersionDiffRule, StructLayoutDiffRule,
};

#[cfg(test)]
mod tests {
    use super::*;
    use sorark_ir::{
        ContractModule, EnumVariantSpec, ErrorEnumSpec, EventParamSpec, EventSpec,
        FunctionParamSpec, FunctionSpec, SorarkConfig, SourceOrigin, StructFieldSpec, StructSpec,
        TypeRef, UnionCaseSpec, UnionSpec,
    };

    #[test]
    fn catches_struct_field_rename_type_change_union_mutation_and_abi_breakage() {
        let mut v1 = ContractModule::new(
            "vault_v1",
            SourceOrigin::RustSource {
                path: "v1/lib.rs".to_string(),
            },
        );
        v1.structs.push(StructSpec {
            name: "UserVault".to_string(),
            fields: vec![
                StructFieldSpec {
                    name: "owner".to_string(),
                    ty: TypeRef::Address,
                    line: Some(10),
                },
                StructFieldSpec {
                    name: "collateral".to_string(),
                    ty: TypeRef::I128,
                    line: Some(11),
                },
            ],
            file: Some("v1/lib.rs".to_string()),
            line: Some(9),
        });
        v1.unions.push(UnionSpec {
            name: "DataKey".to_string(),
            cases: vec![
                UnionCaseSpec {
                    name: "Admin".to_string(),
                    payload: vec![],
                    line: Some(20),
                },
                UnionCaseSpec {
                    name: "Vault".to_string(),
                    payload: vec![TypeRef::Address],
                    line: Some(21),
                },
            ],
            file: Some("v1/lib.rs".to_string()),
            line: Some(19),
        });
        v1.error_enums.push(ErrorEnumSpec {
            name: "VaultError".to_string(),
            variants: vec![EnumVariantSpec {
                name: "InsufficientFunds".to_string(),
                discriminant: 1,
                line: Some(30),
            }],
            file: Some("v1/lib.rs".to_string()),
            line: Some(29),
        });
        v1.functions.push(FunctionSpec {
            name: "withdraw".to_string(),
            params: vec![FunctionParamSpec {
                name: "amount".to_string(),
                ty: TypeRef::I128,
            }],
            return_type: TypeRef::I128,
            file: Some("v1/lib.rs".to_string()),
            line: Some(40),
        });

        let mut v2 = ContractModule::new(
            "vault_v2",
            SourceOrigin::RustSource {
                path: "v2/lib.rs".to_string(),
            },
        );
        v2.structs.push(StructSpec {
            name: "UserVault".to_string(),
            fields: vec![
                StructFieldSpec {
                    name: "owner".to_string(),
                    ty: TypeRef::Symbol,
                    line: Some(10),
                },
                StructFieldSpec {
                    name: "amount".to_string(),
                    ty: TypeRef::I128,
                    line: Some(11),
                },
            ],
            file: Some("v2/lib.rs".to_string()),
            line: Some(9),
        });
        v2.unions.push(UnionSpec {
            name: "DataKey".to_string(),
            cases: vec![
                UnionCaseSpec {
                    name: "Admin".to_string(),
                    payload: vec![],
                    line: Some(20),
                },
                UnionCaseSpec {
                    name: "Vault".to_string(),
                    payload: vec![TypeRef::Address, TypeRef::U32],
                    line: Some(21),
                },
            ],
            file: Some("v2/lib.rs".to_string()),
            line: Some(19),
        });
        v2.error_enums.push(ErrorEnumSpec {
            name: "VaultError".to_string(),
            variants: vec![EnumVariantSpec {
                name: "InsufficientFunds".to_string(),
                discriminant: 2,
                line: Some(30),
            }],
            file: Some("v2/lib.rs".to_string()),
            line: Some(29),
        });
        v2.functions.push(FunctionSpec {
            name: "withdraw".to_string(),
            params: vec![FunctionParamSpec {
                name: "amount".to_string(),
                ty: TypeRef::U64,
            }],
            return_type: TypeRef::I128,
            file: Some("v2/lib.rs".to_string()),
            line: Some(40),
        });

        let report = compare_contract_modules(&v1, &v2, &SorarkConfig::default());
        assert!(!report.is_upgrade_safe);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-001")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-002")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-003")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-004")
        );
    }

    #[test]
    fn catches_event_schema_breakage_and_constructor_change_without_migrate() {
        let mut v1 = ContractModule::new(
            "token_v1",
            SourceOrigin::RustSource {
                path: "v1/lib.rs".to_string(),
            },
        );
        v1.functions.push(FunctionSpec {
            name: "__constructor".to_string(),
            params: vec![FunctionParamSpec {
                name: "admin".to_string(),
                ty: TypeRef::Address,
            }],
            return_type: TypeRef::Void,
            file: Some("v1/lib.rs".to_string()),
            line: Some(10),
        });
        v1.events.push(EventSpec {
            name: "TransferEvent".to_string(),
            prefix_topics: vec!["transfer_event".to_string()],
            params: vec![
                EventParamSpec {
                    name: "from".to_string(),
                    ty: TypeRef::Address,
                    is_topic: true,
                },
                EventParamSpec {
                    name: "amount".to_string(),
                    ty: TypeRef::I128,
                    is_topic: false,
                },
            ],
            file: Some("v1/lib.rs".to_string()),
            line: Some(20),
        });

        let mut v2 = ContractModule::new(
            "token_v2",
            SourceOrigin::RustSource {
                path: "v2/lib.rs".to_string(),
            },
        );
        v2.functions.push(FunctionSpec {
            name: "__constructor".to_string(),
            params: vec![
                FunctionParamSpec {
                    name: "admin".to_string(),
                    ty: TypeRef::Address,
                },
                FunctionParamSpec {
                    name: "fee_bps".to_string(),
                    ty: TypeRef::U32,
                },
            ],
            return_type: TypeRef::Void,
            file: Some("v2/lib.rs".to_string()),
            line: Some(10),
        });
        v2.events.push(EventSpec {
            name: "TransferEvent".to_string(),
            prefix_topics: vec!["transfer_event".to_string()],
            params: vec![
                EventParamSpec {
                    name: "from".to_string(),
                    ty: TypeRef::Address,
                    is_topic: false,
                },
                EventParamSpec {
                    name: "amount".to_string(),
                    ty: TypeRef::I128,
                    is_topic: false,
                },
            ],
            file: Some("v2/lib.rs".to_string()),
            line: Some(20),
        });

        let report = compare_contract_modules(&v1, &v2, &SorarkConfig::default());
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-DIFF-006"),
            "Expected ARK-DIFF-006, got: {:#?}",
            report.diagnostics
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule_id == "ARK-UPG-003"),
            "Expected ARK-UPG-003, got: {:#?}",
            report.diagnostics
        );
    }
}
