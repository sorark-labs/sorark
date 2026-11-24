//! Two-pass Rust AST static analyzer for Soroban smart contracts (`sorark-ast`).
//!
//! - **Pass 1 (`parser`):** Collects `#[contracttype]` structs/enums, computes transitive
//!   unbounded types, resolves module constants, and builds an intra-module helper function
//!   call graph for `extend_ttl` and `require_auth`.
//! - **Pass 2 (`rules`):** Executes registered [`AstRule`] implementations against
//!   [`AstAnalysisContext`].

pub mod error;
pub mod parser;
pub mod rules;
pub mod scanner;

pub use error::AstEngineError;
pub use parser::{
    AstAnalysisContext, ParsedFunction, StorageOp, StorageOpKind, SymbolLiteralCall,
    WasmUpgradeCall, parse_inline_suppressions, parse_rust_source_into_context,
    parse_single_source, syn_type_to_typeref,
};
pub use rules::{
    AstRule, CriticalStateInTempStorageRule, InvalidSymbolLiteralRule, InvalidTtlBoundsRule,
    LoopStorageAccessRule, MissingExtendTtlRule, MissingUpgradeMechanismRule,
    RedundantHasBeforeGetRule, UnboundedInstanceStorageRule, UnprotectedWasmUpgradeRule,
    default_ast_rules,
};
pub use scanner::{AstScanReport, run_rules_on_context, scan_rust_path};

#[cfg(test)]
mod tests {
    use super::*;
    use sorark_ir::SorarkConfig;

    #[test]
    fn detects_transitive_unbounded_instance_storage_and_missing_ttl() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map};

            #[contracttype]
            pub struct VaultRegistry {
                pub admin: Address,
                pub balances: Map<Address, i128>,
            }

            #[contracttype]
            pub enum DataKey {
                Registry,
                TempAdmin,
            }

            #[contract]
            pub struct VaultContract;

            #[contractimpl]
            impl VaultContract {
                pub fn set_registry(env: Env, reg: VaultRegistry) {
                    env.storage().instance().set(&DataKey::Registry, &reg);
                    env.storage().temporary().set(&DataKey::TempAdmin, &reg.admin);
                }
            }
        "#;

        let ctx = parse_single_source("vault", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-001"));
        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-002"));
        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-003"));
    }

    #[test]
    fn two_pass_helper_call_graph_suppresses_false_positives_for_ttl_and_auth() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

            const DAY_IN_LEDGERS: u32 = 17_280;

            #[contracttype]
            pub enum DataKey {
                Admin,
                Balance(Address),
            }

            #[contract]
            pub struct SafeVault;

            #[contractimpl]
            impl SafeVault {
                pub fn deposit(env: Env, user: Address, amount: i128) {
                    env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
                    bump_balance_ttl(&env, &user);
                }

                pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
                    assert_admin(&env);
                    env.deployer().update_current_contract_wasm(new_wasm_hash);
                }
            }

            fn bump_balance_ttl(env: &Env, user: &Address) {
                env.storage().persistent().extend_ttl(
                    &DataKey::Balance(user.clone()),
                    DAY_IN_LEDGERS,
                    DAY_IN_LEDGERS * 30,
                );
            }

            fn assert_admin(env: &Env) {
                let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
                admin.require_auth();
            }
        "#;

        let ctx = parse_single_source("safe_vault", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(
            diags.is_empty(),
            "Expected zero false positives with helper call-graph, got: {diags:#?}"
        );
    }

    #[test]
    fn detects_invalid_ttl_bounds_and_unprotected_upgrade() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, BytesN, Env};

            #[contract]
            pub struct BadContract;

            #[contractimpl]
            impl BadContract {
                pub fn bad_ttl(env: Env) {
                    // threshold (50_000) > extend_to (10_000) -> host trap!
                    env.storage().instance().extend_ttl(50_000, 10_000);
                }

                pub fn open_upgrade(env: Env, hash: BytesN<32>) {
                    env.deployer().update_current_contract_wasm(hash);
                }
            }
        "#;

        let ctx = parse_single_source("bad", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(diags.iter().any(|d| d.rule_id == "ARK-STOR-004"));
        assert!(diags.iter().any(|d| d.rule_id == "ARK-UPG-001"));
    }

    #[test]
    fn respects_inline_sorark_ignore_comments() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, BytesN, Env};

            #[contract]
            pub struct IgnoredContract;

            #[contractimpl]
            impl IgnoredContract {
                pub fn open_upgrade(env: Env, hash: BytesN<32>) {
                    // sorark-ignore: ARK-UPG-001
                    env.deployer().update_current_contract_wasm(hash);
                }
            }
        "#;

        let ctx = parse_single_source("ignored", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());
        assert!(!diags.iter().any(|d| d.rule_id == "ARK-UPG-001"));
    }

    #[test]
    fn detects_redundant_has_loop_storage_and_invalid_symbol_literals() {
        let src = r#"
            use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec};

            #[contracttype]
            pub enum DataKey {
                Balance(Address),
            }

            #[contract]
            pub struct TokenOps;

            #[contractimpl]
            impl TokenOps {
                pub fn batch_airdrop(env: Env, users: Vec<Address>, amount: i128) {
                    let bad_short = symbol_short!("TOO_LONG_SHORT_SYMBOL");
                    let bad_chars = Symbol::new(&env, "invalid-hyphen-symbol");
                    let _ = (bad_short, bad_chars);

                    for user in users.iter() {
                        let key = DataKey::Balance(user);
                        if env.storage().persistent().has(&key) {
                            let prev: i128 = env.storage().persistent().get(&key).unwrap();
                            env.storage().persistent().set(&key, &(prev + amount));
                        }
                    }
                }
            }
        "#;

        let ctx = parse_single_source("token_ops", "src/lib.rs", src).unwrap();
        let diags = run_rules_on_context(&ctx, &SorarkConfig::default());

        assert!(
            diags.iter().any(|d| d.rule_id == "ARK-STOR-005"),
            "Expected ARK-STOR-005, got: {diags:#?}"
        );
        assert!(
            diags.iter().any(|d| d.rule_id == "ARK-STOR-006"),
            "Expected ARK-STOR-006, got: {diags:#?}"
        );
        let sym_error_count = diags.iter().filter(|d| d.rule_id == "ARK-STOR-007").count();
        assert_eq!(sym_error_count, 2, "Expected 2 ARK-STOR-007 findings");
    }

    #[test]
    fn resolves_cross_file_module_qualified_calls_and_parses_contractevent() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("src");
        std::fs::create_dir_all(&src_dir).unwrap();

        std::fs::write(
            src_dir.join("lib.rs"),
            r#"
            use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, BytesN, Env};
            mod auth;
            mod storage;

            #[contracttype]
            pub enum DataKey {
                Admin,
                Balance(Address),
            }

            #[contractevent]
            pub struct DepositEvent {
                #[topic]
                pub user: Address,
                pub amount: i128,
            }

            #[contract]
            pub struct ModularVault;

            #[contractimpl]
            impl ModularVault {
                pub fn deposit(env: Env, user: Address, amount: i128) {
                    env.storage().persistent().set(&DataKey::Balance(user.clone()), &amount);
                    storage::extend_balance_ttl(&env, &user);
                }

                pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
                    crate::auth::require_admin(&env);
                    env.deployer().update_current_contract_wasm(new_wasm_hash);
                }
            }
            "#,
        )
        .unwrap();

        std::fs::write(
            src_dir.join("storage.rs"),
            r#"
            use crate::DataKey;
            use soroban_sdk::{Address, Env};

            pub fn extend_balance_ttl(env: &Env, user: &Address) {
                env.storage().persistent().extend_ttl(&DataKey::Balance(user.clone()), 17_280, 518_400);
            }
            "#,
        )
        .unwrap();

        std::fs::write(
            src_dir.join("auth.rs"),
            r#"
            use crate::DataKey;
            use soroban_sdk::{Address, Env};

            pub fn require_admin(env: &Env) {
                let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
                admin.require_auth();
            }
            "#,
        )
        .unwrap();

        let report = scan_rust_path(tmp.path(), &SorarkConfig::default()).unwrap();
        assert_eq!(report.files_scanned, 3);
        assert!(
            report.diagnostics.is_empty(),
            "Expected 0 false positives across multi-file module calls, got: {:#?}",
            report.diagnostics
        );
        assert_eq!(report.context.module.events.len(), 1);
        let ev = &report.context.module.events[0];
        assert_eq!(ev.name, "DepositEvent");
        assert_eq!(ev.prefix_topics, vec!["deposit_event".to_string()]);
        assert!(ev.params[0].is_topic);
        assert!(!ev.params[1].is_topic);
    }
}
