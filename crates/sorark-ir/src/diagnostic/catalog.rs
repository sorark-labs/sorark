//! Static catalog of built-in SORARK rules across the AST, WASM, and Diff engines.

use super::{RuleCategory, Severity};
use serde::{Deserialize, Serialize};

/// Static metadata describing a registered SORARK rule (used by `sorark rules`, `--explain`, and SARIF `tool.driver.rules`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDescriptor {
    pub id: &'static str,
    pub title: &'static str,
    pub category: RuleCategory,
    pub default_severity: Severity,
    pub description: &'static str,
    pub remediation: &'static str,
    pub bad_example: &'static str,
    pub good_example: &'static str,
}

/// Complete catalog of built-in SORARK rules across AST, WASM, SEP-41, and Upgrade Diff engines.
#[must_use]
pub fn builtin_rule_catalog() -> Vec<RuleDescriptor> {
    let mut rules = Vec::with_capacity(19);
    rules.extend(ast_rule_descriptors());
    rules.extend(wasm_rule_descriptors());
    rules.extend(diff_rule_descriptors());
    rules
}

/// Looks up a single [`RuleDescriptor`] by its rule ID (case-insensitive, e.g. `"ARK-STOR-001"`).
#[must_use]
pub fn find_rule_descriptor(rule_id: &str) -> Option<RuleDescriptor> {
    builtin_rule_catalog()
        .into_iter()
        .find(|r| r.id.eq_ignore_ascii_case(rule_id.trim()))
}

/// Descriptors for the 9 Pass-2 Rust AST static analysis rules (`ARK-STOR-*`, `ARK-UPG-*`).
fn ast_rule_descriptors() -> [RuleDescriptor; 9] {
    [
        RuleDescriptor {
            id: "ARK-STOR-001",
            title: "Unbounded Collection in Instance Storage",
            category: RuleCategory::StorageSafety,
            default_severity: Severity::Error,
            description: "Detects Map, Vec, Bytes, String, or structs transitively containing them stored inside env.storage().instance(), which shares a single 64 KiB ledger entry loaded on every invocation and can permanently brick the contract.",
            remediation: "Move dynamically growing collections to env.storage().persistent() with dedicated per-item DataKey variants.",
            bad_example: r#"#[contracttype]
pub struct VaultState {
    pub balances: Map<Address, i128>, // Unbounded Map!
}
env.storage().instance().set(&DataKey::State, &state);"#,
            good_example: r#"#[contracttype]
pub enum DataKey {
    Balance(Address), // Dedicated per-user persistent key
}
env.storage().persistent().set(&DataKey::Balance(user), &amount);"#,
        },
        RuleDescriptor {
            id: "ARK-STOR-002",
            title: "Missing TTL Extension on Persistent/Instance Mutation",
            category: RuleCategory::StateArchival,
            default_severity: Severity::Warning,
            description: "Detects entrypoints that mutate persistent() or instance() storage without extending the entry's Time-To-Live (extend_ttl) directly or via a local helper function.",
            remediation: "Call env.storage().persistent().extend_ttl(&key, threshold, extend_to) or env.storage().instance().extend_ttl(threshold, extend_to) after state writes.",
            bad_example: r#"pub fn deposit(env: Env, user: Address, amount: i128) {
    env.storage().persistent().set(&DataKey::Balance(user), &amount);
    // Missing extend_ttl() leaves entry vulnerable to State Archival!
}"#,
            good_example: r#"pub fn deposit(env: Env, user: Address, amount: i128) {
    let key = DataKey::Balance(user);
    env.storage().persistent().set(&key, &amount);
    env.storage().persistent().extend_ttl(&key, 17_280, 518_400);
}"#,
        },
        RuleDescriptor {
            id: "ARK-STOR-003",
            title: "Critical State Stored in Ephemeral Temporary Storage",
            category: RuleCategory::StorageSafety,
            default_severity: Severity::Error,
            description: "Detects security-critical keys (Admin, Owner, Balance, Allowance, Nonce, Paused, Role) stored in env.storage().temporary(), where expiration permanently deletes the ledger entry without archival recovery.",
            remediation: "Store administrative, access-control, and financial state in env.storage().instance() or env.storage().persistent().",
            bad_example: r#"pub fn initialize(env: Env, admin: Address) {
    // Temporary storage is permanently deleted on TTL expiry!
    env.storage().temporary().set(&DataKey::Admin, &admin);
}"#,
            good_example: r#"pub fn initialize(env: Env, admin: Address) {
    env.storage().instance().set(&DataKey::Admin, &admin);
    env.storage().instance().extend_ttl(17_280, 518_400);
}"#,
        },
        RuleDescriptor {
            id: "ARK-STOR-004",
            title: "Invalid or Out-of-Bounds extend_ttl Parameters",
            category: RuleCategory::StateArchival,
            default_severity: Severity::Error,
            description: "Detects extend_ttl(threshold, extend_to) calls where threshold > extend_to (causes a host trap), extend_to == 0, or extend_to exceeds Stellar Mainnet max_entry_ttl (3,110,400 ledgers).",
            remediation: "Ensure 0 < threshold <= extend_to <= 3_110,400 ledgers (~180 days on Stellar Mainnet).",
            bad_example: r#"// Host traps at runtime because threshold (50_000) > extend_to (10_000)
env.storage().instance().extend_ttl(50_000, 10_000);"#,
            good_example: r#"const DAY_IN_LEDGERS: u32 = 17_280;
env.storage().instance().extend_ttl(DAY_IN_LEDGERS * 7, DAY_IN_LEDGERS * 30);"#,
        },
        RuleDescriptor {
            id: "ARK-STOR-005",
            title: "Redundant Ledger Read-Before-Read (`has` Followed by `get`)",
            category: RuleCategory::ResourceBudget,
            default_severity: Severity::Warning,
            description: "Detects calling env.storage().<tier>().has(&key) followed by env.storage().<tier>().get(&key) on the same key in the same function, performing two host storage lookups instead of matching on the Option returned by get(&key).",
            remediation: "Replace the `has(&key)` + `get(&key)` pair with a single `if let Some(val) = env.storage().<tier>().get(&key)` or `.get(&key).unwrap_or_default()`.",
            bad_example: r#"let key = DataKey::Balance(user);
if env.storage().persistent().has(&key) {
    let bal: i128 = env.storage().persistent().get(&key).unwrap();
}"#,
            good_example: r#"let key = DataKey::Balance(user);
let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);"#,
        },
        RuleDescriptor {
            id: "ARK-STOR-006",
            title: "Storage Read/Write Inside Loop (`for` / `while` / `loop`)",
            category: RuleCategory::ResourceBudget,
            default_severity: Severity::Warning,
            description: "Detects Soroban storage reads, writes, or TTL extensions executed inside a loop body. Repeated per-iteration host storage accesses can quickly exceed Soroban's per-transaction ledger footprint entry and CPU instruction limits.",
            remediation: "Bound batch sizes explicitly, hoist invariant `instance()` reads outside the loop, or aggregate state updates before writing once.",
            bad_example: r#"for recipient in recipients.iter() {
    env.storage().persistent().set(&DataKey::Claimed(recipient), &true);
}"#,
            good_example: r#"// Hoist shared state reads/writes outside the loop body
let mut total_distributed: i128 = 0;
for amount in amounts.iter() {
    total_distributed += amount;
}
env.storage().instance().set(&DataKey::TotalDistributed, &total_distributed);"#,
        },
        RuleDescriptor {
            id: "ARK-STOR-007",
            title: "Invalid Soroban `Symbol` Literal Length or Character Set",
            category: RuleCategory::StorageSafety,
            default_severity: Severity::Error,
            description: "Detects `symbol_short!(\"...\")` literals longer than 9 characters, `Symbol::new(&env, \"...\")` literals longer than 32 characters, or symbols containing characters outside `[a-zA-Z0-9_]`.",
            remediation: "Use `symbol_short!` only for 1..=9 character `[a-zA-Z0-9_]` identifiers, and `Symbol::new(&env, ...)` for 10..=32 character `[a-zA-Z0-9_]` identifiers.",
            bad_example: r#"// Compile/runtime failure: symbol_short! max length is 9 characters
let tag = symbol_short!("VERY_LONG_SYMBOL_KEY");"#,
            good_example: r#"let short_tag = symbol_short!("VAULT_V1");
let long_tag = Symbol::new(&env, "VAULT_GOVERNANCE_CONFIG_V1");"#,
        },
        RuleDescriptor {
            id: "ARK-UPG-001",
            title: "Unprotected Contract WASM Upgrade",
            category: RuleCategory::UpgradeAuth,
            default_severity: Severity::Error,
            description: "Detects calls to env.deployer().update_current_contract_wasm(...) without a dominating require_auth() check in the function or its helper call chain.",
            remediation: "Load the stored Admin address and invoke admin.require_auth() before calling update_current_contract_wasm.",
            bad_example: r#"pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
    env.deployer().update_current_contract_wasm(new_wasm_hash);
}"#,
            good_example: r#"pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
    env.deployer().update_current_contract_wasm(new_wasm_hash);
}"#,
        },
        RuleDescriptor {
            id: "ARK-UPG-002",
            title: "Stateful Contract Missing Upgrade Mechanism",
            category: RuleCategory::UpgradeAuth,
            default_severity: Severity::Info,
            description: "Detects stateful Soroban contracts that initialize administrative state but expose no update_current_contract_wasm upgrade path.",
            remediation: "Add an admin-guarded upgrade(env: Env, new_wasm_hash: BytesN<32>) entrypoint or document immutability intentionally.",
            bad_example: r#"#[contractimpl]
impl Vault {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
    }
    // No upgrade() entrypoint defined
}"#,
            good_example: r#"#[contractimpl]
impl Vault {
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}"#,
        },
    ]
}

/// Descriptors for compiled WebAssembly binary resource and SEP-0048/SEP-0041 checks (`ARK-WASM-*`, `ARK-SEP-*`).
fn wasm_rule_descriptors() -> [RuleDescriptor; 3] {
    [
        RuleDescriptor {
            id: "ARK-WASM-001",
            title: "WASM Binary Ledger Size Budget & SEP-0048 Metadata Check",
            category: RuleCategory::ResourceBudget,
            default_severity: Severity::Warning,
            description: "Checks compiled .wasm contract size against Stellar ledger size thresholds (48 KiB warning / 64 KiB limit) and verifies presence of contractspecv0 and contractenvmetav0 sections.",
            remediation: "Enable release optimizations (opt-level = \"z\", lto = true, strip = \"symbols\") in Cargo.toml and compile with stellar contract build.",
            bad_example: r#"[profile.release]
# Unoptimized WASM builds often exceed the 64 KiB Stellar Mainnet ledger limit
opt-level = 0"#,
            good_example: r#"[profile.release]
opt-level = "z"
overflow-checks = true
lto = true
codegen-units = 1
strip = "symbols""#,
        },
        RuleDescriptor {
            id: "ARK-WASM-002",
            title: "Excessive WASM Initial Linear Memory Pages or Export Count",
            category: RuleCategory::ResourceBudget,
            default_severity: Severity::Warning,
            description: "Detects compiled .wasm binaries requesting excessive initial linear memory pages (> 16 pages / 1 MiB) or exporting an unusually high number of WebAssembly symbols (> 64 exports), inflating per-invocation Soroban VM memory rent.",
            remediation: "Avoid large static buffers in #![no_std] contract crates and restrict `pub` exports to intended `#[contractimpl]` entrypoints.",
            bad_example: r#"// Allocating large static buffers forces high initial WASM linear memory pages
static SCRATCH_BUFFER: [u8; 2_097_152] = [0; 2_097_152];"#,
            good_example: r#"// Use Soroban host-managed collections (Bytes, Vec) instead of large static WASM buffers
let buf = Bytes::new(&env);"#,
        },
        RuleDescriptor {
            id: "ARK-SEP-041",
            title: "Missing or Non-Conformant SEP-41 Token Interface Entrypoint",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Error,
            description: "Verifies whether a Soroban token contract (.rs or .wasm) implements all 10 required Stellar SEP-41 TokenInterface methods (allowance, approve, balance, transfer, transfer_from, burn, burn_from, decimals, name, symbol) with exact parameter and return types.",
            remediation: "Implement `soroban_sdk::token::TokenInterface` on your `#[contractimpl]` struct so all 10 SEP-41 signatures match the standard.",
            bad_example: r#"// Non-conformant SEP-41 balance signature (returns u64 instead of i128)
pub fn balance(env: Env, id: Address) -> u64"#,
            good_example: r#"pub fn balance(env: Env, id: Address) -> i128 {
    env.storage().persistent().get(&DataKey::Balance(id)).unwrap_or(0)
}"#,
        },
    ]
}

/// Descriptors for the 7 upgrade storage-layout, constructor, event, and ABI compatibility rules (`ARK-DIFF-*`, `ARK-UPG-003`).
fn diff_rule_descriptors() -> [RuleDescriptor; 7] {
    [
        RuleDescriptor {
            id: "ARK-DIFF-001",
            title: "Incompatible #[contracttype] Struct Storage Layout Mutation",
            category: RuleCategory::StorageCompatibility,
            default_severity: Severity::Error,
            description: "Detects removed fields, renamed ScMap field keys, changed field types, or reordered positional tuple struct fields between v1 and v2 that corrupt existing on-chain ledger entries.",
            remediation: "Keep existing #[contracttype] struct fields immutable across in-place upgrades, or introduce a versioned DataKey enum variant (e.g., StateV2) with an explicit migration routine.",
            bad_example: r#"// v1: pub struct Position { pub collateral: i128 }
// v2: renaming `collateral` to `locked_collateral` breaks ScMap deserialization!
#[contracttype]
pub struct Position {
    pub locked_collateral: i128,
}"#,
            good_example: r#"#[contracttype]
pub struct PositionV2 {
    pub locked_collateral: i128,
    pub boost_bps: u32,
}"#,
        },
        RuleDescriptor {
            id: "ARK-DIFF-002",
            title: "Incompatible #[contracttype] Enum or Tagged Union Mutation",
            category: RuleCategory::StorageCompatibility,
            default_severity: Severity::Error,
            description: "Detects removed enum/union variants, shifted u32 enum discriminants, or mutated union variant payload types between v1 and v2.",
            remediation: "Only append new variants at the end of enums/unions; never remove, rename, or alter existing variant payloads used as storage keys or values.",
            bad_example: r#"// v1: DataKey::Position(Address)
// v2: mutating payload tuple arity corrupts existing ledger key lookups!
#[contracttype]
pub enum DataKey {
    Position(Address, u32),
}"#,
            good_example: r#"#[contracttype]
pub enum DataKey {
    Position(Address),
    PositionV2(Address, u32),
}"#,
        },
        RuleDescriptor {
            id: "ARK-DIFF-003",
            title: "Breaking Public Contract Entrypoint Signature Change",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects removed public contract functions, changed parameter counts/types, or altered return types between v1 and v2.",
            remediation: "Preserve existing entrypoint signatures or introduce a new versioned entrypoint (e.g., deposit_v2) to avoid breaking cross-contract callers and indexers.",
            bad_example: r#"// v1: pub fn deposit(env: Env, user: Address, amount: i128)
// v2: changing `amount` from i128 to u64 breaks existing callers
pub fn deposit(env: Env, user: Address, amount: u64)"#,
            good_example: r#"pub fn deposit(env: Env, user: Address, amount: i128) { /* ... */ }
pub fn deposit_v2(env: Env, user: Address, amount: i128, min_shares: i128) { /* ... */ }"#,
        },
        RuleDescriptor {
            id: "ARK-DIFF-004",
            title: "Mutated #[contracterror] Error Code Mapping",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects removed error enum variants or shifted integer error codes in #[contracterror] between v1 and v2.",
            remediation: "Keep existing #[contracterror] integer codes stable so cross-contract try_invoke_contract callers handle errors deterministically.",
            bad_example: r#"#[contracterror]
#[repr(u32)]
pub enum VaultError {
    // Shifting InsufficientFunds from 2 to 3 breaks downstream error matching
    InvalidAmount = 1,
    Paused = 2,
    InsufficientFunds = 3,
}"#,
            good_example: r#"#[contracterror]
#[repr(u32)]
pub enum VaultError {
    InvalidAmount = 1,
    InsufficientFunds = 2,
    Paused = 3,
}"#,
        },
        RuleDescriptor {
            id: "ARK-DIFF-005",
            title: "Soroban Environment Protocol Version Mismatch",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects protocol version regressions or major environment interface shifts in contractenvmetav0 between v1 and v2 WASM binaries.",
            remediation: "Verify that the target Stellar network supports the new Soroban environment protocol version before upgrading.",
            bad_example: r#"# v1 compiled with Soroban Protocol 22
# v2 compiled with an older toolchain targeting Soroban Protocol 20"#,
            good_example: r#"# Keep v2 on Soroban Protocol >= v1 and verify target network protocol support"#,
        },
        RuleDescriptor {
            id: "ARK-DIFF-006",
            title: "Breaking Contract Event Schema Change (`#[contractevent]` / `EventV0`)",
            category: RuleCategory::AbiCompatibility,
            default_severity: Severity::Warning,
            description: "Detects removed contract events, changed event prefix topics, or altered event topic/data field types and locations between v1 and v2 that break off-chain Stellar indexers.",
            remediation: "Preserve existing event topic and data schemas across minor upgrades or emit a new versioned event struct (e.g., DepositEventV2).",
            bad_example: r#"// v1: #[contractevent] pub struct DepositEvent { #[topic] pub user: Address, pub amount: i128 }
// v2: moving `user` from topic to data breaks topic filters in off-chain indexers!
#[contractevent]
pub struct DepositEvent {
    pub user: Address,
    pub amount: i128,
}"#,
            good_example: r#"#[contractevent]
pub struct DepositEvent {
    #[topic]
    pub user: Address,
    pub amount: i128,
}"#,
        },
        RuleDescriptor {
            id: "ARK-UPG-003",
            title: "Modified `__constructor` Signature Without `migrate` Entrypoint Across Upgrade",
            category: RuleCategory::UpgradeAuth,
            default_severity: Severity::Warning,
            description: "Detects when v2 adds or modifies `__constructor` parameters relative to v1 without providing a `migrate` entrypoint. In Soroban, `update_current_contract_wasm` replaces bytecode in place and never re-runs `__constructor`.",
            remediation: "Add an admin-authenticated `migrate(env: Env, ...)` entrypoint to initialize new v2 storage keys after an in-place WASM upgrade.",
            bad_example: r#"// v1: pub fn __constructor(env: Env, admin: Address)
// v2 adds `fee_recipient` to __constructor, which will NOT run on live upgraded contracts!
pub fn __constructor(env: Env, admin: Address, fee_recipient: Address)"#,
            good_example: r#"pub fn __constructor(env: Env, admin: Address, fee_recipient: Address) { /* ... */ }
pub fn migrate(env: Env, fee_recipient: Address) { /* initialize v2 state */ }"#,
        },
    ]
}
