# SORARK Architecture & Internal Design

This document describes the internal architecture of **SORARK** (`sorark`), its intermediate representation (`sorark-ir`), its two-pass Rust AST analysis engine (`sorark-ast`), its SEP-0048 WebAssembly XDR decoder (`sorark-wasm`), and its storage-layout diffing engine (`sorark-diff`).

---

## 1. Design Goals

Stellar Soroban smart contracts have consensus-enforced execution and state rules that differ from EVM and CosmWasm runtimes:

1. **Three-Tier State Archival & 64 KiB Ledger Entry Limits:**
   - Every Soroban `ContractData` ledger entry is capped at **64 KiB (`65,536` bytes)** on Stellar Mainnet.
   - **Instance Storage (`env.storage().instance()`)** shares a single ledger entry with the contract instance itself and is loaded on *every* invocation. Storing unbounded collections (`Map`, `Vec`, `Bytes`, `String`) or structs transitively containing them inside `instance()` causes the contract to hit the 64 KiB ceiling and permanently trap.
   - **Persistent Storage (`env.storage().persistent()`)** and **Instance Storage** require explicit `extend_ttl(threshold, extend_to)` calls (`min_persistent_entry_ttl = 4,096` ledgers, `max_entry_ttl = 3,110,400` ledgers).
   - **Temporary Storage (`env.storage().temporary()`)** (`min_temp_entry_ttl = 16` ledgers) is **permanently deleted** from the ledger upon TTL expiration and cannot be restored via `RestoreFootprintOp`.

2. **In-Place WASM Bytecode Upgrades (`update_current_contract_wasm`) & `ScVal` Serialization:**
   - Soroban serializes named `#[contracttype]` structs as key-sorted `ScMap`s (keyed by field name `ScSymbol`), tuple structs as positional `ScVec`s, data enums as `ScSpecUdtUnionV0` tagged vectors, and unit enums as `u32` discriminants (`ScSpecUdtEnumV0`).
   - Mutating field names, field types, tuple ordering, or enum variants between `v1` and `v2` without an explicit state migration causes host deserialization traps when reading historical ledger entries.

---

## 2. Data Flow & Crate Boundaries

```text
sorark/
├── crates/
│   ├── sorark-ir/        # Source-agnostic ContractModule IR, Diagnostics, & Config
│   ├── sorark-ast/       # Two-Pass syn v3 AST Semantic Analyzer & Storage/TTL Rules
│   ├── sorark-wasm/      # wasmparser + stellar-xdr SEP-0048 Spec Decoder & Budget Checks
│   ├── sorark-diff/      # Ledger Storage-Layout & ABI Upgrade Diff Engine (v1 vs v2)
│   └── sorark-cli/       # CLI binary + Text / JSON / SARIF v2.1.0 / Markdown Formatters
└── examples/
    ├── vulnerable-vault/ # #![no_std] Soroban contract exhibiting storage/TTL/auth bugs
    ├── upgrade-v1/       # Production-safe Soroban baseline vault contract
    └── upgrade-v2-broken/# Mutated v2 upgrade candidate with breaking storage/ABI changes
```

### 2.1 `sorark-ir` (Normalized Contract Representation)
Provides a source-agnostic intermediate representation (`ContractModule`) populated identically from either Rust source files (`sorark-ast`) or compiled `.wasm` SEP-0048 custom sections (`sorark-wasm`):
- `StructSpec` (named fields mapped to `ScMap` `ScSymbol` keys)
- `TupleStructSpec` (positional fields mapped to `ScVec` indices)
- `EnumSpec` (`u32` discriminant cases mapped to `ScSpecUdtEnumV0`)
- `UnionSpec` (tagged union cases mapped to `ScSpecUdtUnionV0`)
- `ErrorEnumSpec` (`#[contracterror]` codes mapped to `ScSpecUdtErrorEnumV0`)
- `FunctionSpec` (exported contract entrypoints, parameter names/types, return type)
- `UnboundedAnalyzer` (cycle-safe fixed-point reachability over user-defined `#[contracttype]` graphs)
- `Diagnostic`, `DiagnosticBuilder`, `Severity`, `Confidence`, `SourceSpan`, and `SorarkConfig` (`sorark.toml`).

### 2.2 `sorark-ast` (Two-Pass Semantic AST Engine)
Uses `syn` v3 (`visit` + `full` + `extra-traits`) and `proc-macro2` (`span-locations`):
- **Pass 1 (Symbol, Type & Call-Graph Discovery):**
  - Collects all `#[contracttype]` structs/enums and `#[contracterror]` definitions across scanned files.
  - Evaluates constant integer expressions (`const DAY_IN_LEDGERS: u32 = 17_280;`, arithmetic expressions) for static TTL bound verification.
  - Builds an intra-module helper function summary recording which helpers invoke `.extend_ttl(...)` (and on which storage tier) and which invoke `.require_auth()`.
  - Parses inline suppression comments (`// sorark-ignore: ARK-STOR-002`).
- **Pass 2 (Rule Execution via `AstRule` Trait):**
  - Executes isolated rule modules (`ARK-STOR-001` through `ARK-STOR-004`, `ARK-UPG-001`, `ARK-UPG-002`) against the enriched `AstAnalysisContext`.

### 2.3 `sorark-wasm` (Binary WASM & `stellar-xdr` SEP-0048 Decoder)
Uses `wasmparser` and `stellar-xdr` v30:
- Extracts `contractspecv0`, `contractenvmetav0`, and `contractmetav0` custom sections.
- Decodes XDR `ScSpecEntry` streams into `sorark_ir::ContractModule` and extracts `ScEnvMetaEntry` protocol and interface version metadata.
- Evaluates `ARK-WASM-001` (WASM byte size budget warnings/errors against the 64 KiB Stellar Mainnet ledger ceiling and missing SEP-0048 sections).

### 2.4 `sorark-diff` (Upgrade & Storage-Layout Compatibility Engine)
Compares `old: &ContractModule` and `new: &ContractModule` via the `DiffRule` trait:
- Because both `sorark-ast` and `sorark-wasm` lower into `ContractModule`, `sorark diff` can compare `.rs` against `.rs`, `.wasm` against `.wasm`, or `.rs` against `.wasm`.
- Detects incompatible `ScMap` field mutations (`ARK-DIFF-001`), `ScSpecUdtEnumV0` / `ScSpecUdtUnionV0` layout shifts (`ARK-DIFF-002`), entrypoint ABI breakages (`ARK-DIFF-003`), `#[contracterror]` code shifts (`ARK-DIFF-004`), and Soroban protocol version regressions (`ARK-DIFF-005`).
