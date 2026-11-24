# SORARK Engineering Roadmap

This document tracks planned features, static analysis rules, and ecosystem integrations for **SORARK** (`sorark`).

---

## Milestone `v0.2.0` — Deeper AST Semantics & CLI Filtering (Completed)

- [x] **Severity Filtering (`--min-severity`):** Add `--min-severity <info|warning|error>` to `sorark lint` and `sorark diff` along with per-rule severity overrides (`[rules.<RULE_ID>]`) in `sorark.toml`.
- [x] **Rule Explanations (`sorark rules --explain <RULE_ID>`):** Print detailed vulnerability rationales alongside vulnerable vs. remediated Soroban code snippets directly in the terminal.
- [x] **`ARK-STOR-005` (Redundant Ledger Read-Before-Write):** Detect `env.storage().<tier>().has(&k)` immediately followed by `.get(&k)` on the identical key within the same control-flow block.
- [x] **`ARK-STOR-006` (Unbounded Loops Over Storage Operations):** Flag `persistent()` or `temporary()` reads/writes inside `for` and `while` loops that risk exceeding Soroban per-transaction footprint limits.
- [x] **`ARK-STOR-007` (`Symbol` Key Length & Character Validation):** Statically validate `symbol_short!` (<= 9 chars, `[a-zA-Z0-9_]`) and `Symbol::new` (<= 32 chars) literals.
- [x] **GitHub Actions Annotation Formatter (`--format github`):** Emit native GitHub Actions workflow commands (`::error file=...,line=...,col=...,title=...::...`) for inline PR annotations without requiring SARIF upload permissions.

---

## Milestone `v0.3.0` — Multi-File Call Graphs, SEP-41 & Event Diffing (Completed)

- [x] **Cross-File Workspace Call-Graph Resolution (`sorark-ast`):** Resolve module-qualified helper functions (e.g., `storage::bump_instance(&env)`, `auth::require_admin(&env)`) across multi-file Soroban contract crates.
- [x] **`ARK-SEP-041` (SEP-41 Token Interface Conformance):** Verify whether a contract (from `.rs` or `.wasm`) implements the Stellar SEP-41 token specification (`allowance`, `approve`, `balance`, `transfer`, `transfer_from`, `burn`, `burn_from`, `decimals`, `name`, `symbol`) with exact parameter and return types.
- [x] **`ARK-DIFF-006` (`#[contractevent]` / `ScSpecEntry::EventV0` Schema Compatibility):** Decode Soroban contract event specifications from AST and WASM XDR sections and detect breaking event topic or payload changes between `v1` and `v2`.
- [x] **`ARK-UPG-003` (`__constructor` Upgrade Assumption Detection):** Warn when a `v2` upgrade modifies `__constructor` parameters without introducing a dedicated `migrate` entrypoint (since `update_current_contract_wasm` does not re-run `__constructor`).
- [x] **`ARK-WASM-002` (WASM Linear Memory & Export Footprint):** Flag excessive initial WASM linear memory pages or exported entrypoint counts in `sorark-wasm`.

---

## Milestone `v0.4.0` — Git Revision Diffing, Auto-Fixes & Ecosystem Benchmarks

- [ ] **Git Revision Diffing (`sorark diff --old-rev <ref> --new-rev <ref>`):** Compare two git commits, tags, or branches directly without checking out separate working trees.
- [ ] **XDR Ledger Entry Byte Estimator (`ARK-FOOT-001`):** Statically estimate serialized `ScVal` / `ScMap` byte overhead for fixed-size `#[contracttype]` structs and keys.
- [ ] **Auto-Remediation Suggestions (`sorark lint --suggest-patch`):** Output unified diffs suggesting `extend_ttl` insertions for `ARK-STOR-002` findings.
- [ ] **Turnkey Composite GitHub Action (`action.yml`):** Allow Soroban repositories to run `sorark lint` and `sorark diff` in CI with a single workflow step.
- [ ] **Real-World Ecosystem Corpus Benchmarks:** Continuously test and benchmark `sorark` against upstream open-source Soroban contracts (`stellar/soroban-examples`, OpenZeppelin Soroban contracts, and DeFi protocols).
