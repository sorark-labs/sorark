# Changelog

All notable changes to **SORARK** (`sorark`) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-24

### Added
- **`ARK-STOR-005` (`sorark-ast`):** New rule detecting redundant `env.storage().<tier>().has(&k)` followed by `.get(&k)` on the same key within a function body.
- **`ARK-STOR-006` (`sorark-ast`):** New rule detecting Soroban storage reads, writes, or TTL extensions inside `for`, `while`, and `loop` bodies that risk exhausting per-transaction ledger footprint limits.
- **`ARK-STOR-007` (`sorark-ast`):** New rule validating `symbol_short!("...")` (<= 9 chars) and `Symbol::new(&env, "...")` (<= 32 chars) literals against Soroban's `[a-zA-Z0-9_]` symbol alphabet.
- **Per-Rule Severity & Enablement Overrides (`sorark-ir`):** Support `[rules.<RULE_ID>] severity = "error" | "warning" | "info"` and `enabled = true | false` in `sorark.toml` across all engines (`sorark-ast`, `sorark-wasm`, `sorark-diff`).
- **Rule Explanation Mode (`sorark rules --explain <RULE_ID>`):** Print detailed vulnerability descriptions, remediations, and vulnerable vs. fixed Soroban Rust examples in text, Markdown, or JSON format.
- **Minimum Severity Filter (`--min-severity <info|warning|error>`):** Added `--min-severity` filtering to `sorark lint` and `sorark diff`.
- **GitHub Actions Annotation Output (`--format github`):** Emit native `::error`, `::warning`, and `::notice` workflow commands for inline Pull Request annotations.
- **Architecture & Roadmap Docs:** Added `docs/ARCHITECTURE.md`, `ROADMAP.md`, and crates.io packaging metadata across all workspace crates.

## [0.1.0] - 2026-11-02

### Added
- **`sorark-ir`:** Source-agnostic Soroban contract intermediate representation (`ContractModule`, `StructSpec`, `TupleStructSpec`, `EnumSpec`, `UnionSpec`, `ErrorEnumSpec`, `FunctionSpec`, `TypeRef`), cycle-safe `UnboundedAnalyzer`, fluent `DiagnosticBuilder`, and `sorark.toml` configuration loader.
- **`sorark-ast`:** Two-pass `syn` v3 static analyzer with helper call-graph resolution (`extend_ttl`, `require_auth`), constant folding, inline `// sorark-ignore:` comment support, and 6 isolated rule modules (`ARK-STOR-001` through `ARK-STOR-004`, `ARK-UPG-001`, `ARK-UPG-002`).
- **`sorark-wasm`:** Binary WebAssembly inspector using `wasmparser` and `stellar-xdr` v30 to decode `contractspecv0` (`ScSpecEntry`), `contractenvmetav0` (`ScEnvMetaEntry`), and `contractmetav0` (`ScMetaEntry`) custom sections, plus `ARK-WASM-001` ledger byte budget verification.
- **`sorark-diff`:** Storage-layout (`ScMap`/`ScVec`/`ScSpecUdtUnionV0`) and ABI upgrade compatibility engine (`ARK-DIFF-001` through `ARK-DIFF-005`) comparing `v1` and `v2` contracts across `.rs` and `.wasm` targets.
- **`sorark-cli` (`sorark`):** Command-line binary supporting `lint`, `diff`, `inspect`, `rules`, and `init` with dedicated `text`, `json`, `sarif` (v2.1.0), `markdown`, and `inspect` formatters.
- **`examples/`:** Three real `#![no_std]` Soroban smart contracts (`vulnerable-vault`, `upgrade-v1`, `upgrade-v2-broken`) built with `soroban-sdk`.
