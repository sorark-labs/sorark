# SORARK Real-World Stellar Soroban Ecosystem Benchmarks

This document records the results of running **SORARK** (`sorark v0.4.0`) against all **36 official Stellar Soroban example contract workspaces** in [`stellar/soroban-examples`](https://github.com/stellar/soroban-examples) (commit `03d42aa`).

---

## 1. Executive Summary

- **Total Contracts Analyzed:** `36` official Soroban smart contract workspaces (`stellar/soroban-examples`)
- **Total Wall-Clock Analysis Time:** `1.04 seconds` across all 36 workspaces (**median `17.6 ms` per contract**)
- **SEP-41 Reference Token Verification (`token`):** Passed `sorark lint token --sep41` with **0 errors and 0 warnings** (`66.1 ms`), confirming full conformance across all 10 `TokenInterface` entrypoints and zero false positives on helper-delegated TTL extensions.
- **True-Positive Storage & Footprint Findings:**
  - **`ARK-STOR-001` (Unbounded Type in 64 KiB Shared `instance()` Storage):** Flagged 4 example contracts (`timelock`, `bls_signature`, `modular_account`, `privacy-pools`) that store dynamically sized collections (`Vec<Address>`, `Bytes`) inside `env.storage().instance()`. For example, `timelock` stores `ClaimableBalance { claimants: Vec<Address>, ... }` in `instance()`, which works for small demos but risks hitting the 64 KiB shared instance entry ceiling if unbounded claimant lists are permitted in production.
  - **`ARK-STOR-006` (Storage Access Inside Loops):** Flagged 3 multi-signer / account abstraction contracts (`account`, `modular_account`, `multisig_1_of_n_account`) that iterate over signer lists while querying `env.storage()` inside a `for` loop.
  - **`ARK-STOR-002` (Unextended `persistent()` / `instance()` Writes):** Flagged 20 minimal pedagogical contracts that write to `instance()` or `persistent()` without calling `extend_ttl` (whereas the dedicated `ttl` and `token` examples handle TTL extensions explicitly).

---

## 2. Per-Contract Benchmark Matrix (`stellar/soroban-examples @ 03d42aa`)

| Contract Workspace | Errors | Warnings | Info | Triggered Rules | Time (ms) |
| :--- | :---: | :---: | :---: | :--- | ---: |
| `account` | 0 | 5 | 1 | `ARK-STOR-002`, `ARK-STOR-006`, `ARK-UPG-002` | `28.5 ms` |
| `alloc` | 0 | 0 | 0 | — (Clean) | `7.4 ms` |
| `atomic_multiswap` | 0 | 0 | 0 | — (Clean) | `26.0 ms` |
| `atomic_swap` | 0 | 0 | 0 | — (Clean) | `16.2 ms` |
| `auth` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `15.7 ms` |
| `bls_signature` | 1 | 4 | 1 | `ARK-STOR-001`, `ARK-STOR-002`, `ARK-UPG-002` | `17.3 ms` |
| `cross_contract` | 0 | 0 | 0 | — (Clean) | `7.2 ms` |
| `custom_types` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `10.0 ms` |
| `deep_contract_auth` | 0 | 0 | 0 | — (Clean) | `10.4 ms` |
| `deployer` | 0 | 2 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `13.2 ms` |
| `errors` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `7.2 ms` |
| `eth_abi` | 0 | 0 | 0 | — (Clean) | `13.7 ms` |
| `events` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `6.7 ms` |
| `fuzzing` | 0 | 3 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `41.5 ms` |
| `groth16_verifier` | 0 | 0 | 0 | — (Clean) | `70.0 ms` |
| `hello_world` | 0 | 0 | 0 | — (Clean) | `7.1 ms` |
| `import_ark_bn254` | 0 | 0 | 0 | — (Clean) | `14.6 ms` |
| `increment` | 0 | 0 | 1 | `ARK-UPG-002` | `8.3 ms` |
| `increment_with_fuzz` | 0 | 0 | 1 | `ARK-UPG-002` | `10.1 ms` |
| `increment_with_pause` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `21.8 ms` |
| `liquidity_pool` | 0 | 0 | 1 | `ARK-UPG-002` | `72.0 ms` |
| `logging` | 0 | 0 | 0 | — (Clean) | `18.7 ms` |
| `merkle_distribution` | 0 | 3 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `31.5 ms` |
| `mint-lock` | 0 | 3 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `22.0 ms` |
| `modular_account` | 1 | 4 | 1 | `ARK-STOR-001`, `ARK-STOR-002`, `ARK-STOR-006`, `ARK-UPG-002` | `20.6 ms` |
| `multisig_1_of_n_account` | 0 | 2 | 1 | `ARK-STOR-002`, `ARK-STOR-006`, `ARK-UPG-002` | `23.8 ms` |
| `other_custom_types` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `17.3 ms` |
| `pause` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `6.9 ms` |
| `privacy-pools` | 4 | 16 | 1 | `ARK-STOR-001`, `ARK-STOR-002`, `ARK-UPG-002` | `370.4 ms` |
| `simple_account` | 0 | 1 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `18.3 ms` |
| `single_offer` | 0 | 0 | 1 | `ARK-UPG-002` | `26.4 ms` |
| `timelock` | 1 | 2 | 1 | `ARK-STOR-001`, `ARK-STOR-002`, `ARK-UPG-002` | `35.3 ms` |
| `token` (`--sep41`) | 0 | 0 | 1 | `ARK-UPG-002` (`ARK-SEP-041` passed!) | `66.1 ms` |
| `ttl` | 0 | 2 | 1 | `ARK-STOR-002`, `ARK-UPG-002` | `25.1 ms` |
| `upgradeable_contract` | 0 | 4 | 1 | `ARK-STOR-002` (`ARK-UPG-001` & `ARK-UPG-002` passed!) | `17.8 ms` |
| `workspace` | 0 | 0 | 0 | — (Clean) | `9.9 ms` |

---

## 3. Reproducing This Benchmark Locally

```bash
git clone --depth 1 https://github.com/stellar/soroban-examples.git /tmp/soroban-examples
sorark lint /tmp/soroban-examples/token --sep41
sorark lint /tmp/soroban-examples/timelock
sorark lint /tmp/soroban-examples/account
```
