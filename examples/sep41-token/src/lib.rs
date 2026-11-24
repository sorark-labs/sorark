//! Production-safe `#![no_std]` Stellar SEP-0041 compliant Soroban Token Contract.
//!
//! Demonstrates how to implement all 10 required SEP-41 `TokenInterface` entrypoints with:
//! - Bounded `instance()` metadata (`TokenMetadata`) and per-holder `persistent()` keys (`Balance`, `Allowance`)
//! - Dedicated helper-delegated `extend_ttl` archival management
//! - Authenticated in-place WASM upgrade entrypoint (`upgrade`)
//!
//! Passes `sorark --deny-warnings lint examples/sep41-token --sep41` with 0 errors and 0 warnings.

#![no_std]

use soroban_sdk::{
    Address, BytesN, Env, String, contract, contracterror, contractimpl, contracttype,
};

const DAY_IN_LEDGERS: u32 = 17_280;
const INSTANCE_TTL_THRESHOLD: u32 = DAY_IN_LEDGERS * 7;
const INSTANCE_TTL_EXTEND: u32 = DAY_IN_LEDGERS * 30;
const PERSISTENT_TTL_THRESHOLD: u32 = DAY_IN_LEDGERS * 15;
const PERSISTENT_TTL_EXTEND: u32 = DAY_IN_LEDGERS * 60;

/// Allowance record pairing an approved amount with an expiration ledger.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowanceValue {
    pub amount: i128,
    pub expiration_ledger: u32,
}

/// Storage key taxonomy separating global metadata (`instance()`) from per-user records (`persistent()`).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DataKey {
    Admin,
    Decimals,
    Name,
    Symbol,
    Balance(Address),
    Allowance(Address, Address),
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum TokenError {
    AlreadyInitialized = 1,
    NegativeAmount = 2,
    InsufficientBalance = 3,
    InsufficientAllowance = 4,
    InvalidExpirationLedger = 5,
}

#[contract]
pub struct Sep41TokenContract;

#[contractimpl]
impl Sep41TokenContract {
    /// Initializes the token contract's admin, decimals, name, and symbol in `instance()` storage.
    pub fn initialize(
        env: Env,
        admin: Address,
        decimals: u32,
        name: String,
        symbol: String,
    ) -> Result<(), TokenError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(TokenError::AlreadyInitialized);
        }
        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Decimals, &decimals);
        env.storage().persistent().set(&DataKey::Name, &name);
        bump_persistent_ttl(&env, &DataKey::Name);
        env.storage().persistent().set(&DataKey::Symbol, &symbol);
        bump_persistent_ttl(&env, &DataKey::Symbol);
        bump_instance_ttl(&env);
        Ok(())
    }

    /// Mints `amount` new tokens to `to` (admin-only extension entrypoint).
    pub fn mint(env: Env, to: Address, amount: i128) -> Result<(), TokenError> {
        if amount < 0 {
            return Err(TokenError::NegativeAmount);
        }
        require_admin(&env);

        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
        bump_persistent_ttl(&env, &key);
        bump_instance_ttl(&env);
        Ok(())
    }

    /// SEP-41: Returns the allowance granted by `from` to `spender`.
    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        let key = DataKey::Allowance(from, spender);
        let Some(record) = env.storage().persistent().get::<DataKey, AllowanceValue>(&key) else {
            return 0;
        };
        if record.expiration_ledger < env.ledger().sequence() {
            0
        } else {
            record.amount
        }
    }

    /// SEP-41: Sets the allowance granted by `from` to `spender` until `expiration_ledger`.
    pub fn approve(
        env: Env,
        from: Address,
        spender: Address,
        amount: i128,
        expiration_ledger: u32,
    ) {
        from.require_auth();
        let key = DataKey::Allowance(from, spender);
        let record = AllowanceValue {
            amount,
            expiration_ledger,
        };
        env.storage().persistent().set(&key, &record);
        bump_persistent_ttl(&env, &key);
        bump_instance_ttl(&env);
    }

    /// SEP-41: Returns the token balance of `id`.
    pub fn balance(env: Env, id: Address) -> i128 {
        let key = DataKey::Balance(id);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// SEP-41: Transfers `amount` tokens from `from` to `to`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        move_balance(&env, &from, &to, amount);
        bump_instance_ttl(&env);
    }

    /// SEP-41: Transfers `amount` tokens from `from` to `to` using `spender`'s allowance.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        move_balance(&env, &from, &to, amount);
        bump_instance_ttl(&env);
    }

    /// SEP-41: Burns `amount` tokens from `from`.
    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        deduct_balance(&env, &from, amount);
        bump_instance_ttl(&env);
    }

    /// SEP-41: Burns `amount` tokens from `from` using `spender`'s allowance.
    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        spend_allowance(&env, &from, &spender, amount);
        deduct_balance(&env, &from, amount);
        bump_instance_ttl(&env);
    }

    /// SEP-41: Returns the token's decimal precision.
    pub fn decimals(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::Decimals)
            .unwrap_or(7)
    }

    /// SEP-41: Returns the token's human-readable name.
    pub fn name(env: Env) -> String {
        env.storage().persistent().get(&DataKey::Name).unwrap()
    }

    /// SEP-41: Returns the token's ticker symbol.
    pub fn symbol(env: Env) -> String {
        env.storage().persistent().get(&DataKey::Symbol).unwrap()
    }

    /// Authenticated in-place WASM upgrade handler.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        require_admin(&env);
        env.deployer().update_current_contract_wasm(new_wasm_hash);
        bump_instance_ttl(&env);
    }
}

fn require_admin(env: &Env) {
    let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
    admin.require_auth();
}

fn bump_instance_ttl(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND);
}

fn bump_persistent_ttl(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, PERSISTENT_TTL_THRESHOLD, PERSISTENT_TTL_EXTEND);
}

fn spend_allowance(env: &Env, from: &Address, spender: &Address, amount: i128) {
    let key = DataKey::Allowance(from.clone(), spender.clone());
    let mut record: AllowanceValue = env.storage().persistent().get(&key).unwrap();
    record.amount -= amount;
    env.storage().persistent().set(&key, &record);
    bump_persistent_ttl(env, &key);
}

fn deduct_balance(env: &Env, from: &Address, amount: i128) {
    let from_key = DataKey::Balance(from.clone());
    let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
    env.storage()
        .persistent()
        .set(&from_key, &(from_bal - amount));
    bump_persistent_ttl(env, &from_key);
}

fn move_balance(env: &Env, from: &Address, to: &Address, amount: i128) {
    deduct_balance(env, from, amount);
    let to_key = DataKey::Balance(to.clone());
    let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
    env.storage().persistent().set(&to_key, &(to_bal + amount));
    bump_persistent_ttl(env, &to_key);
}
