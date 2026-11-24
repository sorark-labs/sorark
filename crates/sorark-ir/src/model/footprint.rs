//! Exact Stellar XDR (`ScVal` / `ScMap` / `ScVec`) serialized byte size estimator for fixed-size
//! `#[contracttype]` definitions (`ARK-FOOT-001`).

use super::{ContractModule, TypeRef};
use std::collections::HashSet;

/// XDR 4-byte alignment helper (`((len + 3) / 4) * 4`).
#[must_use]
const fn xdr_pad4(len: usize) -> usize {
    (len + 3) & !3
}

/// Estimates the serialized Stellar XDR byte size of an `ScSymbol(name)` (`4` byte discriminant +
/// `4` byte length prefix + 4-byte padded ASCII payload).
#[must_use]
pub const fn estimate_sc_symbol_xdr_bytes(name: &str) -> usize {
    4 + 4 + xdr_pad4(name.len())
}

/// Cycle-safe XDR byte size estimator for [`TypeRef`] and user-defined `#[contracttype]` specs.
pub struct FootprintEstimator<'a> {
    module: &'a ContractModule,
}

impl<'a> FootprintEstimator<'a> {
    /// Creates a new XDR footprint estimator bound to `module`.
    #[must_use]
    pub const fn new(module: &'a ContractModule) -> Self {
        Self { module }
    }

    /// Returns the exact worst-case XDR serialized byte size of `ty` if `ty` is fixed-size,
    /// or `None` if `ty` is dynamically sized (`Vec`, `Map`, `Bytes`, `String`) or recursive.
    #[must_use]
    pub fn estimate_xdr_bytes(&self, ty: &TypeRef) -> Option<usize> {
        let mut visiting = HashSet::new();
        self.estimate_inner(ty, &mut visiting)
    }

    fn estimate_inner(&self, ty: &TypeRef, visiting: &mut HashSet<String>) -> Option<usize> {
        match ty {
            // 4-byte ScVal discriminant only
            TypeRef::Void => Some(4),
            // 4-byte ScVal discriminant + 4-byte payload
            TypeRef::Bool | TypeRef::U32 | TypeRef::I32 | TypeRef::Error | TypeRef::Val => Some(8),
            // 4-byte ScVal discriminant + 8-byte payload
            TypeRef::U64 | TypeRef::I64 | TypeRef::Timepoint | TypeRef::Duration => Some(12),
            // 4-byte ScVal discriminant + 16-byte payload
            TypeRef::U128 | TypeRef::I128 => Some(20),
            // 4-byte ScVal discriminant + 32-byte payload
            TypeRef::U256 | TypeRef::I256 => Some(36),
            // ScVal::Address (4-byte disc + 4-byte ScAddress disc + 32-byte hash/ed25519 key)
            TypeRef::Address => Some(40),
            // Worst-case 32-char ScSymbol (4-byte disc + 4-byte len + 32 bytes)
            TypeRef::Symbol => Some(40),
            // Fixed-size BytesN<N>: 4-byte ScVal::Bytes disc + 4-byte length + padded N bytes
            TypeRef::BytesN(n) => Some(4 + 4 + xdr_pad4(*n as usize)),
            // Option<T>: worst-case Some(T) serializes as T directly in Soroban ScVal
            TypeRef::Option(inner) => self.estimate_inner(inner, visiting),
            // Result<T, E>: max of ok and err branch sizes
            TypeRef::Result { ok, err } => {
                let ok_sz = self.estimate_inner(ok, visiting)?;
                let err_sz = self.estimate_inner(err, visiting)?;
                Some(ok_sz.max(err_sz))
            }
            // Tuple(T1, T2, ...): ScVal::Vec (4-byte disc + 4-byte Option::Some + 4-byte len) + elements
            TypeRef::Tuple(elems) => {
                let mut total = 12;
                for el in elems {
                    total += self.estimate_inner(el, visiting)?;
                }
                Some(total)
            }
            // Dynamically sized collections have no static upper bound
            TypeRef::Vec(_) | TypeRef::Map { .. } | TypeRef::Bytes | TypeRef::String => None,
            // User-defined #[contracttype] struct, tuple struct, enum, or union
            TypeRef::Custom(name) => self.estimate_custom_type(name, visiting),
        }
    }

    fn estimate_custom_type(&self, name: &str, visiting: &mut HashSet<String>) -> Option<usize> {
        if !visiting.insert(name.to_string()) {
            return None;
        }
        let result = if let Some(s) = self.module.find_struct(name) {
            // Named struct serializes as ScVal::Map (4-byte disc + 4-byte Option::Some + 4-byte map len)
            // plus each ScMapEntry (key: ScSymbol(field.name) + val: field.ty)
            let mut total = 12;
            for f in &s.fields {
                total += estimate_sc_symbol_xdr_bytes(&f.name);
                total += self.estimate_inner(&f.ty, visiting)?;
            }
            Some(total)
        } else if let Some(ts) = self.module.find_tuple_struct(name) {
            // Positional tuple struct serializes as ScVal::Vec (12-byte header) + elements
            let mut total = 12;
            for f in &ts.fields {
                total += self.estimate_inner(f, visiting)?;
            }
            Some(total)
        } else if self.module.find_enum(name).is_some()
            || self.module.find_error_enum(name).is_some()
        {
            // Unit enum serializes as ScVal::U32 (8 bytes)
            Some(8)
        } else if let Some(u) = self.module.find_union(name) {
            // Tagged union serializes as ScVal::Vec ([ScSymbol(case.name), ...payload]); take max case
            let mut max_case = 12;
            for case in &u.cases {
                let mut case_sz = 12 + estimate_sc_symbol_xdr_bytes(&case.name);
                for p in &case.payload {
                    case_sz += self.estimate_inner(p, visiting)?;
                }
                max_case = max_case.max(case_sz);
            }
            Some(max_case)
        } else {
            None
        };
        visiting.remove(name);
        result
    }
}
