//! Source-agnostic Soroban contract model.
//!
//! - [`type_ref`]: normalized `ScSpecTypeDef` equivalent ([`TypeRef`]).
//! - [`specs`]: struct / enum / union / error / function / event specifications.
//! - [`origin`]: where a module was loaded from ([`SourceOrigin`]).
//! - [`contract_module`]: the [`ContractModule`] aggregate and its queries.
//! - [`sep41`]: Stellar SEP-0041 Token Interface conformance verification (`ARK-SEP-041`).

mod contract_module;
mod footprint;
mod origin;
mod sep41;
mod specs;
mod type_ref;
mod unbounded;

pub use contract_module::ContractModule;
pub use footprint::{FootprintEstimator, estimate_sc_symbol_xdr_bytes};
pub use origin::SourceOrigin;
pub use sep41::check_sep41_conformance;
pub use specs::{
    EnumSpec, EnumVariantSpec, ErrorEnumSpec, EventParamSpec, EventSpec, FunctionParamSpec,
    FunctionSpec, StorageTier, StructFieldSpec, StructSpec, TupleStructSpec, UnionCaseSpec,
    UnionSpec,
};
pub use type_ref::TypeRef;
