//! Soroban storage-layout, constructor, event, and ABI upgrade compatibility rules.

mod constructor_migration;
mod enum_union;
mod error_enum;
mod event_schema;
mod function_abi;
mod protocol;
mod struct_layout;

pub use constructor_migration::ConstructorMigrationDiffRule;
pub use enum_union::EnumAndUnionLayoutDiffRule;
pub use error_enum::ErrorEnumDiffRule;
pub use event_schema::EventSchemaDiffRule;
pub use function_abi::FunctionAbiDiffRule;
pub use protocol::ProtocolVersionDiffRule;
pub use struct_layout::StructLayoutDiffRule;
