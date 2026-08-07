//! Rust reference implementation of NAOME's immutable Foundation V0 contract.
//!
//! Foundation V0 defines a valid-by-construction formula language, executable
//! logical axiom constructors and primitive inference rules, seven
//! fixed ZFC axioms, and the Separation and Replacement schemas. It
//! intentionally does not parse source text, verify complete proofs, or admit
//! definitions. Its versioned formula codec supports the separate proof
//! protocol and does not change the abstract Foundation V0 identity.

mod formula;
mod logic;
mod zfc;

pub use formula::{
    FORMULA_V0_MAX_BYTES, FORMULA_V0_MAX_DEPTH, FORMULA_V0_MAX_NODES, Formula, FormulaCodecError,
    FreeVariable,
};
pub use logic::{LogicError, LogicV0};
pub use zfc::{Replacement, SchemaError, Separation, ZfcAxiom};

/// The immutable protocol identifier for Foundation V0.
pub const FOUNDATION_ID: &str = "naome:zfc:v0";

/// The human-readable name of the logical calculus selected by Foundation V0.
pub const LOGIC_NAME: &str = "classical-first-order-logic-with-equality";
