//! Rust reference implementation of NAOME's immutable Foundation contract.
//!
//! Foundation defines a valid-by-construction formula language, executable
//! logical axiom constructors and primitive inference rules, seven
//! fixed ZFC axioms, and the Separation and Replacement schemas. It
//! intentionally does not parse source text, verify complete proofs, or admit
//! definitions. Its canonical formula codec supports the separate proof
//! protocol and does not change the abstract Foundation identity.

mod formula;
mod logic;
mod zfc;

pub use formula::{
    FORMULA_MAX_BYTES, FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, Formula, FormulaCodecError,
    FreeVariable,
};
pub use logic::{Logic, LogicError};
pub use zfc::{Replacement, SchemaError, Separation, ZfcAxiom};

/// The immutable protocol identifier for Foundation.
pub const FOUNDATION_ID: &str = "naome:zfc";
