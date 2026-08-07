//! Rust reference implementation of NAOME's immutable Foundation V0 contract.
//!
//! Foundation V0 defines a valid-by-construction formula language, executable
//! logical axiom constructors, primitive inference-rule identifiers, seven
//! fixed ZFC axioms, and the Separation and Replacement schemas. It
//! intentionally does not parse source text, verify complete proofs, admit
//! definitions, or define canonical bytes.

mod formula;
mod logic;
mod zfc;

pub use formula::{Formula, FreeVariable};
pub use logic::{InferenceRule, LogicError, LogicV0};
pub use zfc::{Replacement, SchemaError, Separation, ZfcAxiom};

/// The immutable protocol identifier for Foundation V0.
pub const FOUNDATION_ID: &str = "naome:zfc:v0";

/// The human-readable name of the logical calculus selected by Foundation V0.
pub const LOGIC_NAME: &str = "classical-first-order-logic-with-equality";
