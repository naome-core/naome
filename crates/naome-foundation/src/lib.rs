//! NAOME's immutable first-order logic and ZFC foundation contract.
//!
//! Foundation V0 defines the primitive formula language, logical axiom
//! schemas, inference-rule identifiers, seven fixed ZFC axioms, and the
//! Separation and Replacement schemas. It intentionally does not parse source
//! text, verify complete proofs, admit definitions, or define canonical bytes.

mod formula;
mod logic;
mod zfc;

pub use formula::{Formula, FormulaError, FreeVariable, Term};
pub use logic::{
    INFERENCE_RULES, InferenceRule, LOGICAL_AXIOM_SCHEMAS, LogicError, LogicV0, LogicalAxiomSchema,
};
pub use zfc::{
    Replacement, SchemaError, Separation, ZFC_AXIOM_SCHEMAS, ZFC_AXIOMS, ZfcAxiom, ZfcAxiomSchema,
};

/// The immutable protocol identifier for Foundation V0.
pub const FOUNDATION_ID: &str = "naome:zfc:v0";

/// The human-readable name of the logical calculus selected by Foundation V0.
pub const LOGIC_NAME: &str = "classical-first-order-logic-with-equality";

/// The complete manifest for Foundation V0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FoundationV0;

impl FoundationV0 {
    /// Returns the immutable foundation identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        FOUNDATION_ID
    }

    /// Returns the selected logical calculus name.
    #[must_use]
    pub const fn logic(self) -> &'static str {
        LOGIC_NAME
    }

    /// Returns the fixed ZFC axioms in their normative order.
    #[must_use]
    pub const fn zfc_axioms(self) -> &'static [ZfcAxiom; 7] {
        &ZFC_AXIOMS
    }

    /// Returns the ZFC axiom schemas in their normative order.
    #[must_use]
    pub const fn zfc_axiom_schemas(self) -> &'static [ZfcAxiomSchema; 2] {
        &ZFC_AXIOM_SCHEMAS
    }

    /// Returns the logical axiom schemas in their normative order.
    #[must_use]
    pub const fn logical_axiom_schemas(self) -> &'static [LogicalAxiomSchema; 8] {
        &LOGICAL_AXIOM_SCHEMAS
    }

    /// Returns the primitive inference rules in their normative order.
    #[must_use]
    pub const fn inference_rules(self) -> &'static [InferenceRule; 2] {
        &INFERENCE_RULES
    }
}

#[cfg(test)]
mod tests {
    use super::{FOUNDATION_ID, FoundationV0, LOGIC_NAME};

    #[test]
    fn manifest_exposes_the_complete_v0_boundary() {
        let foundation = FoundationV0;

        assert_eq!(foundation.id(), FOUNDATION_ID);
        assert_eq!(foundation.logic(), LOGIC_NAME);
        assert_eq!(foundation.logical_axiom_schemas().len(), 8);
        assert_eq!(foundation.inference_rules().len(), 2);
        assert_eq!(foundation.zfc_axioms().len(), 7);
        assert_eq!(foundation.zfc_axiom_schemas().len(), 2);
    }
}
