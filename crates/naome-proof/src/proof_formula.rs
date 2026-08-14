//! Proof-certificate formula storage with a zero-conversion primitive path.

use std::borrow::Cow;
use std::collections::BTreeSet;

use naome_foundation::{Formula, FormulaCodecError, FreeVariable};

use crate::{
    DefinedFormula, DefinedFormulaCodecError, DefinitionExpansionError, DefinitionId,
    DefinitionResolver,
};

/// One formula field in a canonical proof certificate.
///
/// Existing primitive formulas stay as their original Foundation value, so
/// checking and encoding them require no definition-aware conversion. Only a
/// formula that actually contains a `DefinitionId` uses the extended tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofFormula(FormulaRepresentation);

#[derive(Clone, Debug, PartialEq, Eq)]
enum FormulaRepresentation {
    Primitive(Formula),
    Defined(Box<DefinedFormula>),
}

impl ProofFormula {
    /// Returns the primitive formula without conversion when this is the fast path.
    #[must_use]
    pub const fn as_primitive(&self) -> Option<&Formula> {
        match &self.0 {
            FormulaRepresentation::Primitive(formula) => Some(formula),
            FormulaRepresentation::Defined(_) => None,
        }
    }

    /// Returns the definition-aware formula when one is present.
    #[must_use]
    pub const fn as_defined(&self) -> Option<&DefinedFormula> {
        match &self.0 {
            FormulaRepresentation::Primitive(_) => None,
            FormulaRepresentation::Defined(formula) => Some(formula),
        }
    }

    /// Constructs the canonical representation of a definition-aware formula.
    ///
    /// Definition-free values are converted to the primitive representation so
    /// equal canonical bytes cannot have two distinct in-memory forms.
    pub fn from_defined(formula: DefinedFormula) -> Result<Self, DefinedFormulaCodecError> {
        if formula.contains_definition() {
            Ok(Self(FormulaRepresentation::Defined(Box::new(formula))))
        } else {
            formula
                .into_primitive()
                .map(FormulaRepresentation::Primitive)
                .map(Self)
        }
    }

    /// Maps all free variables without converting primitive formulas.
    #[must_use]
    pub fn map_free_variables(self, map: impl FnMut(FreeVariable) -> FreeVariable) -> Self {
        match self.0 {
            FormulaRepresentation::Primitive(formula) => Self(FormulaRepresentation::Primitive(
                formula.map_free_variables(map),
            )),
            FormulaRepresentation::Defined(formula) => Self(FormulaRepresentation::Defined(
                Box::new((*formula).map_free_variables(map)),
            )),
        }
    }

    /// Returns the formula's free variables.
    #[must_use]
    pub fn free_variables(&self) -> BTreeSet<FreeVariable> {
        match &self.0 {
            FormulaRepresentation::Primitive(formula) => formula.free_variables(),
            FormulaRepresentation::Defined(formula) => formula.free_variables(),
        }
    }

    /// Returns definition references in canonical prefix order.
    #[must_use]
    pub fn definition_references(&self) -> Vec<DefinitionId> {
        match &self.0 {
            FormulaRepresentation::Primitive(_) => Vec::new(),
            FormulaRepresentation::Defined(formula) => formula.definition_references(),
        }
    }

    /// Borrows a primitive formula or expands only the definition-aware path.
    pub fn expand_with<'a, R: DefinitionResolver + ?Sized>(
        &'a self,
        resolver: &R,
    ) -> Result<Cow<'a, Formula>, DefinitionExpansionError> {
        match &self.0 {
            FormulaRepresentation::Primitive(formula) => Ok(Cow::Borrowed(formula)),
            FormulaRepresentation::Defined(formula) => {
                formula.expand_with(resolver).map(Cow::Owned)
            }
        }
    }

    /// Borrows a primitive formula or performs bounded definition expansion.
    ///
    /// Primitive formulas report zero definition-expansion work.
    pub fn expand_with_node_limit<'a, R: DefinitionResolver + ?Sized>(
        &'a self,
        resolver: &R,
        maximum_nodes: usize,
    ) -> Result<(Cow<'a, Formula>, usize), DefinitionExpansionError> {
        match &self.0 {
            FormulaRepresentation::Primitive(formula) => Ok((Cow::Borrowed(formula), 0)),
            FormulaRepresentation::Defined(formula) => formula
                .expand_with_node_limit(resolver, maximum_nodes)
                .map(|(formula, work)| (Cow::Owned(formula), work)),
        }
    }

    pub(crate) fn encode_canonical_with_node_limit(
        &self,
        maximum_nodes: usize,
    ) -> Result<(Vec<u8>, usize), ProofFormulaCodecError> {
        match &self.0 {
            FormulaRepresentation::Primitive(formula) => formula
                .encode_canonical_with_node_limit(maximum_nodes)
                .map_err(ProofFormulaCodecError::Primitive),
            FormulaRepresentation::Defined(formula) => formula
                .encode_canonical_with_node_limit(maximum_nodes)
                .map_err(ProofFormulaCodecError::Defined),
        }
    }

    pub(crate) fn decode_canonical_with_node_limit(
        bytes: &[u8],
        maximum_nodes: usize,
    ) -> Result<(Self, usize), ProofFormulaCodecError> {
        match Formula::decode_canonical_with_node_limit(bytes, maximum_nodes) {
            Ok((formula, nodes)) => Ok((Self(FormulaRepresentation::Primitive(formula)), nodes)),
            Err(FormulaCodecError::UnknownFormulaTag(0x05)) => {
                DefinedFormula::decode_canonical_with_node_limit(bytes, maximum_nodes)
                    .map(|(formula, nodes)| {
                        (
                            Self(FormulaRepresentation::Defined(Box::new(formula))),
                            nodes,
                        )
                    })
                    .map_err(ProofFormulaCodecError::Defined)
            }
            Err(source) => Err(ProofFormulaCodecError::Primitive(source)),
        }
    }
}

impl From<Formula> for ProofFormula {
    fn from(formula: Formula) -> Self {
        Self(FormulaRepresentation::Primitive(formula))
    }
}

impl TryFrom<DefinedFormula> for ProofFormula {
    type Error = DefinedFormulaCodecError;

    fn try_from(formula: DefinedFormula) -> Result<Self, Self::Error> {
        Self::from_defined(formula)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProofFormulaCodecError {
    Primitive(FormulaCodecError),
    Defined(DefinedFormulaCodecError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefinitionResolution;

    struct EmptyResolver;

    impl DefinitionResolver for EmptyResolver {
        fn resolve_definition(
            &self,
            _definition_id: DefinitionId,
        ) -> Option<DefinitionResolution<'_>> {
            None
        }
    }

    #[test]
    fn primitive_expansion_is_borrowed_and_charges_no_definition_work() {
        let formula = Formula::equal(FreeVariable::new(3), FreeVariable::new(3));
        let proof_formula = ProofFormula::from(formula);

        let (expanded, work) = proof_formula
            .expand_with_node_limit(&EmptyResolver, 0)
            .unwrap();

        assert!(matches!(expanded, Cow::Borrowed(_)));
        assert!(std::ptr::eq(
            expanded.as_ref(),
            proof_formula.as_primitive().unwrap()
        ));
        assert_eq!(work, 0);
    }

    #[test]
    fn construction_and_codec_round_trip_have_one_canonical_representation() {
        let variable = FreeVariable::new(4);
        let primitive = ProofFormula::from_defined(DefinedFormula::equal(variable, variable))
            .expect("a primitive DefinedFormula has a Foundation representation");
        assert!(primitive.as_primitive().is_some());
        assert!(primitive.as_defined().is_none());

        let definition_id = DefinitionId::from_bytes([0x42; 32]);
        let defined =
            ProofFormula::from_defined(DefinedFormula::defined_relation(definition_id, [variable]))
                .unwrap();
        assert!(defined.as_primitive().is_none());
        assert!(defined.as_defined().is_some());

        for formula in [primitive, defined] {
            let bytes = formula
                .encode_canonical_with_node_limit(usize::MAX)
                .unwrap()
                .0;
            let decoded = ProofFormula::decode_canonical_with_node_limit(&bytes, usize::MAX)
                .unwrap()
                .0;
            assert_eq!(decoded, formula);
        }
    }
}
