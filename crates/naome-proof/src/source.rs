//! Derived descriptions of actual certificate constructors, never inference.
use crate::{ProofFormula, ProofStep};

fn formula(value: &ProofFormula) -> Result<String, String> {
    value
        .as_primitive()
        .map(|f| f.to_controlled_english())
        .ok_or_else(|| "controlled English requires an actual primitive formula".into())
}

impl ProofStep {
    /// Describes this exact constructor and every field. The description does
    /// not compute a step's checked consequence or confer validity.
    pub fn to_controlled_english(&self) -> Result<String, String> {
        Ok(match self {
            Self::Simplification {
                antecedent,
                consequent,
            } => format!(
                "Logical simplification instance; A: ({}); B: ({}).",
                formula(antecedent)?,
                formula(consequent)?
            ),
            Self::Frege {
                first,
                second,
                third,
            } => format!(
                "Frege implication instance; A: ({}); B: ({}); C: ({}).",
                formula(first)?,
                formula(second)?,
                formula(third)?
            ),
            Self::ClassicalContraposition {
                antecedent,
                consequent,
            } => format!(
                "Classical contraposition instance; A: ({}); B: ({}).",
                formula(antecedent)?,
                formula(consequent)?
            ),
            Self::UniversalDistribution {
                variable,
                antecedent,
                consequent,
            } => format!(
                "Universal distribution over free variable f{}; A: ({}); B: ({}).",
                variable.identifier(),
                formula(antecedent)?,
                formula(consequent)?
            ),
            Self::VacuousUniversal { formula: body } => format!(
                "Vacuous universal quantifier instance; body: ({}).",
                formula(body)?
            ),
            Self::UniversalInstantiation {
                variable,
                replacement,
                body,
            } => format!(
                "Universal instantiation of free variable f{} with f{}; body before substitution: ({}).",
                variable.identifier(),
                replacement.identifier(),
                formula(body)?
            ),
            Self::EqualityReflexivity { variable } => format!(
                "Equality reflexivity instance: free variable f{} equals f{}.",
                variable.identifier(),
                variable.identifier()
            ),
            Self::EqualitySubstitution { from, to, body } => format!(
                "Equality substitution instance from free variable f{} to f{}; body before substitution: ({}).",
                from.identifier(),
                to.identifier(),
                formula(body)?
            ),
            Self::ZfcAxiom(axiom) => format!(
                "Fixed ZFC axiom constructor {axiom:?}; exact primitive formula: ({}).",
                axiom.formula().to_controlled_english()
            ),
            Self::Separation(payload) => format!(
                "Separation schema instance; candidate element f{}; source set f{}; fresh result set f{}; ordered additional free-variable IDs {:?}; predicate: ({}).",
                payload.element.identifier(),
                payload.source.identifier(),
                payload.result.identifier(),
                payload
                    .parameters
                    .iter()
                    .map(|v| v.identifier())
                    .collect::<Vec<_>>(),
                formula(&payload.predicate)?
            ),
            Self::Replacement(payload) => format!(
                "Replacement schema instance, conditional on the relation being total and single-valued on the source set (for every member of source, exactly one related output); input f{}; output f{}; fresh uniqueness witness f{}; source set f{}; fresh result set f{}; ordered additional free-variable IDs {:?}; relation predicate: ({}).",
                payload.input.identifier(),
                payload.output.identifier(),
                payload.uniqueness_witness.identifier(),
                payload.source.identifier(),
                payload.result.identifier(),
                payload
                    .parameters
                    .iter()
                    .map(|v| v.identifier())
                    .collect::<Vec<_>>(),
                formula(&payload.predicate)?
            ),
            Self::ProofReference { proof_id } => format!(
                "Citation of the concrete proof cite(\"{}\"); this constructor contains its identity, not its conclusion.",
                proof_id
                    .as_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ),
            Self::ModusPonens {
                premise,
                implication,
            } => format!(
                "Modus ponens using earlier normalized premise step {premise} and implication step {implication}."
            ),
            Self::Generalization { premise, variable } => format!(
                "Universal generalization of free variable f{} over earlier normalized premise step {premise}.",
                variable.identifier()
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProofCertificate, ProofId, ProofReplacement};
    use naome_foundation::{Formula, FreeVariable};

    #[test]
    fn descriptions_preserve_certificate_bytes_and_distinguish_actual_operands() {
        let x = FreeVariable::new(7);
        let y = FreeVariable::new(8);
        let first = ProofStep::EqualitySubstitution {
            from: x,
            to: y,
            body: Formula::member(x, y).into(),
        };
        let second = ProofStep::EqualitySubstitution {
            from: y,
            to: x,
            body: Formula::member(x, y).into(),
        };
        let certificate = ProofCertificate::new(vec![first.clone()]).unwrap();
        let bytes = certificate.to_canonical_bytes();
        assert_ne!(
            first.to_controlled_english().unwrap(),
            second.to_controlled_english().unwrap()
        );
        assert!(
            first
                .to_controlled_english()
                .unwrap()
                .contains("f7 is an element of f8")
        );
        assert_eq!(certificate.to_canonical_bytes(), bytes);
        let mut replacement = ProofReplacement {
            predicate: Formula::equal(x, y).into(),
            input: x,
            output: y,
            uniqueness_witness: FreeVariable::new(9),
            source: FreeVariable::new(10),
            result: FreeVariable::new(11),
            parameters: vec![FreeVariable::new(13), FreeVariable::new(12)],
        };
        let original = ProofStep::Replacement(replacement.clone())
            .to_controlled_english()
            .unwrap();
        assert!(original.contains("conditional"));
        assert!(original.contains("for every member of source, exactly one related output"));
        assert!(original.contains("fresh uniqueness witness f9"));
        replacement.uniqueness_witness = FreeVariable::new(14);
        assert_ne!(
            ProofStep::Replacement(replacement.clone())
                .to_controlled_english()
                .unwrap(),
            original
        );
        replacement.parameters.reverse();
        assert!(
            ProofStep::Replacement(replacement)
                .to_controlled_english()
                .unwrap()
                .contains("[12, 13]")
        );
        let citation = ProofStep::ProofReference {
            proof_id: ProofId::from_bytes([0xab; 32]),
        }
        .to_controlled_english()
        .unwrap();
        assert!(citation.contains(&format!("cite(\"{}\")", "ab".repeat(32))));
        assert!(citation.contains("not its conclusion"));
    }
}
