//! Canonically encoded, assumption-free proof programs for NAOME Foundation V0.
//!
//! A certificate records only primitive axiom witnesses and inference inputs.
//! It does not duplicate the formula derived by each step: the checker
//! reconstructs those formulas deterministically. Decoding establishes
//! canonical structure and acyclic local references, not mathematical validity.

mod codec;
mod normal_form;

use std::error::Error;
use std::fmt;

use naome_foundation::{
    Formula, FormulaCodecError, FreeVariable, Replacement, Separation, ZfcAxiom,
};

/// Maximum encoded length admitted for one V0 proof certificate.
pub const CERTIFICATE_V0_MAX_BYTES: usize = 4_194_304;

/// Maximum number of steps admitted in one V0 proof certificate.
pub const CERTIFICATE_V0_MAX_STEPS: usize = 65_536;

/// A canonically encoded, assumption-free Foundation V0 proof program.
///
/// The final step is the claimed conclusion. The checker reconstructs every
/// step and verifies the final formula is closed before admitting a proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofCertificateV0 {
    steps: Vec<ProofStepV0>,
}

impl ProofCertificateV0 {
    /// Constructs a structurally valid certificate.
    ///
    /// This checks that the certificate is non-empty, all values fit the wire
    /// format, every formula satisfies the V0 codec limits, and inference
    /// inputs refer strictly to earlier steps.
    pub fn new(steps: Vec<ProofStepV0>) -> Result<Self, ProofCertificateError> {
        validate_steps(&steps)?;
        let _ = codec::encode_steps(&steps)?;
        Ok(Self { steps })
    }

    /// Returns the proof steps in their encoded execution order.
    #[must_use]
    pub fn steps(&self) -> &[ProofStepV0] {
        &self.steps
    }

    /// Encodes this certificate in the canonical V0 wire format.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        codec::encode_steps(&self.steps)
            .expect("ProofCertificateV0 construction guarantees canonical encodability")
    }

    /// Decodes one complete canonical V0 certificate.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofCertificateError> {
        codec::decode(bytes)
    }

    /// Consumes this certificate and derives its unchecked root-proof normal form.
    ///
    /// The normal form removes unreachable steps, merges exact proof nodes,
    /// renumbers free variables by canonical first occurrence, and emits one
    /// deterministic dependency-first order. This transformation does not
    /// establish mathematical validity. Callers accepting arbitrary
    /// certificates should use the checker's safe check-and-normalize entry
    /// point rather than discarding the input first.
    pub fn into_unchecked_normal_form(self) -> ProofNormalFormV0 {
        ProofNormalFormV0 {
            certificate: normal_form::normalize(self),
        }
    }
}

/// A deterministic, root-reachable projection of one proof certificate.
///
/// This type establishes structural identity only. The mathematical checker
/// must still validate the contained certificate.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofNormalFormV0 {
    certificate: ProofCertificateV0,
}

impl ProofNormalFormV0 {
    /// Returns the canonical certificate carried by this normal form.
    pub const fn certificate(&self) -> &ProofCertificateV0 {
        &self.certificate
    }
}

/// One Foundation V0 axiom witness or primitive inference step.
///
/// Local step indices are zero-based. [`ProofCertificateV0`] admits an
/// inference step only when every referenced index is smaller than its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofStepV0 {
    /// L1: instantiate `A → (B → A)`.
    Simplification {
        antecedent: Formula,
        consequent: Formula,
    },
    /// L2: instantiate the Frege implication schema.
    Frege {
        first: Formula,
        second: Formula,
        third: Formula,
    },
    /// L3: instantiate classical contraposition.
    ClassicalContraposition {
        antecedent: Formula,
        consequent: Formula,
    },
    /// Q1: instantiate universal distribution.
    UniversalDistribution {
        variable: FreeVariable,
        antecedent: Formula,
        consequent: Formula,
    },
    /// Q2: claim a vacuous universal instance.
    ///
    /// The unused binder is nameless, so the certificate stores no redundant
    /// free-variable identifier for it.
    VacuousUniversal { formula: Formula },
    /// Q3: instantiate universal elimination with a free replacement variable.
    UniversalInstantiation {
        variable: FreeVariable,
        replacement: FreeVariable,
        body: Formula,
    },
    /// E1: instantiate equality reflexivity.
    EqualityReflexivity { variable: FreeVariable },
    /// E2: instantiate equality substitution.
    EqualitySubstitution {
        from: FreeVariable,
        to: FreeVariable,
        body: Formula,
    },
    /// Use one of the seven fixed ZFC axioms.
    ZfcAxiom(ZfcAxiom),
    /// Claim an instance of the Separation schema.
    Separation(Separation),
    /// Claim an instance of the Replacement schema.
    Replacement(Replacement),
    /// Derive a consequent from earlier `A` and `A → B` steps.
    ModusPonens { premise: u32, implication: u32 },
    /// Universally quantify a selected free variable in an earlier step.
    Generalization {
        premise: u32,
        variable: FreeVariable,
    },
}

impl ProofStepV0 {
    /// Returns local step references in their rule-role order.
    ///
    /// Modus ponens returns premise then implication. Generalization returns
    /// only its premise. All other V0 steps carry no local references.
    #[must_use]
    pub const fn local_references(&self) -> [Option<u32>; 2] {
        match self {
            Self::ModusPonens {
                premise,
                implication,
            } => [Some(*premise), Some(*implication)],
            Self::Generalization { premise, .. } => [Some(*premise), None],
            Self::Simplification { .. }
            | Self::Frege { .. }
            | Self::ClassicalContraposition { .. }
            | Self::UniversalDistribution { .. }
            | Self::VacuousUniversal { .. }
            | Self::UniversalInstantiation { .. }
            | Self::EqualityReflexivity { .. }
            | Self::EqualitySubstitution { .. }
            | Self::ZfcAxiom(_)
            | Self::Separation(_)
            | Self::Replacement(_) => [None, None],
        }
    }
}

fn validate_steps(steps: &[ProofStepV0]) -> Result<(), ProofCertificateError> {
    if steps.is_empty() {
        return Err(ProofCertificateError::EmptyCertificate);
    }

    if steps.len() > CERTIFICATE_V0_MAX_STEPS {
        return Err(ProofCertificateError::TooManySteps {
            actual: steps.len(),
            maximum: CERTIFICATE_V0_MAX_STEPS,
        });
    }

    for (position, step) in steps.iter().enumerate() {
        let position = u32::try_from(position).expect("the step count was checked above");
        validate_step_references(position, step)?;
    }

    Ok(())
}

fn validate_step_references(
    position: u32,
    step: &ProofStepV0,
) -> Result<(), ProofCertificateError> {
    for reference in step.local_references().into_iter().flatten() {
        validate_reference(position, reference)?;
    }

    Ok(())
}

fn validate_reference(step: u32, reference: u32) -> Result<(), ProofCertificateError> {
    if reference >= step {
        return Err(ProofCertificateError::ReferenceNotEarlier { step, reference });
    }

    Ok(())
}

/// A structural or canonical-encoding failure for Proof Certificate V0.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofCertificateError {
    /// A certificate must contain a claimed conclusion step.
    EmptyCertificate,
    /// The certificate exceeds the deterministic V0 step limit.
    TooManySteps { actual: usize, maximum: usize },
    /// The encoded certificate exceeds the deterministic V0 processing limit.
    InputTooLong { actual: usize, maximum: usize },
    /// A local inference input is not strictly earlier than its consumer.
    ReferenceNotEarlier { step: u32, reference: u32 },
    /// The encoded certificate selects an unsupported format version.
    UnsupportedVersion(u8),
    /// The encoded certificate ends before the selected value is complete.
    UnexpectedEnd,
    /// The encoded certificate uses an unknown proof-step tag.
    UnknownStepTag(u8),
    /// The encoded certificate uses an unknown fixed-ZFC-axiom tag.
    UnknownZfcAxiomTag(u8),
    /// A canonical formula inside the certificate is malformed or unsupported.
    Formula(FormulaCodecError),
    /// A complete certificate is followed by additional bytes.
    TrailingBytes { remaining: usize },
}

impl fmt::Display for ProofCertificateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCertificate => formatter.write_str("proof certificate has no steps"),
            Self::TooManySteps { actual, maximum } => write!(
                formatter,
                "proof certificate has {actual} steps; the V0 limit is {maximum}"
            ),
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "proof certificate has {actual} bytes; the V0 limit is {maximum}"
            ),
            Self::ReferenceNotEarlier { step, reference } => write!(
                formatter,
                "step {step} references non-earlier step {reference}"
            ),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported proof certificate version {version}")
            }
            Self::UnexpectedEnd => formatter.write_str("proof certificate ended unexpectedly"),
            Self::UnknownStepTag(tag) => {
                write!(formatter, "unknown proof-step tag 0x{tag:02x}")
            }
            Self::UnknownZfcAxiomTag(tag) => {
                write!(formatter, "unknown fixed-ZFC-axiom tag 0x{tag:02x}")
            }
            Self::Formula(error) => write!(formatter, "invalid canonical formula: {error}"),
            Self::TrailingBytes { remaining } => {
                write!(
                    formatter,
                    "proof certificate has {remaining} trailing bytes"
                )
            }
        }
    }
}

impl Error for ProofCertificateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Formula(error) => Some(error),
            _ => None,
        }
    }
}

impl From<FormulaCodecError> for ProofCertificateError {
    fn from(error: FormulaCodecError) -> Self {
        Self::Formula(error)
    }
}

#[cfg(test)]
mod tests {
    use super::{CERTIFICATE_V0_MAX_BYTES, ProofCertificateError, ProofCertificateV0, ProofStepV0};
    use naome_foundation::{
        FORMULA_V0_MAX_DEPTH, Formula, FormulaCodecError, FreeVariable, Separation,
    };

    #[test]
    fn certificate_requires_a_conclusion_step() {
        assert_eq!(
            ProofCertificateV0::new(Vec::new()),
            Err(ProofCertificateError::EmptyCertificate)
        );
    }

    #[test]
    fn certificate_rejects_self_and_forward_references() {
        let x = FreeVariable::new(1);

        assert_eq!(
            ProofCertificateV0::new(vec![ProofStepV0::Generalization {
                premise: 0,
                variable: x,
            }]),
            Err(ProofCertificateError::ReferenceNotEarlier {
                step: 0,
                reference: 0,
            })
        );

        assert_eq!(
            ProofCertificateV0::new(vec![
                ProofStepV0::EqualityReflexivity { variable: x },
                ProofStepV0::Generalization {
                    premise: 2,
                    variable: x,
                },
            ]),
            Err(ProofCertificateError::ReferenceNotEarlier {
                step: 1,
                reference: 2,
            })
        );
    }

    #[test]
    fn certificate_accepts_only_earlier_local_references() {
        let x = FreeVariable::new(1);
        let certificate = ProofCertificateV0::new(vec![
            ProofStepV0::EqualityReflexivity { variable: x },
            ProofStepV0::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap();

        assert_eq!(certificate.steps().len(), 2);
    }

    #[test]
    fn certificate_constructor_enforces_formula_codec_limits() {
        let x = FreeVariable::new(1);
        let mut oversized = Formula::equal(x, x);
        for _ in 0..FORMULA_V0_MAX_DEPTH {
            oversized = Formula::negate(oversized);
        }

        assert_eq!(
            ProofCertificateV0::new(vec![ProofStepV0::VacuousUniversal { formula: oversized }]),
            Err(ProofCertificateError::Formula(
                FormulaCodecError::DepthLimitExceeded {
                    maximum: FORMULA_V0_MAX_DEPTH,
                }
            ))
        );
    }

    #[test]
    fn certificate_constructor_enforces_the_total_byte_limit() {
        let element = FreeVariable::new(1);
        let source = FreeVariable::new(2);
        let result_variable = FreeVariable::new(3);
        let parameter = FreeVariable::new(4);
        let parameters = vec![parameter; CERTIFICATE_V0_MAX_BYTES / 4 + 1];

        let construction = ProofCertificateV0::new(vec![ProofStepV0::Separation(Separation {
            predicate: Formula::member(element, source),
            element,
            source,
            result: result_variable,
            parameters,
        })]);

        assert!(matches!(
            construction,
            Err(ProofCertificateError::InputTooLong {
                maximum: CERTIFICATE_V0_MAX_BYTES,
                ..
            })
        ));
    }
}
