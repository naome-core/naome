//! Canonically encoded, assumption-free proof programs for NAOME Foundation.
//!
//! A certificate records primitive axiom witnesses, inference inputs, and
//! concrete external proof identities. It does not duplicate the formula
//! derived by each step: the checker reconstructs those formulas
//! deterministically. Decoding establishes canonical structure and acyclic
//! local references, not mathematical validity or external-proof existence.

mod codec;
mod identity;
mod normal_form;

use std::error::Error;
use std::fmt;
use std::sync::OnceLock;

use naome_foundation::{
    Formula, FormulaCodecError, FreeVariable, Replacement, Separation, ZfcAxiom,
};

pub use identity::{DerivationId, ProofId, StatementId};

/// Maximum encoded length admitted for one proof certificate.
pub const CERTIFICATE_MAX_BYTES: usize = 4_194_304;

/// Maximum number of steps admitted in one proof certificate.
pub const CERTIFICATE_MAX_STEPS: usize = 65_536;

const SIMPLIFICATION: u8 = 0x00;
const FREGE: u8 = 0x01;
const CLASSICAL_CONTRAPOSITION: u8 = 0x02;
const UNIVERSAL_DISTRIBUTION: u8 = 0x03;
const VACUOUS_UNIVERSAL: u8 = 0x04;
const UNIVERSAL_INSTANTIATION: u8 = 0x05;
const EQUALITY_REFLEXIVITY: u8 = 0x06;
const EQUALITY_SUBSTITUTION: u8 = 0x07;
const ZFC_AXIOM: u8 = 0x10;
const SEPARATION: u8 = 0x11;
const REPLACEMENT: u8 = 0x12;
const MODUS_PONENS: u8 = 0x20;
const GENERALIZATION: u8 = 0x21;
const PROOF_REFERENCE: u8 = 0x30;

/// A canonically encoded, assumption-free Foundation proof program.
///
/// The final step is the root and claimed conclusion. A certificate may carry
/// structurally valid duplicate or unreachable presentation steps; proof
/// admission operates on its [`ProofNormalForm`].
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofCertificate {
    steps: Vec<ProofStep>,
}

impl ProofCertificate {
    /// Constructs a structurally valid certificate.
    ///
    /// This checks that the certificate is non-empty, all values fit the wire
    /// format, every formula satisfies the codec limits, and inference
    /// inputs refer strictly to earlier steps.
    pub fn new(steps: Vec<ProofStep>) -> Result<Self, ProofCertificateError> {
        validate_steps(&steps)?;
        let _ = codec::encode_steps(&steps)?;
        Ok(Self { steps })
    }

    /// Returns the proof steps in their encoded execution order.
    #[must_use]
    pub fn steps(&self) -> &[ProofStep] {
        &self.steps
    }

    /// Encodes this certificate in the canonical wire format.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        codec::encode_steps(&self.steps)
            .expect("ProofCertificate construction guarantees canonical encodability")
    }

    /// Decodes one complete canonical certificate.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofCertificateError> {
        codec::decode(bytes)
    }

    /// Consumes this certificate and derives its unchecked root-proof normal form.
    ///
    /// The normal form removes unreachable steps, merges exact proof nodes,
    /// renumbers free variables by canonical first occurrence, and emits one
    /// deterministic dependency-first order. This transformation does not
    /// establish mathematical validity; the checker must validate the
    /// resulting normal-form certificate.
    pub fn into_unchecked_normal_form(self) -> ProofNormalForm {
        ProofNormalForm {
            certificate: normal_form::normalize(self),
            canonical_bytes: OnceLock::new(),
        }
    }
}

/// A deterministic, root-reachable projection of one proof certificate.
///
/// This type establishes structural identity only. The mathematical checker
/// must still validate the contained certificate.
#[must_use]
pub struct ProofNormalForm {
    certificate: ProofCertificate,
    canonical_bytes: OnceLock<Box<[u8]>>,
}

impl ProofNormalForm {
    /// Returns the canonical certificate carried by this normal form.
    pub const fn certificate(&self) -> &ProofCertificate {
        &self.certificate
    }

    /// Returns the canonical bytes of this normal-form certificate.
    pub fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes
            .get_or_init(|| self.certificate.to_canonical_bytes().into_boxed_slice())
    }

    /// Reuses a supplied byte buffer when it exactly encodes this normal form.
    ///
    /// Returns `None` when the bytes differ. Equality is established against
    /// this normal form's independently derived canonical encoding before the
    /// supplied bytes can become identity-bearing content.
    #[must_use]
    pub fn with_matching_canonical_bytes(mut self, canonical_bytes: Box<[u8]>) -> Option<Self> {
        let matches = match self.canonical_bytes.get() {
            Some(expected) => expected.as_ref() == canonical_bytes.as_ref(),
            None => self.certificate.to_canonical_bytes().as_slice() == canonical_bytes.as_ref(),
        };
        if !matches {
            return None;
        }
        self.canonical_bytes = OnceLock::from(canonical_bytes);
        Some(self)
    }

    /// Consumes this normal form and returns its canonical certificate bytes.
    #[must_use]
    pub fn into_canonical_bytes(self) -> Box<[u8]> {
        let Self {
            certificate,
            canonical_bytes,
        } = self;
        canonical_bytes
            .into_inner()
            .unwrap_or_else(|| certificate.to_canonical_bytes().into_boxed_slice())
    }
}

impl PartialEq for ProofNormalForm {
    fn eq(&self, other: &Self) -> bool {
        self.certificate == other.certificate
    }
}

impl Eq for ProofNormalForm {}

impl fmt::Debug for ProofNormalForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofNormalForm")
            .field("certificate", &self.certificate)
            .finish()
    }
}

/// One Foundation axiom witness, primitive inference, or proof-reference step.
///
/// Local step indices are zero-based. [`ProofCertificate`] admits an
/// inference step only when every referenced index is smaller than its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofStep {
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
    /// Reuse the checked conclusion of one concrete registered proof.
    ProofReference { proof_id: ProofId },
    /// Derive a consequent from earlier `A` and `A → B` steps.
    ModusPonens { premise: u32, implication: u32 },
    /// Universally quantify a selected free variable in an earlier step.
    Generalization {
        premise: u32,
        variable: FreeVariable,
    },
}

impl ProofStep {
    /// Returns this step's one-byte canonical wire tag.
    #[must_use]
    pub const fn canonical_tag(&self) -> u8 {
        match self {
            Self::Simplification { .. } => SIMPLIFICATION,
            Self::Frege { .. } => FREGE,
            Self::ClassicalContraposition { .. } => CLASSICAL_CONTRAPOSITION,
            Self::UniversalDistribution { .. } => UNIVERSAL_DISTRIBUTION,
            Self::VacuousUniversal { .. } => VACUOUS_UNIVERSAL,
            Self::UniversalInstantiation { .. } => UNIVERSAL_INSTANTIATION,
            Self::EqualityReflexivity { .. } => EQUALITY_REFLEXIVITY,
            Self::EqualitySubstitution { .. } => EQUALITY_SUBSTITUTION,
            Self::ZfcAxiom(_) => ZFC_AXIOM,
            Self::Separation(_) => SEPARATION,
            Self::Replacement(_) => REPLACEMENT,
            Self::ModusPonens { .. } => MODUS_PONENS,
            Self::Generalization { .. } => GENERALIZATION,
            Self::ProofReference { .. } => PROOF_REFERENCE,
        }
    }

    /// Returns local step references in their rule-role order.
    ///
    /// Modus ponens returns premise then implication. Generalization returns
    /// only its premise. All other steps carry no local references.
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
            | Self::Replacement(_)
            | Self::ProofReference { .. } => [None, None],
        }
    }
}

fn validate_steps(steps: &[ProofStep]) -> Result<(), ProofCertificateError> {
    if steps.is_empty() {
        return Err(ProofCertificateError::EmptyCertificate);
    }

    if steps.len() > CERTIFICATE_MAX_STEPS {
        return Err(ProofCertificateError::TooManySteps {
            actual: steps.len(),
            maximum: CERTIFICATE_MAX_STEPS,
        });
    }

    for (position, step) in steps.iter().enumerate() {
        let position = u32::try_from(position).expect("the step count was checked above");
        validate_step_references(position, step)?;
    }

    Ok(())
}

fn validate_step_references(position: u32, step: &ProofStep) -> Result<(), ProofCertificateError> {
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

/// A structural or canonical-encoding failure for Proof Certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofCertificateError {
    /// A certificate must contain a claimed conclusion step.
    EmptyCertificate,
    /// The certificate exceeds the deterministic step limit.
    TooManySteps { actual: usize, maximum: usize },
    /// The encoded certificate exceeds the deterministic processing limit.
    InputTooLong { actual: usize, maximum: usize },
    /// A local inference input is not strictly earlier than its consumer.
    ReferenceNotEarlier { step: u32, reference: u32 },
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
                "proof certificate has {actual} steps; the limit is {maximum}"
            ),
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "proof certificate has {actual} bytes; the limit is {maximum}"
            ),
            Self::ReferenceNotEarlier { step, reference } => write!(
                formatter,
                "step {step} references non-earlier step {reference}"
            ),
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
    use super::{CERTIFICATE_MAX_BYTES, ProofCertificate, ProofCertificateError, ProofStep};
    use naome_foundation::{
        FORMULA_MAX_DEPTH, Formula, FormulaCodecError, FreeVariable, Separation,
    };

    #[test]
    fn certificate_requires_a_conclusion_step() {
        assert_eq!(
            ProofCertificate::new(Vec::new()),
            Err(ProofCertificateError::EmptyCertificate)
        );
    }

    #[test]
    fn certificate_rejects_self_and_forward_references() {
        let x = FreeVariable::new(1);

        assert_eq!(
            ProofCertificate::new(vec![ProofStep::Generalization {
                premise: 0,
                variable: x,
            }]),
            Err(ProofCertificateError::ReferenceNotEarlier {
                step: 0,
                reference: 0,
            })
        );

        assert_eq!(
            ProofCertificate::new(vec![
                ProofStep::EqualityReflexivity { variable: x },
                ProofStep::Generalization {
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
        let certificate = ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
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
        for _ in 0..FORMULA_MAX_DEPTH {
            oversized = Formula::negate(oversized);
        }

        assert_eq!(
            ProofCertificate::new(vec![ProofStep::VacuousUniversal { formula: oversized }]),
            Err(ProofCertificateError::Formula(
                FormulaCodecError::DepthLimitExceeded {
                    maximum: FORMULA_MAX_DEPTH,
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
        let parameters = vec![parameter; CERTIFICATE_MAX_BYTES / 4 + 1];

        let construction = ProofCertificate::new(vec![ProofStep::Separation(Separation {
            predicate: Formula::member(element, source),
            element,
            source,
            result: result_variable,
            parameters,
        })]);

        assert!(matches!(
            construction,
            Err(ProofCertificateError::InputTooLong {
                maximum: CERTIFICATE_MAX_BYTES,
                ..
            })
        ));
    }
}
