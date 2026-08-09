//! Deterministic mathematical checking for Foundation proof certificates.
//!
//! The checker reconstructs every certificate step through the executable
//! Foundation rules, enforces deterministic formula-processing limits, and
//! accepts only a closed final formula. External proof references resolve only
//! through an explicitly supplied, already checked [`ProofState`]. The crate
//! remains deliberately in-memory and has no blocks, persistence, networking,
//! or source parsing.
//! Successful proof admission returns a [`CheckedProof`] that keeps the
//! accepted normal form, reconstructed conclusion, and content identities
//! coupled together.

mod state;

use std::error::Error;
use std::fmt;

use naome_foundation::{
    FORMULA_MAX_DEPTH, FOUNDATION_ID, Formula, FormulaCodecError, Logic, LogicError, SchemaError,
};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, DerivationId, ProofCertificate, ProofId, ProofNormalForm, ProofStep,
    StatementId,
};
use sha2::{Digest, Sha256};

pub use state::{ProofState, ProofStateError};

const STATEMENT_ID_DOMAIN: &[u8] = b"naome:statement\0";
const PROOF_ID_DOMAIN: &[u8] = b"naome:proof\0";
const DERIVATION_NODE_ID_DOMAIN: &[u8] = b"naome:derivation-node\0";

/// Maximum cumulative canonical formula work admitted by Checker.
///
/// Each reconstructed result is charged once. Formulas referenced by modus
/// ponens or generalization are charged before executing that rule, and the
/// conclusion is charged once more before checking closure. This value matches
/// the maximum encoded certificate length and provides one deterministic bound
/// for retained formulas and repeated inference work.
pub const CHECKER_MAX_FORMULA_WORK_BYTES: usize = CERTIFICATE_MAX_BYTES;

/// A normalized Foundation proof accepted by Checker.
///
/// The private fields keep the accepted normal form coupled to the exact
/// closed conclusion and content identities reconstructed from it. Those
/// identities are content addresses; this type does not establish block
/// admission or chain inclusion.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CheckedProof {
    normal_form: ProofNormalForm,
    conclusion: Formula,
    statement_id: StatementId,
    derivation_id: DerivationId,
    proof_id: ProofId,
    canonical_conclusion_length: usize,
}

impl CheckedProof {
    /// Returns the checked proof's canonical normal form.
    pub const fn normal_form(&self) -> &ProofNormalForm {
        &self.normal_form
    }

    /// Returns the closed conclusion reconstructed by Checker.
    pub const fn conclusion(&self) -> &Formula {
        &self.conclusion
    }

    /// Returns the identity of the checked proof's closed conclusion.
    pub const fn statement_id(&self) -> StatementId {
        self.statement_id
    }

    /// Returns the reference-transparent identity of the checked inference DAG.
    pub const fn derivation_id(&self) -> DerivationId {
        self.derivation_id
    }

    /// Returns the identity of the checked proof's canonical normal form.
    pub const fn proof_id(&self) -> ProofId {
        self.proof_id
    }
}

/// Checks one structurally valid Foundation proof certificate.
///
/// Every step is reconstructed in order, including unused or duplicate steps.
/// External proof references fail because this low-level entry point has no
/// checked state. On success, the returned formula is the certificate's closed
/// conclusion.
pub fn check(certificate: &ProofCertificate) -> Result<Formula, CheckError> {
    check_with_canonical_conclusion(
        certificate,
        &ProofState::new(),
        IdentityMode::OmitDerivation,
    )
    .map(|(conclusion, _, _)| conclusion)
}

fn check_with_canonical_conclusion(
    certificate: &ProofCertificate,
    proof_state: &ProofState,
    identity_mode: IdentityMode,
) -> Result<(Formula, Vec<u8>, Option<DerivationId>), CheckError> {
    let steps = certificate.steps();
    let final_step = u32::try_from(steps.len() - 1)
        .expect("ProofCertificate is non-empty and has a bounded step count");
    let last_uses = last_uses(steps);
    let mut results: Vec<Option<CheckedStep>> = Vec::with_capacity(steps.len());
    let mut derivation_ids =
        matches!(identity_mode, IdentityMode::Derive).then(|| Vec::with_capacity(steps.len()));
    let mut remaining_work = CHECKER_MAX_FORMULA_WORK_BYTES;
    let mut canonical_conclusion = None;

    for (position, step) in steps.iter().enumerate() {
        let position = u32::try_from(position)
            .expect("ProofCertificate limits make every step index representable");

        let DerivedStep {
            formula,
            precharged_length,
            referenced_derivation_id,
        } = derive_step(position, step, &results, proof_state, &mut remaining_work)?;
        let derivation_inputs = derivation_ids
            .as_deref()
            .map(|derivation_ids| derivation_inputs(step, derivation_ids));
        for reference in step.local_references().into_iter().flatten() {
            let reference = reference as usize;
            if last_uses[reference] == Some(position) {
                results[reference] = None;
            }
        }

        let canonical = (precharged_length.is_none() || position == final_step)
            .then(|| {
                let canonical = match identity_mode {
                    IdentityMode::OmitDerivation => formula.encode_canonical(),
                    IdentityMode::Derive => formula.encode_free_variable_normalized(),
                };
                canonical.map_err(|source| CheckError::DerivedFormula {
                    step: position,
                    source,
                })
            })
            .transpose()?;
        let canonical_length = match precharged_length {
            Some(length) => length,
            None => {
                let length = canonical
                    .as_ref()
                    .expect("an uncharged formula was canonically encoded")
                    .len();
                charge_formula_work(position, length, &mut remaining_work)?;
                length
            }
        };
        if let Some(derivation_ids) = &mut derivation_ids {
            let derivation_id = referenced_derivation_id.unwrap_or_else(|| {
                derivation_id(
                    step,
                    canonical
                        .as_deref()
                        .expect("every local derivation node has canonical result bytes"),
                    derivation_inputs.expect("derivation mode collects parent identities"),
                )
            });
            derivation_ids.push(derivation_id);
        }
        if position == final_step {
            canonical_conclusion = canonical;
        }
        let retain = position == final_step || last_uses[position as usize].is_some();
        results.push(retain.then_some(CheckedStep {
            formula,
            canonical_length,
        }));
    }

    let CheckedStep {
        formula: conclusion,
        canonical_length,
    } = results
        .pop()
        .flatten()
        .expect("every ProofCertificate has at least one reconstructed step");
    charge_formula_work(final_step, canonical_length, &mut remaining_work)?;

    if !conclusion.is_closed() {
        return Err(CheckError::OpenConclusion { step: final_step });
    }

    Ok((
        conclusion,
        canonical_conclusion.expect("the final step always has a canonical encoding"),
        derivation_ids.and_then(|derivation_ids| derivation_ids.last().copied()),
    ))
}

#[derive(Clone, Copy)]
enum IdentityMode {
    OmitDerivation,
    Derive,
}

/// Normalizes one certificate and checks its canonical proof exactly once.
///
/// Unreachable input steps are not part of the root proof and are removed
/// before mathematical checking. Reachable steps are checked in their
/// deterministic normal-form order. On success, the returned value keeps that
/// exact normal form coupled to the closed conclusion and content identities
/// reconstructed from it. External proof references fail; use
/// [`normalize_and_check_with_state`] when references are expected.
pub fn normalize_and_check(certificate: ProofCertificate) -> Result<CheckedProof, CheckError> {
    normalize_and_check_with_state(certificate, &ProofState::new())
}

/// Normalizes and checks one proof against an immutable checked-proof state.
///
/// Only root-reachable references are resolved. Every requested [`ProofId`]
/// must already be present in `proof_state`; the state is never mutated during
/// checking. On success, the returned proof may be registered afterward.
pub fn normalize_and_check_with_state(
    certificate: ProofCertificate,
    proof_state: &ProofState,
) -> Result<CheckedProof, CheckError> {
    let normal_form = certificate.into_unchecked_normal_form();
    check_normal_form_with_state(normal_form, proof_state)
}

/// Checks one canonical proof normal form against an immutable checked-proof state.
///
/// Unlike [`normalize_and_check_with_state`], this entry point performs no
/// normalization. The [`ProofNormalForm`] type guarantees the structural
/// root-proof projection; this function establishes its mathematical validity
/// and content identities exactly once.
pub fn check_normal_form_with_state(
    normal_form: ProofNormalForm,
    proof_state: &ProofState,
) -> Result<CheckedProof, CheckError> {
    let (conclusion, canonical_conclusion, derivation_id) = check_with_canonical_conclusion(
        normal_form.certificate(),
        proof_state,
        IdentityMode::Derive,
    )?;
    let derivation_id =
        derivation_id.expect("derivation mode computes the final derivation identity");
    let canonical_conclusion_length = canonical_conclusion.len();
    let statement_id = statement_id(&canonical_conclusion);
    drop(canonical_conclusion);
    let proof_id = proof_id(statement_id, &normal_form);
    Ok(CheckedProof {
        normal_form,
        conclusion,
        statement_id,
        derivation_id,
        proof_id,
        canonical_conclusion_length,
    })
}

fn derivation_id(
    step: &ProofStep,
    canonical_result: &[u8],
    inputs: [Option<DerivationId>; 2],
) -> DerivationId {
    let mut hasher = Sha256::new();
    hasher.update(DERIVATION_NODE_ID_DOMAIN);
    update_framed(&mut hasher, FOUNDATION_ID.as_bytes());
    hasher.update([step.canonical_tag()]);
    update_framed(&mut hasher, canonical_result);
    for input in inputs.into_iter().flatten() {
        hasher.update(input.as_bytes());
    }
    DerivationId::from_bytes(hasher.finalize().into())
}

fn statement_id(canonical_conclusion: &[u8]) -> StatementId {
    StatementId::from_bytes(foundation_scoped_hash(
        STATEMENT_ID_DOMAIN,
        &[],
        canonical_conclusion,
    ))
}

fn proof_id(statement_id: StatementId, normal_form: &ProofNormalForm) -> ProofId {
    ProofId::from_bytes(foundation_scoped_hash(
        PROOF_ID_DOMAIN,
        statement_id.as_bytes(),
        normal_form.canonical_bytes(),
    ))
}

fn foundation_scoped_hash(domain: &[u8], binding: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_framed(&mut hasher, FOUNDATION_ID.as_bytes());
    hasher.update(binding);
    update_framed(&mut hasher, payload);
    hasher.finalize().into()
}

fn update_framed(hasher: &mut Sha256, bytes: &[u8]) {
    let length =
        u32::try_from(bytes.len()).expect("Foundation identifiers and canonical payloads fit u32");
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

fn last_uses(steps: &[ProofStep]) -> Vec<Option<u32>> {
    let mut last_uses = vec![None; steps.len()];

    for (position, step) in steps.iter().enumerate() {
        let position = u32::try_from(position)
            .expect("ProofCertificate limits make every step index representable");
        for reference in step.local_references().into_iter().flatten() {
            last_uses[reference as usize] = Some(position);
        }
    }

    last_uses
}

fn preflight_schema_depth(step: u32, parameter_count: usize) -> Result<(), CheckError> {
    if parameter_count >= FORMULA_MAX_DEPTH as usize {
        return Err(CheckError::DerivedFormula {
            step,
            source: FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            },
        });
    }

    Ok(())
}

fn derive_step(
    step: u32,
    proof_step: &ProofStep,
    results: &[Option<CheckedStep>],
    proof_state: &ProofState,
    remaining_work: &mut usize,
) -> Result<DerivedStep, CheckError> {
    let formula = match proof_step {
        ProofStep::Simplification {
            antecedent,
            consequent,
        } => Logic::simplification(antecedent.clone(), consequent.clone()),
        ProofStep::Frege {
            first,
            second,
            third,
        } => Logic::frege(first.clone(), second.clone(), third.clone()),
        ProofStep::ClassicalContraposition {
            antecedent,
            consequent,
        } => Logic::classical_contraposition(antecedent.clone(), consequent.clone()),
        ProofStep::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => Logic::universal_distribution(*variable, antecedent.clone(), consequent.clone()),
        ProofStep::VacuousUniversal { formula } => Logic::vacuous_universal(formula.clone()),
        ProofStep::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => Logic::universal_instantiation(*variable, *replacement, body.clone()),
        ProofStep::EqualityReflexivity { variable } => Logic::equality_reflexivity(*variable),
        ProofStep::EqualitySubstitution { from, to, body } => {
            Logic::equality_substitution(*from, *to, body.clone())
        }
        ProofStep::ZfcAxiom(axiom) => axiom.formula(),
        ProofStep::Separation(schema) => {
            preflight_schema_depth(step, schema.parameters.len())?;
            schema
                .formula()
                .map_err(|source| CheckError::Schema { step, source })?
        }
        ProofStep::Replacement(schema) => {
            preflight_schema_depth(step, schema.parameters.len())?;
            schema
                .formula()
                .map_err(|source| CheckError::Schema { step, source })?
        }
        ProofStep::ProofReference { proof_id } => {
            let resolved =
                proof_state
                    .resolve(*proof_id)
                    .ok_or(CheckError::UnknownProofReference {
                        step,
                        proof_id: *proof_id,
                    })?;
            charge_formula_work(step, resolved.canonical_length, remaining_work)?;
            return Ok(DerivedStep {
                formula: resolved.conclusion.clone(),
                precharged_length: Some(resolved.canonical_length),
                referenced_derivation_id: Some(resolved.derivation_id),
            });
        }
        ProofStep::ModusPonens {
            premise,
            implication,
        } => {
            let premise = result(results, *premise);
            let implication = result(results, *implication);
            let referenced_work = premise
                .canonical_length
                .checked_add(implication.canonical_length)
                .expect("two formula lengths fit usize");
            charge_formula_work(step, referenced_work, remaining_work)?;
            Logic::modus_ponens(&premise.formula, &implication.formula)
                .map_err(|source| CheckError::Logic { step, source })?
        }
        ProofStep::Generalization { premise, variable } => {
            let premise = result(results, *premise);
            charge_formula_work(step, premise.canonical_length, remaining_work)?;
            Logic::generalization(*variable, premise.formula.clone())
        }
    };

    Ok(DerivedStep {
        formula,
        precharged_length: None,
        referenced_derivation_id: None,
    })
}

struct DerivedStep {
    formula: Formula,
    precharged_length: Option<usize>,
    referenced_derivation_id: Option<DerivationId>,
}

struct CheckedStep {
    formula: Formula,
    canonical_length: usize,
}

fn derivation_inputs(
    step: &ProofStep,
    derivation_ids: &[DerivationId],
) -> [Option<DerivationId>; 2] {
    step.local_references()
        .map(|reference| reference.map(|reference| derivation_ids[reference as usize]))
}

fn result(results: &[Option<CheckedStep>], reference: u32) -> &CheckedStep {
    results
        .get(reference as usize)
        .and_then(Option::as_ref)
        .expect("ProofCertificate guarantees references to earlier steps")
}

fn charge_formula_work(step: u32, amount: usize, remaining: &mut usize) -> Result<(), CheckError> {
    if amount > *remaining {
        let actual = (CHECKER_MAX_FORMULA_WORK_BYTES - *remaining)
            .checked_add(amount)
            .expect("formula work charges fit usize");
        return Err(CheckError::FormulaWorkLimitExceeded {
            step,
            actual,
            maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
        });
    }

    *remaining -= amount;
    Ok(())
}

/// A dependency, mathematical, or deterministic-resource checking failure.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckError {
    /// A referenced proof is absent from the supplied checked-proof state.
    UnknownProofReference { step: u32, proof_id: ProofId },
    /// A primitive logical inference rule failed.
    Logic { step: u32, source: LogicError },
    /// A ZFC axiom-schema side condition failed.
    Schema { step: u32, source: SchemaError },
    /// A reconstructed formula exceeded the canonical Formula limits.
    DerivedFormula {
        step: u32,
        source: FormulaCodecError,
    },
    /// Cumulative deterministic formula work exceeded the Checker limit.
    FormulaWorkLimitExceeded {
        step: u32,
        actual: usize,
        maximum: usize,
    },
    /// The final reconstructed formula still contains a free variable.
    OpenConclusion { step: u32 },
}

impl fmt::Display for CheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProofReference { step, .. } => {
                write!(formatter, "proof step {step} references an unknown proof")
            }
            Self::Logic { step, source } => {
                write!(
                    formatter,
                    "proof step {step} violates Foundation logic: {source}"
                )
            }
            Self::Schema { step, source } => {
                write!(
                    formatter,
                    "proof step {step} violates a ZFC schema: {source}"
                )
            }
            Self::DerivedFormula { step, source } => write!(
                formatter,
                "proof step {step} derives a formula outside Formula limits: {source}"
            ),
            Self::FormulaWorkLimitExceeded {
                step,
                actual,
                maximum,
            } => write!(
                formatter,
                "proof step {step} raises formula work to {actual} bytes; the Checker limit is {maximum}"
            ),
            Self::OpenConclusion { step } => {
                write!(formatter, "proof conclusion at step {step} is not closed")
            }
        }
    }
}

impl Error for CheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Logic { source, .. } => Some(source),
            Self::Schema { source, .. } => Some(source),
            Self::DerivedFormula { source, .. } => Some(source),
            Self::UnknownProofReference { .. }
            | Self::FormulaWorkLimitExceeded { .. }
            | Self::OpenConclusion { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::error::Error as _;

    use naome_foundation::{
        FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, Formula, FormulaCodecError, FreeVariable, Logic,
        LogicError, Replacement, SchemaError, Separation, ZfcAxiom,
    };
    use naome_proof::{CERTIFICATE_MAX_STEPS, ProofCertificate, ProofId, ProofStep};

    use super::{
        CHECKER_MAX_FORMULA_WORK_BYTES, CheckError, IdentityMode, ProofState, ProofStateError,
        charge_formula_work, check, check_with_canonical_conclusion, last_uses,
        normalize_and_check, normalize_and_check_with_state,
    };

    fn certificate(steps: Vec<ProofStep>) -> ProofCertificate {
        ProofCertificate::new(steps).expect("the test certificate is structurally valid")
    }

    fn closed_equality(variable: FreeVariable) -> Formula {
        Formula::for_all(variable, Formula::equal(variable, variable))
    }

    fn canonical_length(formula: &Formula) -> usize {
        formula
            .encode_canonical()
            .expect("the test formula is within Formula limits")
            .len()
    }

    #[test]
    fn logical_axiom_steps_reconstruct_exact_foundation_formulas() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let z = FreeVariable::new(3);
        let first = closed_equality(x);
        let second = Formula::for_all(y, Formula::member(y, y));
        let third = Formula::negate(closed_equality(z));
        let quantified_antecedent = Formula::equal(x, x);
        let quantified_consequent = Formula::member(x, x);

        let cases = [
            (
                ProofStep::Simplification {
                    antecedent: first.clone(),
                    consequent: second.clone(),
                },
                Logic::simplification(first.clone(), second.clone()),
            ),
            (
                ProofStep::Frege {
                    first: first.clone(),
                    second: second.clone(),
                    third: third.clone(),
                },
                Logic::frege(first.clone(), second.clone(), third.clone()),
            ),
            (
                ProofStep::ClassicalContraposition {
                    antecedent: first.clone(),
                    consequent: second.clone(),
                },
                Logic::classical_contraposition(first.clone(), second.clone()),
            ),
            (
                ProofStep::UniversalDistribution {
                    variable: x,
                    antecedent: quantified_antecedent.clone(),
                    consequent: quantified_consequent.clone(),
                },
                Logic::universal_distribution(x, quantified_antecedent, quantified_consequent),
            ),
        ];

        for (step, expected) in cases {
            assert_eq!(check(&certificate(vec![step])), Ok(expected));
        }
    }

    #[test]
    fn vacuous_universal_reconstructs_the_nameless_binder() {
        let zero = FreeVariable::new(0);
        let body = Formula::equal(zero, zero);
        let vacuous = Logic::vacuous_universal(body.clone());
        let expected = Logic::generalization(zero, vacuous);
        let proof = certificate(vec![
            ProofStep::VacuousUniversal { formula: body },
            ProofStep::Generalization {
                premise: 0,
                variable: zero,
            },
        ]);

        assert_eq!(check(&proof), Ok(expected));
    }

    #[test]
    fn universal_instantiation_maps_binder_and_replacement_fields() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let body = Formula::member(x, x);
        let instantiation = Logic::universal_instantiation(x, y, body.clone());
        let expected = Logic::generalization(y, instantiation);
        let proof = certificate(vec![
            ProofStep::UniversalInstantiation {
                variable: x,
                replacement: y,
                body,
            },
            ProofStep::Generalization {
                premise: 0,
                variable: y,
            },
        ]);

        assert_eq!(check(&proof), Ok(expected));
    }

    #[test]
    fn equality_reflexivity_generalization_round_trips_from_canonical_bytes() {
        let x = FreeVariable::new(0x0102_0304);
        let direct = certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]);
        let decoded = ProofCertificate::from_canonical_bytes(&direct.to_canonical_bytes())
            .expect("the canonical certificate round-trips");

        assert_eq!(check(&direct), check(&decoded));
        assert_eq!(check(&decoded), Ok(closed_equality(x)));
    }

    #[test]
    fn reordered_and_renamed_proofs_share_one_checked_normal_form() {
        let first = identity_proof(FreeVariable::new(7), false);
        let reordered = identity_proof(FreeVariable::new(42), true);
        let first = normalize_and_check(first).unwrap();
        let reordered = normalize_and_check(reordered).unwrap();

        assert_eq!(reordered, first);
        assert_eq!(
            first.normal_form().certificate().to_canonical_bytes(),
            reordered.normal_form().certificate().to_canonical_bytes()
        );
        assert_eq!(first.statement_id(), reordered.statement_id());
        assert_eq!(first.proof_id(), reordered.proof_id());
    }

    #[test]
    fn alternative_derivations_keep_distinct_normal_forms() {
        let x = FreeVariable::new(5);
        let direct = certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]);
        let detour = identity_proof(x, false);

        let direct = normalize_and_check(direct).unwrap();
        let detour = normalize_and_check(detour).unwrap();

        assert_eq!(direct.conclusion(), detour.conclusion());
        assert_eq!(direct.statement_id(), detour.statement_id());
        assert_ne!(direct.derivation_id(), detour.derivation_id());
        assert_ne!(direct.proof_id(), detour.proof_id());
        assert_ne!(
            direct.normal_form().certificate().to_canonical_bytes(),
            detour.normal_form().certificate().to_canonical_bytes()
        );
    }

    #[test]
    fn content_identity_golden_binds_the_closed_statement_and_normal_proof() {
        let x = FreeVariable::new(42);
        let checked = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .unwrap();

        assert_eq!(
            checked.conclusion().encode_canonical().unwrap(),
            [
                0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            checked.normal_form().certificate().to_canonical_bytes(),
            [
                0x00, 0x00, 0x00, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            checked.statement_id().as_bytes(),
            &[
                0xf9, 0x02, 0xf7, 0x99, 0xc2, 0x4f, 0x06, 0x4e, 0xa9, 0x8b, 0xf7, 0xfa, 0x33, 0xc1,
                0x2c, 0x51, 0x78, 0xf1, 0x72, 0x2f, 0xdf, 0xd9, 0x4b, 0x22, 0x3c, 0x64, 0xea, 0x1a,
                0xa9, 0xae, 0x3d, 0x19,
            ]
        );
        assert_eq!(
            checked.proof_id().as_bytes(),
            &[
                0xc6, 0x17, 0xc9, 0x22, 0x2d, 0xf9, 0x01, 0xd9, 0x94, 0x04, 0x86, 0x8a, 0xab, 0x41,
                0x5e, 0x91, 0x7a, 0xf7, 0x6c, 0xe6, 0x56, 0x99, 0x87, 0x63, 0x42, 0xfe, 0x0c, 0x0f,
                0xf1, 0xe6, 0x2e, 0x73,
            ]
        );
        assert_eq!(
            checked.derivation_id().as_bytes(),
            &[
                0x59, 0x21, 0x9d, 0x63, 0xc7, 0xc2, 0x35, 0x3d, 0xcb, 0x6f, 0xfd, 0x1e, 0x60, 0x41,
                0x53, 0x14, 0x33, 0x80, 0xae, 0x66, 0x02, 0xe0, 0x42, 0x15, 0x70, 0x3b, 0xc0, 0xea,
                0x04, 0x32, 0x43, 0xfb,
            ]
        );
    }

    #[test]
    fn every_inline_reference_partition_has_one_derivation_identity() {
        let baseline = partitioned_weakening_proof(0).0;
        let statement_id = baseline.statement_id();
        let derivation_id = baseline.derivation_id();
        let conclusion = baseline.conclusion().clone();
        let mut proof_ids = BTreeSet::new();

        for cuts in 0..16 {
            let (partitioned, mut state) = partitioned_weakening_proof(cuts);
            let partitioned_proof_id = partitioned.proof_id();
            assert_eq!(partitioned.conclusion(), &conclusion);
            assert_eq!(partitioned.statement_id(), statement_id);
            assert_eq!(partitioned.derivation_id(), derivation_id);
            assert!(proof_ids.insert(partitioned_proof_id));

            let inline = partitioned_weakening_proof(0).0;
            state.register(inline).unwrap();
            let expected = if cuts == 0 {
                ProofStateError::DuplicateProof {
                    proof_id: partitioned_proof_id,
                }
            } else {
                ProofStateError::DuplicateDerivation { derivation_id }
            };
            assert_eq!(state.register(partitioned), Err(expected));
            assert!(!state.contains_proof(partitioned_proof_id) || cuts == 0);
        }

        assert_eq!(proof_ids.len(), 16);
    }

    #[test]
    fn closed_fragment_variable_names_do_not_cross_reference_boundaries() {
        let shared_identifier = FreeVariable::new(7);
        let distinct_outer = FreeVariable::new(42);
        let shared = inline_closed_fragment(shared_identifier, shared_identifier);
        let distinct = inline_closed_fragment(shared_identifier, distinct_outer);

        let source = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity {
                variable: shared_identifier,
            },
            ProofStep::Generalization {
                premise: 0,
                variable: shared_identifier,
            },
        ]))
        .unwrap();
        let source_id = source.proof_id();
        let theorem = source.conclusion().clone();
        let outer = Formula::equal(distinct_outer, distinct_outer);
        let mut state = ProofState::new();
        state.register(source).unwrap();
        let referenced = normalize_and_check_with_state(
            certificate(vec![
                ProofStep::ProofReference {
                    proof_id: source_id,
                },
                ProofStep::Simplification {
                    antecedent: theorem,
                    consequent: outer,
                },
                ProofStep::ModusPonens {
                    premise: 0,
                    implication: 1,
                },
                ProofStep::Generalization {
                    premise: 2,
                    variable: distinct_outer,
                },
            ]),
            &state,
        )
        .unwrap();

        assert_eq!(shared.conclusion(), distinct.conclusion());
        assert_eq!(distinct.conclusion(), referenced.conclusion());
        assert_eq!(shared.derivation_id(), distinct.derivation_id());
        assert_eq!(distinct.derivation_id(), referenced.derivation_id());
        assert_ne!(distinct.proof_id(), referenced.proof_id());
    }

    #[test]
    fn hidden_variable_identifiers_can_be_reused_above_open_fragments() {
        let hidden = FreeVariable::new(7);
        let remaining = FreeVariable::new(42);
        let reused = hidden_variable_proof(hidden, hidden, remaining);
        let fresh = hidden_variable_proof(hidden, FreeVariable::new(99), remaining);

        assert_eq!(reused.conclusion(), fresh.conclusion());
        assert_eq!(reused.statement_id(), fresh.statement_id());
        assert_eq!(reused.derivation_id(), fresh.derivation_id());
        assert_ne!(reused.proof_id(), fresh.proof_id());
    }

    #[test]
    fn statement_identity_is_structural_not_logical_equivalence() {
        let x = FreeVariable::new(3);
        let y = FreeVariable::new(4);
        let once = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .unwrap();
        let twice = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
            ProofStep::Generalization {
                premise: 1,
                variable: y,
            },
        ]))
        .unwrap();

        assert_ne!(once.conclusion(), twice.conclusion());
        assert_ne!(once.statement_id(), twice.statement_id());
    }

    #[test]
    fn a_root_proof_reference_resolves_only_from_checked_state() {
        let x = FreeVariable::new(42);
        let source = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .unwrap();
        let source_proof_id = source.proof_id();
        let source_derivation_id = source.derivation_id();
        let source_statement_id = source.statement_id();
        let source_conclusion = source.conclusion().clone();
        let reference = || {
            certificate(vec![ProofStep::ProofReference {
                proof_id: source_proof_id,
            }])
        };

        assert_eq!(
            normalize_and_check(reference()),
            Err(CheckError::UnknownProofReference {
                step: 0,
                proof_id: source_proof_id,
            })
        );

        let mut state = ProofState::new();
        state.register(source).unwrap();
        let cited = normalize_and_check_with_state(reference(), &state).unwrap();

        assert_eq!(cited.conclusion(), &source_conclusion);
        assert_eq!(cited.statement_id(), source_statement_id);
        assert_eq!(cited.derivation_id(), source_derivation_id);
        assert_eq!(
            cited.normal_form().certificate().to_canonical_bytes(),
            [
                0x00, 0x00, 0x00, 0x01, 0x30, 0xc6, 0x17, 0xc9, 0x22, 0x2d, 0xf9, 0x01, 0xd9, 0x94,
                0x04, 0x86, 0x8a, 0xab, 0x41, 0x5e, 0x91, 0x7a, 0xf7, 0x6c, 0xe6, 0x56, 0x99, 0x87,
                0x63, 0x42, 0xfe, 0x0c, 0x0f, 0xf1, 0xe6, 0x2e, 0x73,
            ]
        );
        assert_eq!(
            cited.proof_id().as_bytes(),
            &[
                0xbf, 0xd4, 0x27, 0xb4, 0x47, 0xe1, 0x51, 0x46, 0x86, 0xcf, 0xa3, 0x1b, 0x0b, 0x5a,
                0xa1, 0xdd, 0x50, 0x36, 0x46, 0x4c, 0xd8, 0xc5, 0xd7, 0x3d, 0x0c, 0x31, 0x12, 0xcb,
                0x46, 0xb0, 0x51, 0x9b,
            ]
        );
        assert!(state.contains_proof(source_proof_id));
    }

    #[test]
    fn unreachable_references_are_pruned_but_direct_check_still_resolves_every_step() {
        let missing = ProofId::from_bytes([0xff; 32]);
        let x = FreeVariable::new(9);
        let proof = || {
            certificate(vec![
                ProofStep::ProofReference { proof_id: missing },
                ProofStep::EqualityReflexivity { variable: x },
                ProofStep::Generalization {
                    premise: 1,
                    variable: x,
                },
            ])
        };

        assert_eq!(
            check(&proof()),
            Err(CheckError::UnknownProofReference {
                step: 0,
                proof_id: missing,
            })
        );
        let checked = normalize_and_check_with_state(proof(), &ProofState::new()).unwrap();
        assert_eq!(checked.conclusion(), &closed_equality(x));
        assert_eq!(checked.normal_form().certificate().steps().len(), 2);
    }

    #[test]
    fn referenced_theorems_participate_in_inference_without_rechecking_their_proof() {
        let x = FreeVariable::new(7);
        let source = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .unwrap();
        let source_id = source.proof_id();
        let theorem = source.conclusion().clone();
        let expected = Formula::implies(theorem.clone(), theorem.clone());
        let mut state = ProofState::new();
        state.register(source).unwrap();

        let checked = normalize_and_check_with_state(
            certificate(vec![
                ProofStep::ProofReference {
                    proof_id: source_id,
                },
                ProofStep::Simplification {
                    antecedent: theorem.clone(),
                    consequent: theorem,
                },
                ProofStep::ModusPonens {
                    premise: 0,
                    implication: 1,
                },
            ]),
            &state,
        )
        .unwrap();

        assert_eq!(checked.conclusion(), &expected);
    }

    #[test]
    fn selected_alternative_citations_change_proof_identity_not_statement_identity() {
        let x = FreeVariable::new(5);
        let direct = normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ]))
        .unwrap();
        let detour = normalize_and_check(identity_proof(x, false)).unwrap();
        let direct_id = direct.proof_id();
        let detour_id = detour.proof_id();
        let theorem = direct.conclusion().clone();
        let mut state = ProofState::new();
        state.register(direct).unwrap();
        state.register(detour).unwrap();

        let dependent = |proof_id| {
            normalize_and_check_with_state(
                certificate(vec![
                    ProofStep::ProofReference { proof_id },
                    ProofStep::Simplification {
                        antecedent: theorem.clone(),
                        consequent: theorem.clone(),
                    },
                    ProofStep::ModusPonens {
                        premise: 0,
                        implication: 1,
                    },
                ]),
                &state,
            )
            .unwrap()
        };
        let cites_direct = dependent(direct_id);
        let cites_detour = dependent(detour_id);

        assert_eq!(cites_direct.conclusion(), cites_detour.conclusion());
        assert_eq!(cites_direct.statement_id(), cites_detour.statement_id());
        assert_ne!(cites_direct.derivation_id(), cites_detour.derivation_id());
        assert_ne!(cites_direct.proof_id(), cites_detour.proof_id());
    }

    #[test]
    fn proof_state_rejects_duplicates_and_remains_dependency_closed() {
        let x = FreeVariable::new(3);
        let checked = || {
            normalize_and_check(certificate(vec![
                ProofStep::EqualityReflexivity { variable: x },
                ProofStep::Generalization {
                    premise: 0,
                    variable: x,
                },
            ]))
            .unwrap()
        };
        let first = checked();
        let proof_id = first.proof_id();
        let derivation_id = first.derivation_id();
        let mut source_state = ProofState::new();
        source_state.register(first).unwrap();
        assert_eq!(
            source_state.register(checked()),
            Err(ProofStateError::DuplicateProof { proof_id })
        );

        let dependent = normalize_and_check_with_state(
            certificate(vec![ProofStep::ProofReference { proof_id }]),
            &source_state,
        )
        .unwrap();
        assert_eq!(
            ProofState::new().register(dependent),
            Err(ProofStateError::MissingProofDependency { proof_id })
        );

        let mut target_state = ProofState::new();
        target_state.register(checked()).unwrap();
        let cited_alias = normalize_and_check_with_state(
            certificate(vec![ProofStep::ProofReference { proof_id }]),
            &source_state,
        )
        .unwrap();
        let cited_alias_id = cited_alias.proof_id();
        assert_eq!(cited_alias.derivation_id(), derivation_id);
        assert_eq!(
            target_state.register(cited_alias),
            Err(ProofStateError::DuplicateDerivation { derivation_id })
        );
        assert!(!target_state.contains_proof(cited_alias_id));
        assert_eq!(
            normalize_and_check_with_state(
                certificate(vec![ProofStep::ProofReference {
                    proof_id: cited_alias_id,
                }]),
                &target_state,
            ),
            Err(CheckError::UnknownProofReference {
                step: 0,
                proof_id: cited_alias_id,
            })
        );

        let theorem = closed_equality(x);
        let dependent = normalize_and_check_with_state(
            certificate(vec![
                ProofStep::ProofReference { proof_id },
                ProofStep::Simplification {
                    antecedent: theorem.clone(),
                    consequent: theorem,
                },
                ProofStep::ModusPonens {
                    premise: 0,
                    implication: 1,
                },
            ]),
            &source_state,
        )
        .unwrap();
        let dependent_id = dependent.proof_id();
        target_state.register(dependent).unwrap();
        assert!(target_state.contains_proof(dependent_id));
    }

    #[test]
    fn checked_proof_couples_a_nontrivial_hilbert_derivation_to_its_conclusion() {
        let x = FreeVariable::new(27);
        let y = FreeVariable::new(42);
        let proposition = Formula::member(x, y);
        let self_implication = Formula::implies(proposition.clone(), proposition.clone());
        let proof = certificate(vec![
            ProofStep::Simplification {
                antecedent: proposition.clone(),
                consequent: proposition.clone(),
            },
            ProofStep::Simplification {
                antecedent: proposition.clone(),
                consequent: self_implication.clone(),
            },
            ProofStep::Frege {
                first: proposition.clone(),
                second: self_implication,
                third: proposition.clone(),
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 3,
            },
            ProofStep::Generalization {
                premise: 4,
                variable: x,
            },
            ProofStep::Generalization {
                premise: 5,
                variable: y,
            },
        ]);
        let expected = Logic::generalization(
            y,
            Logic::generalization(x, Formula::implies(proposition.clone(), proposition)),
        );

        let checked = normalize_and_check(proof).unwrap();

        assert_eq!(checked.normal_form().certificate().steps().len(), 7);
        assert_eq!(checked.conclusion(), &expected);
        assert_eq!(check(checked.normal_form().certificate()), Ok(expected));
    }

    #[test]
    fn equality_substitution_closes_only_through_explicit_generalization() {
        let x = FreeVariable::new(1);
        let y = FreeVariable::new(2);
        let body = Formula::member(x, x);
        let substitution = Logic::equality_substitution(x, y, body.clone());
        let after_x = Logic::generalization(x, substitution);
        let expected = Logic::generalization(y, after_x);
        let proof = certificate(vec![
            ProofStep::EqualitySubstitution {
                from: x,
                to: y,
                body,
            },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
            ProofStep::Generalization {
                premise: 1,
                variable: y,
            },
        ]);

        assert_eq!(check(&proof), Ok(expected));
    }

    #[test]
    fn every_fixed_zfc_axiom_reconstructs_its_foundation_formula() {
        let axioms = [
            ZfcAxiom::Extensionality,
            ZfcAxiom::Pairing,
            ZfcAxiom::Union,
            ZfcAxiom::PowerSet,
            ZfcAxiom::Infinity,
            ZfcAxiom::Foundation,
            ZfcAxiom::Choice,
        ];

        for axiom in axioms {
            assert_eq!(
                check(&certificate(vec![ProofStep::ZfcAxiom(axiom)])),
                Ok(axiom.formula())
            );
        }
    }

    #[test]
    fn valid_separation_and_replacement_reconstruct_exact_schema_formulas() {
        let element = FreeVariable::new(1);
        let source = FreeVariable::new(2);
        let result = FreeVariable::new(3);
        let parameter = FreeVariable::new(4);
        let second_parameter = FreeVariable::new(5);
        let separation = Separation {
            predicate: Formula::conjunction(
                Formula::member(element, source),
                Formula::conjunction(
                    Formula::equal(parameter, parameter),
                    Formula::equal(second_parameter, second_parameter),
                ),
            ),
            element,
            source,
            result,
            parameters: vec![parameter, second_parameter],
        };
        let separation_formula = separation
            .formula()
            .expect("the Separation instance is valid");

        assert_eq!(
            check(&certificate(vec![ProofStep::Separation(separation)])),
            Ok(separation_formula)
        );

        let input = FreeVariable::new(10);
        let output = FreeVariable::new(11);
        let uniqueness_witness = FreeVariable::new(12);
        let replacement_source = FreeVariable::new(13);
        let replacement_result = FreeVariable::new(14);
        let replacement_parameter = FreeVariable::new(15);
        let second_replacement_parameter = FreeVariable::new(16);
        let replacement = Replacement {
            predicate: Formula::conjunction(
                Formula::equal(input, output),
                Formula::conjunction(
                    Formula::equal(replacement_parameter, replacement_parameter),
                    Formula::equal(second_replacement_parameter, second_replacement_parameter),
                ),
            ),
            input,
            output,
            uniqueness_witness,
            source: replacement_source,
            result: replacement_result,
            parameters: vec![replacement_parameter, second_replacement_parameter],
        };
        let replacement_formula = replacement
            .formula()
            .expect("the Replacement instance is valid");

        assert_eq!(
            check(&certificate(vec![ProofStep::Replacement(replacement)])),
            Ok(replacement_formula)
        );
    }

    #[test]
    fn modus_ponens_returns_the_exact_closed_consequent() {
        let premise = ZfcAxiom::Extensionality.formula();
        let nested_antecedent = ZfcAxiom::Pairing.formula();
        let proof = certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStep::Simplification {
                antecedent: premise.clone(),
                consequent: nested_antecedent.clone(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]);

        assert_eq!(
            check(&proof),
            Ok(Formula::implies(nested_antecedent, premise))
        );
    }

    #[test]
    fn results_remain_live_through_their_last_consumer() {
        let premise = ZfcAxiom::Extensionality.formula();
        let nested_antecedent = ZfcAxiom::Choice.formula();
        let steps = vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStep::Simplification {
                antecedent: premise.clone(),
                consequent: nested_antecedent.clone(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ];

        assert_eq!(last_uses(&steps), [Some(3), Some(3), None, None]);
        assert_eq!(
            ProofStep::ModusPonens {
                premise: 7,
                implication: 7,
            }
            .local_references(),
            [Some(7), Some(7)]
        );
        assert_eq!(
            check(&certificate(steps)),
            Ok(Formula::implies(nested_antecedent, premise))
        );
    }

    #[test]
    fn normalization_discards_invalid_unreachable_steps_before_checking() {
        let element = FreeVariable::new(1);
        let source = FreeVariable::new(2);
        let result = FreeVariable::new(3);
        let root = FreeVariable::new(4);
        let invalid = Separation {
            predicate: Formula::equal(result, result),
            element,
            source,
            result,
            parameters: Vec::new(),
        };
        let proof = certificate(vec![
            ProofStep::Separation(invalid),
            ProofStep::EqualityReflexivity { variable: root },
            ProofStep::Generalization {
                premise: 1,
                variable: root,
            },
        ]);

        assert_eq!(
            check(&proof),
            Err(CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(result),
            })
        );
        let checked = normalize_and_check(proof).unwrap();
        assert_eq!(checked.normal_form().certificate().steps().len(), 2);
        assert_eq!(checked.conclusion(), &closed_equality(root));
    }

    #[test]
    fn normalization_reports_reachable_errors_in_normalized_coordinates() {
        let x = FreeVariable::new(10);
        let y = FreeVariable::new(11);
        let proof = certificate(vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Pairing),
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Simplification {
                antecedent: Formula::equal(y, y),
                consequent: closed_equality(x),
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
        ]);

        assert_eq!(
            normalize_and_check(proof),
            Err(CheckError::Logic {
                step: 2,
                source: LogicError::ModusPonensMismatch,
            })
        );

        let element = FreeVariable::new(40);
        let source = FreeVariable::new(50);
        let result = FreeVariable::new(60);
        let proof = certificate(vec![ProofStep::Separation(Separation {
            predicate: Formula::equal(result, result),
            element,
            source,
            result,
            parameters: Vec::new(),
        })]);

        assert_eq!(
            normalize_and_check(proof),
            Err(CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(FreeVariable::new(0)),
            })
        );
    }

    #[test]
    fn checker_localizes_invalid_replacement_and_modus_ponens() {
        let input = FreeVariable::new(1);
        let output = FreeVariable::new(2);
        let uniqueness_witness = FreeVariable::new(3);
        let source = FreeVariable::new(4);
        let result = FreeVariable::new(5);
        let invalid_replacement = Replacement {
            predicate: Formula::equal(uniqueness_witness, output),
            input,
            output,
            uniqueness_witness,
            source,
            result,
            parameters: Vec::new(),
        };

        assert_eq!(
            check(&certificate(vec![ProofStep::Replacement(
                invalid_replacement
            )])),
            Err(CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(uniqueness_witness),
            })
        );

        let x = FreeVariable::new(10);
        let y = FreeVariable::new(11);
        let proof = certificate(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Simplification {
                antecedent: Formula::equal(y, y),
                consequent: closed_equality(x),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ]);

        assert_eq!(
            check(&proof),
            Err(CheckError::Logic {
                step: 2,
                source: LogicError::ModusPonensMismatch,
            })
        );
    }

    #[test]
    fn check_errors_expose_their_step_context_and_sources() {
        let variable = FreeVariable::new(9);
        let reference = CheckError::UnknownProofReference {
            step: 0,
            proof_id: ProofId::from_bytes([0x11; 32]),
        };
        let logic = CheckError::Logic {
            step: 1,
            source: LogicError::ModusPonensMismatch,
        };
        let schema = CheckError::Schema {
            step: 2,
            source: SchemaError::DuplicateParameter(variable),
        };
        let derived = CheckError::DerivedFormula {
            step: 3,
            source: FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            },
        };
        let work = CheckError::FormulaWorkLimitExceeded {
            step: 4,
            actual: 5,
            maximum: 4,
        };
        let open = CheckError::OpenConclusion { step: 5 };

        assert!(
            logic
                .source()
                .unwrap()
                .downcast_ref::<LogicError>()
                .is_some()
        );
        assert!(
            schema
                .source()
                .unwrap()
                .downcast_ref::<SchemaError>()
                .is_some()
        );
        assert!(
            derived
                .source()
                .unwrap()
                .downcast_ref::<FormulaCodecError>()
                .is_some()
        );
        assert!(reference.source().is_none());
        assert!(work.source().is_none());
        assert!(open.source().is_none());

        for (error, fragments) in [
            (&reference, &["step 0", "unknown proof"][..]),
            (&logic, &["step 1", "modus ponens"][..]),
            (&schema, &["step 2", "variable 9"][..]),
            (&derived, &["step 3", "limit of 256"][..]),
            (&work, &["step 4", "5 bytes", "limit is 4"][..]),
            (&open, &["step 5", "not closed"][..]),
        ] {
            let rendered = error.to_string();
            for fragment in fragments {
                assert!(
                    rendered.contains(fragment),
                    "{rendered:?} lacks {fragment:?}"
                );
            }
        }
    }

    #[test]
    fn normalization_preserves_a_valid_proof_conclusion() {
        let x = FreeVariable::new(1);
        let proof = identity_proof(x, false);
        let expected = check(&proof).unwrap();
        let checked = normalize_and_check(proof).unwrap();

        assert_eq!(checked.conclusion(), &expected);
        assert_eq!(check(checked.normal_form().certificate()), Ok(expected));
    }

    #[test]
    fn checker_rejects_an_open_conclusion_but_allows_open_intermediate_steps() {
        let x = FreeVariable::new(1);
        let open = certificate(vec![ProofStep::EqualityReflexivity { variable: x }]);

        assert_eq!(check(&open), Err(CheckError::OpenConclusion { step: 0 }));
        assert_eq!(
            normalize_and_check(open),
            Err(CheckError::OpenConclusion { step: 0 })
        );

        assert!(
            check(&certificate(vec![
                ProofStep::EqualityReflexivity { variable: x },
                ProofStep::Generalization {
                    premise: 0,
                    variable: x,
                },
            ]))
            .is_ok()
        );
    }

    #[test]
    fn checker_enforces_derived_depth_and_node_limits() {
        let x = FreeVariable::new(1);
        let mut depth_steps = vec![ProofStep::EqualityReflexivity { variable: x }];
        for premise in 0..FORMULA_MAX_DEPTH {
            depth_steps.push(ProofStep::Generalization {
                premise,
                variable: x,
            });
        }

        assert_eq!(
            check(&certificate(depth_steps)),
            Err(CheckError::DerivedFormula {
                step: FORMULA_MAX_DEPTH,
                source: FormulaCodecError::DepthLimitExceeded {
                    maximum: FORMULA_MAX_DEPTH,
                },
            })
        );

        let large = balanced_closed_formula(12, x);
        let node_proof = certificate(vec![ProofStep::Frege {
            first: large.clone(),
            second: large.clone(),
            third: large,
        }]);

        assert_eq!(
            check(&node_proof),
            Err(CheckError::DerivedFormula {
                step: 0,
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_MAX_NODES,
                },
            })
        );
    }

    #[test]
    fn schema_depth_preflight_has_an_exact_boundary_and_precedes_schema_errors() {
        let parameters = (0..FORMULA_MAX_DEPTH)
            .map(|offset| FreeVariable::new(1_000 + offset))
            .collect::<Vec<_>>();
        let element = FreeVariable::new(1);
        let source = FreeVariable::new(2);
        let result = FreeVariable::new(3);
        let below_limit = parameters[..parameters.len() - 1].to_vec();

        assert_eq!(
            check(&certificate(vec![ProofStep::Separation(Separation {
                predicate: Formula::equal(result, result),
                element,
                source,
                result,
                parameters: below_limit,
            })])),
            Err(CheckError::Schema {
                step: 0,
                source: SchemaError::ForbiddenPredicateVariable(result),
            })
        );

        let depth_error = Err(CheckError::DerivedFormula {
            step: 0,
            source: FormulaCodecError::DepthLimitExceeded {
                maximum: FORMULA_MAX_DEPTH,
            },
        });

        assert_eq!(
            check(&certificate(vec![ProofStep::Separation(Separation {
                predicate: Formula::equal(result, result),
                element,
                source,
                result,
                parameters: parameters.clone(),
            })])),
            depth_error
        );

        let uniqueness_witness = FreeVariable::new(4);
        assert_eq!(
            check(&certificate(vec![ProofStep::Replacement(Replacement {
                predicate: Formula::equal(uniqueness_witness, source),
                input: element,
                output: source,
                uniqueness_witness,
                source: FreeVariable::new(5),
                result: FreeVariable::new(6),
                parameters,
            })])),
            depth_error
        );
    }

    #[test]
    fn formula_work_limit_is_exact_and_inclusive() {
        assert_eq!(CHECKER_MAX_FORMULA_WORK_BYTES, 4_194_304);

        let mut remaining = CHECKER_MAX_FORMULA_WORK_BYTES;
        assert_eq!(
            charge_formula_work(7, CHECKER_MAX_FORMULA_WORK_BYTES, &mut remaining),
            Ok(())
        );
        assert_eq!(remaining, 0);
        assert_eq!(
            charge_formula_work(8, 1, &mut remaining),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: 8,
                actual: CHECKER_MAX_FORMULA_WORK_BYTES + 1,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    #[test]
    fn formula_work_budget_enforces_result_and_error_precedence() {
        let axiom = ZfcAxiom::Choice;
        let axiom_length = canonical_length(&axiom.formula());
        let filler_count = CHECKER_MAX_FORMULA_WORK_BYTES / axiom_length;
        let used = filler_count * axiom_length;
        let remaining = CHECKER_MAX_FORMULA_WORK_BYTES - used;
        let fillers = vec![ProofStep::ZfcAxiom(axiom); filler_count];
        let step = u32::try_from(filler_count).unwrap();
        assert!(filler_count >= 2);
        assert!(filler_count < CERTIFICATE_MAX_STEPS);

        let mut result_overflow = fillers.clone();
        result_overflow.push(ProofStep::ZfcAxiom(axiom));
        assert_eq!(
            check(&certificate(result_overflow)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step,
                actual: used + axiom_length,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );

        let mut invalid_modus_ponens = fillers.clone();
        invalid_modus_ponens.push(ProofStep::ModusPonens {
            premise: 0,
            implication: 1,
        });
        assert_eq!(
            check(&certificate(invalid_modus_ponens)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step,
                actual: used + 2 * axiom_length,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );

        let x = FreeVariable::new(1);
        let open_length = canonical_length(&Logic::equality_reflexivity(x));
        assert!(open_length <= remaining);
        assert!(2 * open_length > remaining);
        let mut open_conclusion = fillers.clone();
        open_conclusion.push(ProofStep::EqualityReflexivity { variable: x });
        assert_eq!(
            check(&certificate(open_conclusion)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step,
                actual: used + 2 * open_length,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );

        let large = balanced_closed_formula(12, x);
        let mut invalid_derived = fillers;
        invalid_derived.push(ProofStep::Frege {
            first: large.clone(),
            second: large.clone(),
            third: large,
        });
        assert_eq!(
            check(&certificate(invalid_derived)),
            Err(CheckError::DerivedFormula {
                step,
                source: FormulaCodecError::NodeLimitExceeded {
                    maximum: FORMULA_MAX_NODES,
                },
            })
        );
    }

    #[test]
    fn repeated_large_antecedent_modus_ponens_charges_both_operands() {
        let small = ZfcAxiom::Extensionality.formula();
        let large = ZfcAxiom::Choice.formula();
        let implication = Logic::simplification(small.clone(), large.clone());
        let reduced_implication = Formula::implies(large.clone(), small.clone());
        let small_length = canonical_length(&small);
        let large_length = canonical_length(&large);
        let implication_length = canonical_length(&implication);
        let reduced_length = canonical_length(&reduced_implication);
        let mut used = small_length + large_length + implication_length;
        used += small_length + implication_length + reduced_length;
        assert!(used < CHECKER_MAX_FORMULA_WORK_BYTES);

        let mut steps = vec![
            ProofStep::ZfcAxiom(ZfcAxiom::Extensionality),
            ProofStep::ZfcAxiom(ZfcAxiom::Choice),
            ProofStep::Simplification {
                antecedent: small,
                consequent: large,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
        ];
        let (expected_step, expected_actual) = loop {
            let step = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStep::ModusPonens {
                premise: 1,
                implication: 3,
            });

            let referenced = large_length + reduced_length;
            if used + referenced > CHECKER_MAX_FORMULA_WORK_BYTES {
                break (step, used + referenced);
            }
            used += referenced;

            if used + small_length > CHECKER_MAX_FORMULA_WORK_BYTES {
                break (step, used + small_length);
            }
            used += small_length;
        };

        assert!(steps.len() < CERTIFICATE_MAX_STEPS);
        assert_eq!(
            check(&certificate(steps)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: expected_step,
                actual: expected_actual,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    #[test]
    fn generalization_charges_its_premise_before_execution() {
        let axiom = ZfcAxiom::Choice;
        let premise_length = canonical_length(&axiom.formula());
        let filler_count = (CHECKER_MAX_FORMULA_WORK_BYTES - premise_length) / premise_length;
        let used = (filler_count + 1) * premise_length;
        let mut steps = vec![ProofStep::ZfcAxiom(axiom); filler_count + 1];
        let expected_step = u32::try_from(steps.len()).unwrap();
        steps.push(ProofStep::Generalization {
            premise: 0,
            variable: FreeVariable::new(u32::MAX),
        });

        assert!(steps.len() < CERTIFICATE_MAX_STEPS);
        assert_eq!(
            check(&certificate(steps)),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: expected_step,
                actual: used + premise_length,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    #[test]
    fn proof_reference_result_charge_is_exact() {
        let source =
            normalize_and_check(certificate(vec![ProofStep::ZfcAxiom(ZfcAxiom::Choice)])).unwrap();
        let proof_id = source.proof_id();
        let referenced_length = source.canonical_conclusion_length;
        let filler_count = CHECKER_MAX_FORMULA_WORK_BYTES / referenced_length;
        let used = filler_count * referenced_length;
        let expected_step = u32::try_from(filler_count).unwrap();
        let mut state = ProofState::new();
        state.register(source).unwrap();
        let mut steps = vec![ProofStep::ZfcAxiom(ZfcAxiom::Choice); filler_count];
        steps.push(ProofStep::ProofReference { proof_id });

        assert!(used + referenced_length > CHECKER_MAX_FORMULA_WORK_BYTES);
        assert!(steps.len() < CERTIFICATE_MAX_STEPS);
        assert_eq!(
            check_with_canonical_conclusion(
                &certificate(steps),
                &state,
                IdentityMode::OmitDerivation,
            ),
            Err(CheckError::FormulaWorkLimitExceeded {
                step: expected_step,
                actual: used + referenced_length,
                maximum: CHECKER_MAX_FORMULA_WORK_BYTES,
            })
        );
    }

    fn balanced_closed_formula(depth: u32, variable: FreeVariable) -> Formula {
        if depth == 0 {
            return closed_equality(variable);
        }

        let child = balanced_closed_formula(depth - 1, variable);
        Formula::implies(child.clone(), child)
    }

    fn partitioned_weakening_proof(cuts: u8) -> (super::CheckedProof, ProofState) {
        let x = FreeVariable::new(100);
        let antecedents = [
            ZfcAxiom::Extensionality.formula(),
            ZfcAxiom::Pairing.formula(),
            ZfcAxiom::Union.formula(),
            ZfcAxiom::PowerSet.formula(),
        ];
        let mut state = ProofState::new();
        let mut steps = vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ];
        let mut premise = 1;
        let mut theorem = closed_equality(x);

        for (boundary, antecedent) in antecedents.into_iter().enumerate() {
            if cuts & (1 << boundary) != 0 {
                let prefix = normalize_and_check_with_state(certificate(steps), &state).unwrap();
                let proof_id = prefix.proof_id();
                state.register(prefix).unwrap();
                steps = vec![ProofStep::ProofReference { proof_id }];
                premise = 0;
            }

            let implication = u32::try_from(steps.len()).unwrap();
            steps.push(ProofStep::Simplification {
                antecedent: theorem.clone(),
                consequent: antecedent.clone(),
            });
            steps.push(ProofStep::ModusPonens {
                premise,
                implication,
            });
            premise = u32::try_from(steps.len() - 1).unwrap();
            theorem = Formula::implies(antecedent, theorem);
        }

        let checked = normalize_and_check_with_state(certificate(steps), &state).unwrap();
        assert_eq!(checked.conclusion(), &theorem);
        (checked, state)
    }

    fn inline_closed_fragment(inner: FreeVariable, outer: FreeVariable) -> super::CheckedProof {
        let theorem = closed_equality(inner);
        normalize_and_check(certificate(vec![
            ProofStep::EqualityReflexivity { variable: inner },
            ProofStep::Generalization {
                premise: 0,
                variable: inner,
            },
            ProofStep::Simplification {
                antecedent: theorem,
                consequent: Formula::equal(outer, outer),
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: outer,
            },
        ]))
        .unwrap()
    }

    fn hidden_variable_proof(
        hidden: FreeVariable,
        outer: FreeVariable,
        remaining: FreeVariable,
    ) -> super::CheckedProof {
        let substitution =
            Logic::equality_substitution(hidden, remaining, Formula::equal(hidden, hidden));
        let open_fragment = Logic::generalization(hidden, substitution);
        normalize_and_check(certificate(vec![
            ProofStep::EqualitySubstitution {
                from: hidden,
                to: remaining,
                body: Formula::equal(hidden, hidden),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: hidden,
            },
            ProofStep::Simplification {
                antecedent: open_fragment,
                consequent: Formula::equal(outer, outer),
            },
            ProofStep::ModusPonens {
                premise: 1,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: outer,
            },
            ProofStep::Generalization {
                premise: 4,
                variable: remaining,
            },
        ]))
        .unwrap()
    }

    fn identity_proof(variable: FreeVariable, reordered: bool) -> ProofCertificate {
        let formula = Formula::equal(variable, variable);
        let axiom = ProofStep::Simplification {
            antecedent: formula.clone(),
            consequent: formula,
        };
        let reflexivity = ProofStep::EqualityReflexivity { variable };
        let mut steps = if reordered {
            vec![axiom, reflexivity]
        } else {
            vec![reflexivity, axiom]
        };
        let (premise, implication) = if reordered { (1, 0) } else { (0, 1) };
        steps.push(ProofStep::ModusPonens {
            premise,
            implication,
        });
        steps.push(ProofStep::ModusPonens {
            premise,
            implication: 2,
        });
        steps.push(ProofStep::Generalization {
            premise: 3,
            variable,
        });
        certificate(steps)
    }
}
