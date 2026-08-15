//! Deterministic mathematical checking for Foundation proof certificates.
//!
//! The checker reconstructs every certificate step through the executable
//! Foundation rules, enforces deterministic formula-processing limits, and
//! accepts only a closed final formula. External proof references resolve only
//! through an explicitly supplied, already checked [`ArtifactState`]. The crate
//! remains deliberately in-memory and has no blocks, persistence, networking,
//! or source parsing.
//! Successful proof admission returns a [`CheckedProof`] that keeps the
//! accepted normal form, reconstructed conclusion, and content identities
//! coupled together.

mod state;

use std::borrow::Cow;
use std::error::Error;
use std::fmt;

use naome_foundation::{
    FORMULA_MAX_DEPTH, FORMULA_MAX_NODES, FOUNDATION_ID, Formula, FormulaCodecError, FreeVariable,
    Logic, LogicError, Replacement, SchemaError, Separation,
};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, DefinedFormula, DefinedFormulaCodecError, DefinitionCertificate,
    DefinitionCertificateError, DefinitionExpansionError, DefinitionId, DefinitionKind,
    DerivationId, ProofCertificate, ProofFormula, ProofId, ProofNormalForm, ProofReplacement,
    ProofSeparation, ProofStep, StatementId,
};
use sha2::{Digest, Sha256};

pub use state::{ArtifactState, ArtifactStateError};

const STATEMENT_ID_DOMAIN: &[u8] = b"naome:statement\0";
const PROOF_ID_DOMAIN: &[u8] = b"naome:proof\0";
const DERIVATION_NODE_ID_DOMAIN: &[u8] = b"naome:derivation-node\0";
const FUNCTION_OBLIGATION_FIXED_NODES: usize = 9;
const FUNCTION_OBLIGATION_FIXED_DEPTH: u32 = 8;

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

/// A conservative definition accepted against one selected-artifact state.
///
/// The canonical certificate is already fully expanded and determines
/// [`DefinitionId`]. Functions additionally retain the exact computed
/// obligation statement used during checking so registration can revalidate it.
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct CheckedDefinition {
    certificate: DefinitionCertificate,
    definition_id: DefinitionId,
    obligation: Option<CheckedDefinitionObligation>,
}

#[derive(Debug, PartialEq, Eq)]
struct CheckedDefinitionObligation {
    statement_id: StatementId,
    conclusion: Formula,
}

impl CheckedDefinition {
    /// Returns the exact checked definition certificate.
    pub const fn certificate(&self) -> &DefinitionCertificate {
        &self.certificate
    }

    /// Consumes the checked value and returns its original certificate.
    pub fn into_certificate(self) -> DefinitionCertificate {
        self.certificate
    }

    /// Returns the identity of the original definition certificate.
    pub const fn definition_id(&self) -> DefinitionId {
        self.definition_id
    }

    /// Returns the computed selected statement required by a function definition.
    pub fn obligation_statement_id(&self) -> Option<StatementId> {
        self.obligation
            .as_ref()
            .map(|obligation| obligation.statement_id)
    }
}

impl CheckedProof {
    /// Returns the checked proof's canonical normal form.
    pub const fn normal_form(&self) -> &ProofNormalForm {
        &self.normal_form
    }

    /// Consumes this checked proof and returns its canonical normal form.
    pub fn into_normal_form(self) -> ProofNormalForm {
        self.normal_form
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
        &ArtifactState::new(),
        IdentityMode::OmitDerivation,
    )
    .map(|(conclusion, _, _)| conclusion)
}

fn check_with_canonical_conclusion(
    certificate: &ProofCertificate,
    artifact_state: &ArtifactState,
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
        } = derive_step(
            position,
            step,
            &mut results,
            &last_uses,
            artifact_state,
            &mut remaining_work,
        )?;
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
    normalize_and_check_with_state(certificate, &ArtifactState::new())
}

/// Normalizes and checks one proof against immutable selected-artifact state.
///
/// Only root-reachable references are resolved. Every requested [`ProofId`]
/// must already be present in `artifact_state`; the state is never mutated during
/// checking. On success, the returned proof may be registered afterward.
pub fn normalize_and_check_with_state(
    certificate: ProofCertificate,
    artifact_state: &ArtifactState,
) -> Result<CheckedProof, CheckError> {
    let normal_form = certificate.into_unchecked_normal_form();
    check_normal_form_with_state(normal_form, artifact_state)
}

/// Checks one canonical proof normal form against immutable selected-artifact state.
///
/// Unlike [`normalize_and_check_with_state`], this entry point performs no
/// normalization. The [`ProofNormalForm`] type guarantees the structural
/// root-proof projection; this function establishes its mathematical validity
/// and content identities exactly once.
pub fn check_normal_form_with_state(
    normal_form: ProofNormalForm,
    artifact_state: &ArtifactState,
) -> Result<CheckedProof, CheckError> {
    check_normal_form_with_resolver(normal_form, artifact_state)
}

/// Expands an authoring definition body and checks its canonical certificate.
///
/// Selected definition applications are authoring conveniences only. They are
/// eliminated before the strict self-contained certificate is constructed, so
/// they cannot affect [`DefinitionId`].
pub fn normalize_and_check_definition_with_state(
    kind: DefinitionKind,
    body: DefinedFormula,
    artifact_state: &ArtifactState,
) -> Result<CheckedDefinition, DefinitionCheckError> {
    let expanded_body = body
        .expand_with_node_limit(artifact_state, FORMULA_MAX_NODES)
        .map(|value| value.0)
        .map_err(DefinitionCheckError::Expansion)?;
    let expanded_body = DefinedFormula::from_primitive(&expanded_body)
        .map_err(DefinitionCheckError::CanonicalBody)?;
    let certificate = DefinitionCertificate::new(kind, expanded_body)
        .map_err(DefinitionCheckError::Certificate)?;
    check_definition_with_state(certificate, artifact_state)
}

/// Checks one self-contained conservative definition against selected state.
///
/// Definition-certificate construction has already guaranteed a fully expanded
/// primitive body and an exact minimal interface. Functions require their exact
/// checker-derived total-unique statement to exist in earlier selected state.
/// The state is never mutated; register the returned value separately.
pub fn check_definition_with_state(
    certificate: DefinitionCertificate,
    artifact_state: &ArtifactState,
) -> Result<CheckedDefinition, DefinitionCheckError> {
    let obligation = match certificate.kind() {
        DefinitionKind::Relation { .. } => None,
        DefinitionKind::Function { input_arity } => {
            let maximum_body_nodes = maximum_function_body_nodes(input_arity);
            let Some(maximum_body_depth) = maximum_function_body_depth(input_arity) else {
                return Err(DefinitionCheckError::ObligationFormula(
                    FormulaCodecError::DepthLimitExceeded {
                        maximum: FORMULA_MAX_DEPTH,
                    },
                ));
            };
            let body_bytes = match certificate
                .body()
                .encode_canonical_with_limits(maximum_body_nodes, maximum_body_depth)
            {
                Ok((bytes, _)) => bytes,
                Err(DefinedFormulaCodecError::NodeLimitExceeded { .. }) => {
                    return Err(DefinitionCheckError::ObligationFormula(
                        FormulaCodecError::NodeLimitExceeded {
                            maximum: FORMULA_MAX_NODES,
                        },
                    ));
                }
                Err(DefinedFormulaCodecError::DepthLimitExceeded { .. }) => {
                    return Err(DefinitionCheckError::ObligationFormula(
                        FormulaCodecError::DepthLimitExceeded {
                            maximum: FORMULA_MAX_DEPTH,
                        },
                    ));
                }
                Err(source) => return Err(DefinitionCheckError::CanonicalBody(source)),
            };
            let body = Formula::decode_canonical(&body_bytes).map_err(|source| {
                DefinitionCheckError::CanonicalBody(DefinedFormulaCodecError::Primitive(source))
            })?;
            let conclusion = function_obligation(input_arity, body);
            let canonical = conclusion
                .encode_canonical()
                .map_err(DefinitionCheckError::ObligationFormula)?;
            let statement_id = statement_id(&canonical);
            let selected = artifact_state
                .resolve_statement(statement_id)
                .ok_or(DefinitionCheckError::UnknownObligationStatement { statement_id })?;
            if selected != &conclusion {
                return Err(DefinitionCheckError::ObligationConclusionMismatch { statement_id });
            }
            Some(CheckedDefinitionObligation {
                statement_id,
                conclusion,
            })
        }
    };
    let definition_id = certificate.definition_id();
    Ok(CheckedDefinition {
        certificate,
        definition_id,
        obligation,
    })
}

fn maximum_function_body_nodes(input_arity: u32) -> usize {
    let obligation_overhead = usize::try_from(input_arity)
        .expect("DefinitionCertificate bounds function input arity")
        + FUNCTION_OBLIGATION_FIXED_NODES;
    (FORMULA_MAX_NODES - obligation_overhead) / 2
}

fn maximum_function_body_depth(input_arity: u32) -> Option<u32> {
    input_arity
        .checked_add(FUNCTION_OBLIGATION_FIXED_DEPTH)
        .and_then(|overhead| FORMULA_MAX_DEPTH.checked_sub(overhead))
        .filter(|maximum| *maximum > 0)
}

fn function_obligation(input_arity: u32, body: Formula) -> Formula {
    let output = FreeVariable::new(input_arity);
    let uniqueness_witness = FreeVariable::new(
        input_arity
            .checked_add(1)
            .expect("DefinitionCertificate bounds function graph arity"),
    );
    let witness_body = body.clone().substitute_free(output, uniqueness_witness);
    let uniqueness = Formula::for_all(
        uniqueness_witness,
        Formula::implies(witness_body, Formula::equal(uniqueness_witness, output)),
    );
    let mut obligation = Formula::exists(output, Formula::conjunction(body, uniqueness));
    for identifier in (0..input_arity).rev() {
        obligation = Formula::for_all(FreeVariable::new(identifier), obligation);
    }
    obligation
}

fn check_normal_form_with_resolver(
    normal_form: ProofNormalForm,
    artifact_state: &ArtifactState,
) -> Result<CheckedProof, CheckError> {
    let (conclusion, canonical_conclusion, derivation_id) = check_with_canonical_conclusion(
        normal_form.certificate(),
        artifact_state,
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
    results: &mut [Option<CheckedStep>],
    last_uses: &[Option<u32>],
    artifact_state: &ArtifactState,
    remaining_work: &mut usize,
) -> Result<DerivedStep, CheckError> {
    let formula = match proof_step {
        ProofStep::Simplification {
            antecedent,
            consequent,
        } => Logic::simplification(
            primitive_formula(step, antecedent, artifact_state)?.into_owned(),
            primitive_formula(step, consequent, artifact_state)?.into_owned(),
        ),
        ProofStep::Frege {
            first,
            second,
            third,
        } => Logic::frege(
            primitive_formula(step, first, artifact_state)?.into_owned(),
            primitive_formula(step, second, artifact_state)?.into_owned(),
            primitive_formula(step, third, artifact_state)?.into_owned(),
        ),
        ProofStep::ClassicalContraposition {
            antecedent,
            consequent,
        } => Logic::classical_contraposition(
            primitive_formula(step, antecedent, artifact_state)?.into_owned(),
            primitive_formula(step, consequent, artifact_state)?.into_owned(),
        ),
        ProofStep::UniversalDistribution {
            variable,
            antecedent,
            consequent,
        } => Logic::universal_distribution(
            *variable,
            primitive_formula(step, antecedent, artifact_state)?.into_owned(),
            primitive_formula(step, consequent, artifact_state)?.into_owned(),
        ),
        ProofStep::VacuousUniversal { formula } => {
            Logic::vacuous_universal(primitive_formula(step, formula, artifact_state)?.into_owned())
        }
        ProofStep::UniversalInstantiation {
            variable,
            replacement,
            body,
        } => Logic::universal_instantiation(
            *variable,
            *replacement,
            primitive_formula(step, body, artifact_state)?.into_owned(),
        ),
        ProofStep::EqualityReflexivity { variable } => Logic::equality_reflexivity(*variable),
        ProofStep::EqualitySubstitution { from, to, body } => Logic::equality_substitution(
            *from,
            *to,
            primitive_formula(step, body, artifact_state)?.into_owned(),
        ),
        ProofStep::ZfcAxiom(axiom) => axiom.formula(),
        ProofStep::Separation(schema) => {
            preflight_schema_depth(step, schema.parameters.len())?;
            let schema = primitive_separation(step, schema, artifact_state)?;
            schema
                .formula()
                .map_err(|source| CheckError::Schema { step, source })?
        }
        ProofStep::Replacement(schema) => {
            preflight_schema_depth(step, schema.parameters.len())?;
            let schema = primitive_replacement(step, schema, artifact_state)?;
            schema
                .formula()
                .map_err(|source| CheckError::Schema { step, source })?
        }
        ProofStep::ProofReference { proof_id } => {
            let resolved = artifact_state.resolve_proof(*proof_id).ok_or(
                CheckError::UnknownProofReference {
                    step,
                    proof_id: *proof_id,
                },
            )?;
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
            let premise_index = *premise as usize;
            let premise_length = result(results, *premise).canonical_length;
            charge_formula_work(step, premise_length, remaining_work)?;
            let premise = if last_uses[premise_index] == Some(step) {
                results[premise_index]
                    .take()
                    .expect("a final-use premise remains available")
                    .formula
            } else {
                result(results, *premise).formula.clone()
            };
            Logic::generalization(*variable, premise)
        }
    };

    Ok(DerivedStep {
        formula,
        precharged_length: None,
        referenced_derivation_id: None,
    })
}

fn primitive_formula<'a>(
    step: u32,
    formula: &'a ProofFormula,
    artifact_state: &ArtifactState,
) -> Result<Cow<'a, Formula>, CheckError> {
    if let Some(formula) = formula.as_primitive() {
        Ok(Cow::Borrowed(formula))
    } else {
        formula
            .as_defined()
            .expect("every non-primitive proof formula contains a definition")
            .expand_with_node_limit(artifact_state, FORMULA_MAX_NODES)
            .map(|value| Cow::Owned(value.0))
            .map_err(|source| CheckError::DefinitionExpansion { step, source })
    }
}

fn primitive_separation(
    step: u32,
    schema: &ProofSeparation,
    artifact_state: &ArtifactState,
) -> Result<Separation, CheckError> {
    Ok(Separation {
        predicate: primitive_formula(step, &schema.predicate, artifact_state)?.into_owned(),
        element: schema.element,
        source: schema.source,
        result: schema.result,
        parameters: schema.parameters.clone(),
    })
}

fn primitive_replacement(
    step: u32,
    schema: &ProofReplacement,
    artifact_state: &ArtifactState,
) -> Result<Replacement, CheckError> {
    Ok(Replacement {
        predicate: primitive_formula(step, &schema.predicate, artifact_state)?.into_owned(),
        input: schema.input,
        output: schema.output,
        uniqueness_witness: schema.uniqueness_witness,
        source: schema.source,
        result: schema.result,
        parameters: schema.parameters.clone(),
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
    /// A referenced proof is absent from the supplied selected-artifact state.
    UnknownProofReference { step: u32, proof_id: ProofId },
    /// A definition-aware rule formula could not be conservatively expanded.
    DefinitionExpansion {
        step: u32,
        source: DefinitionExpansionError,
    },
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

impl CheckError {
    /// Returns the zero-based normal-form step that caused this failure.
    pub const fn step(&self) -> u32 {
        match self {
            Self::UnknownProofReference { step, .. }
            | Self::DefinitionExpansion { step, .. }
            | Self::Logic { step, .. }
            | Self::Schema { step, .. }
            | Self::DerivedFormula { step, .. }
            | Self::FormulaWorkLimitExceeded { step, .. }
            | Self::OpenConclusion { step } => *step,
        }
    }
}

impl fmt::Display for CheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProofReference { step, .. } => {
                write!(formatter, "proof step {step} references an unknown proof")
            }
            Self::DefinitionExpansion { step, source } => {
                write!(
                    formatter,
                    "proof step {step} cannot expand definitions: {source}"
                )
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
            Self::DefinitionExpansion { source, .. } => Some(source),
            Self::UnknownProofReference { .. }
            | Self::FormulaWorkLimitExceeded { .. }
            | Self::OpenConclusion { .. } => None,
        }
    }
}

/// A normalization or computed function-obligation definition failure.
///
/// Authoring normalization expands selected aliases before certificate
/// construction. Strict checking then constructs the exact obligation, derives
/// its statement identity, requires it from selected state, and compares the
/// complete conclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DefinitionCheckError {
    /// Authoring-only conservative body expansion failed.
    Expansion(DefinitionExpansionError),
    /// The expanded body could not be represented in the canonical formula format.
    CanonicalBody(DefinedFormulaCodecError),
    /// The expanded body could not form a strict canonical definition certificate.
    Certificate(DefinitionCertificateError),
    /// No earlier selected proof establishes the computed obligation statement.
    UnknownObligationStatement { statement_id: StatementId },
    /// The selected statement identity resolves to a conflicting conclusion.
    ObligationConclusionMismatch { statement_id: StatementId },
    /// The generated total-unique formula exceeds Foundation limits.
    ObligationFormula(FormulaCodecError),
}

impl fmt::Display for DefinitionCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expansion(source) => write!(formatter, "definition body cannot expand: {source}"),
            Self::CanonicalBody(source) => {
                write!(formatter, "canonical definition body is invalid: {source}")
            }
            Self::Certificate(source) => {
                write!(
                    formatter,
                    "canonical definition certificate is invalid: {source}"
                )
            }
            Self::UnknownObligationStatement { .. } => {
                formatter.write_str("definition obligation statement is absent from selected state")
            }
            Self::ObligationConclusionMismatch { .. } => {
                formatter.write_str("definition obligation statement has a conflicting conclusion")
            }
            Self::ObligationFormula(source) => {
                write!(
                    formatter,
                    "definition obligation is outside Formula limits: {source}"
                )
            }
        }
    }
}

impl Error for DefinitionCheckError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Expansion(source) => Some(source),
            Self::CanonicalBody(source) => Some(source),
            Self::Certificate(source) => Some(source),
            Self::ObligationFormula(source) => Some(source),
            Self::UnknownObligationStatement { .. } | Self::ObligationConclusionMismatch { .. } => {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
