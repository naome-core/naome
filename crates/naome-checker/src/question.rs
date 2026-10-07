//! Finite, receiver-local question prefilter over checker-validated knowledge.
//!
//! This API has no storage, publication, interest or consensus effects. Its
//! APPROVE outcome establishes only that the supported deterministic checks
//! passed against the supplied complete local snapshot.

use std::collections::{BTreeMap, BTreeSet};

use naome_foundation::{FOUNDATION_ID, Formula, FreeVariable, Logic};
use naome_proof::{ArtifactId, ProofCertificate, ProofId, ProofStep, StatementId};
use sha2::{Digest, Sha256};

use crate::{ArtifactState, CheckError, normalize_and_check_with_state, statement_id};

pub type Identity = [u8; 32];

/// Hard ceilings for the complete comparison scope, never a retrieval top-k.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssessmentLimits {
    pub formula_nodes: usize,
    pub proofs: usize,
    pub definitions: usize,
    pub questions: usize,
    pub dependencies: usize,
    pub comparison_bytes: usize,
    pub operations: usize,
    pub formula_work_bytes: usize,
}

impl AssessmentLimits {
    pub const MAXIMUM: Self = Self {
        formula_nodes: 1024,
        proofs: 1024,
        definitions: 1024,
        questions: 256,
        dependencies: 64,
        comparison_bytes: 1024 * 1024,
        operations: 32_768,
        formula_work_bytes: 64 * 1024 * 1024,
    };

    fn values(self) -> [usize; 8] {
        [
            self.formula_nodes,
            self.proofs,
            self.definitions,
            self.questions,
            self.dependencies,
            self.comparison_bytes,
            self.operations,
            self.formula_work_bytes,
        ]
    }
}

/// Rule set 1 is fixed; a receiving node may version or tighten its limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalPolicy {
    pub revision: u64,
    pub rule_set: u64,
    pub limits: AssessmentLimits,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            revision: 1,
            rule_set: 1,
            limits: AssessmentLimits::MAXIMUM,
        }
    }
}

impl ApprovalPolicy {
    pub fn identity(self) -> Identity {
        let mut digest = Sha256::new();
        digest.update(b"naome:local-question-policy:v1\0");
        digest.update(self.revision.to_le_bytes());
        digest.update(self.rule_set.to_le_bytes());
        for value in self.limits.values() {
            digest.update((value as u64).to_le_bytes());
        }
        digest.finalize().into()
    }

    fn valid(self) -> bool {
        self.revision != 0
            && self.rule_set == 1
            && self
                .limits
                .values()
                .into_iter()
                .zip(AssessmentLimits::MAXIMUM.values())
                .all(|(value, maximum)| value > 0 && value <= maximum)
    }
}

/// Source compilation stays with the existing caller-owned parser. `input`
/// identifies the complete bounded source/submission, including its context.
pub struct AssessmentQuestion<'a> {
    foundation: &'a str,
    formula: &'a Formula,
    question: StatementId,
    input: Identity,
    dependencies: &'a [ArtifactId],
    /// Only a verified receiver-owned registry record may be reassessed.
    registered_record: Option<Identity>,
}

impl<'a> AssessmentQuestion<'a> {
    /// Binds a complete bounded parsed submission before any policy evaluation.
    pub fn new(
        foundation: &'a str,
        formula: &'a Formula,
        source: &[u8],
        dependencies: &'a [ArtifactId],
        registered_record: Option<Identity>,
    ) -> Result<Self, RejectionReason> {
        if foundation.len() > 128 || source.len() > 16 * 1024 {
            return Err(RejectionReason::InputLimit);
        }
        if dependencies.len() > AssessmentLimits::MAXIMUM.dependencies {
            return Err(RejectionReason::DependencyLimit);
        }
        let bytes = formula
            .encode_canonical()
            .map_err(|_| RejectionReason::InputLimit)?;
        let mut hash = Sha256::new();
        hash.update(b"naome:local-question-input:v1\0");
        for field in [foundation.as_bytes(), source, bytes.as_slice()] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field);
        }
        hash.update((dependencies.len() as u64).to_le_bytes());
        for id in dependencies {
            hash.update(id.as_bytes());
        }
        hash.update([u8::from(registered_record.is_some())]);
        if let Some(record) = registered_record {
            hash.update(record);
        }
        Ok(Self {
            foundation,
            formula,
            question: statement_id(&bytes),
            dependencies,
            registered_record,
            input: hash.finalize().into(),
        })
    }
}

#[derive(Clone, Copy)]
pub struct RegisteredQuestion<'a> {
    record: Identity,
    formula: &'a Formula,
}

impl<'a> RegisteredQuestion<'a> {
    pub fn new(record: Identity, formula: &'a Formula) -> Result<Self, RejectionReason> {
        formula
            .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes)
            .map_err(|_| RejectionReason::ComparisonLimit)?;
        if !formula.is_closed() {
            return Err(RejectionReason::InvalidRegistry);
        }
        Ok(Self { record, formula })
    }
}

/// The receiver supplies its actual checked context and complete registry.
/// `context` must bind that owning state even when acquisition exceeds limits;
/// it cannot be chosen by the question sender. No unchecked proof is accepted.
pub struct KnowledgeSnapshot<'a> {
    identity: Identity,
    artifacts: &'a ArtifactState,
    questions: &'a [RegisteredQuestion<'a>],
}

impl<'a> KnowledgeSnapshot<'a> {
    /// Construction fingerprints the complete registry before tighter policy
    /// checks. The artifact fingerprint covers every checker-registered object.
    pub fn new(
        context: Identity,
        artifacts: &'a ArtifactState,
        questions: &'a [RegisteredQuestion<'a>],
    ) -> Result<Self, RejectionReason> {
        if questions.len() > AssessmentLimits::MAXIMUM.questions {
            return Err(RejectionReason::ComparisonLimit);
        }
        let mut entries = BTreeMap::new();
        for entry in questions {
            let bytes = entry
                .formula
                .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes)
                .map_err(|_| RejectionReason::ComparisonLimit)?
                .0;
            if !entry.formula.is_closed() || entries.insert(entry.record, bytes).is_some() {
                return Err(RejectionReason::InvalidRegistry);
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"naome:local-question-snapshot:v1\0");
        hash.update(context);
        hash.update(artifacts.snapshot_id());
        hash.update((entries.len() as u64).to_le_bytes());
        for (record, bytes) in entries {
            hash.update(record);
            hash.update((bytes.len() as u64).to_le_bytes());
            hash.update(bytes);
        }
        Ok(Self {
            identity: hash.finalize().into(),
            artifacts,
            questions,
        })
    }

    pub const fn identity(&self) -> Identity {
        self.identity
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    UnsupportedPolicy,
    FoundationMismatch,
    InvalidTarget,
    MissingDependency,
    DuplicateDependency,
    InvalidRegistry,
    InvalidEvidence,
    InputLimit,
    DependencyLimit,
    ComparisonLimit,
    ExecutionLimit,
    ExactDuplicate,
    KnownProof,
    KnownRefutation,
    ProvenEquivalent,
    KnownLemmaInstance,
    StaleContext,
    ReceivingLimit,
}

impl RejectionReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPolicy => "UNSUPPORTED_POLICY",
            Self::FoundationMismatch => "FOUNDATION_MISMATCH",
            Self::InvalidTarget => "INVALID_TARGET",
            Self::MissingDependency => "MISSING_DEPENDENCY",
            Self::DuplicateDependency => "DUPLICATE_DEPENDENCY",
            Self::InvalidRegistry => "INVALID_REGISTRY",
            Self::InvalidEvidence => "INVALID_EVIDENCE",
            Self::InputLimit => "INPUT_LIMIT",
            Self::DependencyLimit => "DEPENDENCY_LIMIT",
            Self::ComparisonLimit => "COMPARISON_LIMIT",
            Self::ExecutionLimit => "EXECUTION_LIMIT",
            Self::ExactDuplicate => "EXACT_DUPLICATE",
            Self::KnownProof => "KNOWN_PROOF",
            Self::KnownRefutation => "KNOWN_REFUTATION",
            Self::ProvenEquivalent => "PROVEN_EQUIVALENT",
            Self::KnownLemmaInstance => "KNOWN_LEMMA_INSTANCE",
            Self::StaleContext => "STALE_CONTEXT",
            Self::ReceivingLimit => "RECEIVING_LIMIT",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approve,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub outcome: ApprovalOutcome,
    pub reason: Option<RejectionReason>,
    pub rule: &'static str,
    pub question: Option<StatementId>,
    pub input: Identity,
    pub snapshot: Identity,
    pub policy: Identity,
    pub witness: Option<ProofId>,
    pub supporting_witness: Option<ProofId>,
    pub related_record: Option<Identity>,
}

impl ApprovalDecision {
    pub fn approved(&self) -> bool {
        self.outcome == ApprovalOutcome::Approve
    }

    /// Tests an intrinsically bound cache entry against current receiver inputs.
    pub fn matches_inputs(
        &self,
        question: &AssessmentQuestion<'_>,
        snapshot: &KnowledgeSnapshot<'_>,
        policy: &ApprovalPolicy,
    ) -> bool {
        self.question == Some(question.question)
            && self.input == question.input
            && self.snapshot == snapshot.identity
            && self.policy == policy.identity()
    }

    pub fn reject(mut self, reason: RejectionReason, rule: &'static str) -> Self {
        self.outcome = ApprovalOutcome::Reject;
        self.reason = Some(reason);
        self.rule = rule;
        self
    }

    pub fn same_context(&self, other: &Self) -> bool {
        self.question == other.question
            && self.input == other.input
            && self.snapshot == other.snapshot
            && self.policy == other.policy
    }
}

struct Work {
    operations: usize,
    bytes: usize,
}
impl Work {
    fn charge(&mut self, bytes: usize) -> Result<(), RejectionReason> {
        self.operations = self
            .operations
            .checked_sub(1)
            .ok_or(RejectionReason::ExecutionLimit)?;
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or(RejectionReason::ExecutionLimit)?;
        Ok(())
    }
}

type Known<'a> = BTreeMap<StatementId, (ProofId, &'a Formula)>;

/// Assesses one question without changing the snapshot or registering inferred
/// proofs. Every mandatory comparison covers the complete declared snapshot.
/// Rule Q04 permits exactly one checked modus-ponens transfer. Q05 requires
/// both checked implications. Q06 permits one or two outer universal
/// instantiations to one fresh variable, optionally followed by one universal
/// closure. Each matching inference is rechecked as a bounded certificate.
pub fn assess_question(
    question: &AssessmentQuestion<'_>,
    snapshot: &KnowledgeSnapshot<'_>,
    policy: &ApprovalPolicy,
) -> ApprovalDecision {
    let mut decision = ApprovalDecision {
        outcome: ApprovalOutcome::Approve,
        reason: None,
        rule: "Q00_SUPPORTED_PREFILTER",
        question: Some(question.question),
        input: question.input,
        snapshot: snapshot.identity,
        policy: policy.identity(),
        witness: None,
        supporting_witness: None,
        related_record: None,
    };
    if !policy.valid() {
        return decision.reject(RejectionReason::UnsupportedPolicy, "Q09_POLICY");
    }
    let mut work = Work {
        operations: policy.limits.operations,
        bytes: policy.limits.formula_work_bytes,
    };
    let result = evaluate(question, snapshot, policy, &mut work, &mut decision);
    if let Err((reason, rule)) = result {
        decision = decision.reject(reason, rule);
    }
    decision
}

fn evaluate(
    question: &AssessmentQuestion<'_>,
    snapshot: &KnowledgeSnapshot<'_>,
    policy: &ApprovalPolicy,
    work: &mut Work,
    decision: &mut ApprovalDecision,
) -> Result<(), (RejectionReason, &'static str)> {
    let mut known = Known::new();
    let mut available = BTreeSet::new();
    let mut comparison_bytes = 0usize;
    for (index, (proof, statement, formula, length)) in
        snapshot.artifacts.proof_conclusions().enumerate()
    {
        if index >= policy.limits.proofs {
            return Err((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"));
        }
        comparison_bytes = comparison_bytes
            .checked_add(length)
            .ok_or((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"))?;
        if comparison_bytes > policy.limits.comparison_bytes {
            return Err((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"));
        }
        work.charge(length).map_err(|e| (e, "Q08_EXECUTION"))?;
        available.insert(ArtifactId::from_proof_id(proof));
        known.entry(statement).or_insert((proof, formula));
    }
    for (index, definition) in snapshot.artifacts.definition_ids().enumerate() {
        if index >= policy.limits.definitions {
            return Err((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"));
        }
        work.charge(32).map_err(|e| (e, "Q08_EXECUTION"))?;
        available.insert(ArtifactId::from_definition_id(definition));
    }
    if snapshot.questions.len() > policy.limits.questions {
        return Err((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"));
    }
    let mut registry = BTreeMap::new();
    for entry in snapshot.questions {
        let bytes = entry
            .formula
            .encode_canonical_with_node_limit(policy.limits.formula_nodes)
            .map_err(|_| (RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"))?
            .0;
        work.charge(bytes.len()).map_err(|e| (e, "Q08_EXECUTION"))?;
        comparison_bytes = comparison_bytes
            .checked_add(bytes.len())
            .ok_or((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"))?;
        if comparison_bytes > policy.limits.comparison_bytes {
            return Err((RejectionReason::ComparisonLimit, "Q08_COMPLETE_SCOPE"));
        }
        if !entry.formula.is_closed()
            || registry
                .insert(entry.record, (entry.formula, bytes))
                .is_some()
        {
            return Err((RejectionReason::InvalidRegistry, "Q02_CHECKED_CONTEXT"));
        }
    }
    if question.foundation != FOUNDATION_ID {
        return Err((RejectionReason::FoundationMismatch, "Q01_FORMAL_TARGET"));
    }
    let encoded = question
        .formula
        .encode_canonical_with_node_limit(policy.limits.formula_nodes)
        .map_err(|_| (RejectionReason::InputLimit, "Q08_INPUT"))?
        .0;
    work.charge(encoded.len())
        .map_err(|e| (e, "Q08_EXECUTION"))?;
    decision.question = Some(statement_id(&encoded));
    if !question.formula.is_closed() {
        return Err((RejectionReason::InvalidTarget, "Q01_FORMAL_TARGET"));
    }
    if question.dependencies.len() > policy.limits.dependencies {
        return Err((RejectionReason::DependencyLimit, "Q08_DEPENDENCIES"));
    }
    let mut references = BTreeSet::new();
    for id in question.dependencies {
        work.charge(32).map_err(|e| (e, "Q08_EXECUTION"))?;
        if !references.insert(*id) {
            return Err((RejectionReason::DuplicateDependency, "Q02_DEPENDENCY_LIST"));
        }
        if !available.contains(id) {
            return Err((RejectionReason::MissingDependency, "Q02_CHECKED_CONTEXT"));
        }
    }
    if let Some(record) = question.registered_record
        && !registry
            .get(&record)
            .is_some_and(|(formula, _)| *formula == question.formula)
    {
        return Err((RejectionReason::InvalidRegistry, "Q02_SELF_RECORD"));
    }
    for (record, (formula, bytes)) in &registry {
        work.charge(bytes.len() + encoded.len())
            .map_err(|e| (e, "Q08_EXECUTION"))?;
        if Some(*record) != question.registered_record && *formula == question.formula {
            decision.related_record = Some(*record);
            return Err((RejectionReason::ExactDuplicate, "Q03_CANONICAL_DUPLICATE"));
        }
    }
    let negative = Formula::negate(question.formula.clone());
    for (target, reason) in [
        (question.formula, RejectionReason::KnownProof),
        (&negative, RejectionReason::KnownRefutation),
    ] {
        if let Some((proof, _)) = lookup(&known, target, work)? {
            decision.witness = Some(proof);
            return Err((reason, "Q04_EXACT_ANSWER"));
        }
    }
    for (premise_id, premise) in known.values() {
        let premise_bytes = premise
            .encode_canonical()
            .map_err(|_| (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))?
            .len();
        work.charge(premise_bytes * 4 + encoded.len() * 4)
            .map_err(|e| (e, "Q08_EXECUTION"))?;
        for (target, reason) in [
            (question.formula, RejectionReason::KnownProof),
            (&negative, RejectionReason::KnownRefutation),
        ] {
            let implication = Formula::implies((*premise).clone(), target.clone());
            if let Some((bridge, _)) = lookup(&known, &implication, work)? {
                recheck(
                    vec![
                        ProofStep::ProofReference {
                            proof_id: *premise_id,
                        },
                        ProofStep::ProofReference { proof_id: bridge },
                        ProofStep::ModusPonens {
                            premise: 0,
                            implication: 1,
                        },
                    ],
                    target,
                    snapshot.artifacts,
                    work,
                )?;
                decision.witness = Some(*premise_id);
                decision.supporting_witness = Some(bridge);
                return Err((reason, "Q04_CHECKED_TRANSFER"));
            }
        }
        if specialize(
            *premise_id,
            premise,
            question.formula,
            &negative,
            snapshot.artifacts,
            work,
        )? {
            decision.witness = Some(*premise_id);
            return Err((
                RejectionReason::KnownLemmaInstance,
                "Q06_CHECKED_UNIVERSAL_INSTANCE",
            ));
        }
    }
    for (record, (formula, bytes)) in &registry {
        if Some(*record) == question.registered_record {
            continue;
        }
        work.charge(bytes.len() * 4 + encoded.len() * 4)
            .map_err(|e| (e, "Q08_EXECUTION"))?;
        let forward = Formula::implies(question.formula.clone(), (*formula).clone());
        let backward = Formula::implies((*formula).clone(), question.formula.clone());
        if let (Some((first, _)), Some((second, _))) = (
            lookup(&known, &forward, work)?,
            lookup(&known, &backward, work)?,
        ) {
            decision.witness = Some(first);
            decision.supporting_witness = Some(second);
            decision.related_record = Some(*record);
            return Err((
                RejectionReason::ProvenEquivalent,
                "Q05_CHECKED_MUTUAL_IMPLICATIONS",
            ));
        }
    }
    Ok(())
}

fn lookup<'a>(
    known: &Known<'a>,
    formula: &Formula,
    work: &mut Work,
) -> Result<Option<(ProofId, &'a Formula)>, (RejectionReason, &'static str)> {
    let bytes = formula
        .encode_canonical()
        .map_err(|_| (RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
    work.charge(bytes.len()).map_err(|e| (e, "Q08_EXECUTION"))?;
    Ok(known
        .get(&statement_id(&bytes))
        .copied()
        .filter(|(_, registered)| *registered == formula))
}

fn recheck(
    steps: Vec<ProofStep>,
    target: &Formula,
    artifacts: &ArtifactState,
    work: &mut Work,
) -> Result<(), (RejectionReason, &'static str)> {
    let mut referenced = 0usize;
    for step in &steps {
        if let ProofStep::ProofReference { proof_id } = step {
            let proof = artifacts
                .resolve_proof(*proof_id)
                .ok_or((RejectionReason::MissingDependency, "Q02_CHECKED_CONTEXT"))?;
            referenced = referenced
                .checked_add(proof.canonical_length)
                .ok_or((RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
        }
    }
    let certificate = ProofCertificate::new(steps)
        .map_err(|_| (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))?;
    let target_bytes = target
        .encode_canonical()
        .map_err(|_| (RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?
        .len();
    // At most seven synthetic steps: charge explicit formulas, each resolved
    // citation, intermediate reconstruction, rule inputs and final comparison
    // conservatively BEFORE invoking the checker, including referenced data.
    let reserved = certificate
        .to_canonical_bytes()
        .len()
        .checked_add(referenced)
        .and_then(|value| value.checked_add(target_bytes))
        .and_then(|value| value.checked_mul(16))
        .ok_or((RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
    work.charge(reserved).map_err(|e| (e, "Q08_EXECUTION"))?;
    let checked = normalize_and_check_with_state(certificate, artifacts).map_err(|error| {
        let reason = checker_reason(&error);
        (
            reason,
            if reason == RejectionReason::ExecutionLimit {
                "Q08_EXECUTION"
            } else {
                "Q02_CHECKED_CONTEXT"
            },
        )
    })?;
    if checked.conclusion() != target {
        return Err((RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"));
    }
    Ok(())
}

fn checker_reason(error: &CheckError) -> RejectionReason {
    match error {
        CheckError::FormulaWorkLimitExceeded { .. } | CheckError::DerivedFormula { .. } => {
            RejectionReason::ExecutionLimit
        }
        _ => RejectionReason::InvalidEvidence,
    }
}

fn specialize(
    proof_id: ProofId,
    premise: &Formula,
    positive: &Formula,
    negative: &Formula,
    artifacts: &ArtifactState,
    work: &mut Work,
) -> Result<bool, (RejectionReason, &'static str)> {
    let replacement = FreeVariable::new(0);
    let mut current = premise.clone();
    let mut steps = vec![ProofStep::ProofReference { proof_id }];
    for level in 0..2 {
        let fresh = FreeVariable::new(2 + level);
        let Some(body) = current.open_outer_universal(fresh) else {
            break;
        };
        let length = body
            .encode_canonical()
            .map_err(|_| (RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?
            .len();
        work.charge(length * 16).map_err(|e| (e, "Q08_EXECUTION"))?;
        let axiom = Logic::universal_instantiation(fresh, replacement, body.clone());
        let next = Logic::modus_ponens(&current, &axiom)
            .map_err(|_| (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))?;
        let previous = (steps.len() - 1) as u32;
        let implication = steps.len() as u32;
        steps.push(ProofStep::UniversalInstantiation {
            variable: fresh,
            replacement,
            body: body.into(),
        });
        steps.push(ProofStep::ModusPonens {
            premise: previous,
            implication,
        });
        current = next;
        if current == *positive || current == *negative {
            recheck(steps, &current, artifacts, work)?;
            return Ok(true);
        }
        let closed = Logic::generalization(replacement, current.clone());
        if closed == *positive || closed == *negative {
            let mut closed_steps = steps.clone();
            closed_steps.push(ProofStep::Generalization {
                variable: replacement,
                premise: (steps.len() - 1) as u32,
            });
            recheck(closed_steps, &closed, artifacts, work)?;
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests;
