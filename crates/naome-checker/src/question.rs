//! Finite, receiver-local question prefilter over checker-validated knowledge.
//!
//! This API has no storage, publication, interest or consensus effects. Its
//! PASS outcome establishes only that the supported deterministic checks
//! passed against the supplied complete local snapshot.

use std::{borrow::Cow, collections::BTreeSet};

use naome_foundation::{FOUNDATION_ID, Formula};
use naome_proof::{
    ArtifactId, CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_STEPS, ProofId, ProofStep, StatementId,
};
use sha2::{Digest, Sha256};

use crate::context::{BucketKind, StatementHeader};
use crate::{CheckError, ContextError, ContextView, statement_id};

pub type Identity = [u8; 32];

mod deduction;
mod elementary;
pub(crate) mod index;
mod instantiation;
mod registry;
pub use registry::{QuestionRegistry, QuestionRegistryCopy};

/// Hard limits for one question and the work performed by one assessment.
/// These impose no total checked-graph or registry cardinality/byte ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssessmentLimits {
    pub formula_nodes: usize,
    pub dependencies: usize,
    pub operations: usize,
    pub formula_work_bytes: usize,
    pub certificate_steps: usize,
    pub certificate_bytes: usize,
}

impl AssessmentLimits {
    pub const MAXIMUM: Self = Self {
        formula_nodes: 1024,
        dependencies: 64,
        operations: 32_768,
        formula_work_bytes: 64 * 1024 * 1024,
        certificate_steps: CERTIFICATE_MAX_STEPS,
        certificate_bytes: CERTIFICATE_MAX_BYTES,
    };

    fn values(self) -> [usize; 6] {
        [
            self.formula_nodes,
            self.dependencies,
            self.operations,
            self.formula_work_bytes,
            self.certificate_steps,
            self.certificate_bytes,
        ]
    }
}

/// Rule set 3 adds elementary certificates and target-directed universal
/// specialization to finite MP closure. Elementary certificates precede context
/// search; Q05 requires both checked implications.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefilterPolicy {
    pub revision: u64,
    pub rule_set: u64,
    pub limits: AssessmentLimits,
}

impl Default for PrefilterPolicy {
    fn default() -> Self {
        Self {
            revision: 5,
            rule_set: 3,
            limits: AssessmentLimits::MAXIMUM,
        }
    }
}

impl PrefilterPolicy {
    pub fn identity(self) -> Identity {
        let mut digest = Sha256::new();
        digest.update(b"naome:local-question-policy:v5\0");
        digest.update(self.revision.to_le_bytes());
        digest.update(self.rule_set.to_le_bytes());
        for value in self.limits.values() {
            digest.update((value as u64).to_le_bytes());
        }
        digest.finalize().into()
    }

    fn valid(self) -> bool {
        self.revision != 0
            && self.rule_set == 3
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
            .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes)
            .map_err(|_| RejectionReason::InputLimit)?
            .0;
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
            .map_err(|_| RejectionReason::InputLimit)?;
        if !formula.is_closed() {
            return Err(RejectionReason::InvalidRegistry);
        }
        Ok(Self { record, formula })
    }
}

/// The receiver supplies its actual checked context and complete owned registry.
/// The owning context cannot be chosen by the question sender. Construction
/// borrows complete incremental indexes and fingerprints in constant time.
pub struct KnowledgeSnapshot<'a> {
    identity: Identity,
    artifacts: &'a dyn ContextView,
    questions: &'a QuestionRegistry,
}

impl<'a> KnowledgeSnapshot<'a> {
    pub fn new(
        context: Identity,
        artifacts: &'a dyn ContextView,
        questions: &'a QuestionRegistry,
    ) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"naome:local-question-snapshot:v2\0");
        hash.update(context);
        hash.update(artifacts.snapshot_id());
        hash.update(questions.identity());
        Self {
            identity: hash.finalize().into(),
            artifacts,
            questions,
        }
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
pub enum PrefilterOutcome {
    Pass,
    Reject,
    /// The assessment could not complete; this is no mathematical rejection.
    Inconclusive,
}

impl PrefilterOutcome {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Reject => "REJECT",
            Self::Inconclusive => "INCONCLUSIVE",
        }
    }
}

/// Completed first-discovery checks within one exact local world and finite rule set.
/// This historical result does not authorize admission into a receiving node or
/// establish relevance, usefulness or novelty outside the bound snapshot.
///
/// Only the checker can construct or change these bindings.
///
/// ```compile_fail
/// use naome_checker::question::{NodeLocalNovelty, PrefilterDecision};
/// fn forge(decision: &PrefilterDecision) -> NodeLocalNovelty {
///     NodeLocalNovelty {
///         question: decision.question.unwrap(), input: decision.input,
///         snapshot: decision.snapshot, policy: decision.policy, rule_set: 2,
///     }
/// }
/// ```
///
/// ```compile_fail
/// use naome_checker::question::NodeLocalNovelty;
/// fn rebind(result: &mut NodeLocalNovelty) {
///     result.snapshot = [0; 32];
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeLocalNovelty {
    question: StatementId,
    input: Identity,
    snapshot: Identity,
    policy: Identity,
    rule_set: u64,
}

impl NodeLocalNovelty {
    pub const fn question_id(&self) -> StatementId {
        self.question
    }

    pub const fn input_id(&self) -> Identity {
        self.input
    }

    pub const fn snapshot_id(&self) -> Identity {
        self.snapshot
    }

    pub const fn policy_id(&self) -> Identity {
        self.policy
    }

    pub const fn rule_set(&self) -> u64 {
        self.rule_set
    }

    /// Reuse requires the identical normalized input, complete local snapshot
    /// and policy. A mismatch requires fresh receiving-node assessment.
    pub fn matches_inputs(
        &self,
        question: &AssessmentQuestion<'_>,
        snapshot: &KnowledgeSnapshot<'_>,
        policy: &PrefilterPolicy,
    ) -> bool {
        self.question == question.question
            && self.input == question.input
            && self.snapshot == snapshot.identity
            && self.policy == policy.identity()
            && self.rule_set == policy.rule_set
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefilterDecision {
    pub outcome: PrefilterOutcome,
    pub reason: Option<RejectionReason>,
    pub rule: &'static str,
    pub question: Option<StatementId>,
    pub input: Identity,
    pub snapshot: Identity,
    pub policy: Identity,
    pub witness: Option<ProofId>,
    pub supporting_witness: Option<ProofId>,
    pub related_record: Option<Identity>,
    /// Temporary checker-certified evidence, never registered as a new proof.
    pub deduction: Option<DeductionWitness>,
    novelty: Option<NodeLocalNovelty>,
}

/// A checked temporary derivation with every original cited proof identity.
/// Private fields can only be constructed after the actual checker succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeductionWitness {
    proof: ProofId,
    original_proofs: Box<[ProofId]>,
    certificate: Box<[u8]>,
}

impl DeductionWitness {
    pub const fn proof_id(&self) -> ProofId {
        self.proof
    }
    pub fn original_proofs(&self) -> &[ProofId] {
        &self.original_proofs
    }
    pub fn canonical_certificate(&self) -> &[u8] {
        &self.certificate
    }
}

impl PrefilterDecision {
    /// Classifies an answered obligation; this grants no registration authority.
    pub fn has_answer(&self) -> bool {
        matches!(
            self.reason,
            Some(
                RejectionReason::KnownProof
                    | RejectionReason::KnownRefutation
                    | RejectionReason::KnownLemmaInstance
            )
        )
    }

    pub fn inconclusive(&self) -> bool {
        self.outcome == PrefilterOutcome::Inconclusive
    }

    pub fn passed(&self) -> bool {
        self.outcome == PrefilterOutcome::Pass
    }

    /// Returns only an issued result consistent with the public decision fields.
    /// Editing a display field cannot create or rebind checker evidence. A valid
    /// self-record reassessment may pass without establishing first discovery.
    pub fn novelty(&self) -> Option<&NodeLocalNovelty> {
        let novelty = self.novelty.as_ref()?;
        (self.passed()
            && self.reason.is_none()
            && self.rule == "Q00_SUPPORTED_PREFILTER"
            && self.question == Some(novelty.question)
            && self.input == novelty.input
            && self.snapshot == novelty.snapshot
            && self.policy == novelty.policy
            && self.witness.is_none()
            && self.supporting_witness.is_none()
            && self.related_record.is_none()
            && self.deduction.is_none())
        .then_some(novelty)
    }

    /// Tests an intrinsically bound cache entry against current receiver inputs.
    pub fn matches_inputs(
        &self,
        question: &AssessmentQuestion<'_>,
        snapshot: &KnowledgeSnapshot<'_>,
        policy: &PrefilterPolicy,
    ) -> bool {
        self.question == Some(question.question)
            && self.input == question.input
            && self.snapshot == snapshot.identity
            && self.policy == policy.identity()
    }

    pub fn reject(mut self, reason: RejectionReason, rule: &'static str) -> Self {
        self.outcome = if matches!(
            reason,
            RejectionReason::ExecutionLimit
                | RejectionReason::ReceivingLimit
                | RejectionReason::StaleContext
                | RejectionReason::UnsupportedPolicy
                | RejectionReason::InvalidEvidence
        ) {
            PrefilterOutcome::Inconclusive
        } else {
            PrefilterOutcome::Reject
        };
        self.reason = Some(reason);
        self.rule = rule;
        self.novelty = None;
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
    certificate_steps: usize,
    certificate_bytes: usize,
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

// A Patricia query/iterator has at most 256 key-bit branches. Charge its
// worst-case traversal, rather than treating a cache/index hit as free work.
const INDEX_WORK_BYTES: usize = 256 * 64;

impl Work {
    fn index(&mut self) -> Result<(), (RejectionReason, &'static str)> {
        self.charge(INDEX_WORK_BYTES)
            .map_err(|e| (e, "Q08_EXECUTION"))
    }

    fn formula(
        &mut self,
        bytes: usize,
        multiplier: usize,
    ) -> Result<(), (RejectionReason, &'static str)> {
        let reserved = bytes
            .checked_mul(multiplier)
            .ok_or((RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
        self.charge(reserved).map_err(|e| (e, "Q08_EXECUTION"))
    }
}

/// Assesses one question without changing the snapshot or registering inferred
/// proofs. Every mandatory comparison covers the complete declared snapshot.
/// Rule Q04 saturates the finite MP fragment, including derived implication
/// bridges, from the complete checked context. Each successful derivation DAG
/// is checker-revalidated with original proof citations. Q05 requires
/// both checked implications. Q06 permits one or two outer universal
/// instantiations to one fresh variable, optionally followed by one universal
/// closure. Q07 also recognizes elementary logical/equality/ZFC certificates,
/// and composes target-directed specializations of up to 32 outer binders with
/// MP. Unmatched universal parameters use one deterministic default variable. Each
/// successful answer is rechecked as a bounded certificate. Resource or context
/// failures are inconclusive and never issue novelty or admission authority.
pub fn assess_question(
    question: &AssessmentQuestion<'_>,
    snapshot: &KnowledgeSnapshot<'_>,
    policy: &PrefilterPolicy,
) -> PrefilterDecision {
    let reads = crate::context::cache::ReadContext::new(snapshot.artifacts);
    let cached_snapshot = KnowledgeSnapshot {
        identity: snapshot.identity,
        artifacts: &reads,
        questions: snapshot.questions,
    };
    let snapshot = &cached_snapshot;
    let mut decision = PrefilterDecision {
        outcome: PrefilterOutcome::Pass,
        reason: None,
        rule: "Q00_SUPPORTED_PREFILTER",
        question: Some(question.question),
        input: question.input,
        snapshot: snapshot.identity,
        policy: policy.identity(),
        witness: None,
        supporting_witness: None,
        related_record: None,
        deduction: None,
        novelty: None,
    };
    if !policy.valid() {
        return decision.reject(RejectionReason::UnsupportedPolicy, "Q09_POLICY");
    }
    let mut work = Work {
        operations: policy.limits.operations,
        bytes: policy.limits.formula_work_bytes,
        certificate_steps: policy.limits.certificate_steps,
        certificate_bytes: policy.limits.certificate_bytes,
    };
    let result = evaluate(question, snapshot, policy, &mut work, &mut decision);
    match result {
        Err((reason, rule)) => decision = decision.reject(reason, rule),
        Ok(()) if question.registered_record.is_none() => {
            decision.novelty = Some(NodeLocalNovelty {
                question: question.question,
                input: question.input,
                snapshot: snapshot.identity,
                policy: policy.identity(),
                rule_set: policy.rule_set,
            });
        }
        Ok(()) => {}
    }
    decision
}

fn evaluate(
    question: &AssessmentQuestion<'_>,
    snapshot: &KnowledgeSnapshot<'_>,
    policy: &PrefilterPolicy,
    work: &mut Work,
    decision: &mut PrefilterDecision,
) -> Result<(), (RejectionReason, &'static str)> {
    if question.foundation != FOUNDATION_ID {
        return Err((RejectionReason::FoundationMismatch, "Q01_FORMAL_TARGET"));
    }
    let encoded = question
        .formula
        .encode_canonical_with_node_limit(policy.limits.formula_nodes)
        .map_err(|_| (RejectionReason::InputLimit, "Q08_INPUT"))?
        .0;
    work.formula(encoded.len(), 2)?;
    if !question.formula.is_closed() {
        return Err((RejectionReason::InvalidTarget, "Q01_FORMAL_TARGET"));
    }
    if question.dependencies.len() > policy.limits.dependencies {
        return Err((RejectionReason::DependencyLimit, "Q08_DEPENDENCIES"));
    }
    let mut references = BTreeSet::new();
    for id in question.dependencies {
        work.index()?;
        if !references.insert(*id) {
            return Err((RejectionReason::DuplicateDependency, "Q02_DEPENDENCY_LIST"));
        }
        if !snapshot
            .artifacts
            .contains_artifact(*id)
            .map_err(context_failure)?
        {
            return Err((RejectionReason::MissingDependency, "Q02_CHECKED_CONTEXT"));
        }
    }
    if let Some(record) = question.registered_record {
        work.index()?;
        work.formula(encoded.len(), 2)?;
        if snapshot
            .questions
            .get(&record)
            .map_err(context_failure)?
            .as_deref()
            != Some(question.formula)
        {
            return Err((RejectionReason::InvalidRegistry, "Q02_SELF_RECORD"));
        }
    }
    work.index()?;
    for record in snapshot
        .questions
        .records_for(question.question)
        .map_err(context_failure)?
    {
        let record = record.map_err(context_failure)?;
        work.index()?;
        work.formula(encoded.len(), 2)?;
        if Some(record) != question.registered_record
            && snapshot
                .questions
                .get(&record)
                .map_err(context_failure)?
                .as_deref()
                == Some(question.formula)
        {
            decision.related_record = Some(record);
            return Err((RejectionReason::ExactDuplicate, "Q03_CANONICAL_DUPLICATE"));
        }
    }
    work.formula(encoded.len(), 2)?;
    let negative = Formula::negate(question.formula.clone());
    let negative_bytes = negative
        .encode_canonical()
        .map_err(|_| (RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
    let targets = [
        (
            question.question,
            question.formula,
            RejectionReason::KnownProof,
        ),
        (
            statement_id(&negative_bytes),
            &negative,
            RejectionReason::KnownRefutation,
        ),
    ];
    for (target_id, target, reason) in targets {
        if let Some((proof, _)) = lookup_id(snapshot.artifacts, target_id, target, work)? {
            decision.witness = Some(proof);
            return Err((reason, "Q04_EXACT_ANSWER"));
        }
    }
    // Registry/dependency validation and exact-answer authentication still run
    // first. Context search cannot consume the work needed for an independent
    // elementary certificate, which is always checked before issuing an answer.
    for (_, target, reason) in targets {
        if let Some(plan) = elementary::plan(target, work)? {
            decision.deduction = Some(plan.finish(target, snapshot.artifacts, work)?);
            return Err((reason, "Q07_ELEMENTARY_CERTIFICATE"));
        }
    }
    for (target_id, target, reason) in targets {
        if let Some(witness) = deduction::derive(target_id, target, snapshot.artifacts, work)? {
            decision.witness = witness.original_proofs().first().copied();
            decision.supporting_witness = witness.original_proofs().get(1).copied();
            decision.deduction = Some(witness);
            return Err((reason, "Q04_CHECKED_MP_CLOSURE"));
        }
    }
    for (target_id, target, _) in targets {
        work.index()?;
        for statement in snapshot
            .artifacts
            .bucket(BucketKind::Instances, target_id)
            .map_err(context_failure)?
        {
            let statement = statement.map_err(context_failure)?;
            let header = known(snapshot.artifacts, statement, work)?;
            let proof = header.proof;
            let length = header.length;
            // Reserve all four projections and their small certificates before
            // any clone/open/substitution. Relevant bucket exhaustion rejects.
            work.formula(length + encoded.len(), 64)?;
            let premise = load_formula(snapshot.artifacts, statement, length)?;
            for instance in index::universal_instances(proof, &premise) {
                if instance.formula == *target {
                    decision.deduction =
                        Some(recheck(instance.steps, target, snapshot.artifacts, work)?);
                    decision.witness = Some(proof);
                    return Err((
                        RejectionReason::KnownLemmaInstance,
                        "Q06_CHECKED_UNIVERSAL_INSTANCE",
                    ));
                }
            }
        }
    }
    work.index()?;
    for statement in snapshot
        .artifacts
        .bucket(BucketKind::Outgoing, question.question)
        .map_err(context_failure)?
    {
        let statement = statement.map_err(context_failure)?;
        let header = known(snapshot.artifacts, statement, work)?;
        let forward_id = header.proof;
        work.formula(header.length + encoded.len(), 8)?;
        let forward = load_formula(snapshot.artifacts, statement, header.length)?;
        let (antecedent, related) = forward
            .view()
            .implication_parts()
            .expect("indexed implication");
        if antecedent != *question.formula {
            continue;
        }
        let bytes = related
            .encode_canonical()
            .map_err(|_| (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))?;
        work.index()?;
        for record in snapshot
            .questions
            .records_for(statement_id(&bytes))
            .map_err(context_failure)?
        {
            let record = record.map_err(context_failure)?;
            work.index()?;
            if Some(record) == question.registered_record
                || snapshot
                    .questions
                    .get(&record)
                    .map_err(context_failure)?
                    .as_deref()
                    .is_none_or(|formula| related != *formula)
            {
                continue;
            }
            let backward = Formula::implies(related.to_owned(), question.formula.clone());
            if let Some((backward_id, _)) = lookup(snapshot.artifacts, &backward, work)? {
                recheck(
                    vec![ProofStep::ProofReference {
                        proof_id: forward_id,
                    }],
                    &forward,
                    snapshot.artifacts,
                    work,
                )?;
                recheck(
                    vec![ProofStep::ProofReference {
                        proof_id: backward_id,
                    }],
                    &backward,
                    snapshot.artifacts,
                    work,
                )?;
                decision.witness = Some(forward_id);
                decision.supporting_witness = Some(backward_id);
                decision.related_record = Some(record);
                return Err((
                    RejectionReason::ProvenEquivalent,
                    "Q05_CHECKED_MUTUAL_IMPLICATIONS",
                ));
            }
        }
    }
    for (_, target, reason) in targets {
        if let Some(witness) = deduction::derive_instantiated(target, snapshot.artifacts, work)? {
            decision.witness = witness.original_proofs().first().copied();
            decision.supporting_witness = witness.original_proofs().get(1).copied();
            decision.deduction = Some(witness);
            return Err((reason, "Q07_CHECKED_INSTANTIATED_CLOSURE"));
        }
    }
    Ok(())
}

fn context_failure(error: ContextError) -> (RejectionReason, &'static str) {
    match error {
        ContextError::Limit => (RejectionReason::ExecutionLimit, "Q08_EXECUTION"),
        _ => (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"),
    }
}

fn known(
    artifacts: &dyn ContextView,
    statement: StatementId,
    work: &mut Work,
) -> Result<StatementHeader, (RejectionReason, &'static str)> {
    work.index()?;
    work.index()?;
    artifacts
        .statement_header(statement)
        .map_err(context_failure)?
        .ok_or((RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))
}

// Callers reserve header.length before materializing a cold formula.
fn load_formula(
    artifacts: &dyn ContextView,
    statement: StatementId,
    length: usize,
) -> Result<Cow<'_, Formula>, (RejectionReason, &'static str)> {
    artifacts
        .statement_formula(statement, length)
        .map_err(context_failure)?
        .ok_or((RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))
}

type FormulaLookup<'a> =
    Result<Option<(ProofId, Cow<'a, Formula>)>, (RejectionReason, &'static str)>;

fn lookup_id<'a>(
    artifacts: &'a dyn ContextView,
    statement: StatementId,
    formula: &Formula,
    work: &mut Work,
) -> FormulaLookup<'a> {
    work.index()?;
    work.index()?;
    let Some(header) = artifacts
        .statement_header(statement)
        .map_err(context_failure)?
    else {
        return Ok(None);
    };
    work.formula(header.length, 2)?;
    let registered = load_formula(artifacts, statement, header.length)?;
    Ok((registered.as_ref() == formula).then_some((header.proof, registered)))
}

fn lookup<'a>(
    artifacts: &'a dyn ContextView,
    formula: &Formula,
    work: &mut Work,
) -> FormulaLookup<'a> {
    let bytes = formula
        .encode_canonical()
        .map_err(|_| (RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
    work.formula(bytes.len(), 2)?;
    lookup_id(artifacts, statement_id(&bytes), formula, work)
}

fn recheck(
    steps: Vec<ProofStep>,
    target: &Formula,
    artifacts: &dyn ContextView,
    work: &mut Work,
) -> Result<DeductionWitness, (RejectionReason, &'static str)> {
    deduction::check_steps(steps, target, artifacts, work)
}

fn checker_reason(error: &CheckError) -> RejectionReason {
    match error {
        CheckError::FormulaWorkLimitExceeded { .. }
        | CheckError::DerivedFormula { .. }
        | CheckError::ContextAccess {
            source: ContextError::Limit,
            ..
        } => RejectionReason::ExecutionLimit,
        _ => RejectionReason::InvalidEvidence,
    }
}

#[cfg(test)]
mod disk_tests;
#[cfg(test)]
mod improvements;
#[cfg(test)]
mod tests;
