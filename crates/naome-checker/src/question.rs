//! Finite, receiver-local question prefilter over checker-validated knowledge.
//!
//! This API has no storage, publication, interest or consensus effects. Its
//! APPROVE outcome establishes only that the supported deterministic checks
//! passed against the supplied complete local snapshot.

use std::collections::BTreeSet;

use naome_foundation::{FOUNDATION_ID, Formula};
use naome_proof::{ArtifactId, ProofCertificate, ProofId, ProofStep, StatementId};
use sha2::{Digest, Sha256};

use crate::{ArtifactState, CheckError, normalize_and_check_with_state, statement_id};

pub type Identity = [u8; 32];

pub(crate) mod index;
mod registry;
pub use registry::QuestionRegistry;

/// Hard limits for one question and the work performed by one assessment.
/// These impose no total checked-graph or registry cardinality/byte ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssessmentLimits {
    pub formula_nodes: usize,
    pub dependencies: usize,
    pub operations: usize,
    pub formula_work_bytes: usize,
}

impl AssessmentLimits {
    pub const MAXIMUM: Self = Self {
        formula_nodes: 1024,
        dependencies: 64,
        operations: 32_768,
        formula_work_bytes: 64 * 1024 * 1024,
    };

    fn values(self) -> [usize; 4] {
        [
            self.formula_nodes,
            self.dependencies,
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
            revision: 2,
            rule_set: 1,
            limits: AssessmentLimits::MAXIMUM,
        }
    }
}

impl ApprovalPolicy {
    pub fn identity(self) -> Identity {
        let mut digest = Sha256::new();
        digest.update(b"naome:local-question-policy:v2\0");
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
    artifacts: &'a ArtifactState,
    questions: &'a QuestionRegistry,
}

impl<'a> KnowledgeSnapshot<'a> {
    pub fn new(
        context: Identity,
        artifacts: &'a ArtifactState,
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
        if !snapshot.artifacts.question_index.contains_artifact(id) {
            return Err((RejectionReason::MissingDependency, "Q02_CHECKED_CONTEXT"));
        }
    }
    if let Some(record) = question.registered_record {
        work.index()?;
        work.formula(encoded.len(), 2)?;
        if snapshot.questions.get(&record) != Some(question.formula) {
            return Err((RejectionReason::InvalidRegistry, "Q02_SELF_RECORD"));
        }
    }
    work.index()?;
    for record in snapshot.questions.records_for(question.question) {
        work.index()?;
        work.formula(encoded.len(), 2)?;
        if Some(record) != question.registered_record
            && snapshot.questions.get(&record) == Some(question.formula)
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
    for (target_id, target, reason) in targets {
        work.index()?;
        for statement in snapshot.artifacts.question_index.incoming(target_id) {
            let (bridge, implication, length) = known(snapshot.artifacts, statement, work)?;
            work.formula(length + encoded.len(), 8)?;
            let (premise, consequence) = implication
                .implication_parts()
                .expect("indexed implication");
            if consequence != *target {
                continue;
            }
            if let Some((premise_id, _)) = lookup(snapshot.artifacts, &premise, work)? {
                recheck(
                    vec![
                        ProofStep::ProofReference {
                            proof_id: premise_id,
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
                decision.witness = Some(premise_id);
                decision.supporting_witness = Some(bridge);
                return Err((reason, "Q04_CHECKED_TRANSFER"));
            }
        }
    }
    for (target_id, target, _) in targets {
        work.index()?;
        for statement in snapshot.artifacts.question_index.instances(target_id) {
            let (proof, premise, length) = known(snapshot.artifacts, statement, work)?;
            // Reserve all four projections and their small certificates before
            // any clone/open/substitution. Relevant bucket exhaustion rejects.
            work.formula(length + encoded.len(), 64)?;
            for instance in index::universal_instances(proof, premise) {
                if instance.formula == *target {
                    recheck(instance.steps, target, snapshot.artifacts, work)?;
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
        .question_index
        .outgoing(question.question)
    {
        let (forward_id, forward, length) = known(snapshot.artifacts, statement, work)?;
        work.formula(length + encoded.len(), 8)?;
        let (antecedent, related) = forward.implication_parts().expect("indexed implication");
        if antecedent != *question.formula {
            continue;
        }
        let bytes = related
            .encode_canonical()
            .map_err(|_| (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))?;
        work.index()?;
        for record in snapshot.questions.records_for(statement_id(&bytes)) {
            work.index()?;
            if Some(record) == question.registered_record
                || snapshot.questions.get(&record) != Some(&related)
            {
                continue;
            }
            let backward = Formula::implies(related.clone(), question.formula.clone());
            if let Some((backward_id, _)) = lookup(snapshot.artifacts, &backward, work)? {
                recheck(
                    vec![ProofStep::ProofReference {
                        proof_id: forward_id,
                    }],
                    forward,
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
    Ok(())
}

fn known<'a>(
    artifacts: &'a ArtifactState,
    statement: StatementId,
    work: &mut Work,
) -> Result<(ProofId, &'a Formula, usize), (RejectionReason, &'static str)> {
    work.index()?;
    work.index()?;
    artifacts
        .known_statement(statement)
        .ok_or((RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT"))
}

fn lookup_id<'a>(
    artifacts: &'a ArtifactState,
    statement: StatementId,
    formula: &Formula,
    work: &mut Work,
) -> Result<Option<(ProofId, &'a Formula)>, (RejectionReason, &'static str)> {
    work.index()?;
    work.index()?;
    let Some((proof, registered, length)) = artifacts.known_statement(statement) else {
        return Ok(None);
    };
    work.formula(length, 2)?;
    Ok((registered == formula).then_some((proof, registered)))
}

fn lookup<'a>(
    artifacts: &'a ArtifactState,
    formula: &Formula,
    work: &mut Work,
) -> Result<Option<(ProofId, &'a Formula)>, (RejectionReason, &'static str)> {
    let bytes = formula
        .encode_canonical()
        .map_err(|_| (RejectionReason::ExecutionLimit, "Q08_EXECUTION"))?;
    work.formula(bytes.len(), 2)?;
    lookup_id(artifacts, statement_id(&bytes), formula, work)
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

#[cfg(test)]
mod tests;
