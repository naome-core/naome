//! Complete finite MP closure over checked facts and their consequent spines.
//!
//! A projected consequence is only a candidate clause. All leading antecedents
//! must be seeded or previously derived. The final dependency DAG is materialized
//! iteratively and checker-revalidated with the original concrete proof IDs.

use std::collections::{BTreeMap, BTreeSet};

use naome_foundation::{Formula, FreeVariable};
use naome_proof::{
    CERTIFICATE_MAX_BYTES, CERTIFICATE_MAX_FORMULA_NODES, CERTIFICATE_MAX_STEPS, ProofCertificate,
    ProofCertificateError, ProofId, ProofStep, StatementId,
};

use super::{
    DeductionWitness, INDEX_WORK_BYTES, RejectionReason, Work, checker_reason, context_failure,
    known, load_formula, lookup_id,
};
use crate::{
    CHECKER_MAX_FORMULA_WORK_BYTES, ContextView, normalize_and_check_with_state, statement_id,
};

pub(super) type Failure = (RejectionReason, &'static str);
pub(super) const LIMIT: Failure = (RejectionReason::ExecutionLimit, "Q08_EXECUTION");
pub(super) const INVALID: Failure = (RejectionReason::InvalidEvidence, "Q02_CHECKED_CONTEXT");

struct Goal {
    formula: Formula,
    length: usize,
    seed: Option<Source>,
}
struct Clause {
    source: Source,
    premises: Vec<StatementId>,
    consequence: StatementId,
    intermediate_lengths: Vec<usize>,
}
#[derive(Clone, Copy)]
enum Evidence {
    Seed(StatementId),
    Derived(usize),
}

enum Source {
    Proof(ProofId),
    Generated(Program),
}

fn add_goal(
    formula: Formula,
    upper_length: usize,
    goals: &mut BTreeMap<StatementId, Goal>,
    pending: &mut BTreeSet<StatementId>,
    work: &mut Work,
) -> Result<StatementId, Failure> {
    work.formula(upper_length, 8)?;
    let bytes = formula.encode_canonical().map_err(|_| LIMIT)?;
    if bytes.len() > upper_length {
        return Err(INVALID);
    }
    let id = statement_id(&bytes);
    work.index()?;
    if let Some(existing) = goals.get(&id) {
        if existing.formula != formula {
            return Err(INVALID);
        }
        return Ok(id);
    }
    work.charge(std::mem::size_of::<Goal>() + 128)
        .map_err(|_| LIMIT)?;
    goals.insert(
        id,
        Goal {
            formula,
            length: bytes.len(),
            seed: None,
        },
    );
    pending.insert(id);
    Ok(id)
}

mod search;

/// The same resumable search drives both ordinary and instantiated closure.
/// An answer is sufficient for rejection; PASS requires both searches to finish.
pub(super) fn derive_answers(
    targets: [&Formula; 2],
    artifacts: &dyn ContextView,
    work: &mut Work,
    instantiated: bool,
) -> Result<Option<(usize, DeductionWitness)>, Failure> {
    let mut searches = [
        Some(search::Search::new(
            targets[0],
            artifacts,
            instantiated,
            work,
        )?),
        Some(search::Search::new(
            targets[1],
            artifacts,
            instantiated,
            work,
        )?),
    ];
    let mut exhausted = false;
    while searches.iter().any(Option::is_some) {
        for (index, slot) in searches.iter_mut().enumerate() {
            let Some(search) = slot else { continue };
            match search.advance(work) {
                Ok(search::Progress::Pending) => {}
                Ok(search::Progress::Complete(Some(witness))) => return Ok(Some((index, witness))),
                Ok(search::Progress::Complete(None)) => *slot = None,
                Err((RejectionReason::ExecutionLimit, _)) => {
                    // A failed large reservation may leave enough shared work
                    // for the opposite target. No incomplete search issues PASS.
                    exhausted = true;
                    *slot = None;
                }
                Err(error) => return Err(error),
            }
        }
    }
    if exhausted { Err(LIMIT) } else { Ok(None) }
}

#[cfg(test)]
pub(super) fn derive(
    target_id: StatementId,
    target: &Formula,
    artifacts: &dyn ContextView,
    work: &mut Work,
) -> Result<Option<DeductionWitness>, Failure> {
    if statement_id(&target.encode_canonical().map_err(|_| LIMIT)?) != target_id {
        return Err(INVALID);
    }
    let mut search = search::Search::new(target, artifacts, false, work)?;
    loop {
        if let search::Progress::Complete(witness) = search.advance(work)? {
            return Ok(witness);
        }
    }
}

struct PlannedStep {
    step: ProofStep,
    length: usize,
}
pub(super) struct Program {
    steps: Vec<PlannedStep>,
}
pub(super) struct Plan {
    steps: Vec<PlannedStep>,
    encoded_bytes: usize,
    checker_work: usize,
    references: BTreeMap<ProofId, u32>,
}

impl Work {
    fn certificate_limits(&self, steps: usize, bytes: usize) -> Result<(), Failure> {
        if steps == 0
            || steps > self.certificate_steps
            || steps > CERTIFICATE_MAX_STEPS
            || bytes > self.certificate_bytes
            || bytes > CERTIFICATE_MAX_BYTES
        {
            return Err(LIMIT);
        }
        Ok(())
    }

    fn reserve_certificate(
        &mut self,
        steps: usize,
        bytes: usize,
        checker_work: usize,
        references: usize,
    ) -> Result<(), Failure> {
        self.certificate_limits(steps, bytes)?;
        if checker_work > CHECKER_MAX_FORMULA_WORK_BYTES {
            return Err(LIMIT);
        }
        let levels = (usize::BITS - steps.max(2).leading_zeros()) as usize;
        let operations = steps
            .checked_mul(levels + 2)
            .and_then(|n| n.checked_add(references.checked_mul(3)?))
            .ok_or(LIMIT)?;
        self.operations = self.operations.checked_sub(operations).ok_or(LIMIT)?;
        let metadata = steps
            .checked_mul(std::mem::size_of::<ProofStep>() * 8 + 128)
            .ok_or(LIMIT)?;
        let reserved = bytes
            .checked_mul(16)
            .and_then(|n| n.checked_add(checker_work.checked_mul(8)?))
            .and_then(|n| n.checked_add(metadata))
            .and_then(|n| n.checked_add(references.checked_mul(INDEX_WORK_BYTES * 3)?))
            .ok_or(LIMIT)?;
        // Actual step/reference/intermediate work replaces the old seven-step
        // premise. Reserve before construction, normalization and checking.
        self.charge(reserved).map_err(|_| LIMIT)
    }
}

impl Plan {
    pub(super) fn into_program(self) -> Program {
        Program { steps: self.steps }
    }

    fn append(
        &mut self,
        program: &Program,
        artifacts: &dyn ContextView,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        work.charge(program.steps.len().checked_mul(8).ok_or(LIMIT)?)
            .map_err(|_| LIMIT)?;
        let mut remapped = Vec::new();
        for entry in &program.steps {
            let position = match &entry.step {
                ProofStep::ProofReference { proof_id } => {
                    self.reference(*proof_id, artifacts, work)?
                }
                ProofStep::ModusPonens {
                    premise,
                    implication,
                } => self.modus_ponens(
                    remapped[*premise as usize],
                    remapped[*implication as usize],
                    entry.length,
                    work,
                )?,
                ProofStep::Generalization { premise, variable } => {
                    self.generalize(remapped[*premise as usize], *variable, work)?
                }
                step => {
                    work.formula(entry.length, 8)?;
                    self.axiom(step.clone(), entry.length, work)?
                }
            };
            if self.steps[position as usize].length != entry.length {
                return Err(INVALID);
            }
            remapped.push(position);
        }
        remapped.last().copied().ok_or(INVALID)
    }

    fn source(
        &mut self,
        source: &Source,
        artifacts: &dyn ContextView,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        match source {
            Source::Proof(proof) => self.reference(*proof, artifacts, work),
            Source::Generated(program) => self.append(program, artifacts, work),
        }
    }

    pub(super) fn new() -> Self {
        Self {
            steps: Vec::new(),
            encoded_bytes: 4,
            checker_work: 0,
            references: BTreeMap::new(),
        }
    }

    fn push(
        &mut self,
        step: ProofStep,
        length: usize,
        encoded: usize,
        checker_work: usize,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        let count = self.steps.len().checked_add(1).ok_or(LIMIT)?;
        let bytes = self.encoded_bytes.checked_add(encoded).ok_or(LIMIT)?;
        work.certificate_limits(count, bytes)?;
        let total_work = self.checker_work.checked_add(checker_work).ok_or(LIMIT)?;
        if total_work > CHECKER_MAX_FORMULA_WORK_BYTES {
            return Err(LIMIT);
        }
        work.charge(std::mem::size_of::<PlannedStep>() * 4 + 128)
            .map_err(|_| LIMIT)?;
        let index = u32::try_from(self.steps.len()).map_err(|_| LIMIT)?;
        self.steps.push(PlannedStep { step, length });
        self.encoded_bytes = bytes;
        self.checker_work = total_work;
        Ok(index)
    }

    pub(super) fn reference(
        &mut self,
        proof_id: ProofId,
        artifacts: &dyn ContextView,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        work.index()?;
        if let Some(index) = self.references.get(&proof_id) {
            return Ok(*index);
        }
        for _ in 0..3 {
            work.index()?;
        }
        let proof = artifacts
            .proof_header(proof_id)
            .map_err(context_failure)?
            .ok_or(INVALID)?;
        let index = self.push(
            ProofStep::ProofReference { proof_id },
            proof.length,
            33,
            proof.length,
            work,
        )?;
        self.references.insert(proof_id, index);
        Ok(index)
    }

    pub(super) fn modus_ponens(
        &mut self,
        premise: u32,
        implication: u32,
        length: usize,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        let inputs = self.steps[premise as usize]
            .length
            .checked_add(self.steps[implication as usize].length)
            .and_then(|n| n.checked_add(length))
            .ok_or(LIMIT)?;
        self.push(
            ProofStep::ModusPonens {
                premise,
                implication,
            },
            length,
            9,
            inputs,
            work,
        )
    }

    pub(super) fn axiom(
        &mut self,
        step: ProofStep,
        length: usize,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        if step
            .local_references()
            .into_iter()
            .any(|reference| reference.is_some())
        {
            return Err(INVALID);
        }
        work.formula(length, 8)?;
        let encoded = step.encoded_length().map_err(|_| LIMIT)?;
        self.push(step, length, encoded, length, work)
    }

    pub(super) fn generalize(
        &mut self,
        premise: u32,
        variable: FreeVariable,
        work: &mut Work,
    ) -> Result<u32, Failure> {
        let previous = self.steps[premise as usize].length;
        let length = previous.checked_add(1).ok_or(LIMIT)?;
        self.push(
            ProofStep::Generalization { premise, variable },
            length,
            9,
            previous.checked_add(length).ok_or(LIMIT)?,
            work,
        )
    }

    pub(super) fn finish(
        self,
        target: &Formula,
        artifacts: &dyn ContextView,
        work: &mut Work,
    ) -> Result<DeductionWitness, Failure> {
        let length = self.steps.last().ok_or(INVALID)?.length;
        let checker_work = self.checker_work.checked_add(length).ok_or(LIMIT)?;
        work.reserve_certificate(
            self.steps.len(),
            self.encoded_bytes,
            checker_work,
            self.references.len(),
        )?;
        check_reserved(
            self.steps.into_iter().map(|entry| entry.step).collect(),
            target,
            artifacts,
        )
    }
}

fn materialize(
    target_id: StatementId,
    artifacts: &dyn ContextView,
    goals: &BTreeMap<StatementId, Goal>,
    clauses: &[Clause],
    evidence: &BTreeMap<StatementId, Evidence>,
    work: &mut Work,
) -> Result<Plan, Failure> {
    let mut plan = Plan::new();
    let mut outputs = BTreeMap::new();
    let mut pending = vec![(target_id, false)];
    // No recursion: MP dependency depth is independent of formula AST depth.
    while let Some((id, finish)) = pending.pop() {
        work.index()?;
        if outputs.contains_key(&id) {
            continue;
        }
        match evidence.get(&id).copied().ok_or(INVALID)? {
            Evidence::Seed(seed) => {
                let step =
                    plan.source(goals[&seed].seed.as_ref().ok_or(INVALID)?, artifacts, work)?;
                outputs.insert(id, step);
            }
            Evidence::Derived(index) => {
                let clause = &clauses[index];
                if !finish {
                    work.charge(clause.premises.len().checked_mul(128).ok_or(LIMIT)?)
                        .map_err(|_| LIMIT)?;
                    pending.push((id, true));
                    for premise in clause.premises.iter().rev() {
                        if !outputs.contains_key(premise) {
                            pending.push((*premise, false));
                        }
                    }
                } else {
                    let mut implication = plan.source(&clause.source, artifacts, work)?;
                    for (premise, length) in
                        clause.premises.iter().zip(&clause.intermediate_lengths)
                    {
                        let premise = *outputs.get(premise).ok_or(INVALID)?;
                        implication = plan.modus_ponens(premise, implication, *length, work)?;
                    }
                    if plan.steps[implication as usize].length != goals[&id].length {
                        return Err(INVALID);
                    }
                    outputs.insert(id, implication);
                }
            }
        }
    }
    let root = *outputs.get(&target_id).ok_or(INVALID)?;
    if root as usize + 1 != plan.steps.len() {
        return Err(INVALID);
    }
    Ok(plan)
}

#[allow(clippy::too_many_arguments)]
fn add_clause(
    source: Source,
    formula: &Formula,
    goal: StatementId,
    goals: &mut BTreeMap<StatementId, Goal>,
    pending: &mut BTreeSet<StatementId>,
    clauses: &mut Vec<Clause>,
    work: &mut Work,
) -> Result<(), Failure> {
    let length = formula.encode_canonical().map_err(|_| LIMIT)?.len();
    let projection = formula
        .canonical_implication()
        .map_err(|_| LIMIT)?
        .ok_or(INVALID)?;
    let mut lengths = projection.consequents().map(<[u8]>::len);
    let mut current = formula.view();
    let mut current_length = length;
    let mut antecedents = Vec::new();
    let mut intermediate_lengths = Vec::new();
    while let Some((antecedent, consequent)) = current.implication_parts() {
        work.formula(current_length, 8)?;
        work.charge(std::mem::size_of::<Formula>() + 64)
            .map_err(|_| LIMIT)?;
        antecedents.push(antecedent.to_owned());
        let next_length = lengths.next().ok_or(INVALID)?;
        intermediate_lengths.push(next_length);
        if consequent == goals[&goal].formula {
            let mut premises = Vec::new();
            for antecedent in antecedents {
                let premise = add_goal(antecedent, length, goals, pending, work)?;
                work.charge(64).map_err(|_| LIMIT)?;
                premises.push(premise);
            }
            work.charge(std::mem::size_of::<Clause>() + 128)
                .map_err(|_| LIMIT)?;
            clauses.push(Clause {
                source,
                premises,
                consequence: goal,
                intermediate_lengths,
            });
            return Ok(());
        }
        current_length = next_length;
        current = consequent;
    }
    Err(INVALID)
}

/// Preflight the small existing Q05/Q06 certificates dynamically as well.
/// Their caller reserves projection/clone work before producing these steps.
pub(super) fn check_steps(
    steps: Vec<ProofStep>,
    target: &Formula,
    artifacts: &dyn ContextView,
    work: &mut Work,
) -> Result<DeductionWitness, Failure> {
    work.certificate_limits(steps.len(), 4)?;
    work.charge(steps.len().checked_mul(64).ok_or(LIMIT)?)
        .map_err(|_| LIMIT)?;
    let mut max_reference = 0;
    let mut reference_count = 0usize;
    for step in &steps {
        if let ProofStep::ProofReference { proof_id } = step {
            for _ in 0..3 {
                work.index()?;
            }
            let proof = artifacts
                .proof_header(*proof_id)
                .map_err(context_failure)?
                .ok_or(INVALID)?;
            max_reference = max_reference.max(proof.length);
            reference_count += 1;
        }
    }
    let mut lengths: Vec<usize> = Vec::new();
    let mut encoded = 4usize;
    let mut formula_work = 0usize;
    let mut body_nodes = 0usize;
    for step in &steps {
        let (length, bytes, cost) = match step {
            ProofStep::ProofReference { proof_id } => {
                let proof = artifacts
                    .proof_header(*proof_id)
                    .map_err(context_failure)?
                    .ok_or(INVALID)?;
                (proof.length, 33, proof.length)
            }
            ProofStep::UniversalInstantiation { body, .. } => {
                work.formula(max_reference, 8)?;
                let body = body.as_primitive().ok_or(INVALID)?;
                let (bytes, nodes) = body
                    .encode_canonical_with_node_limit(CERTIFICATE_MAX_FORMULA_NODES)
                    .map_err(|_| LIMIT)?;
                body_nodes = body_nodes.checked_add(nodes).ok_or(LIMIT)?;
                if body_nodes > CERTIFICATE_MAX_FORMULA_NODES || bytes.len() > max_reference {
                    return Err(LIMIT);
                }
                let length = bytes
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(LIMIT)?;
                (length, bytes.len() + 13, length)
            }
            ProofStep::ModusPonens {
                premise,
                implication,
            } => {
                let premise = *lengths.get(*premise as usize).ok_or(INVALID)?;
                let implication = *lengths.get(*implication as usize).ok_or(INVALID)?;
                (
                    implication,
                    9,
                    premise
                        .checked_add(implication.checked_mul(2).ok_or(LIMIT)?)
                        .ok_or(LIMIT)?,
                )
            }
            ProofStep::Generalization { premise, .. } => {
                let premise = *lengths.get(*premise as usize).ok_or(INVALID)?;
                let length = premise.checked_add(1).ok_or(LIMIT)?;
                (length, 9, premise.checked_add(length).ok_or(LIMIT)?)
            }
            _ => return Err(INVALID),
        };
        lengths.push(length);
        encoded = encoded.checked_add(bytes).ok_or(LIMIT)?;
        formula_work = formula_work.checked_add(cost).ok_or(LIMIT)?;
    }
    let target_length = target.encode_canonical().map_err(|_| LIMIT)?.len();
    let formula_work = formula_work.checked_add(target_length).ok_or(LIMIT)?;
    work.reserve_certificate(steps.len(), encoded, formula_work, reference_count)?;
    check_reserved(steps, target, artifacts)
}

fn check_reserved(
    steps: Vec<ProofStep>,
    target: &Formula,
    artifacts: &dyn ContextView,
) -> Result<DeductionWitness, Failure> {
    let certificate = ProofCertificate::new(steps).map_err(|error| match error {
        ProofCertificateError::TooManySteps { .. }
        | ProofCertificateError::InputTooLong { .. }
        | ProofCertificateError::FormulaNodeLimitExceeded { .. }
        | ProofCertificateError::Formula(_)
        | ProofCertificateError::DefinedFormula(_) => LIMIT,
        _ => INVALID,
    })?;
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
        return Err(INVALID);
    }
    let original_proofs: BTreeSet<_> = checked
        .normal_form()
        .certificate()
        .steps()
        .iter()
        .filter_map(|step| {
            if let ProofStep::ProofReference { proof_id } = step {
                Some(*proof_id)
            } else {
                None
            }
        })
        .collect();
    Ok(DeductionWitness {
        proof: checked.proof_id(),
        original_proofs: original_proofs.into_iter().collect(),
        certificate: checked.normal_form().canonical_bytes().into(),
    })
}

#[cfg(test)]
mod tests;
