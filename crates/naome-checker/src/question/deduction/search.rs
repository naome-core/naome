//! Resumable reverse relevance and forward propagation. Each turn visits one
//! candidate, premise or dependent edge, so opposite targets can share a budget.
use super::*;
use crate::context::{BucketKind, StatementCursor};

enum Expansion<'a> {
    Instances(StatementId, StatementCursor<'a>),
    Deductions(StatementId, StatementCursor<'a>),
}

pub(super) enum Progress {
    Pending,
    Complete(Option<DeductionWitness>),
}

pub(super) struct Search<'a> {
    target: &'a Formula,
    root: StatementId,
    closing: Vec<FreeVariable>,
    artifacts: &'a dyn ContextView,
    instantiated: bool,
    goals: BTreeMap<StatementId, Goal>,
    pending: BTreeSet<StatementId>,
    clauses: Vec<Clause>,
    expansion: Option<Expansion<'a>>,
    indexed: usize,
    premise: usize,
    remaining: Vec<usize>,
    dependents: BTreeMap<StatementId, Vec<usize>>,
    evidence: BTreeMap<StatementId, Evidence>,
    ready: BTreeSet<StatementId>,
    propagating: Option<(StatementId, usize)>,
}

impl<'a> Search<'a> {
    pub(super) fn new(
        target: &'a Formula,
        artifacts: &'a dyn ContextView,
        instantiated: bool,
        work: &mut Work,
    ) -> Result<Self, Failure> {
        let length = target.encode_canonical().map_err(|_| LIMIT)?.len();
        work.formula(length, 8)?;
        let mut opened = target.clone();
        let mut closing = Vec::new();
        if instantiated {
            for identifier in 0..super::super::instantiation::MAX_INSTANTIATIONS {
                work.formula(length, 4)?;
                let variable = FreeVariable::new(identifier as u32);
                let Some(body) = opened.open_outer_universal(variable) else {
                    break;
                };
                closing.push(variable);
                opened = body;
            }
        }
        let mut goals = BTreeMap::new();
        let mut pending = BTreeSet::new();
        let root = add_goal(opened, length, &mut goals, &mut pending, work)?;
        Ok(Self {
            target,
            root,
            closing,
            artifacts,
            instantiated,
            goals,
            pending,
            clauses: Vec::new(),
            expansion: None,
            indexed: 0,
            premise: 0,
            remaining: Vec::new(),
            dependents: BTreeMap::new(),
            evidence: BTreeMap::new(),
            ready: BTreeSet::new(),
            propagating: None,
        })
    }

    fn establish(&mut self, id: StatementId, evidence: Evidence) {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.evidence.entry(id) {
            entry.insert(evidence);
            self.ready.insert(id);
        }
    }

    pub(super) fn advance(&mut self, work: &mut Work) -> Result<Progress, Failure> {
        if self.evidence.contains_key(&self.root) {
            let mut plan = materialize(
                self.root,
                self.artifacts,
                &self.goals,
                &self.clauses,
                &self.evidence,
                work,
            )?;
            let mut root = u32::try_from(plan.steps.len() - 1).map_err(|_| LIMIT)?;
            for variable in self.closing.iter().rev() {
                root = plan.generalize(root, *variable, work)?;
            }
            return plan
                .finish(self.target, self.artifacts, work)
                .map(|witness| Progress::Complete(Some(witness)));
        }
        if self.propagating.is_none() {
            self.propagating = self.ready.pop_first().map(|id| (id, 0));
        }
        if let Some((id, offset)) = self.propagating {
            work.index()?;
            let next = self.dependents.get(&id).and_then(|edges| edges.get(offset));
            if let Some(&index) = next {
                work.charge(64).map_err(|_| LIMIT)?;
                self.remaining[index] = self.remaining[index].checked_sub(1).ok_or(INVALID)?;
                self.propagating = Some((id, offset + 1));
                if self.remaining[index] == 0 {
                    self.establish(self.clauses[index].consequence, Evidence::Derived(index));
                }
            } else {
                self.propagating = None;
            }
            return Ok(Progress::Pending);
        }
        if self.indexed < self.clauses.len() {
            let index = self.indexed;
            if self.premise == 0 {
                work.charge(32).map_err(|_| LIMIT)?;
                self.remaining.push(0);
            }
            if let Some(&id) = self.clauses[index].premises.get(self.premise) {
                work.index()?;
                if !self.evidence.contains_key(&id) {
                    work.charge(64).map_err(|_| LIMIT)?;
                    self.remaining[index] += 1;
                    self.dependents.entry(id).or_default().push(index);
                }
                self.premise += 1;
            } else {
                if self.remaining[index] == 0 {
                    self.establish(self.clauses[index].consequence, Evidence::Derived(index));
                }
                self.indexed += 1;
                self.premise = 0;
            }
            return Ok(Progress::Pending);
        }
        if let Some(expansion) = self.expansion.take() {
            return self.expand(expansion, work);
        }
        let Some(goal_id) = self.pending.pop_first() else {
            return Ok(Progress::Complete(None));
        };
        work.index()?;
        if let Some((proof, _)) =
            lookup_id(self.artifacts, goal_id, &self.goals[&goal_id].formula, work)?
        {
            self.goals.get_mut(&goal_id).ok_or(INVALID)?.seed = Some(Source::Proof(proof));
            self.establish(goal_id, Evidence::Seed(goal_id));
        } else if self.instantiated {
            if let Some(plan) = super::super::elementary::plan(&self.goals[&goal_id].formula, work)?
            {
                self.goals.get_mut(&goal_id).ok_or(INVALID)?.seed =
                    Some(Source::Generated(plan.into_program()));
                self.establish(goal_id, Evidence::Seed(goal_id));
            } else {
                work.formula(self.goals[&goal_id].length, 8)?;
                let key = super::super::instantiation::key(&self.goals[&goal_id].formula);
                work.index()?;
                self.expansion = Some(Expansion::Instances(
                    goal_id,
                    self.artifacts
                        .bucket(BucketKind::Instances, key)
                        .map_err(context_failure)?,
                ));
            }
        } else {
            self.deductions(goal_id, work)?;
        }
        Ok(Progress::Pending)
    }

    fn deductions(&mut self, goal_id: StatementId, work: &mut Work) -> Result<(), Failure> {
        work.index()?;
        self.expansion = Some(Expansion::Deductions(
            goal_id,
            self.artifacts
                .bucket(BucketKind::Deductions, goal_id)
                .map_err(context_failure)?,
        ));
        Ok(())
    }

    fn expand(&mut self, expansion: Expansion<'a>, work: &mut Work) -> Result<Progress, Failure> {
        let (goal_id, mut cursor, instances) = match expansion {
            Expansion::Instances(goal, cursor) => (goal, cursor, true),
            Expansion::Deductions(goal, cursor) => (goal, cursor, false),
        };
        work.index()?;
        let Some(source) = cursor.next() else {
            if instances {
                self.deductions(goal_id, work)?;
            }
            return Ok(Progress::Pending);
        };
        let source = source.map_err(context_failure)?;
        let header = known(self.artifacts, source, work)?;
        work.formula(header.length, 8)?;
        let formula = load_formula(self.artifacts, source, header.length)?;
        if instances {
            if let Some(candidate) = super::super::instantiation::specialize(
                header.proof,
                &formula,
                &self.goals[&goal_id].formula,
                self.artifacts,
                work,
            )? {
                if candidate.formula == self.goals[&goal_id].formula {
                    self.goals.get_mut(&goal_id).ok_or(INVALID)?.seed =
                        Some(Source::Generated(candidate.program));
                    self.establish(goal_id, Evidence::Seed(goal_id));
                    return Ok(Progress::Pending);
                }
                add_clause(
                    Source::Generated(candidate.program),
                    &candidate.formula,
                    goal_id,
                    &mut self.goals,
                    &mut self.pending,
                    &mut self.clauses,
                    work,
                )?;
            }
            self.expansion = Some(Expansion::Instances(goal_id, cursor));
        } else {
            add_clause(
                Source::Proof(header.proof),
                &formula,
                goal_id,
                &mut self.goals,
                &mut self.pending,
                &mut self.clauses,
                work,
            )?;
            self.expansion = Some(Expansion::Deductions(goal_id, cursor));
        }
        Ok(Progress::Pending)
    }
}
