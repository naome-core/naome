use naome_foundation::{Formula, FreeVariable, Logic};
use naome_proof::{ArtifactId, DefinitionId, ProofId, ProofStep, StatementId};

use crate::{context::BucketKind, state::persistent_map::PersistentMap, statement_id};

use super::AssessmentLimits;

type Statements = PersistentMap<StatementId, ()>;
type Buckets = PersistentMap<StatementId, Statements>;

/// Complete derived indexes maintained only after checked registration.
/// The authoritative artifact snapshot binds their entire source set.
#[derive(Clone, Default)]
pub(crate) struct KnowledgeIndex {
    artifacts: PersistentMap<ArtifactId, ()>,
    witnesses: PersistentMap<StatementId, (usize, ProofId)>,
    outgoing: Buckets,
    deductions: Buckets,
    instances: Buckets,
}

impl KnowledgeIndex {
    pub(crate) const fn new() -> Self {
        Self {
            artifacts: PersistentMap::new(),
            witnesses: PersistentMap::new(),
            outgoing: PersistentMap::new(),
            deductions: PersistentMap::new(),
            instances: PersistentMap::new(),
        }
    }

    pub(crate) fn register_definition(&mut self, definition: DefinitionId) {
        self.artifacts
            .insert(ArtifactId::from_definition_id(definition), ());
    }

    pub(crate) fn register_proof(
        &mut self,
        proof: ProofId,
        statement: StatementId,
        formula: &Formula,
        bytes: usize,
    ) {
        let candidate = (bytes, proof);
        self.artifacts.insert(ArtifactId::from_proof_id(proof), ());
        if let Some(existing) = self.witnesses.get(&statement) {
            if candidate < *existing {
                self.witnesses.set(statement, candidate);
            }
            return;
        }
        self.witnesses.insert(statement, candidate);
        for (kind, target) in projections(formula) {
            let index = match kind {
                BucketKind::Outgoing => &mut self.outgoing,
                BucketKind::Deductions => &mut self.deductions,
                BucketKind::Instances => &mut self.instances,
            };
            insert(index, target, statement);
        }
    }

    pub(crate) fn contains_artifact(&self, artifact: &ArtifactId) -> bool {
        self.artifacts.contains_key(artifact)
    }

    pub(crate) fn witness(&self, statement: StatementId) -> Option<&ProofId> {
        self.witnesses.get(&statement).map(|(_, proof)| proof)
    }

    pub(crate) fn outgoing(&self, target: StatementId) -> impl Iterator<Item = StatementId> + '_ {
        entries(self.outgoing.get(&target))
    }

    pub(crate) fn instances(&self, target: StatementId) -> impl Iterator<Item = StatementId> + '_ {
        entries(self.instances.get(&target))
    }

    pub(crate) fn deductions(&self, target: StatementId) -> impl Iterator<Item = StatementId> + '_ {
        entries(self.deductions.get(&target))
    }
}

/// Shared complete structural projections for memory and authenticated disk indexes.
pub(crate) fn projections(formula: &Formula) -> Vec<(BucketKind, StatementId)> {
    let mut result = Vec::new();
    if let Some(parts) = formula.canonical_implication().expect("checked subformula") {
        result.push((BucketKind::Outgoing, statement_id(parts.antecedent())));
        for consequent in parts.consequents() {
            result.push((BucketKind::Deductions, statement_id(consequent)));
        }
    }
    for (instance, ()) in universal_openings(formula, |_, _| ()) {
        let closed = Logic::generalization(UNIVERSAL_REPLACEMENT, instance.clone());
        for projected in [instance, closed] {
            // Oversized or deep projections cannot equal a bounded question target.
            if let Ok((bytes, _)) = projected
                .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes + 1)
            {
                result.push((BucketKind::Instances, statement_id(&bytes)));
            }
        }
    }
    result.extend(
        super::instantiation::projections(formula)
            .into_iter()
            .map(|key| (BucketKind::Instances, key)),
    );
    result
}

fn insert(index: &mut Buckets, key: StatementId, statement: StatementId) {
    let mut bucket = index.get(&key).cloned().unwrap_or_default();
    bucket.insert(statement, ());
    index.set(key, bucket);
}

fn entries(bucket: Option<&Statements>) -> impl Iterator<Item = StatementId> + '_ {
    bucket
        .into_iter()
        .flat_map(PersistentMap::entries)
        .map(|(statement, ())| *statement)
}

pub(super) struct UniversalInstance {
    pub(super) formula: Formula,
    pub(super) steps: Vec<ProofStep>,
}

const UNIVERSAL_REPLACEMENT: FreeVariable = FreeVariable::new(0);

/// Shares the finite openings and substitutions between the index and certificates.
fn universal_openings<E>(
    premise: &Formula,
    mut capture: impl FnMut(FreeVariable, &Formula) -> E,
) -> impl Iterator<Item = (Formula, E)> {
    let mut current = premise.clone();
    (0..2).map_while(move |level| {
        let fresh = FreeVariable::new(2 + level);
        let body = current.open_outer_universal(fresh)?;
        let captured = capture(fresh, &body);
        current = body.substitute_free(fresh, UNIVERSAL_REPLACEMENT);
        Some((current.clone(), captured))
    })
}

/// Builds temporary certificates that the caller rechecks before use.
pub(super) fn universal_instances(proof_id: ProofId, premise: &Formula) -> Vec<UniversalInstance> {
    let mut steps = vec![ProofStep::ProofReference { proof_id }];
    let mut instances = Vec::new();
    for (formula, (fresh, body)) in universal_openings(premise, |fresh, body| (fresh, body.clone()))
    {
        let previous = (steps.len() - 1) as u32;
        let implication = steps.len() as u32;
        steps.push(ProofStep::UniversalInstantiation {
            variable: fresh,
            replacement: UNIVERSAL_REPLACEMENT,
            body: body.into(),
        });
        steps.push(ProofStep::ModusPonens {
            premise: previous,
            implication,
        });
        instances.push(UniversalInstance {
            formula: formula.clone(),
            steps: steps.clone(),
        });
        let mut closed_steps = steps.clone();
        closed_steps.push(ProofStep::Generalization {
            variable: UNIVERSAL_REPLACEMENT,
            premise: (steps.len() - 1) as u32,
        });
        instances.push(UniversalInstance {
            formula: Logic::generalization(UNIVERSAL_REPLACEMENT, formula),
            steps: closed_steps,
        });
    }
    instances
}
