use naome_foundation::{Formula, FreeVariable, Logic};
use naome_proof::{ArtifactId, DefinitionId, ProofId, ProofStep, StatementId};

use crate::{state::persistent_map::PersistentMap, statement_id};

use super::AssessmentLimits;

type Statements = PersistentMap<StatementId, ()>;
type Buckets = PersistentMap<StatementId, Statements>;

/// Complete derived indexes maintained only after checked registration.
/// The authoritative artifact snapshot binds their entire source set.
#[derive(Clone, Default)]
pub(crate) struct KnowledgeIndex {
    artifacts: PersistentMap<ArtifactId, ()>,
    witnesses: PersistentMap<StatementId, ProofId>,
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
    ) {
        self.artifacts.insert(ArtifactId::from_proof_id(proof), ());
        if let Some(existing) = self.witnesses.get(&statement) {
            if proof < *existing {
                self.witnesses.set(statement, proof);
            }
            return;
        }
        self.witnesses.insert(statement, proof);
        if let Some((antecedent, mut consequent)) = formula.implication_parts() {
            let antecedent =
                statement_id(&antecedent.encode_canonical().expect("checked subformula"));
            insert(&mut self.outgoing, antecedent, statement);
            // Every consequent-spine projection is a potential MP goal, not a
            // checked fact. Its complete leading antecedents must be derived
            // from checked seeds, and its full DAG must pass the checker.
            // Intermediate formulas retain the global checked formula limits;
            // the smaller question-input limit must never omit a bridge here.
            loop {
                let bytes = consequent.encode_canonical().expect("checked subformula");
                insert(&mut self.deductions, statement_id(&bytes), statement);
                let Some((_, next)) = consequent.implication_parts() else {
                    break;
                };
                consequent = next;
            }
        }
        for instance in universal_instances(proof, formula) {
            // Only individually admissible question targets can match this
            // index. Oversized/deep projections cannot equal a bounded input;
            // no artifact or eligible target is omitted by graph cardinality.
            if let Ok((bytes, _)) = instance
                .formula
                .encode_canonical_with_node_limit(AssessmentLimits::MAXIMUM.formula_nodes + 1)
            {
                insert(&mut self.instances, statement_id(&bytes), statement);
            }
        }
    }

    pub(crate) fn contains_artifact(&self, artifact: &ArtifactId) -> bool {
        self.artifacts.contains_key(artifact)
    }

    pub(crate) fn witness(&self, statement: StatementId) -> Option<&ProofId> {
        self.witnesses.get(&statement)
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

/// The same finite structural projections build the complete index and the
/// temporary certificate. Only the caller's subsequent checker recheck can
/// establish a mathematical witness; indexing never registers inferred proofs.
pub(super) fn universal_instances(proof_id: ProofId, premise: &Formula) -> Vec<UniversalInstance> {
    let replacement = FreeVariable::new(0);
    let mut current = premise.clone();
    let mut steps = vec![ProofStep::ProofReference { proof_id }];
    let mut instances = Vec::new();
    for level in 0..2 {
        let fresh = FreeVariable::new(2 + level);
        let Some(body) = current.open_outer_universal(fresh) else {
            break;
        };
        let previous = (steps.len() - 1) as u32;
        let implication = steps.len() as u32;
        current = body.clone().substitute_free(fresh, replacement);
        steps.push(ProofStep::UniversalInstantiation {
            variable: fresh,
            replacement,
            body: body.into(),
        });
        steps.push(ProofStep::ModusPonens {
            premise: previous,
            implication,
        });
        instances.push(UniversalInstance {
            formula: current.clone(),
            steps: steps.clone(),
        });
        let mut closed_steps = steps.clone();
        closed_steps.push(ProofStep::Generalization {
            variable: replacement,
            premise: (steps.len() - 1) as u32,
        });
        instances.push(UniversalInstance {
            formula: Logic::generalization(replacement, current.clone()),
            steps: closed_steps,
        });
    }
    instances
}
