//! Bounded structural memory for proof retrieval. Repeated contributing
//! citations in the same goal family strengthen a connection. Older, weak
//! connections yield space to new evidence. The graph owns all proof content.
use super::{Features, Graph, ResearchQuestion, finder};
use naome_checker::ContextView;
use naome_proof::{ArtifactId, ProofId};
use serde::{Deserialize, Serialize};

const CAPACITY: usize = 32;
const FANOUT: usize = 4;
const MAX_USES: u8 = 8;
const RECENCY: u64 = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Edge {
    context: u16,
    proof: [u8; 32],
    consumer: [u8; 32],
    uses: u8,
    observed: u64,
}

impl Edge {
    fn strength(&self, now: u64) -> u8 {
        let age = now.saturating_sub(self.observed) / RECENCY;
        self.uses
            .saturating_sub(age.min(u64::from(MAX_USES)) as u8)
            .max(1)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub(super) struct Memory(Vec<Edge>);

impl Memory {
    // Includes the transaction copy and serialized working representations.
    pub(super) const RESERVATION: usize = CAPACITY * 1024 + 4096;

    pub(super) fn validate(&self, observations: u64) -> Result<(), crate::Error> {
        let mut keys = std::collections::BTreeSet::new();
        if self.0.len() > CAPACITY
            || self.0.iter().any(|edge| {
                edge.context > 127
                    || ArtifactId::from_proof_id(ProofId::from_bytes(edge.proof)).as_bytes()
                        == &edge.consumer
                    || !(1..=MAX_USES).contains(&edge.uses)
                    || edge.observed == 0
                    || edge.observed > observations
                    || !keys.insert((edge.context, edge.proof))
            })
        {
            return Err(crate::ResearchFailure::FinderRecallInvalid.into());
        }
        Ok(())
    }

    pub(super) fn context(family: u16, question: &ResearchQuestion) -> u16 {
        2 * family + u16::from(question.negation_parity())
    }

    pub(super) fn observe(
        &mut self,
        goal: &ResearchQuestion,
        consumer: ArtifactId,
        proofs: &[ProofId],
        now: u64,
    ) {
        let context = Self::context(Features::of(goal).family, goal);
        for proof in proofs.iter().take(FANOUT) {
            let proof = *proof.as_bytes();
            if let Some(edge) = self
                .0
                .iter_mut()
                .find(|edge| edge.context == context && edge.proof == proof)
            {
                if &edge.consumer != consumer.as_bytes() {
                    edge.uses = (edge.strength(now) + 1).min(MAX_USES);
                    edge.consumer = *consumer.as_bytes();
                    edge.observed = now;
                }
            } else {
                if self.0.len() == CAPACITY {
                    let weakest = self
                        .0
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, edge)| (edge.strength(now), edge.observed))
                        .expect("full recall memory")
                        .0;
                    self.0.swap_remove(weakest);
                }
                self.0.push(Edge {
                    context,
                    proof,
                    consumer: *consumer.as_bytes(),
                    uses: 1,
                    observed: now,
                });
            }
        }
    }

    pub(super) fn opportunity(&self, context: u16, now: u64) -> u64 {
        self.0
            .iter()
            .filter(|edge| edge.context == context)
            .map(|edge| edge.strength(now))
            .filter(|&strength| strength >= 2)
            .max()
            .map_or(0, |strength| u64::from(strength).div_ceil(4))
    }

    pub(super) fn offers(&self, context: u16, now: u64) -> Vec<(ProofId, u8)> {
        let mut offers = self
            .0
            .iter()
            .filter(|edge| edge.context == context)
            .filter_map(|edge| {
                let strength = edge.strength(now);
                (strength >= 2).then_some((strength, edge.observed, edge.proof))
            })
            .collect::<Vec<_>>();
        offers.sort_unstable_by_key(|&(strength, observed, proof)| {
            (
                std::cmp::Reverse(strength),
                std::cmp::Reverse(observed),
                proof,
            )
        });
        offers.truncate(FANOUT);
        offers
            .into_iter()
            .map(|(strength, _, proof)| (ProofId::from_bytes(proof), strength))
            .collect()
    }
}

/// Only graph-owned proof dependencies that contributed to the checked result
/// qualify. References used only for their formula, trivial wrappers, and
/// reserved examples cannot create recall edges.
pub(super) fn contributing(
    graph: &Graph,
    goal: &ResearchQuestion,
    dependencies: &[ArtifactId],
) -> Result<Vec<ProofId>, crate::Error> {
    if !crate::learning::State::eligible(&goal.to_hex()) {
        return Ok(Vec::new());
    }
    let mut proofs = Vec::new();
    // Bound projections as well as retained edges, even on very wide proofs.
    for &dependency in dependencies.iter().take(FANOUT * 2) {
        let context = graph.checked_context();
        let Some(proof) = context.artifact_proof_id(dependency)? else {
            continue;
        };
        let Some(header) = context.proof_header(proof)? else {
            continue;
        };
        let bytes = header.canonical_length();
        if bytes > naome_checker::question::QUESTION_BYTES {
            continue;
        }
        let Ok(_projection) = crate::resources::MemoryLease::acquire(bytes * 8 + 2048) else {
            continue;
        };
        let Some(formula) = context.proof_formula(header, bytes)? else {
            continue;
        };
        let Ok(lemma) = ResearchQuestion::from_formula(formula.as_ref().clone()) else {
            continue;
        };
        if crate::learning::State::eligible(&lemma.to_hex())
            && finder::independent_goal(&lemma, goal)
        {
            proofs.push(proof);
            if proofs.len() == FANOUT {
                break;
            }
        }
    }
    Ok(proofs)
}
