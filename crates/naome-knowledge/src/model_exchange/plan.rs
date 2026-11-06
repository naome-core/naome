use super::{Profile, Registration};
use crate::learning::digest;
use naome_authoring::CompiledQuestion;
use naome_foundation::{Formula, FreeVariable, graph::Node};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

pub(super) const EXPANSIONS: usize = 8;
pub(super) const FAMILIES: usize = 3;

pub(crate) fn budget(profile: Profile) -> serde_json::Value {
    serde_json::json!({
        "families_per_block": FAMILIES, "expansions_per_task": EXPANSIONS,
        "attempts_per_family": 1, "context": "empty_native_tableau",
        "candidate_slots_per_family": slots(profile),
    })
}

fn slots(profile: Profile) -> usize {
    match profile {
        Profile::Solver => 1,
        Profile::Finder => 3,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Challenge {
    /// The operator's own verifier draws this nonce after both registrations.
    nonce: String,
    verifier_key: String,
    signature: String,
    pub(crate) verifier: String,
    pub(crate) peer: String,
    pub(crate) local: Registration,
    pub(crate) remote: Registration,
}

impl Challenge {
    pub(crate) fn new(
        nonce: [u8; 32],
        key: &libp2p::identity::Keypair,
        peer: libp2p::PeerId,
        local: Registration,
        remote: Registration,
    ) -> Result<Self, String> {
        let mut challenge = Self {
            nonce: crate::hex(&nonce),
            verifier_key: crate::hex(&key.public().encode_protobuf()),
            signature: String::new(),
            verifier: key.public().to_peer_id().to_string(),
            peer: peer.to_string(),
            local,
            remote,
        };
        challenge.signature = crate::hex(
            &key.sign(challenge.id().as_bytes())
                .map_err(|e| e.to_string())?,
        );
        challenge.validate()?;
        Ok(challenge)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        crate::object::id_bytes(&self.nonce)?;
        for peer in [&self.verifier, &self.peer] {
            let id = peer.parse::<libp2p::PeerId>().map_err(|e| e.to_string())?;
            if id.to_string() != *peer {
                return Err("noncanonical comparison peer identity".into());
            }
        }
        if self.verifier_key.len() > 256 || self.signature.len() != 128 {
            return Err("comparison signature capacity differs".into());
        }
        let key =
            libp2p::identity::PublicKey::try_decode_protobuf(&crate::unhex(&self.verifier_key)?)
                .map_err(|e| e.to_string())?;
        let signature = crate::unhex(&self.signature)?;
        if key.to_peer_id().to_string() != self.verifier
            || self.verifier_key != crate::hex(&key.encode_protobuf())
            || self.signature != crate::hex(&signature)
            || !key.verify(self.id().as_bytes(), &signature)
        {
            return Err("comparison signature or verifier binding differs".into());
        }
        self.local.validate()?;
        self.remote.validate()?;
        if self.verifier == self.peer || self.local.reference != self.remote.reference {
            return Err("incompatible comparison registrations".into());
        }
        Ok(())
    }

    pub(super) fn id(&self) -> String {
        digest(&(
            "naome:model-challenge",
            &self.nonce,
            &self.verifier,
            &self.peer,
            &self.local,
            &self.remote,
        ))
    }
}

fn marker() -> &'static Formula {
    static MARKER: LazyLock<Formula> = LazyLock::new(|| {
        let a = FreeVariable::new(0);
        let b = FreeVariable::new(1);
        let x = Formula::equal(a, b);
        let y = Formula::equal(b, a);
        Formula::implies(
            Formula::implies(x.clone(), y.clone()),
            Formula::implies(Formula::negate(y), Formula::negate(x)),
        )
    });
    &MARKER
}

/// Reserve the whole protocol namespace from the owned training curriculum,
/// including generated calibration tasks that have never been drawn.
pub(crate) fn reserved(question: &CompiledQuestion) -> bool {
    let mut view = question.proved_target().view();
    while let Node::ForAll(inner) = view.graph_node() {
        view = inner;
    }
    view.implication_parts().is_some_and(|(first, _)| {
        let expected = marker().view();
        fn same(
            left: naome_foundation::FormulaView<'_>,
            right: naome_foundation::FormulaView<'_>,
        ) -> bool {
            use naome_foundation::graph::Variable::{Bound, Free};
            match (left.graph_node(), right.graph_node()) {
                (Node::Implies(a, b), Node::Implies(x, y)) => same(a, x) && same(b, y),
                (Node::Not(a), Node::Not(b)) => same(a, b),
                (Node::Equal(Bound(a), Bound(b)), Node::Equal(Free(x), Free(y))) => {
                    a + u64::from(x) == 7 && b + u64::from(y) == 7
                }
                _ => false,
            }
        }
        same(first, expected)
    })
}

#[derive(Clone, Copy, Serialize)]
pub(super) enum Lane {
    Score,
    Calibration,
}

pub(super) struct Family {
    pub(super) candidates: Vec<CompiledQuestion>,
    pub(super) draw: u64,
}

/// A fixed width of each family is considered in each block. For the finder
/// each family offers a page and pays for one attempted question. The two
/// lanes differ in the mathematical premises as well as the draw domain.
pub(super) fn block(challenge: &Challenge, index: u64, lane: Lane) -> Result<Vec<Family>, String> {
    let slots = slots(challenge.local.model.profile());
    (0..FAMILIES)
        .map(|family| {
            let entropy = crate::object::id_bytes(&digest(&(
                "naome:model-task-draw",
                &challenge.nonce,
                index,
                lane,
                family,
            )))?;
            let candidates = (0..slots)
                .map(|slot| task(&entropy, index, lane, family, slot))
                .collect::<Result<_, _>>()?;
            Ok(Family {
                candidates,
                draw: u64::from_le_bytes(entropy[..8].try_into().expect("fixed draw width")),
            })
        })
        .collect()
}

fn task(
    entropy: &[u8; 32],
    index: u64,
    lane: Lane,
    family: usize,
    slot: usize,
) -> Result<CompiledQuestion, String> {
    // Directed membership entailments. The families differ in the number
    // of productive links. Extra implications compete with the useful path.
    // The lane, family and slot choose distinct ordered target pairs.
    let variables: Vec<_> = (0..8).map(FreeVariable::new).collect();
    let atom = |a, b| Formula::member(variables[a], variables[b]);
    let lane_offset = match lane {
        Lane::Score => 0,
        Lane::Calibration => 3,
    };
    let target = atom(1 + family, 2 + slot + lane_offset);
    let start = atom(0, 1);
    let mut from = start.clone();
    let mut premises = vec![marker().clone(), start];
    for (link, noise_draw) in entropy.iter().take(family + 1).enumerate() {
        let to = if link == family {
            target.clone()
        } else {
            atom(4 + link, 0)
        };
        premises.push(Formula::implies(from.clone(), to.clone()));
        let noise = atom(4 + link, 5 + usize::from(noise_draw % 3));
        premises.push(Formula::implies(from, noise));
        from = to;
    }
    // Encode the block ordinal in a single competing clause. For long
    // ordinals use a balanced tree to stay within the existing question depth.
    fn balanced(edges: &[Formula]) -> Formula {
        if edges.len() == 1 {
            return edges[0].clone();
        }
        let (left, right) = edges.split_at(edges.len() / 2);
        Formula::implies(balanced(left), balanced(right))
    }
    let edges = (0..(u64::BITS - index.leading_zeros()))
        .map(|bit| {
            if (index >> bit) & 1 == 0 {
                atom(6, 7)
            } else {
                atom(7, 6)
            }
        })
        .collect::<Vec<_>>();
    let distractor = if edges.len() > 8 {
        Formula::implies(balanced(&edges), atom(7, 6))
    } else {
        edges
            .into_iter()
            .fold(atom(7, 6), |rest, edge| Formula::implies(edge, rest))
    };
    let position = 2 + usize::from(entropy[3]) % (premises.len() - 1);
    premises.insert(position, Formula::implies(atom(0, 0), distractor));
    let body = premises
        .into_iter()
        .rev()
        .fold(target, |body, premise| Formula::implies(premise, body));
    let closed = variables
        .into_iter()
        .rev()
        .fold(body, |body, variable| Formula::for_all(variable, body));
    let question = CompiledQuestion::from_formula(closed).map_err(|e| e.to_string())?;
    if !reserved(&question) {
        return Err("comparison task escaped its held-out family".into());
    }
    Ok(question)
}
