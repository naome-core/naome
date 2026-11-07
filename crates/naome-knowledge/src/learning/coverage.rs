//! Checked structural coverage for bounded replay retention, never model inputs.
use super::{CompiledQuestion, Example, digest, graph::Graph, search};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[cfg(test)]
pub(super) mod control;

pub(super) fn losses(replay: &[Example], anchors: &[Example]) -> Result<Vec<usize>, String> {
    #[cfg(test)]
    if !control::enabled() {
        return Ok(vec![0; replay.len()]);
    }
    let profiles = replay
        .iter()
        .map(Profile::of)
        .collect::<Result<Vec<_>, _>>()?;
    let anchors = anchors
        .iter()
        .map(Profile::of)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Profile::losses(&profiles, &anchors))
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Feature {
    Action(String),
    Dependency(u8, usize, u8),
    Rule(u8),
    Definition(u8),
    Depth(usize),
    Branch(u8, usize),
    Transition(u8, usize, u8),
}
// One quarter of each existing replay share bounds structural metadata.
// The filter is a lossy selection proxy: collisions can hide distinct features.
// Complete trajectories, native identities and admission never use this filter.
const PROFILE_BYTES: usize = 32 * 1024 / (4 * super::REPLAY);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    features: usize,
    #[serde(with = "packed")]
    bits: Vec<u8>,
}
mod packed {
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        if bytes.len() != super::PROFILE_BYTES {
            return Err(serde::ser::Error::custom("replay coverage capacity"));
        }
        STANDARD_NO_PAD.encode(bytes).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > (4 * super::PROFILE_BYTES).div_ceil(3) {
            return Err(serde::de::Error::custom("replay coverage capacity"));
        }
        let bytes = STANDARD_NO_PAD
            .decode(value)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != super::PROFILE_BYTES {
            return Err(serde::de::Error::custom("replay coverage width"));
        }
        Ok(bytes)
    }
}

std::thread_local! {
    static CACHE: std::cell::RefCell<VecDeque<(String, Profile)>> = const { std::cell::RefCell::new(VecDeque::new()) };
}
impl Profile {
    pub fn validate(&self) -> Result<(), String> {
        if self.bits.len() != PROFILE_BYTES
            || self.features == 0
            || self.features > crate::resources::limits().closure_steps
            || self
                .bits
                .iter()
                .map(|byte| byte.count_ones() as usize)
                .sum::<usize>()
                > self.features
            || self.bits.iter().all(|byte| *byte == 0)
        {
            return Err("replay coverage filter capacity or occupancy".into());
        }
        Ok(())
    }
    pub fn of(example: &Example) -> Result<Self, String> {
        if let search::Tree::Stored { coverage, .. } = &example.tree {
            coverage.validate()?;
            return Ok(coverage.clone());
        }
        let key = digest(&(
            &example.question,
            &example.proof_id,
            example.refuted,
            &example.tree,
        ));
        if let Some(profile) = CACHE.with(|c| {
            let mut c = c.borrow_mut();
            let index = c.iter().position(|(known, _)| *known == key)?;
            let entry = c.remove(index)?;
            let profile = entry.1.clone();
            c.push_back(entry);
            Some(profile)
        }) {
            return Ok(profile);
        }
        let q = CompiledQuestion::compile(&example.question).map_err(|e| e.to_string())?;
        let target = if example.refuted {
            q.refuted_target()
        } else {
            q.proved_target()
        };
        let (core, _, checked) = search::core::checked(target, &example.tree)?;
        if crate::hex(checked.native_id.as_bytes()) != example.proof_id {
            return Err("replay coverage proof identity differs".into());
        }
        let mut features = BTreeSet::new();
        // Canonical traversal preserves shared variables and binder backlinks.
        // Irrelevant context, offered alternatives and artifact IDs are omitted.
        for graph in search::compile(target, &core)?.1 {
            for action in &graph.successes {
                let selected = *graph
                    .candidates
                    .get(*action)
                    .ok_or("coverage action missing")?;
                features.insert(Feature::Action(digest(&structure(&graph, &[selected])?)));
            }
        }
        for certificate in checked
            .lemmas
            .iter()
            .chain(std::iter::once(&checked.certificate))
        {
            let steps = certificate.steps();
            let mut depths = Vec::<usize>::new();
            for (index, step) in steps.iter().enumerate() {
                let references = step.local_references();
                let mut depth = 0;
                for (role, reference) in references.into_iter().enumerate() {
                    if let Some(reference) = reference {
                        let reference = reference as usize;
                        if reference >= index {
                            return Err("coverage dependency order differs".into());
                        }
                        depth = depth.max(depths[reference] + 1);
                        features.insert(Feature::Dependency(
                            step.canonical_tag(),
                            role,
                            steps[reference].canonical_tag(),
                        ));
                    }
                }
                features.insert(Feature::Rule(step.canonical_tag()));
                if !step.definition_references().is_empty() {
                    features.insert(Feature::Definition(step.canonical_tag()));
                }
                depths.push(depth);
            }
            // The normal-form certificate contains only ancestors of its result.
            features.insert(Feature::Depth(depths.last().copied().unwrap_or(0)));
        }
        branches(&core, &mut features);
        let mut profile = Self {
            features: features.len(),
            bits: vec![0; PROFILE_BYTES],
        };
        for feature in features {
            let hash = crate::object::id_bytes(&digest(&feature))?;
            let index = u64::from_le_bytes(hash[..8].try_into().expect("digest prefix")) as usize
                % (PROFILE_BYTES * 8);
            profile.bits[index / 8] |= 1 << (index % 8);
        }
        profile.validate()?;
        CACHE.with(|c| {
            let mut c = c.borrow_mut();
            if c.len() >= 2 * super::REPLAY {
                c.pop_front();
            }
            c.push_back((key, profile.clone()));
        });
        Ok(profile)
    }
    /// Unique occupied filter bits, not an exact count of proof strategies.
    pub fn losses(profiles: &[Self], anchors: &[Self]) -> Vec<usize> {
        let mut counts = [0usize; PROFILE_BYTES * 8];
        for profile in profiles.iter().chain(anchors) {
            for (index, count) in counts.iter_mut().enumerate() {
                *count += usize::from(profile.bits[index / 8] & (1 << (index % 8)) != 0);
            }
        }
        profiles
            .iter()
            .map(|profile| {
                counts
                    .iter()
                    .enumerate()
                    .filter(|(index, count)| {
                        **count == 1 && profile.bits[index / 8] & (1 << (index % 8)) != 0
                    })
                    .count()
            })
            .collect()
    }
}
fn structure(graph: &Graph, roots: &[usize]) -> Result<Vec<(i32, usize, usize)>, String> {
    fn visit(
        graph: &Graph,
        at: usize,
        ids: &mut BTreeMap<usize, usize>,
        out: &mut Vec<(i32, usize, usize)>,
    ) -> Result<usize, String> {
        if let Some(id) = ids.get(&at) {
            return Ok(*id);
        }
        let node = graph
            .nodes
            .get(at)
            .ok_or("coverage graph reference missing")?;
        let id = out.len();
        ids.insert(at, id);
        out.push((node.kind, 0, 0));
        let left = visit(graph, node.left, ids, out)?;
        let right = visit(graph, node.right, ids, out)?;
        out[id] = (node.kind, left, right);
        Ok(id)
    }
    let mut ids = BTreeMap::new();
    let mut out = Vec::new();
    for root in roots {
        visit(graph, *root, &mut ids, &mut out)?;
    }
    Ok(out)
}
fn action_kind(action: &search::Action) -> u8 {
    match action {
        search::Action::Double(_) => 0,
        search::Action::NotImp(_) => 1,
        search::Action::Mp(..) => 2,
        search::Action::Beta(_) => 3,
        search::Action::Instantiate(..) => 4,
        search::Action::Witness(..) => 5,
        search::Action::Substitute(..) => 6,
        search::Action::Cite(_) => 7,
    }
}
fn branches(tree: &search::Tree, features: &mut BTreeSet<Feature>) {
    match tree {
        search::Tree::Step { action, children } => {
            features.insert(Feature::Branch(action_kind(action), children.len()));
            for (role, child) in children.iter().enumerate() {
                if let search::Tree::Step { action: next, .. } = child {
                    features.insert(Feature::Transition(
                        action_kind(action),
                        role,
                        action_kind(next),
                    ));
                }
                branches(child, features);
            }
        }
        search::Tree::Knowledge { proof, .. } | search::Tree::Definitions { proof, .. } => {
            branches(proof, features)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests;
