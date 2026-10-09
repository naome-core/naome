//! Bounded immutable projections of accepted node-local proof content.
//! Canonical certificates remain checked by the graph; derived search metadata
//! and ranking never confer proof validity or admission authority.
use crate::{Envelope, Graph};
use serde::{Deserialize, Serialize};
use std::time::Instant;

pub(crate) mod semantic;

pub(crate) const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reference {
    pub(crate) proof: Envelope,
    pub(crate) native_conclusion: String,
    pub(crate) dependencies: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofCorpus {
    pub(crate) artifact_snapshot: String,
    pub(crate) graph_root: String,
    /// Complete checked local proof set, including every referenced dependency.
    pub(crate) references: Vec<Reference>,
    /// The current proof-only graph cannot admit definitions or definition helpers.
    pub(crate) definitions_supported: bool,
    /// The existing local registry remains bound by binding.snapshot. Its entries
    /// are not exported by this graph; the model cannot infer registry absence.
    pub(crate) registry_entries_included: bool,
}
impl ProofCorpus {
    /// Imports bounded snapshot bytes and checks all actual certificates and bindings.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err("proof corpus snapshot byte limit".into());
        }
        let corpus: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        corpus.recheck()?;
        Ok(corpus)
    }

    pub fn capture(graph: &Graph) -> Result<Self, String> {
        if graph.checked_context().definition_ids().next().is_some() {
            return Err("generation context contains unsupported definitions".into());
        }
        let mut context = Self {
            artifact_snapshot: crate::hex(&graph.checked_context().snapshot_id()),
            graph_root: crate::hex(&graph.content_root()),
            references: Vec::new(),
            definitions_supported: false,
            registry_entries_included: false,
        };
        let mut bytes = 0usize;
        let mut steps = 0usize;
        for (id, _, conclusion, canonical_length) in graph.checked_context().proof_conclusions() {
            if canonical_length > MAX_SNAPSHOT_BYTES {
                return Err("generation checked context byte limit".into());
            }
            let proof = graph
                .get(&crate::hex(id.as_bytes()))?
                .ok_or("generation checked proof unavailable")?
                .clone();
            let candidate = proof.clone().prepare()?;
            steps = steps
                .checked_add(candidate.normal.certificate().steps().len())
                .ok_or("generation context step overflow")?;
            if steps > crate::intake::MAX_CLOSURE_STEPS {
                return Err("generation checked context step limit".into());
            }
            let reference = Reference {
                proof,
                native_conclusion: conclusion.to_source(),
                dependencies: candidate
                    .dependencies
                    .iter()
                    .map(|id| crate::hex(id.as_bytes()))
                    .collect(),
            };
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(&reference)
                        .map_err(|e| e.to_string())?
                        .len(),
                )
                .ok_or("generation context overflow")?;
            if bytes > MAX_SNAPSHOT_BYTES {
                return Err("generation checked context byte limit".into());
            }
            context.references.push(reference);
        }
        Ok(context)
    }
    /// Identity of the checked proof snapshot and concrete local graph.
    pub fn snapshot_identity(&self) -> (&str, &str) {
        (&self.artifact_snapshot, &self.graph_root)
    }
    /// Loads an actual stored canonical certificate from this immutable snapshot.
    /// Original native proof source and external metadata are not stored.
    pub fn get_proof(&self, proof_id: &str) -> Result<Option<Envelope>, String> {
        crate::object::id_bytes(proof_id)?;
        self.recheck()?;
        Ok(self
            .references
            .iter()
            .find(|r| r.proof.proof_id == proof_id)
            .map(|r| r.proof.clone()))
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.references.len() > crate::MAX_OBJECTS {
            return Err("proof corpus count limit".into());
        }
        let mut total = 0usize;
        for reference in &self.references {
            if reference.native_conclusion.len() > MAX_SNAPSHOT_BYTES
                || reference.proof.proof.len() > 2 * crate::MAX_PROOF_BYTES
                || reference.dependencies.len() > crate::MAX_DEPENDENCIES
            {
                return Err("proof corpus reference capacity differs".into());
            }
            total = total
                .checked_add(
                    serde_json::to_vec(reference)
                        .map_err(|e| e.to_string())?
                        .len(),
                )
                .ok_or("proof corpus byte overflow")?;
            if total > MAX_SNAPSHOT_BYTES {
                return Err("proof corpus snapshot byte limit".into());
            }
        }

        crate::object::id_bytes(&self.artifact_snapshot)?;
        crate::object::id_bytes(&self.graph_root)?;
        let ids = self
            .references
            .iter()
            .map(|r| r.proof.proof_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        for reference in &self.references {
            crate::object::id_bytes(&reference.proof.proof_id)?;
            crate::object::id_bytes(&reference.proof.statement_id)?;
            if reference.native_conclusion.len() > MAX_SNAPSHOT_BYTES
                || reference.proof.proof.len() > 2 * crate::MAX_PROOF_BYTES
                || reference.dependencies.len() > crate::MAX_DEPENDENCIES
            {
                return Err("generation reference capacity differs".into());
            }
            for dependency in &reference.dependencies {
                crate::object::id_bytes(dependency)?;
                if !ids.contains(dependency.as_str()) {
                    return Err("generation checked dependency unavailable".into());
                }
            }
        }
        if self.definitions_supported
            || self.registry_entries_included
            || self.references.len() > crate::MAX_OBJECTS
        {
            return Err("generation checked context scope differs".into());
        }
        let mut previous = None;
        for reference in &self.references {
            if previous
                .as_ref()
                .is_some_and(|id| id >= &reference.proof.proof_id)
            {
                return Err("generation checked references are not canonical".into());
            }
            previous = Some(reference.proof.proof_id.clone());
        }
        Ok(())
    }
    pub fn recheck(&self) -> Result<(), String> {
        self.validate()?;
        let mut graph = Graph::default();
        let mut remaining = self.references.iter().collect::<Vec<_>>();
        while !remaining.is_empty() {
            let before = remaining.len();
            let mut waiting = Vec::new();
            for reference in remaining {
                let mut ready = true;
                for dependency in &reference.dependencies {
                    if graph.get(dependency)?.is_none() {
                        ready = false;
                        break;
                    }
                }
                if ready {
                    graph.ingest(reference.proof.clone(), Instant::now())?;
                } else {
                    waiting.push(reference);
                }
            }
            if waiting.len() == before {
                return Err("generation checked closure is missing or cyclic".into());
            }
            remaining = waiting;
        }
        if graph.ids().len() != self.references.len() || Self::capture(&graph)? != *self {
            return Err("generation checked context binding or closure differs".into());
        }
        Ok(())
    }
}
