//! Bounded immutable projections of accepted node-local proof content.
//! Canonical certificates remain checked by the graph; derived search metadata
//! and ranking never confer proof validity or admission authority.
use crate::{Envelope, Graph};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Instant};

pub(crate) mod cache;
pub(crate) mod cursor;
pub(crate) mod host;
mod indexing;
pub(crate) mod local;
pub(crate) mod retrieval;
pub(crate) mod semantic;
pub(crate) mod service;
pub(crate) mod snapshot;

// A node-owned snapshot can hold the complete accepted graph (hex certificates,
// derived conclusions and bounded dependencies). It never enters a model request.
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 160 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reference {
    pub(crate) proof: Envelope,
    pub(crate) native_conclusion: Arc<str>,
    pub(crate) dependencies: Vec<String>,
}

/// Checked Graph custody creates this immutable projection once on acceptance.
/// A content digest avoids serializing certificates in the gossip capture path.
#[derive(Clone)]
pub(crate) struct CachedReference {
    pub reference: Arc<Reference>,
    pub digest: String,
    /// Derived solely from the checker-owned conclusion; never serialized into
    /// a native snapshot, accepted object, Request or identity-bearing row.
    pub controlled_conclusion: Arc<str>,
}

impl CachedReference {
    pub fn new(reference: Reference, controlled_conclusion: Arc<str>) -> Self {
        let digest = crate::hex(&Sha256::digest(
            serde_json::to_vec(&reference).expect("finite checked projection"),
        ));
        Self {
            reference: Arc::new(reference),
            digest,
            controlled_conclusion,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProofCorpus {
    pub(crate) artifact_snapshot: String,
    pub(crate) graph_root: String,
    /// Complete checked local proof set, including every referenced dependency.
    pub(crate) references: Vec<Arc<Reference>>,
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
        let context = Self {
            artifact_snapshot: crate::hex(&graph.checked_context().snapshot_id()),
            graph_root: crate::hex(&graph.content_root()),
            references: graph
                .corpus_references()
                .map(|row| row.reference.clone())
                .collect(),
            definitions_supported: false,
            registry_entries_included: false,
        };
        if context.references.len() != graph.accepted_count() {
            return Err("checked graph projection is incomplete".into());
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
        let mut certificate_bytes = 0usize;
        let mut statements = std::collections::BTreeMap::new();
        for reference in &self.references {
            if reference.native_conclusion.len() > 16 * naome_foundation::FORMULA_MAX_BYTES
                || reference.proof.proof.len() > 2 * crate::MAX_PROOF_BYTES
                || reference.dependencies.len() > crate::MAX_DEPENDENCIES
            {
                return Err("proof corpus reference capacity differs".into());
            }
            certificate_bytes = certificate_bytes
                .checked_add(reference.proof.proof.len() / 2)
                .ok_or("proof corpus certificate byte overflow")?;
            if certificate_bytes > crate::MAX_ACCEPTED_BYTES {
                return Err("proof corpus accepted certificate byte limit".into());
            }
            if let Some(previous) =
                statements.insert(&reference.proof.statement_id, &reference.native_conclusion)
                && previous != &reference.native_conclusion
            {
                return Err("proof corpus same-statement conclusions differ".into());
            }
        }
        if statements
            .values()
            .map(|source| source.len())
            .sum::<usize>()
            > 16 * crate::MAX_CONTEXT_BYTES
        {
            return Err("proof corpus distinct statement source byte limit".into());
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
        self.checked_graph().map(|_| ())
    }
    pub(crate) fn checked_graph(&self) -> Result<Graph, String> {
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
        Ok(graph)
    }
}
