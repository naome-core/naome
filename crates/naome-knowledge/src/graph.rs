use crate::object::{Candidate, MAX_DEPTH, id_bytes};
use crate::store::Store;
use crate::{Envelope, compatibility};
use naome_checker::{ArtifactState, check_normal_form_with_state};
use naome_proof::ProofId;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, Instant},
};

pub const MAX_OBJECTS: usize = 4096;
pub const MAX_ACCEPTED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CONTEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PENDING: usize = 128;
pub const PENDING_TTL: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct Ingest {
    pub status: &'static str,
    pub id: ProofId,
    pub admitted: Vec<ProofId>,
    pub rejected: Vec<(ProofId, String)>,
}

/// The sole acceptance owner for this operating path. Checked state is private.
#[derive(Default)]
pub struct Graph {
    context: ArtifactState,
    objects: BTreeMap<ProofId, Envelope>,
    depths: BTreeMap<ProofId, usize>,
    pending: BTreeMap<ProofId, (Candidate, Instant)>,
    bytes: usize,
    context_bytes: usize,
    storage_error: Option<String>,
    store: Option<Store>,
}

impl Graph {
    pub(crate) fn checked_context(&self) -> &ArtifactState {
        &self.context
    }
    /// Locks the directory, checks all persisted bytes and reconstructs dependencies.
    /// Missing, invalid, incompatible or cyclic durable content fails startup.
    pub fn open(directory: &Path) -> Result<Self, String> {
        let store = Store::open(directory)?;
        let mut remaining = store.load()?;
        let mut graph = Self::default();
        while !remaining.is_empty() {
            let before = remaining.len();
            let mut waiting = Vec::new();
            for envelope in remaining {
                let candidate = envelope.prepare()?;
                if graph.ready(&candidate) {
                    graph.admit(candidate)?;
                } else {
                    waiting.push(candidate.envelope);
                }
            }
            if waiting.len() == before {
                return Err("durable graph has missing or cyclic dependencies".into());
            }
            remaining = waiting;
        }
        graph.store = Some(store);
        Ok(graph)
    }

    pub fn author(&self, source: &str) -> Result<Envelope, String> {
        if source.len() > crate::MAX_PROOF_BYTES {
            return Err("producer source byte limit".into());
        }
        naome_authoring::compile_against_proof_context(source, &self.context)
            .map(Envelope::from_compiled)
            .map_err(|error| error.to_string())
    }

    pub fn ingest(&mut self, envelope: Envelope, now: Instant) -> Result<Ingest, String> {
        if let Some(error) = &self.storage_error {
            return Err(format!("storage halted: {error}"));
        }
        let candidate = envelope.prepare()?;
        let id = candidate.id;
        if let Some(existing) = self.objects.get(&id) {
            if existing != &candidate.envelope {
                return Err("proof identity collision".into());
            }
            return Ok(Ingest {
                status: "duplicate",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        if self.pending.contains_key(&id) {
            return Ok(Ingest {
                status: "waiting_duplicate",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        if !self.ready(&candidate) {
            if self.pending.len() >= MAX_PENDING {
                return Err("pending capacity".into());
            }
            self.require_acyclic(&candidate)?;
            self.pending.insert(id, (candidate, now));
            return Ok(Ingest {
                status: "waiting",
                id,
                admitted: Vec::new(),
                rejected: Vec::new(),
            });
        }
        self.admit(candidate)?;
        let mut result = Ingest {
            status: "accepted",
            id,
            admitted: vec![id],
            rejected: Vec::new(),
        };
        // Each candidate is removed once. No asynchronous checker queue or busy polling.
        loop {
            let ready: Vec<_> = self
                .pending
                .iter()
                .filter_map(|(id, (candidate, _))| self.ready(candidate).then_some(*id))
                .collect();
            if ready.is_empty() {
                break;
            }
            for id in ready {
                let (candidate, _) = self
                    .pending
                    .remove(&id)
                    .expect("selected pending candidate");
                match self.admit(candidate) {
                    Ok(()) => result.admitted.push(id),
                    Err(error) => result.rejected.push((id, error)),
                }
            }
        }
        Ok(result)
    }

    fn ready(&self, candidate: &Candidate) -> bool {
        candidate
            .dependencies
            .iter()
            .all(|id| self.objects.contains_key(id))
    }

    fn admit(&mut self, candidate: Candidate) -> Result<(), String> {
        if let Some(error) = &self.storage_error {
            return Err(format!("storage halted: {error}"));
        }
        let size = candidate.envelope.proof.len() / 2;
        if self.objects.len() >= MAX_OBJECTS || self.bytes + size > MAX_ACCEPTED_BYTES {
            return Err("accepted capacity".into());
        }
        let depth = candidate
            .dependencies
            .iter()
            .map(|id| self.depths[id])
            .max()
            .unwrap_or(0)
            + 1;
        if depth > MAX_DEPTH {
            return Err("dependency depth limit".into());
        }
        let checked = check_normal_form_with_state(candidate.normal, &self.context)
            .map_err(|error| format!("mathematically invalid: {error}"))?;
        if checked.proof_id() != candidate.id || checked.statement_id() != candidate.statement {
            return Err("checked identity mismatch".into());
        }
        let context_growth = if self.context.contains_statement(checked.statement_id()) {
            0
        } else {
            checked
                .conclusion()
                .encode_canonical()
                .map_err(|error| error.to_string())?
                .len()
        };
        if self.context_bytes + context_growth > MAX_CONTEXT_BYTES {
            return Err("checked context capacity".into());
        }
        let mut context = self.context.clone();
        context
            .register_proof_for_replication(checked)
            .map_err(|error| error.to_string())?;
        if let Some(store) = &self.store
            && let Err(error) = store.persist(&candidate.envelope)
        {
            self.storage_error = Some(error.clone());
            return Err(format!("storage halted: {error}"));
        }
        // Publish only after checked registration and successful durable write.
        self.context = context;
        self.bytes += size;
        self.context_bytes += context_growth;
        self.depths.insert(candidate.id, depth);
        self.objects.insert(candidate.id, candidate.envelope);
        Ok(())
    }

    fn require_acyclic(&self, candidate: &Candidate) -> Result<(), String> {
        let mut queue: Vec<_> = candidate.dependencies.iter().copied().collect();
        let mut seen = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if id == candidate.id {
                return Err("dependency cycle".into());
            }
            if seen.insert(id)
                && let Some((parent, _)) = self.pending.get(&id)
            {
                queue.extend(parent.dependencies.iter().copied());
            }
        }
        Ok(())
    }

    pub fn expire(&mut self, now: Instant) -> Vec<ProofId> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(id, (_, since))| {
                (now.saturating_duration_since(*since) >= PENDING_TTL).then_some(*id)
            })
            .collect();
        for id in &expired {
            self.pending.remove(id);
        }
        expired
    }

    pub fn missing(&self) -> BTreeSet<ProofId> {
        self.pending
            .values()
            .flat_map(|(candidate, _)| candidate.dependencies.iter().copied())
            .filter(|id| !self.objects.contains_key(id) && !self.pending.contains_key(id))
            .collect()
    }

    pub fn pending_ids(&self) -> Vec<ProofId> {
        self.pending.keys().copied().collect()
    }
    pub fn storage_error(&self) -> Option<&str> {
        self.storage_error.as_deref()
    }
    pub fn contains(&self, id: ProofId) -> bool {
        self.objects.contains_key(&id)
    }
    pub fn waiting(&self, id: ProofId) -> bool {
        self.pending.contains_key(&id)
    }
    pub fn object(&self, id: ProofId) -> Option<&Envelope> {
        self.objects.get(&id)
    }
    pub fn ids(&self) -> Vec<ProofId> {
        self.objects.keys().copied().collect()
    }
    pub fn content_root(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"naome:knowledge:set:v1\0");
        hash.update(compatibility());
        hash.update((self.objects.len() as u32).to_be_bytes());
        for id in self.objects.keys() {
            hash.update(id.as_bytes());
        }
        hash.finalize().into()
    }

    pub fn get(&self, id: &str) -> Result<Option<&Envelope>, String> {
        Ok(self.object(ProofId::from_bytes(id_bytes(id)?)))
    }
}

#[cfg(test)]
mod tests;
