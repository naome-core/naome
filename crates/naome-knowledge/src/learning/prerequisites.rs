//! Temporary job inputs from the graph, independent of the bounded neural view.
use super::{State, definitions, knowledge, proof};
use crate::object::{CandidatePayload, Envelope};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    artifacts: Vec<Envelope>,
    programs: Vec<knowledge::Entry>,
    #[serde(skip)]
    _memory: Option<Arc<crate::resources::MemoryLease>>,
}

/// Exact untrusted bytes are shared across queue, journal and worker snapshots.
/// Identity claims permit scheduling only; `terms` checks every supplied proof.
#[derive(Clone, Debug, Default)]
pub(crate) struct Prerequisites(Arc<Data>);
impl Serialize for Prerequisites {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Prerequisites {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Data::deserialize(deserializer)?;
        Self::from_inputs(data.artifacts, data.programs).map_err(serde::de::Error::custom)
    }
}
impl Prerequisites {
    #[cfg(test)]
    pub fn new(artifacts: Vec<Envelope>) -> Result<Self, String> {
        Self::from_inputs(artifacts, Vec::new())
    }

    pub fn from_inputs(
        artifacts: Vec<Envelope>,
        programs: Vec<knowledge::Entry>,
    ) -> Result<Self, String> {
        let mut value = Self(Arc::new(Data {
            artifacts,
            programs,
            _memory: None,
        }));
        value.validate()?;
        let program_bytes = value
            .0
            .programs
            .iter()
            .map(|entry| entry.packet.capacity())
            .sum::<usize>();
        let bytes = program_bytes
            + value
                .0
                .artifacts
                .iter()
                .map(|a| a.payload.len() + 512)
                .sum::<usize>();
        if bytes > 0 {
            Arc::get_mut(&mut value.0).expect("new inputs")._memory =
                Some(crate::resources::MemoryLease::acquire(bytes).map_err(|e| e.to_string())?);
        }
        Ok(value)
    }
    pub fn is_empty(&self) -> bool {
        self.0.artifacts.is_empty() && self.0.programs.is_empty()
    }
    pub fn contains_inputs(&self, requested: &Self) -> bool {
        requested
            .0
            .artifacts
            .iter()
            .all(|input| self.0.artifacts.contains(input))
            && requested
                .0
                .programs
                .iter()
                .all(|input| self.0.programs.contains(input))
    }
    pub fn has_definitions(&self) -> bool {
        self.0
            .artifacts
            .iter()
            .any(|artifact| artifact.statement_id.is_none())
    }
    pub fn definitions(
        &self,
        base: &[definitions::Entry],
        required: &[String],
    ) -> Result<Vec<definitions::Entry>, String> {
        if !self.has_definitions() {
            return Ok(base.to_vec());
        }
        let (_, mut selected) = self.resolve(required)?;
        let mut bytes = selected
            .iter()
            .map(definitions::Entry::bytes)
            .sum::<usize>();
        for entry in base {
            if !selected.contains(entry)
                && selected.len() < definitions::CAPACITY
                && bytes + entry.bytes() <= definitions::BYTES
            {
                bytes += entry.bytes();
                selected.push(entry.clone());
            }
        }
        Ok(selected)
    }
    pub fn validate(&self) -> Result<(), String> {
        let limits = crate::resources::limits();
        let mut ids = BTreeSet::new();
        let mut bytes = self
            .0
            .programs
            .iter()
            .map(|entry| entry.packet.len())
            .sum::<usize>();
        if self.0.artifacts.len() + self.0.programs.len() >= limits.closure_objects
            || self.0.programs.len() > knowledge::CAPACITY
            || self
                .0
                .programs
                .iter()
                .any(|entry| entry.packet.len() > knowledge::BYTES)
        {
            return Err("temporary prerequisite object capacity".into());
        }
        for artifact in &self.0.artifacts {
            let id = crate::object::id_bytes(&artifact.artifact_id)?;
            if !ids.insert(id)
                || artifact.compatibility != crate::hex(&crate::object::compatibility())
                || artifact.payload.len() > 2 * limits.proof_bytes
                || artifact.payload.len() % 2 != 0
            {
                return Err("temporary prerequisite identity or capacity".into());
            }
            if let Some(statement) = &artifact.statement_id {
                crate::object::id_bytes(statement)?;
            }
            if let Some(obligation) = &artifact.obligation_proof {
                crate::object::id_bytes(obligation)?;
            }
            bytes = bytes
                .checked_add(artifact.payload.len() / 2)
                .ok_or("temporary prerequisite byte overflow")?;
        }
        if bytes > limits.closure_bytes {
            return Err("temporary prerequisite byte capacity".into());
        }
        Ok(())
    }
    pub fn aliases(&self, required: &[String]) -> Result<Vec<super::program::Reference>, String> {
        let mut aliases = Vec::new();
        for entry in &self.0.programs {
            let data = super::evidence::decode(&entry.packet)?;
            let origin = data.program.ok_or("temporary program origin missing")?;
            let proof = origin.manifest.proof_id();
            if !required
                .iter()
                .any(|id| *id == crate::hex(proof.as_bytes()))
            {
                return Err("temporary program is outside the selected proof set".into());
            }
            let checked = entry.verified()?;
            super::program::validate(&origin, &checked)?;
            let reference = super::program::Reference {
                proof: *proof.as_bytes(),
                projection: *checked.native_id.as_bytes(),
            };
            if aliases.iter().any(|entry: &super::program::Reference| {
                entry.proof == reference.proof || entry.projection == reference.projection
            }) {
                return Err("temporary program projection is ambiguous".into());
            }
            aliases.push(reference);
        }
        Ok(aliases)
    }

    pub fn require(&self, base: &State, required: &[String]) -> Result<(), String> {
        self.validate()?;
        if required.len() > knowledge::CAPACITY
            || required.iter().collect::<BTreeSet<_>>().len() != required.len()
        {
            return Err("required theorem capacity or duplicate".into());
        }
        let aliases = self.aliases(required)?;
        let mut missing = Vec::new();
        for id in required {
            let address = crate::hex(
                crate::object::proof_address(id)
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            );
            if !self.0.artifacts.iter().any(|a| a.artifact_id == address)
                && !aliases
                    .iter()
                    .any(|reference| crate::hex(&reference.proof) == *id)
            {
                missing.push(id.clone());
            }
        }
        base.require_theorems(&missing)
    }
    /// Reconstruct the current ordinary checker context in dependency order.
    /// No envelope's claimed statement or address is accepted as a theorem.
    pub fn terms(&self, required: &[String]) -> Result<Vec<proof::Term>, String> {
        self.resolve(required).map(|(terms, _)| terms)
    }

    fn resolve(
        &self,
        required: &[String],
    ) -> Result<(Vec<proof::Term>, Vec<definitions::Entry>), String> {
        self.validate()?;
        let mut context = naome_checker::ArtifactState::new();
        let mut definitions = Vec::new();
        let mut lemmas = Vec::new();
        let mut terms = Vec::new();
        let mut steps = 0usize;
        for envelope in &self.0.artifacts {
            let candidate = envelope.clone().prepare().map_err(|e| e.to_string())?;
            match &candidate.payload {
                CandidatePayload::Proof(normal) => {
                    steps = steps
                        .checked_add(normal.certificate().steps().len())
                        .ok_or("temporary prerequisite step overflow")?;
                    if steps > crate::resources::limits().closure_steps {
                        return Err("temporary prerequisite checker capacity".into());
                    }
                    let checked = proof::check(normal.certificate().clone(), &context)
                        .map_err(|e| e.to_string())?;
                    if candidate.id != checked.proof_id().into()
                        || candidate.statement != Some(checked.statement_id())
                    {
                        return Err("temporary prerequisite checked binding differs".into());
                    }
                    let id = crate::hex(checked.proof_id().as_bytes());
                    if required.contains(&id) {
                        if !checked.conclusion().free_variables().is_empty() {
                            return Err("temporary prerequisite is not closed".into());
                        }
                        terms.push(proof::Term::Native {
                            certificate: checked.normal_form().certificate().clone(),
                            target: checked.conclusion().clone(),
                            lemmas: lemmas.clone(),
                            definitions: definitions.clone(),
                        });
                    }
                    lemmas.push(checked.normal_form().certificate().clone());
                    context.register_proof(checked).map_err(|e| e.to_string())?;
                }
                CandidatePayload::Definition(certificate) => {
                    let obligation = candidate
                        .obligation
                        .map(|id| {
                            lemmas
                                .iter()
                                .find_map(|c| {
                                    proof::check(c.clone(), &context)
                                        .ok()
                                        .filter(|p| p.proof_id() == id)
                                        .map(|_| c.to_canonical_bytes())
                                })
                                .ok_or("temporary definition obligation missing")
                        })
                        .transpose()?;
                    let entry = definitions::Entry {
                        certificate: certificate.to_canonical_bytes(),
                        obligation,
                    };
                    definitions.push(entry.clone());
                    // Preserve the existing definition snapshot bounds too.
                    if definitions.len() > definitions::CAPACITY
                        || definitions
                            .iter()
                            .map(definitions::Entry::bytes)
                            .sum::<usize>()
                            > definitions::BYTES
                    {
                        return Err("temporary definition reference capacity".into());
                    }
                    definitions::register(&mut context, &entry)?;
                }
            }
        }
        for entry in &self.0.programs {
            terms.push(entry.term()?);
        }
        Ok((terms, definitions))
    }
}

#[cfg(test)]
mod tests;
