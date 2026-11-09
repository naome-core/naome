//! Temporary job inputs from the graph, independent of the bounded neural view.
use super::{State, definitions, knowledge, peer::Packet, proof};
use crate::object::{CandidatePayload, Envelope};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    artifacts: Vec<Envelope>,
    programs: Vec<Packet>,
    offered: Option<[u8; 32]>,
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
        Self::from_inputs(data.artifacts, data.programs, data.offered)
            .map_err(serde::de::Error::custom)
    }
}
impl Prerequisites {
    #[cfg(test)]
    pub fn new(artifacts: Vec<Envelope>) -> Result<Self, crate::Error> {
        Self::from_inputs(artifacts, Vec::new(), None)
    }

    pub fn from_inputs(
        artifacts: Vec<Envelope>,
        programs: Vec<Packet>,
        offered: Option<[u8; 32]>,
    ) -> Result<Self, crate::Error> {
        let mut value = Self(Arc::new(Data {
            artifacts,
            programs,
            offered,
            _memory: None,
        }));
        value.validate()?;
        let program_bytes = value
            .0
            .programs
            .iter()
            .map(Packet::retained_bytes)
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
                Some(crate::resources::MemoryLease::acquire(bytes)?);
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
            && requested
                .0
                .offered
                .is_none_or(|id| self.0.offered == Some(id))
    }
    pub fn has_definitions(&self) -> bool {
        self.0
            .artifacts
            .iter()
            .any(|artifact| artifact.statement_id.is_none())
    }
    pub(crate) fn has_optional_context(&self) -> bool {
        self.has_definitions() || self.has_offer()
    }

    pub fn definitions(
        &self,
        base: &[definitions::Entry],
        required: &[String],
    ) -> Result<Vec<definitions::Entry>, crate::Error> {
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
    pub fn validate(&self) -> Result<(), crate::Error> {
        let limits = crate::resources::limits();
        let mut ids = BTreeSet::new();
        let mut bytes = self
            .0
            .programs
            .iter()
            .map(Packet::retained_bytes)
            .sum::<usize>();
        if self.0.artifacts.len() + self.0.programs.len() >= limits.closure_objects
            || self.0.programs.len() > knowledge::CAPACITY
        {
            return Err(crate::InputLimit::PrerequisiteObjectCapacity.into());
        }
        for entry in &self.0.programs {
            if entry.validate_width().is_err() {
                return Err(crate::InputFault::PrerequisiteProgramInvalid.into());
            }
            if !ids.insert(*entry.manifest.artifact_id().as_bytes()) {
                return Err(crate::InputFault::PrerequisiteDuplicate.into());
            }
        }
        for artifact in &self.0.artifacts {
            let id = crate::object::id_bytes(&artifact.artifact_id)?;
            if !ids.insert(id) {
                return Err(crate::InputFault::PrerequisiteDuplicate.into());
            }
            if artifact.compatibility != crate::hex(&crate::object::compatibility()) {
                return Err(crate::InputFault::ArtifactCompatibilityMismatch.into());
            }
            if artifact.payload.len() > 2 * limits.proof_bytes {
                return Err(crate::InputLimit::PrerequisiteArtifactBytes.into());
            }
            if artifact.payload.len() % 2 != 0 {
                return Err(crate::InputFault::HexWidth.into());
            }
            if let Some(statement) = &artifact.statement_id {
                crate::object::id_bytes(statement)?;
            }
            if let Some(obligation) = &artifact.obligation_proof {
                crate::object::id_bytes(obligation)?;
            }
            bytes = bytes
                .checked_add(artifact.payload.len() / 2)
                .ok_or(crate::InputLimit::PrerequisiteBytesOverflow)?;
        }
        if let Some(id) = self.0.offered {
            let artifact = crate::hex(
                naome_proof::ArtifactId::from_proof_id(naome_proof::ProofId::from_bytes(id))
                    .as_bytes(),
            );
            if !self
                .0
                .programs
                .iter()
                .any(|p| p.manifest.proof_id().as_bytes() == &id)
                && !self
                    .0
                    .artifacts
                    .iter()
                    .any(|a| a.artifact_id == artifact && a.statement_id.is_some())
            {
                return Err(crate::InputFault::PrerequisiteOfferedProofMissing.into());
            }
        }
        if bytes > limits.closure_bytes {
            return Err(crate::InputLimit::PrerequisiteByteCapacity.into());
        }
        Ok(())
    }
    pub fn has_programs(&self) -> bool {
        !self.0.programs.is_empty()
    }

    pub(super) fn has_offer(&self) -> bool {
        self.0.offered.is_some()
    }

    pub(super) fn search_native_lemma(
        &self,
        target: &naome_foundation::Formula,
        ranker: &mut dyn super::model::Ranker,
        maximum: usize,
        started: std::time::Instant,
    ) -> Result<(Option<Packet>, usize), crate::Error> {
        use naome_checker::ContextView;
        use naome_proof::{ProofId, program::Command};

        let _work =
            crate::resources::MemoryLease::acquire(32 * crate::resources::limits().closure_bytes)?;
        let artifacts = self
            .0
            .artifacts
            .iter()
            .map(|a| a.clone().prepare())
            .collect::<Result<Vec<_>, _>>()?;
        let context = Packet::checked_inputs(&self.0.programs, &artifacts)?;
        let id = ProofId::from_bytes(
            self.0
                .offered
                .ok_or(crate::ResearchFailure::OfferedProofMissing)?,
        );
        let header = context
            .proof_header(id)?
            .ok_or(crate::ResearchFailure::OfferedProofBinding)?;
        if header.canonical_length() > naome_checker::question::QUESTION_BYTES {
            return Ok((None, 0));
        }
        let formula = context
            .proof_formula(header, header.canonical_length())?
            .ok_or(crate::ResearchFailure::OfferedProofFormulaMissing)?;
        let (commands, used) = if formula.as_ref() == target {
            (
                Some(vec![
                    Command::ProofReference {
                        proof_id: *id.as_bytes(),
                    },
                    Command::Seal { proof: 0 },
                ]),
                1,
            )
        } else {
            super::search::scope::search_with_lemma(target, id, &formula, ranker, maximum, started)?
        };
        drop(context);
        drop(_work);
        let packet = commands
            .map(|commands| {
                Packet::compose(
                    target,
                    &commands,
                    &self.0.programs,
                    artifacts.iter().map(|a| a.bytes.clone()),
                )
            })
            .transpose()?;
        Ok((packet, used))
    }

    pub(super) fn native_proof(
        &self,
        target: &naome_foundation::Formula,
        required: &[String],
    ) -> Result<Option<Packet>, crate::Error> {
        use naome_checker::ContextView;
        use naome_proof::{
            ProofId,
            program::{Command, Projection},
        };

        let _work =
            crate::resources::MemoryLease::acquire(32 * crate::resources::limits().closure_bytes)?;
        let artifacts = self
            .0
            .artifacts
            .iter()
            .map(|envelope| envelope.clone().prepare())
            .collect::<Result<Vec<_>, _>>()?;
        let context = Packet::checked_inputs(&self.0.programs, &artifacts)?;
        let mut sources = Vec::new();
        for id in required {
            let id = ProofId::from_bytes(crate::object::id_bytes(id)?);
            if let Some(header) = context.proof_header(id)? {
                let formula = context
                    .proof_formula(header, header.canonical_length())?
                    .ok_or(crate::ResearchFailure::PeerPrerequisiteFormulaMissing)?;
                sources.push((id, formula.into_owned()));
            }
        }
        let select = |formula: &naome_foundation::Formula| {
            sources
                .iter()
                .find(|(_, known)| known == formula)
                .map(|(id, _)| *id)
        };
        let commands = if let Some(id) = select(target) {
            vec![
                Command::ProofReference {
                    proof_id: *id.as_bytes(),
                },
                Command::Seal { proof: 0 },
            ]
        } else {
            let Some((left, right)) = super::conjunction_operands(target) else {
                return Ok(None);
            };
            if left == right {
                return Ok(None);
            }
            let (Some(left_id), Some(right_id)) = (select(&left), select(&right)) else {
                return Ok(None);
            };
            let definitions = self.definitions(&[], required)?;
            Projection::conjoin(&[
                (left_id, definitions::represent(&left, &definitions)?),
                (right_id, definitions::represent(&right, &definitions)?),
            ])
        };
        drop(context);
        drop(_work);
        Packet::compose(
            target,
            &commands,
            &self.0.programs,
            artifacts.iter().map(|a| a.bytes.clone()),
        )
        .map(Some)
    }

    pub fn require(&self, base: &State, required: &[String]) -> Result<(), String> {
        self.validate()?;
        if required.len() > knowledge::CAPACITY
            || required.iter().collect::<BTreeSet<_>>().len() != required.len()
        {
            return Err("required theorem capacity or duplicate".into());
        }
        let mut missing = Vec::new();
        for id in required {
            let address = crate::hex(
                crate::object::proof_address(id)
                    .map_err(|e| e.to_string())?
                    .as_bytes(),
            );
            if !self.0.artifacts.iter().any(|a| a.artifact_id == address)
                && !self
                    .0
                    .programs
                    .iter()
                    .any(|program| crate::hex(program.manifest.proof_id().as_bytes()) == *id)
            {
                missing.push(id.clone());
            }
        }
        base.require_theorems(&missing)
    }
    /// Reconstruct the current ordinary checker context in dependency order.
    /// No envelope's claimed statement or address is accepted as a theorem.
    pub fn terms(&self, required: &[String]) -> Result<Vec<proof::Term>, crate::Error> {
        self.resolve(required).map(|(terms, _)| terms)
    }

    fn resolve(
        &self,
        required: &[String],
    ) -> Result<(Vec<proof::Term>, Vec<definitions::Entry>), crate::Error> {
        self.validate()?;
        let mut context = naome_checker::ArtifactState::new();
        let mut definitions = Vec::new();
        let mut lemmas = Vec::new();
        let mut terms = Vec::new();
        let mut steps = 0usize;
        let mut program_dependent = self
            .0
            .programs
            .iter()
            .map(|program| program.manifest.artifact_id())
            .collect::<BTreeSet<_>>();
        for envelope in &self.0.artifacts {
            let candidate = envelope.clone().prepare()?;
            // These inputs are checked by the mixed program context. They
            // cannot be used as standalone Hilbert certificate terms.
            if candidate
                .dependencies
                .iter()
                .copied()
                .chain(candidate.obligation.map(Into::into))
                .any(|id| program_dependent.contains(&id))
            {
                program_dependent.insert(candidate.id);
                continue;
            }
            match &candidate.payload {
                CandidatePayload::Proof(normal) => {
                    steps = steps
                        .checked_add(normal.certificate().steps().len())
                        .ok_or(crate::InputLimit::PrerequisiteStepsOverflow)?;
                    if steps > crate::resources::limits().closure_steps {
                        return Err(crate::InputLimit::PrerequisiteCheckerCapacity.into());
                    }
                    let checked = proof::check(normal.certificate().clone(), &context)?;
                    if candidate.id != checked.proof_id().into()
                        || candidate.statement != Some(checked.statement_id())
                    {
                        return Err(crate::InputFault::CheckedIdentityMismatch.into());
                    }
                    let id = crate::hex(checked.proof_id().as_bytes());
                    if required.contains(&id) {
                        if !checked.conclusion().free_variables().is_empty() {
                            return Err(crate::InputFault::PrerequisiteNotClosed.into());
                        }
                        terms.push(proof::Term::Native {
                            certificate: checked.normal_form().certificate().clone(),
                            target: checked.conclusion().clone(),
                            lemmas: lemmas.clone(),
                            definitions: definitions.clone(),
                        });
                    }
                    lemmas.push(checked.normal_form().certificate().clone());
                    context.register_proof(checked)?;
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
                                .ok_or(crate::InputFault::PrerequisiteObligationMissing)
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
                        return Err(crate::InputLimit::PrerequisiteDefinitionCapacity.into());
                    }
                    definitions::register(&mut context, &entry)?;
                }
            }
        }
        Ok((terms, definitions))
    }
}

#[cfg(test)]
mod tests;
