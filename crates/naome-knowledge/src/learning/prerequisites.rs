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
    internal_cut: Option<Vec<u8>>,
    offered: Option<[u8; 32]>,
    #[serde(skip)]
    _memory: Option<Arc<crate::resources::MemoryLease>>,
}

/// Exact untrusted bytes are shared across queue, journal and worker snapshots.
/// Identity claims permit scheduling only; `terms` checks every supplied proof.
#[derive(Clone, Debug, Default)]
pub(crate) struct Prerequisites(Arc<Data>);
/// Reconstructed native inputs for semantic reference selection in a worker.
pub(super) struct ProgramInputs<'a> {
    pub context: naome_checker::DiskArtifactState,
    pub programs: &'a [Packet],
    pub artifacts: Vec<crate::object::Candidate>,
    _memory: Arc<crate::resources::MemoryLease>,
}

impl<'a> ProgramInputs<'a> {
    pub fn proof_ids(
        &self,
    ) -> impl Iterator<Item = Result<naome_proof::ProofId, crate::Error>> + '_ {
        self.programs
            .iter()
            .map(|packet| Ok(packet.manifest.proof_id()))
            .chain(
                self.artifacts
                    .iter()
                    .filter_map(|artifact| artifact.record().proof_id().transpose()),
            )
    }

    pub fn into_sources(self) -> (&'a [Packet], Vec<crate::object::Candidate>) {
        (self.programs, self.artifacts)
    }
}

impl Serialize for Prerequisites {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Prerequisites {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Data::deserialize(deserializer)?;
        Self::from_parts(
            data.artifacts,
            data.programs,
            data.offered,
            data.internal_cut,
        )
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
        Self::from_parts(artifacts, programs, offered, None)
    }

    pub(crate) fn internal_cut(certificate: Vec<u8>) -> Result<Self, crate::Error> {
        Self::from_parts(Vec::new(), Vec::new(), None, Some(certificate))
    }

    pub(super) fn cut_certificate(&self) -> Option<&[u8]> {
        self.0.internal_cut.as_deref()
    }

    fn from_parts(
        artifacts: Vec<Envelope>,
        programs: Vec<Packet>,
        offered: Option<[u8; 32]>,
        internal_cut: Option<Vec<u8>>,
    ) -> Result<Self, crate::Error> {
        let mut value = Self(Arc::new(Data {
            artifacts,
            programs,
            offered,
            internal_cut,
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
            + value.cut_certificate().map_or(0, <[u8]>::len)
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
        self.0.artifacts.is_empty()
            && self.0.programs.is_empty()
            && self.cut_certificate().is_none()
    }
    pub fn contains_inputs(&self, requested: &Self) -> bool {
        requested
            .cut_certificate()
            .is_none_or(|cut| self.cut_certificate() == Some(cut))
            && requested
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
        self.has_definitions() || self.has_offer() || self.cut_certificate().is_some()
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
        if let Some(certificate) = self.cut_certificate()
            && (certificate.is_empty()
                || certificate.len() > knowledge::BYTES
                || !self.0.artifacts.is_empty()
                || !self.0.programs.is_empty())
        {
            return Err(crate::InputFault::InternalCutContext.into());
        }
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

    pub(super) fn supplies_program(&self, id: &str) -> bool {
        self.0
            .programs
            .iter()
            .any(|packet| crate::hex(packet.manifest.proof_id().as_bytes()) == id)
    }

    pub(super) fn has_offer(&self) -> bool {
        self.0.offered.is_some()
    }

    pub(super) fn checked_program_inputs(&self) -> Result<ProgramInputs<'_>, crate::Error> {
        let memory =
            crate::resources::MemoryLease::acquire(32 * crate::resources::limits().closure_bytes)?;
        let artifacts = self
            .0
            .artifacts
            .iter()
            .map(|envelope| envelope.clone().prepare())
            .collect::<Result<Vec<_>, _>>()?;
        let context = Packet::checked_inputs(&self.0.programs, &artifacts)?;
        Ok(ProgramInputs {
            context,
            programs: &self.0.programs,
            artifacts,
            _memory: memory,
        })
    }

    pub(super) fn search_native_lemma(
        &self,
        target: &naome_foundation::Formula,
        ranker: &mut dyn super::model::Ranker,
        maximum: usize,
        started: std::time::Instant,
    ) -> Result<(Option<Packet>, usize), crate::Error> {
        use naome_checker::ContextView;
        use naome_proof::{
            ProofId,
            program::{Command, Projection},
        };

        let inputs = self.checked_program_inputs()?;
        let context = &inputs.context;
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
        } else if maximum >= 2
            && super::knowledge::universal_source(target).as_ref() == Some(formula.as_ref())
        {
            use super::{calculus, construction::logic, proof};
            let variable = naome_foundation::FreeVariable::new(0);
            let mut names = calculus::Names::default();
            names.native_programs = true;
            let instance = calculus::instantiate(
                proof::Term::CheckedInput(id, formula.into_owned()),
                variable,
            )?;
            let term = logic::exists_intro(target, variable, instance, &mut names)?;
            let recipe = proof::recipe(&term, target)?;
            (
                Some(Projection::from_inference_steps(&recipe.steps)?.into_commands()),
                2,
            )
        } else {
            super::search::scope::search_with_lemma(target, id, &formula, ranker, maximum, started)?
        };
        let (programs, artifacts) = inputs.into_sources();
        let packet = commands
            .map(|commands| {
                Packet::compose(
                    target,
                    &commands,
                    programs,
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
        maximum: usize,
        started: std::time::Instant,
    ) -> Result<(Option<super::construction::ProgramCandidate>, usize), crate::Error> {
        use naome_checker::ContextView;
        use naome_proof::{
            ProofId, ProofStep,
            program::{Command, Projection},
        };

        let inputs = self.checked_program_inputs()?;
        let context = &inputs.context;
        let mut sources = Vec::new();
        for id in required {
            let id = ProofId::from_bytes(crate::object::id_bytes(id)?);
            if let Some(header) = context.proof_header(id)? {
                let formula = context
                    .proof_formula(header, header.canonical_length())?
                    .ok_or(crate::ResearchFailure::PeerPrerequisiteFormulaMissing)?;
                if !formula.is_closed() {
                    return Err(crate::InputFault::PrerequisiteNotClosed.into());
                }
                sources.push((id, formula.into_owned()));
            }
        }
        let select = |formula: &naome_foundation::Formula| {
            sources
                .iter()
                .find(|(_, known)| known == formula)
                .map(|(id, _)| *id)
        };
        let direct = if let Some(id) = select(target) {
            Some(vec![
                Command::ProofReference {
                    proof_id: *id.as_bytes(),
                },
                Command::Seal { proof: 0 },
            ])
        } else if let Some((left, right)) = super::conjunction_operands(target)
            && left != right
            && let (Some(left_id), Some(right_id)) = (select(&left), select(&right))
        {
            let definitions = self.definitions(&[], required)?;
            Some(Projection::conjoin(&[
                (left_id, definitions::represent(&left, &definitions)?),
                (right_id, definitions::represent(&right, &definitions)?),
            ]))
        } else {
            None
        };
        let (programs, artifacts) = inputs.into_sources();
        let artifacts = || artifacts.iter().map(|a| a.bytes.clone());
        if let Some(commands) = direct {
            let packet = Packet::compose(target, &commands, programs, artifacts())?;
            return Ok((
                Some(super::construction::ProgramCandidate {
                    packet,
                    helpers: Vec::new(),
                }),
                1,
            ));
        }

        let program_ids = programs
            .iter()
            .map(|packet| packet.manifest.proof_id())
            .collect::<BTreeSet<_>>();
        if (1..=2).contains(&sources.len())
            && let Some(cut) = super::search::scope::cut::plan(target, sources.len(), |formula| {
                select(formula).filter(|id| program_ids.contains(id))
            })
            && cut.work() <= maximum
            && started.elapsed() < std::time::Duration::from_millis(2500)
        {
            let packet = Packet::compose(target, &cut.commands(), programs, artifacts())?;
            return Ok((
                Some(super::construction::ProgramCandidate {
                    packet,
                    helpers: Vec::new(),
                }),
                cut.work(),
            ));
        }

        if sources.iter().all(|(id, _)| !program_ids.contains(id)) {
            return Ok((None, 0));
        }
        let terms = sources
            .into_iter()
            .map(|(id, formula)| proof::Term::CheckedInput(id, formula))
            .collect::<Vec<_>>();
        let (term, work) = super::construction::composition::construct_term(
            target, &terms, maximum, started, true,
        )?;
        let Some(term) = term else {
            return Ok((None, work));
        };
        let recipe = proof::recipe(&term, target)?;
        if !recipe.steps.iter().any(|step| {
            matches!(step, ProofStep::ProofReference { proof_id } if program_ids.contains(proof_id))
        }) {
            return Ok((None, work));
        }
        let candidate = super::construction::program_from_recipe_with_inputs(
            target,
            recipe,
            programs,
            artifacts(),
            None,
        )?;
        Ok((Some(candidate), work))
    }

    pub fn require(&self, base: &State, required: &[String]) -> Result<(), crate::Error> {
        self.validate()?;
        if self.cut_certificate().is_some() && !required.is_empty() {
            return Err(crate::InputFault::InternalCutContext.into());
        }
        if required.len() > knowledge::CAPACITY
            || required.iter().collect::<BTreeSet<_>>().len() != required.len()
        {
            return Err(crate::InputFault::RequiredTheorems.into());
        }
        let mut missing = Vec::new();
        for id in required {
            let address = crate::hex(crate::object::proof_address(id)?.as_bytes());
            if !self.0.artifacts.iter().any(|a| a.artifact_id == address)
                && !self.supplies_program(id)
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
