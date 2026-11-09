//! Bounded learning snapshots derived only from the checked canonical graph.
use super::*;
impl Graph {
    /// Capture exact canonical inputs; mathematical checking belongs to the
    /// granted worker, rather than this graph/async scheduling path.
    #[cfg(test)]
    pub(crate) fn prerequisites(
        &self,
        required: &[String],
    ) -> Result<Option<crate::learning::Prerequisites>, crate::Error> {
        self.solving_inputs(required, &[])
    }

    pub(crate) fn solving_inputs(
        &self,
        required: &[String],
        definitions: &[ArtifactId],
    ) -> Result<Option<crate::learning::Prerequisites>, crate::Error> {
        self.capture_solving_inputs(required, definitions, None)
    }

    pub(crate) fn offered_solving_inputs(
        &self,
        proof: naome_proof::ProofId,
        definitions: &[ArtifactId],
    ) -> Result<Option<crate::learning::Prerequisites>, crate::Error> {
        self.capture_solving_inputs(&[], definitions, Some(proof))
    }

    fn capture_solving_inputs(
        &self,
        required: &[String],
        definitions: &[ArtifactId],
        offered: Option<naome_proof::ProofId>,
    ) -> Result<Option<crate::learning::Prerequisites>, crate::Error> {
        struct Capture<'a> {
            graph: &'a Graph,
            active: std::collections::BTreeSet<ArtifactId>,
            seen: std::collections::BTreeSet<ArtifactId>,
            artifacts: Vec<Envelope>,
            programs: Vec<crate::learning::peer::Packet>,
            bytes: usize,
        }
        impl Capture<'_> {
            fn visit(&mut self, id: ArtifactId) -> Result<bool, crate::Error> {
                if self.seen.contains(&id) {
                    return Ok(true);
                }
                if !self.active.insert(id) {
                    return Err(crate::InputFault::LearningPrerequisiteCycle.into());
                }
                if self.active.len() + self.seen.len() >= crate::resources::limits().closure_objects
                {
                    return Ok(false);
                }
                let Some(object) = self.graph.binary_object(id)? else {
                    return Ok(false);
                };
                self.bytes = self
                    .bytes
                    .checked_add(object.bytes.len())
                    .ok_or(crate::InputFault::LearningPrerequisiteBytes)?;
                if self.bytes > crate::resources::limits().closure_bytes {
                    return Ok(false);
                }
                if let Some(manifest) = crate::object::program_manifest(&object.bytes)? {
                    // Preserve the canonical program and its exact checked inputs.
                    let Some(packet) = self.graph.peer_program(manifest)? else {
                        return Ok(false);
                    };
                    self.bytes = self
                        .bytes
                        .checked_add(packet.retained_bytes())
                        .ok_or(crate::InputFault::LearningPrerequisitePacketWidth)?;
                    if self.bytes > crate::resources::limits().closure_bytes {
                        return Ok(false);
                    }
                    self.programs.push(packet);
                    self.active.remove(&id);
                    self.seen.insert(id);
                    return Ok(true);
                }
                for dependency in &object.dependencies {
                    if !self.visit(*dependency)? {
                        return Ok(false);
                    }
                }
                self.artifacts.push(object.envelope());
                self.active.remove(&id);
                self.seen.insert(id);
                Ok(true)
            }
        }
        if required.len() > crate::learning::knowledge::CAPACITY {
            return Err(crate::InputFault::LearningPrerequisiteCapacity.into());
        }
        let mut capture = Capture {
            graph: self,
            active: Default::default(),
            seen: Default::default(),
            artifacts: Vec::new(),
            programs: Vec::new(),
            bytes: 0,
        };
        for &id in definitions {
            if self
                .cold(self.context.artifact_definition_id(id))?
                .is_none()
                || !capture.visit(id)?
            {
                return Ok(None);
            }
        }
        for id in required {
            if !capture.visit(crate::object::proof_address(id)?)? {
                return Ok(None);
            }
        }
        if let Some(proof) = offered
            && !capture.visit(proof.into())?
        {
            return Ok(None);
        }
        crate::learning::Prerequisites::from_inputs(
            capture.artifacts,
            capture.programs,
            offered.map(|p| *p.as_bytes()),
        )
        .map(Some)
    }
    pub(crate) fn peer_learning_page(
        &self,
        after: u64,
    ) -> Result<Vec<(u64, ArtifactId, Option<libp2p::PeerId>)>, crate::Error> {
        self.ensure_live()?;
        if after > self.count as u64 {
            return Err(crate::ResearchFailure::PeerCursorBeyondGraph.into());
        }
        self.cold(self.store.peer_learning_page(
            after,
            crate::resources::active_limits().id_page.min(4),
            self.fixed_summary(),
        ))
    }
    pub(crate) fn learning_question(
        &self,
        id: ArtifactId,
    ) -> Result<Option<naome_checker::question::ResearchQuestion>, crate::Error> {
        use naome_checker::ContextView;
        self.ensure_live()?;
        let Some(proof) = self.cold(self.context.artifact_proof_id(id))? else {
            return Ok(None);
        };
        let Some(header) =
            self.cold(self.context.proof_header(proof).map_err(crate::Error::from))?
        else {
            return Ok(None);
        };
        if header.canonical_length() > crate::resources::limits().closure_bytes {
            return Ok(None);
        }
        let _memory = crate::resources::MemoryLease::acquire(
            header
                .canonical_length()
                .checked_mul(16)
                .and_then(|n| n.checked_add(4096))
                .ok_or(crate::InputFault::LearningFormulaMemory)?,
        )?;
        let formula = self
            .cold(
                self.context
                    .proof_formula(header, header.canonical_length())
                    .map_err(crate::Error::from),
            )?
            .ok_or(crate::InputFault::LearningFormulaMissing)?
            .into_owned();
        Ok(naome_checker::question::ResearchQuestion::from_formula(formula).ok())
    }
    pub(crate) fn learning_definition(
        &self,
        id: ArtifactId,
    ) -> Result<Option<crate::learning::definitions::Entry>, crate::Error> {
        self.ensure_live()?;
        if self
            .cold(self.context.artifact_definition_id(id))?
            .is_none()
        {
            return Ok(None);
        }
        let object = self
            .binary_object(id)?
            .ok_or(crate::InputFault::LearningDefinitionMissing)?;
        let Some((&naome_proof::ArtifactPayload::DEFINITION_TAG, certificate)) =
            object.bytes.split_first()
        else {
            return Err(crate::InputFault::LearningDefinitionType.into());
        };
        if certificate.len() > crate::learning::definitions::BYTES {
            return Ok(None);
        }
        let obligation = if let Some(proof) = object.obligation {
            let Some(proof) = self.binary_object(proof.into())? else {
                return Err(crate::InputFault::LearningDefinitionObligation.into());
            };
            if !proof.dependencies.is_empty()
                || proof.bytes.len() + certificate.len() > crate::learning::definitions::BYTES
            {
                return Ok(None);
            }
            let Some((&naome_proof::ArtifactPayload::PROOF_TAG, bytes)) = proof.bytes.split_first()
            else {
                return Ok(None);
            };
            Some(bytes.to_vec())
        } else {
            None
        };
        let entry = crate::learning::definitions::Entry {
            certificate: certificate.to_vec(),
            obligation,
        };
        let _ = crate::learning::definitions::context(std::slice::from_ref(&entry))?;
        Ok(Some(entry))
    }
    /// Snapshot the exact checked input and its ordered proof and definition dependencies.
    /// A replay worker rechecks these objects and the original program seal.
    pub(crate) fn peer_program(
        &self,
        manifest: naome_proof::program::Manifest,
    ) -> Result<Option<crate::learning::peer::Packet>, crate::Error> {
        use naome_proof::{
            DefinitionId, ProofId,
            program::{CHUNK_BYTES, CHUNK_RECORDS, Command, Manifest},
        };
        use std::collections::BTreeSet;
        fn references(commands: &[Command]) -> impl Iterator<Item = ArtifactId> + '_ {
            commands.iter().filter_map(|command| match command {
                Command::ProofReference { proof_id } => Some(ProofId::from_bytes(*proof_id).into()),
                Command::DefinedRelation { definition_id, .. } => {
                    Some(DefinitionId::from_bytes(*definition_id).into())
                }
                _ => None,
            })
        }
        let limits = crate::resources::limits();
        let bounded = |m: &Manifest| {
            m.commands <= limits.closure_steps as u64
                && m.input_bytes <= limits.closure_bytes as u64
        };
        if !bounded(&manifest) {
            return Ok(None);
        }
        let _memory = crate::resources::MemoryLease::acquire(8 * limits.closure_bytes)?;
        let read = |manifest: &Manifest| -> Result<Vec<Command>, crate::Error> {
            let id = manifest.artifact_id();
            let mut commands = Vec::new();
            while (commands.len() as u64) < manifest.commands {
                let chunk = self
                    .program_chunk(id, commands.len() as u64, CHUNK_RECORDS, CHUNK_BYTES)?
                    .ok_or(crate::InputFault::LearningPeerProgramMissing)?;
                if chunk.records.is_empty() {
                    return Err(crate::InputFault::LearningPeerProgramChunk.into());
                }
                commands.extend(chunk.records);
            }
            Ok(commands)
        };
        let commands = read(&manifest)?;
        let mut pending = references(&commands)
            .map(|id| (id, None))
            .collect::<Vec<_>>();
        let mut active = BTreeSet::new();
        let mut seen = BTreeSet::new();
        let mut context = Vec::new();
        let mut bytes = manifest.input_bytes as usize;
        // Iterative postorder over the checked certificate closure. No source
        // is exposed until the entire bounded context is available.
        while let Some((id, payload)) = pending.pop() {
            if let Some(payload) = payload {
                active.remove(&id);
                seen.insert(id);
                context.push(payload);
                continue;
            }
            if seen.contains(&id) {
                continue;
            }
            if !active.insert(id) {
                return Err(crate::InputFault::LearningPeerProgramCycle.into());
            }
            if active.len() + seen.len() >= limits.closure_objects {
                return Ok(None);
            }
            let object = self
                .binary_object(id)?
                .ok_or(crate::InputFault::LearningPeerOperandMissing)?;
            let (record, dependencies) = if let Some(dependency) =
                crate::object::program_manifest(&object.bytes)?
            {
                if !bounded(&dependency)
                    || bytes.saturating_add(dependency.input_bytes as usize) > limits.closure_bytes
                {
                    return Ok(None);
                }
                let records = read(&dependency)?;
                let children = references(&records).collect::<Vec<_>>();
                (
                    crate::learning::peer::Packet::context_record(&dependency, &records)?,
                    children,
                )
            } else {
                let mut children = object.dependencies.into_iter().collect::<Vec<_>>();
                if let Some(proof) = object.obligation {
                    children.push(proof.into());
                }
                (object.bytes, children)
            };
            bytes = bytes
                .checked_add(record.len())
                .ok_or(crate::InputFault::LearningPeerContextBytes)?;
            if bytes > limits.closure_bytes {
                return Ok(None);
            }
            pending.push((id, Some(record)));
            pending.extend(
                dependencies
                    .into_iter()
                    .map(|dependency| (dependency, None)),
            );
        }
        crate::learning::peer::Packet::pack(manifest, &commands, &context)
    }

    pub(crate) fn learning_certificate(
        &self,
        id: ArtifactId,
    ) -> Result<Option<Vec<u8>>, crate::Error> {
        struct Snapshot<'a> {
            graph: &'a Graph,
            active: std::collections::BTreeSet<ArtifactId>,
            seen: std::collections::BTreeSet<ArtifactId>,
            bytes: usize,
        }
        impl Snapshot<'_> {
            fn visit(
                &mut self,
                id: ArtifactId,
            ) -> Result<Option<crate::learning::proof::Verified>, crate::Error> {
                if !self.active.insert(id) {
                    return Err(crate::InputFault::LearningClosureCycle.into());
                }
                self.seen.insert(id);
                let limits = crate::resources::limits();
                if self.seen.len() > limits.closure_objects {
                    return Ok(None);
                }
                let Some(object) = self.graph.binary_object(id)? else {
                    return Ok(None);
                };
                let Some((&naome_proof::ArtifactPayload::PROOF_TAG, payload)) =
                    object.bytes.split_first()
                else {
                    return Ok(None);
                };
                self.bytes = self
                    .bytes
                    .checked_add(object.bytes.len())
                    .ok_or(crate::InputFault::LearningClosureBytes)?;
                if self.bytes > limits.closure_bytes {
                    return Ok(None);
                }
                let mut definitions = Vec::new();
                let mut lemmas = Vec::new();
                for dependency in &object.dependencies {
                    if let Some(definition) = self.graph.learning_definition(*dependency)? {
                        if !definitions.contains(&definition) {
                            definitions.push(definition);
                        }
                        continue;
                    }
                    let Some(verified) = self.visit(*dependency)? else {
                        return Ok(None);
                    };
                    for definition in verified.definitions {
                        if !definitions.contains(&definition) {
                            definitions.push(definition);
                        }
                    }
                    for certificate in verified
                        .lemmas
                        .into_iter()
                        .chain(std::iter::once(verified.certificate))
                    {
                        if !lemmas.contains(&certificate) {
                            lemmas.push(certificate);
                        }
                    }
                }
                let certificate = naome_proof::ProofCertificate::from_canonical_bytes(payload)
                    .map_err(|error| crate::object::certificate_error(payload, error))?;
                // This theorem is already accepted by the graph. A smaller
                // learning snapshot can skip it without classifying it as corrupt.
                if !crate::learning::definitions::fits(&definitions)
                    || certificate.steps().len()
                        + definitions.len()
                        + lemmas
                            .iter()
                            .map(|lemma| lemma.steps().len())
                            .sum::<usize>()
                        > limits.closure_steps
                {
                    return Ok(None);
                }
                let verified =
                    crate::learning::proof::verify_native(certificate, definitions, lemmas, None)?;
                if ArtifactId::from(verified.native_id) != id {
                    return Err(crate::InputFault::LearningCertificateIdentity.into());
                }
                self.active.remove(&id);
                Ok(Some(verified))
            }
        }
        self.ensure_live()?;
        let _memory =
            crate::resources::MemoryLease::acquire(64 * crate::resources::limits().closure_bytes)?;
        let mut snapshot = Snapshot {
            graph: self,
            active: Default::default(),
            seen: Default::default(),
            bytes: 0,
        };
        let Some(verified) = snapshot.visit(id)? else {
            return Ok(None);
        };
        match crate::learning::evidence::pack(&verified) {
            Ok(packet) => Ok((packet.len() <= crate::learning::knowledge::BYTES).then_some(packet)),
            Err(crate::learning::evidence::Failure::Limit { .. }) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
}
