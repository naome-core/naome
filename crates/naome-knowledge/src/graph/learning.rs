//! Bounded learning snapshots derived only from the checked canonical graph.
use super::*;
impl Graph {
    /// Capture exact canonical inputs; mathematical checking belongs to the
    /// granted worker, rather than this graph/async scheduling path.
    pub(crate) fn prerequisites(
        &self,
        required: &[String],
    ) -> Result<Option<crate::learning::Prerequisites>, crate::Error> {
        struct Capture<'a> {
            graph: &'a Graph,
            active: std::collections::BTreeSet<ArtifactId>,
            seen: std::collections::BTreeSet<ArtifactId>,
            artifacts: Vec<Envelope>,
            bytes: usize,
        }
        impl Capture<'_> {
            fn visit(&mut self, id: ArtifactId) -> Result<bool, crate::Error> {
                if self.seen.contains(&id) {
                    return Ok(true);
                }
                if !self.active.insert(id) {
                    return Err("checked prerequisite cycle".into());
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
                    .ok_or("prerequisite closure byte overflow")?;
                if self.bytes > crate::resources::limits().closure_bytes
                    || crate::object::program_manifest(&object.bytes)?.is_some()
                {
                    return Ok(false);
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
            return Err("required prerequisite capacity".into());
        }
        let mut capture = Capture {
            graph: self,
            active: Default::default(),
            seen: Default::default(),
            artifacts: Vec::new(),
            bytes: 0,
        };
        for id in required {
            if !capture.visit(crate::object::proof_address(id)?)? {
                return Ok(None);
            }
        }
        crate::learning::Prerequisites::new(capture.artifacts)
            .map(Some)
            .map_err(Into::into)
    }
    pub(crate) fn peer_learning_page(
        &self,
        after: u64,
    ) -> Result<Vec<(u64, ArtifactId, Option<libp2p::PeerId>)>, crate::Error> {
        self.ensure_live()?;
        if after > self.count as u64 {
            return Err("peer learning cursor exceeds checked graph".into());
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
    ) -> Result<Option<naome_authoring::CompiledQuestion>, crate::Error> {
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
                .ok_or("learning formula memory overflow")?,
        )?;
        let formula = self
            .cold(
                self.context
                    .proof_formula(header, header.canonical_length())
                    .map_err(crate::Error::from),
            )?
            .ok_or("checked learning formula missing")?
            .into_owned();
        Ok(naome_authoring::CompiledQuestion::from_formula(formula).ok())
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
            .ok_or("checked definition payload missing")?;
        let Some((&naome_proof::ArtifactPayload::DEFINITION_TAG, certificate)) =
            object.bytes.split_first()
        else {
            return Err("checked definition payload type differs".into());
        };
        if certificate.len() > crate::learning::definitions::BYTES {
            return Ok(None);
        }
        let obligation = if let Some(proof) = object.obligation {
            let Some(proof) = self.binary_object(proof.into())? else {
                return Err("checked definition obligation missing".into());
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
    pub(crate) fn learning_certificate(
        &self,
        id: ArtifactId,
    ) -> Result<Option<Vec<u8>>, crate::Error> {
        struct Snapshot<'a> {
            graph: &'a Graph,
            active: std::collections::BTreeSet<ArtifactId>,
            seen: std::collections::BTreeSet<ArtifactId>,
            proofs: std::collections::BTreeMap<ArtifactId, crate::learning::program::Projection>,
            bytes: usize,
        }
        impl Snapshot<'_> {
            fn visit(
                &mut self,
                id: ArtifactId,
            ) -> Result<Option<crate::learning::proof::Verified>, crate::Error> {
                if let Some(p) = self.proofs.get(&id) {
                    let context = crate::learning::proof::lemma_context(&p.definitions, &p.lemmas)?;
                    let checked = crate::learning::proof::check(p.certificate.clone(), &context)
                        .map_err(|e| crate::Error::from(e.to_string()))?;
                    return crate::learning::proof::verify(
                        &crate::learning::proof::Term::Native {
                            certificate: p.certificate.clone(),
                            lemmas: p.lemmas.clone(),
                            definitions: p.definitions.clone(),
                            target: checked.conclusion().clone(),
                        },
                        checked.conclusion(),
                    )
                    .map(Some)
                    .map_err(Into::into);
                }
                if !self.active.insert(id) {
                    return Err("checked learning dependency cycle".into());
                }
                self.seen.insert(id);
                if self.seen.len() > crate::resources::limits().closure_objects {
                    return Ok(None);
                }
                let Some(object) = self.graph.binary_object(id)? else {
                    return Ok(None);
                };
                self.bytes = self
                    .bytes
                    .checked_add(object.bytes.len())
                    .ok_or("learning closure byte overflow")?;
                if self.bytes > crate::resources::limits().closure_bytes {
                    return Ok(None);
                }
                let mut definitions = Vec::new();
                let mut lemmas = Vec::new();
                let manifest = crate::object::program_manifest(&object.bytes)?;
                for dependency in &object.dependencies {
                    if let Some(definition) = self.graph.learning_definition(*dependency)? {
                        if !definitions.contains(&definition) {
                            definitions.push(definition);
                        }
                    } else if manifest.is_none() {
                        let Some(verified) = self.visit(*dependency)? else {
                            return Ok(None);
                        };
                        for d in verified.definitions {
                            if !definitions.contains(&d) {
                                definitions.push(d);
                            }
                        }
                        for c in verified
                            .lemmas
                            .into_iter()
                            .chain(std::iter::once(verified.certificate))
                        {
                            if !lemmas.contains(&c) {
                                lemmas.push(c);
                            }
                        }
                    }
                }
                let (certificate, origin) = if let Some(manifest) = manifest {
                    let graph = self.graph;
                    let source_error = std::cell::RefCell::new(None);
                    let projection = crate::learning::program::project(
                        manifest,
                        |position| {
                            let chunk = graph
                                .program_chunk(id, position, 1, naome_proof::program::RECORD_BYTES)
                                .map_err(|e| {
                                    let message = e.to_string();
                                    *source_error.borrow_mut() = Some(e);
                                    message
                                })?
                                .ok_or("learning program source absent")?;
                            chunk
                                .records
                                .into_iter()
                                .next()
                                .ok_or_else(|| "learning program command absent".into())
                        },
                        |proof| {
                            self.visit(proof.into())
                                .map_err(|e| {
                                    let message = e.to_string();
                                    *source_error.borrow_mut() = Some(e);
                                    message
                                })?
                                .ok_or_else(|| "learning program reference capacity".into())
                        },
                        definitions,
                    );
                    if let Some(error) = source_error.into_inner() {
                        return Err(error);
                    }
                    let projection = match projection {
                        Ok(p) => p,
                        Err(error) if error.contains("capacity") || error.contains("limit") => {
                            return Ok(None);
                        }
                        Err(error) => return Err(error.into()),
                    };
                    self.bytes = self
                        .bytes
                        .checked_add(projection.certificate.to_canonical_bytes().len())
                        .and_then(|bytes| {
                            serde_json::to_vec(&projection.origin)
                                .ok()
                                .and_then(|origin| bytes.checked_add(origin.len()))
                        })
                        .ok_or("learning projection byte overflow")?;
                    if self.bytes > crate::resources::limits().closure_bytes {
                        return Ok(None);
                    }
                    definitions = projection.definitions.clone();
                    lemmas = projection.lemmas.clone();
                    let certificate = projection.certificate.clone();
                    let origin = projection.origin.clone();
                    self.proofs.insert(id, projection);
                    (certificate, Some(origin))
                } else {
                    let Some((&naome_proof::ArtifactPayload::PROOF_TAG, payload)) =
                        object.bytes.split_first()
                    else {
                        return Ok(None);
                    };
                    (
                        naome_proof::ProofCertificate::from_canonical_bytes(payload)
                            .map_err(|e| crate::Error::from(e.to_string()))?,
                        None,
                    )
                };
                let context = crate::learning::proof::lemma_context(&definitions, &lemmas)?;
                let checked = crate::learning::proof::check(certificate, &context)
                    .map_err(|e| crate::Error::from(e.to_string()))?;
                let verified = crate::learning::proof::verify(
                    &crate::learning::proof::Term::Native {
                        certificate: checked.normal_form().certificate().clone(),
                        lemmas,
                        definitions,
                        target: checked.conclusion().clone(),
                    },
                    checked.conclusion(),
                )?;
                if let Some(origin) = origin {
                    crate::learning::program::validate(&origin, &verified)?;
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
            proofs: Default::default(),
            bytes: 0,
        };
        let Some(verified) = snapshot.visit(id)? else {
            return Ok(None);
        };
        let origin = snapshot.proofs.get(&id).map(|p| p.origin.clone());
        let packet = crate::learning::evidence::pack_with_program(&verified, origin)?;
        Ok((packet.len() <= 8 * 1024).then_some(packet))
    }
}
