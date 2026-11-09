//! Helper traffic consumes the selected program root's existing short grant.
//! A cited program needs no separate question or independent admission effect.
use super::*;

impl Programs {
    fn helper_root(&self, peer: PeerId, root: ArtifactId) -> Option<&Root> {
        self.active.as_ref().filter(|active| {
            active.fetching() && active.offer.transfer.authorizes(peer, root, Instant::now())
        })
    }

    pub(in crate::intake) fn helper_contains(&self, id: ArtifactId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|root| root.closure.contains(id))
    }
    pub(in crate::intake) fn authorizes(
        &self,
        peer: PeerId,
        root: ArtifactId,
        id: ArtifactId,
    ) -> bool {
        self.helper_root(peer, root)
            .is_some_and(|root| root.closure.needs(id) || root.closure.contains(id))
    }
    pub(in crate::intake) fn needed(&self) -> Vec<(PeerId, ArtifactId, ArtifactId)> {
        let Some(root) = &self.active else {
            return Vec::new();
        };
        let id = root.offer.metadata.manifest.artifact_id();
        if self.helper_root(root.offer.transfer.peer(), id).is_none() {
            return Vec::new();
        }
        root.closure
            .needed()
            .map(|helper| (root.offer.transfer.peer(), id, helper))
            .collect()
    }
    pub(in crate::intake) fn insert_helper(
        &mut self,
        peer: PeerId,
        root: ArtifactId,
        metadata: ProgramMetadata,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.authorizes(peer, root, metadata.manifest.artifact_id()) {
            return Err(crate::InputFault::IntakeDependencyDescriptionUnrequested.into());
        }
        self.active
            .as_mut()
            .expect("selected program parent")
            .closure
            .insert(metadata, graph)
    }
    pub(in crate::intake) fn helper_payload(
        &mut self,
        peer: PeerId,
        root: ArtifactId,
        id: ArtifactId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.authorizes(peer, root, id) {
            return Err(crate::InputFault::IntakeDependencyChunkUnrequested.into());
        }
        self.active
            .as_mut()
            .expect("selected program parent")
            .closure
            .payload(id, chunk, graph)
    }
    pub(in crate::intake) fn certificate_payload(
        &mut self,
        peer: PeerId,
        root: ArtifactId,
        id: ArtifactId,
        object: Envelope,
        question: Option<String>,
        graph: &Graph,
    ) -> Result<crate::object::Candidate, crate::Error> {
        if !self.authorizes(peer, root, id) {
            return Err(crate::InputFault::IntakeDependencyCertificateUnrequested.into());
        }
        let active = self.active.as_mut().expect("selected program parent");
        let candidate =
            active
                .closure
                .certificate_payload(id, object, graph, &active.offer.transfer)?;
        if let Some(question) = question {
            active.closure.remember_question(id, question);
        }
        Ok(candidate)
    }

    pub(in crate::intake) fn needs_certificate(
        &self,
        peer: PeerId,
        root: ArtifactId,
        id: ArtifactId,
    ) -> bool {
        self.helper_root(peer, root)
            .is_some_and(|root| root.closure.needs(id))
    }
}

impl Intake {
    pub(crate) fn enqueue_program_helper(
        &mut self,
        peer: PeerId,
        root: ArtifactId,
        metadata: ProgramMetadata,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        let id = metadata.manifest.artifact_id();
        if self.definition_authorizes(peer, root, id) {
            if root == id {
                return Err(crate::InputFault::IntakeDefinitionMismatch.into());
            }
            return self
                .definition
                .as_mut()
                .expect("requested definition")
                .closure
                .insert(metadata, graph);
        }
        if self.programs.authorizes(peer, root, id) {
            return self.programs.insert_helper(peer, root, metadata, graph);
        }
        if !self.authorizes(peer, root, id) {
            return Err(crate::InputFault::IntakeCitedDescriptionUnrequested.into());
        }
        self.programs.remove(id);
        self.active
            .as_mut()
            .expect("approved parent")
            .closure
            .insert(metadata, graph)
    }
    pub(in crate::intake) fn advance_program_helpers<F, Fut>(
        &mut self,
        graph: &Graph,
        questions: &mut LocalQuestions<F>,
    ) -> Result<(), crate::Error>
    where
        F: Fn(ResearchQuestion) -> Fut + Send + Sync + 'static,
        Fut:
            Future<Output = Result<bool, crate::question::SelectionProviderError>> + Send + 'static,
    {
        let Some(root) = &mut self.active else {
            return Ok(());
        };
        if !root.fetching() || !root.closure.has_programs() {
            return Ok(());
        }
        root.selection.prepare(graph, questions)?;
        if !root.description.transfer.live(Instant::now()) {
            return Ok(());
        }
        root.closure.advance(graph)?;
        if root.closure.member_count() > crate::resources::limits().closure_objects {
            return Err(crate::Error::InputLimit(
                crate::InputLimit::CitedClosureDependencyCapacity,
            ));
        }
        Ok(())
    }
}
