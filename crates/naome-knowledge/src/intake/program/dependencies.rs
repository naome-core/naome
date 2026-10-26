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
            return Err("unrequested program dependency description".into());
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
            return Err("unrequested program dependency chunk".into());
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
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.authorizes(peer, root, id) {
            return Err("unrequested program dependency certificate".into());
        }
        let active = self.active.as_mut().expect("selected program parent");
        active
            .closure
            .certificate_payload(id, object, graph, &active.offer.transfer)
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
        if self.programs.authorizes(peer, root, id) {
            return self.programs.insert_helper(peer, root, metadata, graph);
        }
        if !self.authorizes(peer, root, id) {
            return Err("unrequested cited program description".into());
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
        F: Fn(CompiledQuestion) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<bool, String>> + Send + 'static,
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
                "cited closure dependency capacity",
            ));
        }
        Ok(())
    }
}
