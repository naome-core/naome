//! Helper traffic consumes the selected program root's existing short grant.
//! A cited program needs no separate question or independent admission effect.
use super::*;

impl Programs {
    fn helper_root(&self, peer: PeerId, root: ProofId) -> Option<&Root> {
        self.active.as_ref().filter(|active| {
            active.fetching() && active.offer.transfer.authorizes(peer, root, Instant::now())
        })
    }

    pub(in crate::intake) fn helper_contains(&self, id: ProofId) -> bool {
        self.active
            .as_ref()
            .is_some_and(|root| root.helpers.contains(id))
    }
    pub(in crate::intake) fn authorizes(&self, peer: PeerId, root: ProofId, id: ProofId) -> bool {
        self.helper_root(peer, root)
            .is_some_and(|root| root.helpers.needs(id) || root.helpers.contains(id))
    }
    pub(in crate::intake) fn needed(&self) -> Vec<(PeerId, ProofId, ProofId)> {
        let Some(root) = &self.active else {
            return Vec::new();
        };
        let id = root.offer.metadata.manifest.proof_id();
        if self.helper_root(root.offer.transfer.peer(), id).is_none() {
            return Vec::new();
        }
        root.helpers
            .needed()
            .map(|helper| (root.offer.transfer.peer(), id, helper))
            .collect()
    }
    pub(in crate::intake) fn insert_helper(
        &mut self,
        peer: PeerId,
        root: ProofId,
        metadata: ProgramMetadata,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.authorizes(peer, root, metadata.manifest.proof_id()) {
            return Err("unrequested program dependency description".into());
        }
        self.active
            .as_mut()
            .expect("selected program parent")
            .helpers
            .insert(metadata, graph)
    }
    pub(in crate::intake) fn helper_payload(
        &mut self,
        peer: PeerId,
        root: ProofId,
        id: ProofId,
        chunk: Chunk,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.authorizes(peer, root, id) {
            return Err("unrequested program dependency chunk".into());
        }
        self.active
            .as_mut()
            .expect("selected program parent")
            .helpers
            .payload(id, chunk, graph)
    }
    pub(in crate::intake) fn certificate_payload(
        &mut self,
        peer: PeerId,
        root: ProofId,
        id: ProofId,
        object: Envelope,
        graph: &Graph,
    ) -> Result<(), crate::Error> {
        if !self.authorizes(peer, root, id) {
            return Err("unrequested program dependency certificate".into());
        }
        self.active
            .as_mut()
            .expect("selected program parent")
            .helpers
            .certificate_payload(id, object, graph)
    }
}
