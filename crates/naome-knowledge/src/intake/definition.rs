//! Resolve exact definition references before assessing a peer's question.
//! The bounded closure checker independently verifies function witnesses and
//! commits only the requested definition and its required dependencies.

use super::*;
use naome_proof::DefinitionId;

pub(super) struct DefinitionFetch {
    pub(super) transfer: TransferGrant,
    pub(super) closure: Closure,
    // Optional helper metadata gets a short, independent transfer. It cannot
    // revoke the selected parent's grant or extend its publication deadline.
    helper: Option<(ArtifactId, Instant)>,
    deadline: Option<Instant>,
}

pub(crate) struct DefinitionRequest {
    pub(crate) peer: PeerId,
    pub(crate) definition: DefinitionId,
    pub(crate) question_proof: Option<ArtifactId>,
    pub(crate) helper_deadline: Option<Instant>,
}

impl DefinitionRequest {
    pub(super) fn for_helper(
        graph: &Graph,
        transfer: &TransferGrant,
        closure: &mut Closure,
    ) -> Option<Self> {
        let now = Instant::now();
        let timeout = crate::resources::limits().request_timeout;
        let deadline = (now + timeout).min(transfer.deadline() - timeout);
        if deadline <= now || !transfer.live(now) {
            return None;
        }
        Some(Self {
            peer: transfer.peer(),
            definition: closure.missing_question_definition(graph)?,
            question_proof: Some(transfer.root()),
            helper_deadline: Some(deadline),
        })
    }
}

impl Intake {
    pub(crate) fn request_question_definition(
        &mut self,
        request: DefinitionRequest,
        graph: &Graph,
        grant: Option<crate::publication::PeerGrant>,
    ) -> Result<(), crate::Error> {
        let root = ArtifactId::from_definition_id(request.definition);
        if self.definition.is_some() || graph.contains(root)? {
            return Ok(());
        }
        let transfer = TransferGrant::new(request.peer, root, grant);
        transfer.check(Instant::now())?;
        let mut closure = Closure::for_definition(root, request.question_proof);
        closure.require_root(graph)?;
        let helper = request.question_proof.zip(request.helper_deadline);
        self.definition = Some(DefinitionFetch {
            transfer,
            closure,
            helper,
            deadline: request.helper_deadline,
        });
        Ok(())
    }

    pub(crate) fn helper_definition_request(&mut self, graph: &Graph) -> Option<DefinitionRequest> {
        if self.definition.is_some() {
            return None;
        }
        if let Some(root) = &mut self.active
            && root.fetching()
            && let Some(request) =
                DefinitionRequest::for_helper(graph, &root.description.transfer, &mut root.closure)
        {
            return Some(request);
        }
        self.programs.helper_definition_request(graph)
    }

    pub(super) fn metadata_waiter(&self) -> Option<ArtifactId> {
        self.definition.as_ref()?.helper.map(|(id, _)| id)
    }

    pub(crate) fn definition_capability(
        &self,
        peer: PeerId,
        root: ArtifactId,
    ) -> Option<crate::publication::PeerGrant> {
        self.definition
            .as_ref()
            .filter(|fetch| fetch.transfer.authorizes(peer, root, Instant::now()))
            .and_then(|fetch| fetch.transfer.capability())
    }

    pub(super) fn definition_authorizes(
        &self,
        peer: PeerId,
        root: ArtifactId,
        id: ArtifactId,
    ) -> bool {
        self.definition.as_ref().is_some_and(|fetch| {
            fetch.transfer.authorizes(peer, root, Instant::now()) && fetch.closure.needs(id)
        })
    }

    pub(super) fn advance_definition(&mut self, graph: &mut Graph) -> Progress {
        let Some(mut fetch) = self.definition.take() else {
            return Progress::Waiting;
        };
        let root = fetch.transfer.root();
        let now = Instant::now();
        let deadline = fetch
            .deadline
            .unwrap_or(fetch.transfer.deadline())
            .min(fetch.transfer.deadline());
        if !fetch.transfer.live(now) || now >= deadline {
            return Progress::Waiting;
        }
        let result = (|| {
            if graph.contains(root)? {
                return Ok(Some(Vec::new()));
            }
            fetch.closure.advance(graph)?;
            if !fetch.closure.ready() {
                return Ok(None);
            }
            let mut batch = fetch.closure.prepare_definition(graph)?;
            // Preparing the root transferred ownership of the checked prefix.
            // Rebuild it if the commit gate defers this publication.
            fetch.closure.invalidate_prefix();
            fetch.closure.attach_questions(graph, &mut batch)?;
            let admitted = graph.commit_batch_granted(
                root,
                batch,
                deadline,
                fetch.transfer.capability(),
                None,
            )?;
            Ok(Some(admitted))
        })();
        match result {
            Ok(Some(ids)) if ids.is_empty() => Progress::Waiting,
            Ok(Some(ids)) => Progress::Accepted(ids),
            Ok(None) => {
                self.definition = Some(fetch);
                Progress::Waiting
            }
            Err(error) => {
                graph.program_failure(&error);
                if error.retryable() {
                    self.definition = Some(fetch);
                    Progress::Waiting
                } else {
                    Progress::Skipped(root, error)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
