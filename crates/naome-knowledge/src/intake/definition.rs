//! Resolve exact definition references in a disposable checked prefix.
//! Definitions become durable only in the selected parent's atomic batch.

use super::*;
use naome_proof::DefinitionId;

pub(super) struct DefinitionFetch {
    pub(super) transfer: TransferGrant,
    pub(super) closure: Closure,
    // Optional helper metadata gets a short, independent transfer. It cannot
    // revoke the selected parent's grant or extend its publication deadline.
    pub(super) helper: Option<(ArtifactId, Instant)>,
    pending: Option<PendingDescription>,
    pending_grant: Option<crate::publication::PeerGrant>,
    pub(super) question_proof: Option<ArtifactId>,
    deadline: Instant,
}

pub(crate) struct DefinitionRequest {
    pub(crate) peer: PeerId,
    pub(crate) definition: DefinitionId,
    pub(crate) question_proof: Option<ArtifactId>,
    pub(crate) helper_deadline: Option<Instant>,
    pub(crate) pending: Option<PendingDescription>,
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
            pending: None,
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
        if self.definition.is_some() {
            return Ok(());
        }
        if graph.contains(root)? {
            if let Some(pending) = request.pending {
                pending.validate(graph.checked_context())?;
                self.enqueue_pending(request.peer, pending, graph, grant, None)?;
            }
            return Ok(());
        }
        let pending_grant = request.pending.as_ref().and(grant.clone());
        let transfer = TransferGrant::new(request.peer, root, grant);
        transfer.check(Instant::now())?;
        let mut closure = Closure::for_definition(root, request.question_proof);
        closure.require_root(graph)?;
        let helper = request.question_proof.zip(request.helper_deadline);
        if let Some((parent, _)) = helper
            && let Some(prefix) = self.take_definition_prefix(parent)
            && let Err(error) = closure.adopt_prefix(graph, prefix)
        {
            self.invalidate_definition_prefix(parent);
            return Err(error);
        }
        let deadline = request
            .helper_deadline
            .unwrap_or(transfer.deadline())
            .min(transfer.deadline());
        self.definition = Some(DefinitionFetch {
            transfer,
            closure,
            helper,
            pending: request.pending,
            pending_grant,
            question_proof: request.question_proof,
            deadline,
        });
        Ok(())
    }

    fn take_definition_prefix(&mut self, parent: ArtifactId) -> Option<CheckedBatch> {
        if let Some(root) = &mut self.active
            && root.description.transfer.root() == parent
        {
            return root.closure.take_prefix();
        }
        self.programs.take_prefix(parent)
    }

    fn restore_definition_prefix(
        &mut self,
        parent: ArtifactId,
        prefix: CheckedBatch,
    ) -> Result<(), crate::Error> {
        if let Some(root) = &mut self.active
            && root.description.transfer.root() == parent
        {
            root.closure.restore_prefix(prefix);
            return Ok(());
        }
        self.programs.restore_prefix(parent, prefix)
    }

    fn invalidate_definition_prefix(&mut self, parent: ArtifactId) {
        if let Some(root) = &mut self.active
            && root.description.transfer.root() == parent
        {
            root.closure.invalidate_prefix();
            return;
        }
        self.programs.invalidate_prefix(parent);
    }

    pub(super) fn abandon_definition(&mut self, fetch: &DefinitionFetch) {
        if let Some((parent, _)) = fetch.helper {
            self.invalidate_definition_prefix(parent);
        }
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
        let deadline = fetch.deadline.min(fetch.transfer.deadline());
        if !fetch.transfer.live(now) || now >= deadline {
            self.abandon_definition(&fetch);
            return Progress::Waiting;
        }
        let result = (|| {
            if graph.contains(root)? {
                return Ok(Some(fetch.closure.take_prefix()));
            }
            fetch.closure.advance(graph)?;
            if !fetch.closure.ready() {
                return Ok(None);
            }
            let mut batch = fetch.closure.prepare_definition(graph)?;
            // Ownership moves to the selected parent; this path never publishes
            // a standalone definition batch.
            fetch.closure.invalidate_prefix();
            fetch.closure.attach_questions(graph, &mut batch)?;
            Ok(Some(Some(batch)))
        })();
        match result {
            Ok(Some(batch)) => {
                if let Some(pending) = fetch.pending.take() {
                    let context = batch
                        .as_ref()
                        .map_or(graph.checked_context(), CheckedBatch::context);
                    match pending.validate(context) {
                        Err(crate::Error::MissingQuestionDefinition(definition)) => {
                            let next = ArtifactId::from_definition_id(definition);
                            let peer = fetch.transfer.peer();
                            let transfer = TransferGrant::new(peer, next, None);
                            let mut closure = Closure::for_definition(next, fetch.question_proof);
                            if let Err(error) = closure.require_root(graph).and_then(|_| {
                                if let Some(prefix) = batch {
                                    closure.adopt_prefix(graph, prefix)
                                } else {
                                    Ok(())
                                }
                            }) {
                                graph.program_failure(&error);
                                return Progress::Skipped(root, error);
                            }
                            fetch.transfer = transfer;
                            fetch.closure = closure;
                            fetch.pending = Some(pending);
                            self.definition = Some(fetch);
                            return Progress::Waiting;
                        }
                        Err(error) => {
                            graph.program_failure(&error);
                            return Progress::Skipped(root, error);
                        }
                        Ok(()) => {}
                    }
                    if let Err(error) = self
                        .enqueue_pending(
                            fetch.transfer.peer(),
                            pending,
                            graph,
                            fetch.pending_grant.take(),
                            batch,
                        )
                        .map(|_| ())
                    {
                        graph.program_failure(&error);
                        return Progress::Skipped(root, error);
                    }
                } else if let Some((parent, _)) = fetch.helper
                    && let Some(batch) = batch
                    && let Err(error) = self.restore_definition_prefix(parent, batch)
                {
                    graph.program_failure(&error);
                    self.invalidate_definition_prefix(parent);
                    return Progress::Skipped(root, error);
                }
                Progress::Waiting
            }
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
                    self.abandon_definition(&fetch);
                    Progress::Skipped(root, error)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
