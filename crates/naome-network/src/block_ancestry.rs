//! Caller-selected acquisition of one bounded artifact-block ancestry.

use std::error::Error;
use std::fmt;

use naome::block_exchange::ArtifactBlockRequest;
use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactSetRoot};
use naome_storage::{ArtifactChainJournal, ArtifactChainJournalError};

use super::{
    BlockRequestTicket, NetworkEvent, OutboundArtifactBlockFailure, PeerId, RequestStartError,
    StaticArtifactNetwork, selected_context_contains_block,
};

/// Maximum number of blocks retained by one ancestry pull.
pub const MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS: usize = 16;

#[derive(Clone, Copy)]
pub(super) struct ArtifactBlockAncestryShapeContext {
    anchor_block_id: ArtifactBlockId,
    anchor_artifact_set_root: ArtifactSetRoot,
    virtual_genesis_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
}

impl ArtifactBlockAncestryShapeContext {
    pub(super) const fn new(
        anchor_block_id: ArtifactBlockId,
        anchor_artifact_set_root: ArtifactSetRoot,
        virtual_genesis_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
    ) -> Self {
        Self {
            anchor_block_id,
            anchor_artifact_set_root,
            virtual_genesis_block_id,
            target_block_id,
        }
    }
}

pub(super) enum ArtifactBlockAncestryShapeError<E> {
    SelectedState(E),
    ArtifactSetRootMismatch {
        preceding_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    RepeatedBlockId {
        block_id: ArtifactBlockId,
    },
    DivergentAncestry {
        expected_anchor: ArtifactBlockId,
        encountered: ArtifactBlockId,
    },
    AncestryLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
}

pub(super) fn retain_ancestry_block<E>(
    context: ArtifactBlockAncestryShapeContext,
    blocks: &mut Vec<ArtifactBlock>,
    block: ArtifactBlock,
    mut selected_contains: impl FnMut(ArtifactBlockId) -> Result<bool, E>,
) -> Result<Option<ArtifactBlockId>, ArtifactBlockAncestryShapeError<E>> {
    let block_id = block.id();

    if let Some(child) = blocks.last() {
        require_root_continuity(
            block_id,
            block.resulting_artifact_set_root(),
            child.previous_artifact_set_root(),
        )?;
    }

    let parent_block_id = block.parent_block_id();
    if parent_block_id == context.anchor_block_id {
        require_root_continuity(
            context.anchor_block_id,
            context.anchor_artifact_set_root,
            block.previous_artifact_set_root(),
        )?;
        blocks.push(block);
        blocks.reverse();
        return Ok(None);
    }

    if ArtifactBlockAncestryPull::was_already_requested(
        context.target_block_id,
        blocks,
        parent_block_id,
    ) {
        return Err(ArtifactBlockAncestryShapeError::RepeatedBlockId {
            block_id: parent_block_id,
        });
    }
    if parent_block_id == context.virtual_genesis_block_id
        || selected_contains(parent_block_id)
            .map_err(ArtifactBlockAncestryShapeError::SelectedState)?
    {
        return Err(ArtifactBlockAncestryShapeError::DivergentAncestry {
            expected_anchor: context.anchor_block_id,
            encountered: parent_block_id,
        });
    }

    let retained = blocks.len() + 1;
    if retained == MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS {
        return Err(ArtifactBlockAncestryShapeError::AncestryLimitExceeded {
            maximum: MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS,
            next_block_id: parent_block_id,
        });
    }

    blocks.push(block);
    Ok(Some(parent_block_id))
}

fn require_root_continuity<E>(
    preceding_block_id: ArtifactBlockId,
    expected: ArtifactSetRoot,
    actual: ArtifactSetRoot,
) -> Result<(), ArtifactBlockAncestryShapeError<E>> {
    if expected != actual {
        return Err(ArtifactBlockAncestryShapeError::ArtifactSetRootMismatch {
            preceding_block_id,
            expected,
            actual,
        });
    }
    Ok(())
}

/// One bounded caller-selected artifact-block ancestry pull in progress.
///
/// The caller supplies the exact target identity and one statically authorized
/// peer. Blocks are requested one at a time from the target toward the
/// snapshotted selected head. The pull never acquires artifact payloads or mutates
/// selected state.
#[derive(Debug)]
#[must_use]
pub struct ArtifactBlockAncestryPull {
    anchor_block_id: ArtifactBlockId,
    anchor_artifact_set_root: ArtifactSetRoot,
    virtual_genesis_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    blocks: Vec<ArtifactBlock>,
    ticket: BlockRequestTicket,
}

impl StaticArtifactNetwork {
    /// Starts one bounded ancestry pull for an exact caller-selected target.
    ///
    /// The selected journal supplies only the immutable local anchor snapshot
    /// and divergence checks. The returned workflow is retrieval-only and
    /// must be advanced with exact events accepted by
    /// [`ArtifactBlockAncestryPull::accepts_event`].
    pub fn start_artifact_block_ancestry_pull(
        &mut self,
        selected: &ArtifactChainJournal,
        peer_id: PeerId,
        target_block_id: ArtifactBlockId,
    ) -> Result<ArtifactBlockAncestryPull, ArtifactBlockAncestryPullError> {
        let anchor_block_id = selected
            .head_block_id()
            .map_err(ArtifactBlockAncestryPullError::selected_state)?;
        let virtual_genesis_block_id = selected.chain_id().virtual_genesis_block_id();
        if selected_context_contains_block(
            selected,
            anchor_block_id,
            virtual_genesis_block_id,
            target_block_id,
        )
        .map_err(ArtifactBlockAncestryPullError::selected_state)?
        {
            return Err(ArtifactBlockAncestryPullError::TargetAlreadySelected {
                block_id: target_block_id,
            });
        }
        let anchor_artifact_set_root = selected
            .artifact_set_root()
            .map_err(ArtifactBlockAncestryPullError::selected_state)?;
        let ticket = self
            .request_block(peer_id, ArtifactBlockRequest::new(target_block_id))
            .map_err(|source| ArtifactBlockAncestryPullError::RequestStart {
                block_id: target_block_id,
                source,
            })?;

        Ok(ArtifactBlockAncestryPull {
            anchor_block_id,
            anchor_artifact_set_root,
            virtual_genesis_block_id,
            target_block_id,
            blocks: Vec::new(),
            ticket,
        })
    }
}

impl ArtifactBlockAncestryPull {
    /// Returns the selected head captured when this pull started.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the exact target identity selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns the exact block identity awaited by the active request.
    pub const fn pending_block_id(&self) -> ArtifactBlockId {
        self.ticket.request().block_id()
    }

    /// Returns the authenticated peer serving the active request.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.ticket.peer_id()
    }

    /// Returns whether `event` is the exact terminal awaited by this pull.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        matches!(event, NetworkEvent::OutboundBlock(event) if self.ticket.accepts_event(event))
    }

    /// Cancels this pull and immediately releases every retained block.
    ///
    /// Dropping the active block ticket does not cancel its physical libp2p
    /// request. The transport retains that peer slot and shared permit until
    /// the corresponding response or failure becomes terminal.
    pub fn cancel(self) {}

    /// Advances this pull with its exact correlated block terminal.
    ///
    /// `network` must be the same instance that started the active request.
    /// The selected journal is read only; every outcome leaves its bytes,
    /// selected head, artifact set, and records unchanged.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        selected: &ArtifactChainJournal,
        event: NetworkEvent,
    ) -> Result<ArtifactBlockAncestryPullProgress, ArtifactBlockAncestryPullError> {
        if !self.accepts_event(&event) {
            return Err(ArtifactBlockAncestryPullError::UnexpectedEvent);
        }

        let Self {
            anchor_block_id,
            anchor_artifact_set_root,
            virtual_genesis_block_id,
            target_block_id,
            mut blocks,
            ticket,
        } = self;
        let NetworkEvent::OutboundBlock(event) = event else {
            unreachable!("an accepted ancestry event is an outbound block terminal")
        };
        if !ticket.belongs_to_network(network) {
            return Err(ArtifactBlockAncestryPullError::UnexpectedEvent);
        }

        let peer_id = ticket.peer_id();
        let block_id = ticket.request().block_id();
        let response = ticket
            .complete(event)
            .expect("the accepted block event matches its ancestry ticket")
            .map_err(
                |source| ArtifactBlockAncestryPullError::BlockRequestFailed {
                    peer_id,
                    block_id,
                    source,
                },
            )?;
        let block = response
            .into_block()
            .ok_or(ArtifactBlockAncestryPullError::BlockUnavailable { peer_id, block_id })?;

        let actual_head = selected
            .head_block_id()
            .map_err(ArtifactBlockAncestryPullError::selected_state)?;
        if actual_head != anchor_block_id {
            return Err(ArtifactBlockAncestryPullError::SelectedHeadChanged {
                expected: anchor_block_id,
                actual: actual_head,
            });
        }

        let next_block_id = retain_ancestry_block(
            ArtifactBlockAncestryShapeContext::new(
                anchor_block_id,
                anchor_artifact_set_root,
                virtual_genesis_block_id,
                target_block_id,
            ),
            &mut blocks,
            block,
            |block_id| selected.block(block_id).map(|block| block.is_some()),
        )
        .map_err(ArtifactBlockAncestryPullError::from_shape)?;
        let Some(parent_block_id) = next_block_id else {
            return Ok(ArtifactBlockAncestryPullProgress::Complete(
                UnselectedArtifactBlockAncestry {
                    peer_id,
                    anchor_block_id,
                    target_block_id,
                    blocks,
                },
            ));
        };

        let ticket = network
            .request_block(peer_id, ArtifactBlockRequest::new(parent_block_id))
            .map_err(|source| ArtifactBlockAncestryPullError::RequestStart {
                block_id: parent_block_id,
                source,
            })?;
        Ok(ArtifactBlockAncestryPullProgress::AwaitingResponse(
            ArtifactBlockAncestryPull {
                anchor_block_id,
                anchor_artifact_set_root,
                virtual_genesis_block_id,
                target_block_id,
                blocks,
                ticket,
            },
        ))
    }

    fn was_already_requested(
        target_block_id: ArtifactBlockId,
        blocks: &[ArtifactBlock],
        candidate: ArtifactBlockId,
    ) -> bool {
        candidate == target_block_id
            || blocks
                .iter()
                .any(|block| block.parent_block_id() == candidate)
    }
}

/// Progress after one exact ancestry block terminal.
#[derive(Debug)]
#[must_use]
pub enum ArtifactBlockAncestryPullProgress {
    /// Another exact parent request is active.
    AwaitingResponse(ArtifactBlockAncestryPull),
    /// The bounded path reached the snapshotted selected head.
    Complete(UnselectedArtifactBlockAncestry),
}

/// One authenticated, structurally continuous, but unselected block ancestry.
///
/// Blocks are ordered from the anchor's direct child through the exact target.
/// Exact content identities, parent links, and artifact-set-root equality do not
/// establish artifact validity, payload availability, selection, consensus, or
/// finality.
#[derive(Debug)]
#[must_use]
pub struct UnselectedArtifactBlockAncestry {
    peer_id: PeerId,
    anchor_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    blocks: Vec<ArtifactBlock>,
}

impl UnselectedArtifactBlockAncestry {
    #[cfg(test)]
    pub(super) fn from_parts_for_test(
        peer_id: PeerId,
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
        blocks: Vec<ArtifactBlock>,
    ) -> Self {
        assert!(!blocks.is_empty());
        assert!(blocks.len() <= MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS);
        assert_eq!(blocks.first().unwrap().parent_block_id(), anchor_block_id);
        assert_eq!(blocks.last().unwrap().id(), target_block_id);
        for adjacent in blocks.windows(2) {
            assert_eq!(adjacent[1].parent_block_id(), adjacent[0].id());
            assert_eq!(
                adjacent[1].previous_artifact_set_root(),
                adjacent[0].resulting_artifact_set_root()
            );
        }
        Self {
            peer_id,
            anchor_block_id,
            target_block_id,
            blocks,
        }
    }

    /// Returns the authenticated peer that supplied the complete path.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the selected head against which the path was checked.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.anchor_block_id
    }

    /// Returns the exact caller-selected target at the path tip.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.target_block_id
    }

    /// Returns blocks in forward application order.
    pub fn blocks(&self) -> &[ArtifactBlock] {
        &self.blocks
    }

    /// Consumes this path and returns its forward-ordered blocks.
    pub fn into_blocks(self) -> Vec<ArtifactBlock> {
        self.blocks
    }

    pub(super) fn into_parts(
        self,
    ) -> (PeerId, ArtifactBlockId, ArtifactBlockId, Vec<ArtifactBlock>) {
        (
            self.peer_id,
            self.anchor_block_id,
            self.target_block_id,
            self.blocks,
        )
    }
}

/// A fail-closed caller-selected artifact-block ancestry pull error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockAncestryPullError {
    /// The selected journal failed a required read.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The target is the current head, virtual genesis, or a committed block.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// One exact block request could not be started.
    RequestStart {
        block_id: ArtifactBlockId,
        source: RequestStartError,
    },
    /// The supplied event or driver did not belong to this pull generation.
    UnexpectedEvent,
    /// One exact block request failed before yielding a usable response.
    BlockRequestFailed {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
        source: Box<OutboundArtifactBlockFailure>,
    },
    /// The authenticated peer reported no block for an exact path address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
    },
    /// The selected head changed after this pull captured its anchor.
    SelectedHeadChanged {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// One child block did not start at its parent's resulting artifact-set root.
    ArtifactSetRootMismatch {
        preceding_block_id: ArtifactBlockId,
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
    /// The path met selected history other than its captured head.
    DivergentAncestry {
        expected_anchor: ArtifactBlockId,
        encountered: ArtifactBlockId,
    },
    /// A parent address repeated within this pull.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// The path did not reach its anchor within the fixed block bound.
    AncestryLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
}

impl ArtifactBlockAncestryPullError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }

    fn from_shape(error: ArtifactBlockAncestryShapeError<ArtifactChainJournalError>) -> Self {
        match error {
            ArtifactBlockAncestryShapeError::SelectedState(source) => Self::selected_state(source),
            ArtifactBlockAncestryShapeError::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            },
            ArtifactBlockAncestryShapeError::RepeatedBlockId { block_id } => {
                Self::RepeatedBlockId { block_id }
            }
            ArtifactBlockAncestryShapeError::DivergentAncestry {
                expected_anchor,
                encountered,
            } => Self::DivergentAncestry {
                expected_anchor,
                encountered,
            },
            ArtifactBlockAncestryShapeError::AncestryLimitExceeded {
                maximum,
                next_block_id,
            } => Self::AncestryLimitExceeded {
                maximum,
                next_block_id,
            },
        }
    }
}

impl fmt::Display for ArtifactBlockAncestryPullError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "artifact-block ancestry cannot use selected state: {source}"
                )
            }
            Self::TargetAlreadySelected { block_id } => {
                write!(
                    formatter,
                    "artifact-block ancestry target {block_id:?} is already selected"
                )
            }
            Self::RequestStart { block_id, source } => {
                write!(
                    formatter,
                    "cannot request ancestry block {block_id:?}: {source}"
                )
            }
            Self::UnexpectedEvent => formatter.write_str(
                "network event or driver does not belong to this artifact-block ancestry pull",
            ),
            Self::BlockRequestFailed {
                peer_id,
                block_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed ancestry block request {block_id:?}: {source}"
            ),
            Self::BlockUnavailable { peer_id, block_id } => write!(
                formatter,
                "peer {peer_id} has no ancestry block at {block_id:?}"
            ),
            Self::SelectedHeadChanged { expected, actual } => write!(
                formatter,
                "selected head changed during ancestry pull: expected {expected:?}, actual {actual:?}"
            ),
            Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "ancestry predecessor {preceding_block_id:?} ends at artifact-set root {expected:?}, but its child starts at {actual:?}"
            ),
            Self::DivergentAncestry {
                expected_anchor,
                encountered,
            } => write!(
                formatter,
                "artifact-block ancestry expected anchor {expected_anchor:?} but encountered selected-chain context {encountered:?}"
            ),
            Self::RepeatedBlockId { block_id } => {
                write!(
                    formatter,
                    "artifact-block ancestry repeats block {block_id:?}"
                )
            }
            Self::AncestryLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "artifact-block ancestry did not reach its anchor within {maximum} blocks; next parent is {next_block_id:?}"
            ),
        }
    }
}

impl Error for ArtifactBlockAncestryPullError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::RequestStart { source, .. } => Some(source),
            Self::BlockRequestFailed { source, .. } => Some(source.as_ref()),
            Self::TargetAlreadySelected { .. }
            | Self::UnexpectedEvent
            | Self::BlockUnavailable { .. }
            | Self::SelectedHeadChanged { .. }
            | Self::ArtifactSetRootMismatch { .. }
            | Self::DivergentAncestry { .. }
            | Self::RepeatedBlockId { .. }
            | Self::AncestryLimitExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
