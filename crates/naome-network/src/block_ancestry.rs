//! Caller-selected acquisition of one bounded proof-block ancestry.

use std::error::Error;
use std::fmt;

use naome::block_exchange::ProofBlockRequest;
use naome_chain::{ProofBlock, ProofBlockId, ProofChainState, ProofSetRoot};
use naome_storage::{ProofChainJournal, ProofChainJournalError};

use super::{
    BlockRequestTicket, NetworkEvent, OutboundProofBlockFailure, PeerId, RequestStartError,
    StaticProofNetwork, selected_context_contains_block,
};

/// Maximum number of blocks retained by one ancestry pull.
pub const MAX_PROOF_BLOCK_ANCESTRY_BLOCKS: usize = 16;

/// One bounded caller-selected proof-block ancestry pull in progress.
///
/// The caller supplies the exact target identity and one statically authorized
/// peer. Blocks are requested one at a time from the target toward the
/// snapshotted selected head. The pull never acquires proof payloads or mutates
/// selected state.
#[derive(Debug)]
#[must_use]
pub struct ProofBlockAncestryPull {
    anchor_block_id: ProofBlockId,
    anchor_proof_set_root: ProofSetRoot,
    virtual_genesis_block_id: ProofBlockId,
    target_block_id: ProofBlockId,
    blocks: Vec<ProofBlock>,
    ticket: BlockRequestTicket,
}

impl StaticProofNetwork {
    /// Starts one bounded ancestry pull for an exact caller-selected target.
    ///
    /// The selected journal supplies only the immutable local anchor snapshot
    /// and divergence checks. The returned workflow is retrieval-only and
    /// must be advanced with exact events accepted by
    /// [`ProofBlockAncestryPull::accepts_event`].
    pub fn start_proof_block_ancestry_pull(
        &mut self,
        selected: &ProofChainJournal,
        peer_id: PeerId,
        target_block_id: ProofBlockId,
    ) -> Result<ProofBlockAncestryPull, ProofBlockAncestryPullError> {
        let anchor_block_id = selected
            .head_block_id()
            .map_err(ProofBlockAncestryPullError::selected_state)?;
        let virtual_genesis_block_id = ProofChainState::new(selected.chain_id()).head_block_id();
        if selected_context_contains_block(
            selected,
            anchor_block_id,
            virtual_genesis_block_id,
            target_block_id,
        )
        .map_err(ProofBlockAncestryPullError::selected_state)?
        {
            return Err(ProofBlockAncestryPullError::TargetAlreadySelected {
                block_id: target_block_id,
            });
        }
        let anchor_proof_set_root = selected
            .proof_set_root()
            .map_err(ProofBlockAncestryPullError::selected_state)?;
        let ticket = self
            .request_block(peer_id, ProofBlockRequest::new(target_block_id))
            .map_err(|source| ProofBlockAncestryPullError::RequestStart {
                block_id: target_block_id,
                source,
            })?;

        Ok(ProofBlockAncestryPull {
            anchor_block_id,
            anchor_proof_set_root,
            virtual_genesis_block_id,
            target_block_id,
            blocks: Vec::new(),
            ticket,
        })
    }
}

impl ProofBlockAncestryPull {
    /// Returns the selected head captured when this pull started.
    pub const fn anchor_block_id(&self) -> ProofBlockId {
        self.anchor_block_id
    }

    /// Returns the exact target identity selected by the caller.
    pub const fn target_block_id(&self) -> ProofBlockId {
        self.target_block_id
    }

    /// Returns the exact block identity awaited by the active request.
    pub const fn pending_block_id(&self) -> ProofBlockId {
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
    /// selected head, proof set, and records unchanged.
    pub fn on_event(
        self,
        network: &mut StaticProofNetwork,
        selected: &ProofChainJournal,
        event: NetworkEvent,
    ) -> Result<ProofBlockAncestryPullProgress, ProofBlockAncestryPullError> {
        if !self.accepts_event(&event) {
            return Err(ProofBlockAncestryPullError::UnexpectedEvent);
        }

        let Self {
            anchor_block_id,
            anchor_proof_set_root,
            virtual_genesis_block_id,
            target_block_id,
            mut blocks,
            ticket,
        } = self;
        let NetworkEvent::OutboundBlock(event) = event else {
            unreachable!("an accepted ancestry event is an outbound block terminal")
        };
        if !ticket.belongs_to_network(network) {
            return Err(ProofBlockAncestryPullError::UnexpectedEvent);
        }

        let peer_id = ticket.peer_id();
        let block_id = ticket.request().block_id();
        let response = ticket
            .complete(event)
            .expect("the accepted block event matches its ancestry ticket")
            .map_err(|source| ProofBlockAncestryPullError::BlockRequestFailed {
                peer_id,
                block_id,
                source,
            })?;
        let block = response
            .into_block()
            .ok_or(ProofBlockAncestryPullError::BlockUnavailable { peer_id, block_id })?;

        let actual_head = selected
            .head_block_id()
            .map_err(ProofBlockAncestryPullError::selected_state)?;
        if actual_head != anchor_block_id {
            return Err(ProofBlockAncestryPullError::SelectedHeadChanged {
                expected: anchor_block_id,
                actual: actual_head,
            });
        }

        if let Some(child) = blocks.last() {
            Self::require_root_continuity(
                block_id,
                block.transition().resulting_proof_set_root(),
                child.transition().previous_proof_set_root(),
            )?;
        }

        let parent_block_id = block.parent_block_id();
        if parent_block_id == anchor_block_id {
            Self::require_root_continuity(
                anchor_block_id,
                anchor_proof_set_root,
                block.transition().previous_proof_set_root(),
            )?;
            blocks.push(block);
            blocks.reverse();
            return Ok(ProofBlockAncestryPullProgress::Complete(
                UnselectedProofBlockAncestry {
                    peer_id,
                    anchor_block_id,
                    target_block_id,
                    blocks,
                },
            ));
        }

        if Self::was_already_requested(target_block_id, &blocks, parent_block_id) {
            return Err(ProofBlockAncestryPullError::RepeatedBlockId {
                block_id: parent_block_id,
            });
        }
        if parent_block_id == virtual_genesis_block_id
            || selected
                .block(parent_block_id)
                .map_err(ProofBlockAncestryPullError::selected_state)?
                .is_some()
        {
            return Err(ProofBlockAncestryPullError::DivergentAncestry {
                expected_anchor: anchor_block_id,
                encountered: parent_block_id,
            });
        }

        let retained = blocks.len() + 1;
        if retained == MAX_PROOF_BLOCK_ANCESTRY_BLOCKS {
            return Err(ProofBlockAncestryPullError::AncestryLimitExceeded {
                maximum: MAX_PROOF_BLOCK_ANCESTRY_BLOCKS,
                next_block_id: parent_block_id,
            });
        }

        let ticket = network
            .request_block(peer_id, ProofBlockRequest::new(parent_block_id))
            .map_err(|source| ProofBlockAncestryPullError::RequestStart {
                block_id: parent_block_id,
                source,
            })?;
        blocks.push(block);
        Ok(ProofBlockAncestryPullProgress::AwaitingResponse(
            ProofBlockAncestryPull {
                anchor_block_id,
                anchor_proof_set_root,
                virtual_genesis_block_id,
                target_block_id,
                blocks,
                ticket,
            },
        ))
    }

    fn require_root_continuity(
        preceding_block_id: ProofBlockId,
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    ) -> Result<(), ProofBlockAncestryPullError> {
        if expected != actual {
            return Err(ProofBlockAncestryPullError::TransitionRootMismatch {
                preceding_block_id,
                expected,
                actual,
            });
        }
        Ok(())
    }

    fn was_already_requested(
        target_block_id: ProofBlockId,
        blocks: &[ProofBlock],
        candidate: ProofBlockId,
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
pub enum ProofBlockAncestryPullProgress {
    /// Another exact parent request is active.
    AwaitingResponse(ProofBlockAncestryPull),
    /// The bounded path reached the snapshotted selected head.
    Complete(UnselectedProofBlockAncestry),
}

/// One authenticated, structurally continuous, but unselected block ancestry.
///
/// Blocks are ordered from the anchor's direct child through the exact target.
/// Exact content identities, parent links, and transition-root equality do not
/// establish proof validity, payload availability, selection, consensus, or
/// finality.
#[derive(Debug)]
#[must_use]
pub struct UnselectedProofBlockAncestry {
    peer_id: PeerId,
    anchor_block_id: ProofBlockId,
    target_block_id: ProofBlockId,
    blocks: Vec<ProofBlock>,
}

impl UnselectedProofBlockAncestry {
    /// Returns the authenticated peer that supplied the complete path.
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Returns the selected head against which the path was checked.
    pub const fn anchor_block_id(&self) -> ProofBlockId {
        self.anchor_block_id
    }

    /// Returns the exact caller-selected target at the path tip.
    pub const fn target_block_id(&self) -> ProofBlockId {
        self.target_block_id
    }

    /// Returns blocks in forward application order.
    pub fn blocks(&self) -> &[ProofBlock] {
        &self.blocks
    }

    /// Consumes this path and returns its forward-ordered blocks.
    pub fn into_blocks(self) -> Vec<ProofBlock> {
        self.blocks
    }
}

/// A fail-closed caller-selected proof-block ancestry pull error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofBlockAncestryPullError {
    /// The selected journal failed a required read.
    SelectedState { source: Box<ProofChainJournalError> },
    /// The target is the current head, virtual genesis, or a committed block.
    TargetAlreadySelected { block_id: ProofBlockId },
    /// One exact block request could not be started.
    RequestStart {
        block_id: ProofBlockId,
        source: RequestStartError,
    },
    /// The supplied event or driver did not belong to this pull generation.
    UnexpectedEvent,
    /// One exact block request failed before yielding a usable response.
    BlockRequestFailed {
        peer_id: PeerId,
        block_id: ProofBlockId,
        source: Box<OutboundProofBlockFailure>,
    },
    /// The authenticated peer reported no block for an exact path address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ProofBlockId,
    },
    /// The selected head changed after this pull captured its anchor.
    SelectedHeadChanged {
        expected: ProofBlockId,
        actual: ProofBlockId,
    },
    /// One child transition did not start at its parent's resulting root.
    TransitionRootMismatch {
        preceding_block_id: ProofBlockId,
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
    /// The path met selected history other than its captured head.
    DivergentAncestry {
        expected_anchor: ProofBlockId,
        encountered: ProofBlockId,
    },
    /// A parent address repeated within this pull.
    RepeatedBlockId { block_id: ProofBlockId },
    /// The path did not reach its anchor within the fixed block bound.
    AncestryLimitExceeded {
        maximum: usize,
        next_block_id: ProofBlockId,
    },
}

impl ProofBlockAncestryPullError {
    fn selected_state(source: ProofChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }
}

impl fmt::Display for ProofBlockAncestryPullError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelectedState { source } => {
                write!(
                    formatter,
                    "proof-block ancestry cannot use selected state: {source}"
                )
            }
            Self::TargetAlreadySelected { block_id } => {
                write!(
                    formatter,
                    "proof-block ancestry target {block_id:?} is already selected"
                )
            }
            Self::RequestStart { block_id, source } => {
                write!(
                    formatter,
                    "cannot request ancestry block {block_id:?}: {source}"
                )
            }
            Self::UnexpectedEvent => formatter.write_str(
                "network event or driver does not belong to this proof-block ancestry pull",
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
            Self::TransitionRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "ancestry predecessor {preceding_block_id:?} ends at proof-set root {expected:?}, but its child starts at {actual:?}"
            ),
            Self::DivergentAncestry {
                expected_anchor,
                encountered,
            } => write!(
                formatter,
                "proof-block ancestry expected anchor {expected_anchor:?} but encountered selected-chain context {encountered:?}"
            ),
            Self::RepeatedBlockId { block_id } => {
                write!(formatter, "proof-block ancestry repeats block {block_id:?}")
            }
            Self::AncestryLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "proof-block ancestry did not reach its anchor within {maximum} blocks; next parent is {next_block_id:?}"
            ),
        }
    }
}

impl Error for ProofBlockAncestryPullError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::RequestStart { source, .. } => Some(source),
            Self::BlockRequestFailed { source, .. } => Some(source.as_ref()),
            Self::TargetAlreadySelected { .. }
            | Self::UnexpectedEvent
            | Self::BlockUnavailable { .. }
            | Self::SelectedHeadChanged { .. }
            | Self::TransitionRootMismatch { .. }
            | Self::DivergentAncestry { .. }
            | Self::RepeatedBlockId { .. }
            | Self::AncestryLimitExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
