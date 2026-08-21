//! Durable caller-selected acquisition of one bounded artifact-block ancestry.

use std::error::Error;
use std::fmt;

use naome::block_exchange::ArtifactBlockRequest;
use naome_chain::{ArtifactBlock, ArtifactBlockId, ArtifactChainId, ArtifactSetRoot};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, ArtifactChainJournal,
    ArtifactChainJournalError,
};

use super::{
    BlockRequestTicket, MAX_STATIC_PEERS, NetworkEvent, OutboundArtifactBlockFailure, PeerId,
    RequestStartError, StaticArtifactNetwork,
    block_ancestry::{
        ArtifactBlockAncestryShapeContext, ArtifactBlockAncestryShapeError, retain_ancestry_block,
    },
    selected_context_contains_block,
};

/// One durable candidate-store ancestry fill awaiting an exact block terminal.
///
/// The workflow exclusively borrows one candidate store so completion cannot be
/// assembled across different same-chain stores. It retains each shape-checked
/// found block before scanning or requesting its parent. Previously acknowledged
/// insertions survive cancellation and later failure, but no continuation starts
/// without another explicit caller action.
#[must_use]
pub struct ArtifactBlockCandidateAncestryFill<'store> {
    state: ArtifactBlockCandidateAncestryFillState<'store>,
    ticket: BlockRequestTicket,
    peers: ArtifactBlockCandidateAncestryFillPeers,
}

struct ArtifactBlockCandidateAncestryFillState<'store> {
    candidates: &'store mut ArtifactBlockCandidateStore,
    anchor_mode: ArtifactBlockCandidateAncestryAnchorMode,
    anchor_block_id: ArtifactBlockId,
    anchor_artifact_set_root: ArtifactSetRoot,
    virtual_genesis_block_id: ArtifactBlockId,
    target_block_id: ArtifactBlockId,
    blocks: Vec<ArtifactBlock>,
}

#[derive(Clone, Copy)]
enum ArtifactBlockCandidateAncestryAnchorMode {
    CurrentHead,
    ExplicitSelected,
}

enum ArtifactBlockCandidateAncestryFillPeers {
    Direct(PeerId),
    Fallback(ArtifactBlockCandidateAncestryFallbackPeers),
}

struct ArtifactBlockCandidateAncestryFallbackPeers {
    peer_ids: Box<[PeerId]>,
    next_peer_index: usize,
}

impl StaticArtifactNetwork {
    /// Starts or resumes one durable bounded ancestry fill.
    ///
    /// Already retained blocks are integrity-read and shape-checked without a
    /// network request. Only the first missing exact address is requested from
    /// `block_peer_id`. A fully retained path completes synchronously and does
    /// not inspect the peer configuration or connection state. The selected
    /// journal supplies only a read-only anchor and divergence checks.
    pub fn start_artifact_block_candidate_ancestry_fill<'store>(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &'store mut ArtifactBlockCandidateStore,
        block_peer_id: PeerId,
        target_block_id: ArtifactBlockId,
    ) -> Result<
        ArtifactBlockCandidateAncestryFillProgress<'store>,
        ArtifactBlockCandidateAncestryFillError,
    > {
        let state = ArtifactBlockCandidateAncestryFillState::new_current_head(
            selected,
            candidates,
            target_block_id,
        )?;
        match state.scan(selected, target_block_id)? {
            None => Ok(None),
            Some((state, block_id)) => {
                ArtifactBlockCandidateAncestryFillPeers::Direct(block_peer_id)
                    .start_request(self, state, block_id, None)
            }
        }
    }

    /// Starts or resumes one durable bounded ancestry fill with ordered peer fallback.
    ///
    /// Already retained blocks are integrity-read and shape-checked before the
    /// peer slice is inspected. At the first missing address, `block_peer_ids`
    /// must contain one to [`MAX_STATIC_PEERS`] distinct statically configured
    /// identities. Requests consider those peers once in exact caller order;
    /// busy or disconnected peers are skipped, while matched retryable
    /// terminals may advance to the next peer. The direct single-peer start
    /// remains a no-fallback operation.
    pub fn start_artifact_block_candidate_ancestry_fill_with_peer_fallback<'store>(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &'store mut ArtifactBlockCandidateStore,
        block_peer_ids: &[PeerId],
        target_block_id: ArtifactBlockId,
    ) -> Result<
        ArtifactBlockCandidateAncestryFillProgress<'store>,
        ArtifactBlockCandidateAncestryFillError,
    > {
        let state = ArtifactBlockCandidateAncestryFillState::new_current_head(
            selected,
            candidates,
            target_block_id,
        )?;
        match state.scan(selected, target_block_id)? {
            None => Ok(None),
            Some((state, block_id)) => {
                ArtifactBlockCandidateAncestryFillPeers::validated_fallback(self, block_peer_ids)?
                    .start_request(self, state, block_id, None)
            }
        }
    }

    /// Starts or resumes a durable bounded ancestry fill to one exact selected anchor.
    ///
    /// `selected_anchor_block_id` may be virtual genesis, the current selected
    /// head, or a historical selected block. The exact anchor and its artifact
    /// root are captured before candidate reads. Unlike the current-head start,
    /// unrelated later selected-head advancement does not abort this mode. The
    /// target and every retained or retrieved candidate-path block must remain
    /// unselected, and encountering any selected position other than the exact
    /// anchor is terminal rather than silently changing anchors.
    ///
    /// Already retained blocks are integrity-read and shape-checked before
    /// `block_peer_id` is inspected. Only the first missing exact address is
    /// requested, with no peer fallback or retry.
    pub fn start_artifact_block_candidate_ancestry_fill_from_selected_anchor<'store>(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &'store mut ArtifactBlockCandidateStore,
        block_peer_id: PeerId,
        selected_anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
    ) -> Result<
        ArtifactBlockCandidateAncestryFillProgress<'store>,
        ArtifactBlockCandidateAncestryFillError,
    > {
        let state = ArtifactBlockCandidateAncestryFillState::new_explicit_selected(
            selected,
            candidates,
            selected_anchor_block_id,
            target_block_id,
        )?;
        match state.scan(selected, target_block_id)? {
            None => Ok(None),
            Some((state, block_id)) => {
                ArtifactBlockCandidateAncestryFillPeers::Direct(block_peer_id)
                    .start_request(self, state, block_id, None)
            }
        }
    }

    /// Starts or resumes an exact-selected-anchor fill with ordered peer fallback.
    ///
    /// This preserves the explicit-anchor behavior of
    /// [`Self::start_artifact_block_candidate_ancestry_fill_from_selected_anchor`].
    /// At the first missing address, `block_peer_ids` must contain one to
    /// [`MAX_STATIC_PEERS`] distinct statically configured identities. Each peer
    /// is considered once in exact caller order for that address under the
    /// existing retry, durability, and per-attempt timeout contract.
    pub fn start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback<
        'store,
    >(
        &mut self,
        selected: &ArtifactChainJournal,
        candidates: &'store mut ArtifactBlockCandidateStore,
        block_peer_ids: &[PeerId],
        selected_anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
    ) -> Result<
        ArtifactBlockCandidateAncestryFillProgress<'store>,
        ArtifactBlockCandidateAncestryFillError,
    > {
        let state = ArtifactBlockCandidateAncestryFillState::new_explicit_selected(
            selected,
            candidates,
            selected_anchor_block_id,
            target_block_id,
        )?;
        match state.scan(selected, target_block_id)? {
            None => Ok(None),
            Some((state, block_id)) => {
                ArtifactBlockCandidateAncestryFillPeers::validated_fallback(self, block_peer_ids)?
                    .start_request(self, state, block_id, None)
            }
        }
    }
}

impl<'store> ArtifactBlockCandidateAncestryFillState<'store> {
    fn new_current_head(
        selected: &ArtifactChainJournal,
        candidates: &'store mut ArtifactBlockCandidateStore,
        target_block_id: ArtifactBlockId,
    ) -> Result<Self, ArtifactBlockCandidateAncestryFillError> {
        let selected_chain_id = selected.chain_id();
        let candidate_chain_id = candidates.chain_id();
        if selected_chain_id != candidate_chain_id {
            return Err(ArtifactBlockCandidateAncestryFillError::ChainIdMismatch {
                selected: selected_chain_id,
                candidates: candidate_chain_id,
            });
        }

        let anchor_block_id = selected
            .head_block_id()
            .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?;
        let virtual_genesis_block_id = selected_chain_id.virtual_genesis_block_id();
        if selected_context_contains_block(
            selected,
            anchor_block_id,
            virtual_genesis_block_id,
            target_block_id,
        )
        .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?
        {
            return Err(
                ArtifactBlockCandidateAncestryFillError::TargetAlreadySelected {
                    block_id: target_block_id,
                },
            );
        }
        let anchor_artifact_set_root = selected
            .artifact_set_root()
            .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?;

        Ok(Self {
            candidates,
            anchor_mode: ArtifactBlockCandidateAncestryAnchorMode::CurrentHead,
            anchor_block_id,
            anchor_artifact_set_root,
            virtual_genesis_block_id,
            target_block_id,
            blocks: Vec::new(),
        })
    }

    fn new_explicit_selected(
        selected: &ArtifactChainJournal,
        candidates: &'store mut ArtifactBlockCandidateStore,
        anchor_block_id: ArtifactBlockId,
        target_block_id: ArtifactBlockId,
    ) -> Result<Self, ArtifactBlockCandidateAncestryFillError> {
        let selected_chain_id = selected.chain_id();
        let candidate_chain_id = candidates.chain_id();
        if selected_chain_id != candidate_chain_id {
            return Err(ArtifactBlockCandidateAncestryFillError::ChainIdMismatch {
                selected: selected_chain_id,
                candidates: candidate_chain_id,
            });
        }

        let anchor = selected
            .branch_snapshot_at(anchor_block_id)
            .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?
            .ok_or(
                ArtifactBlockCandidateAncestryFillError::SelectedAnchorNotRetained {
                    block_id: anchor_block_id,
                },
            )?;
        let virtual_genesis_block_id = selected_chain_id.virtual_genesis_block_id();
        if selected_context_contains_block(
            selected,
            anchor_block_id,
            virtual_genesis_block_id,
            target_block_id,
        )
        .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?
        {
            return Err(
                ArtifactBlockCandidateAncestryFillError::TargetAlreadySelected {
                    block_id: target_block_id,
                },
            );
        }

        Ok(Self {
            candidates,
            anchor_mode: ArtifactBlockCandidateAncestryAnchorMode::ExplicitSelected,
            anchor_block_id,
            anchor_artifact_set_root: anchor.artifact_set_root(),
            virtual_genesis_block_id,
            target_block_id,
            blocks: Vec::new(),
        })
    }

    fn scan(
        mut self,
        selected: &ArtifactChainJournal,
        mut block_id: ArtifactBlockId,
    ) -> Result<Option<(Self, ArtifactBlockId)>, ArtifactBlockCandidateAncestryFillError> {
        loop {
            self.require_explicit_path_position_unselected(selected, block_id)?;
            let Some(block) = self.candidates.get(block_id).map_err(|source| {
                ArtifactBlockCandidateAncestryFillError::CandidateStoreRead {
                    block_id,
                    source: Box::new(source),
                }
            })?
            else {
                return Ok(Some((self, block_id)));
            };

            let next_block_id =
                retain_ancestry_block(selected, self.shape_context(), &mut self.blocks, block)
                    .map_err(ArtifactBlockCandidateAncestryFillError::from_shape)?;
            let Some(next_block_id) = next_block_id else {
                return Ok(None);
            };
            block_id = next_block_id;
        }
    }

    fn require_explicit_path_position_unselected(
        &self,
        selected: &ArtifactChainJournal,
        block_id: ArtifactBlockId,
    ) -> Result<(), ArtifactBlockCandidateAncestryFillError> {
        if !matches!(
            self.anchor_mode,
            ArtifactBlockCandidateAncestryAnchorMode::ExplicitSelected
        ) {
            return Ok(());
        }
        if selected_context_contains_block(
            selected,
            self.anchor_block_id,
            self.virtual_genesis_block_id,
            block_id,
        )
        .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?
        {
            return Err(ArtifactBlockCandidateAncestryFillError::DivergentAncestry {
                expected_anchor: self.anchor_block_id,
                encountered: block_id,
            });
        }
        Ok(())
    }

    fn require_explicit_anchor_and_path(
        &self,
        selected: &ArtifactChainJournal,
        pending_block_id: ArtifactBlockId,
    ) -> Result<(), ArtifactBlockCandidateAncestryFillError> {
        if !matches!(
            self.anchor_mode,
            ArtifactBlockCandidateAncestryAnchorMode::ExplicitSelected
        ) {
            return Ok(());
        }

        let anchor = selected
            .branch_snapshot_at(self.anchor_block_id)
            .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?
            .ok_or(
                ArtifactBlockCandidateAncestryFillError::SelectedAnchorNotRetained {
                    block_id: self.anchor_block_id,
                },
            )?;
        debug_assert_eq!(
            anchor.artifact_set_root(),
            self.anchor_artifact_set_root,
            "one selected block identity has one immutable artifact-set root"
        );
        for block in &self.blocks {
            self.require_explicit_path_position_unselected(selected, block.id())?;
        }
        self.require_explicit_path_position_unselected(selected, pending_block_id)
    }

    fn require_current_head(
        &self,
        selected: &ArtifactChainJournal,
    ) -> Result<(), ArtifactBlockCandidateAncestryFillError> {
        debug_assert!(matches!(
            self.anchor_mode,
            ArtifactBlockCandidateAncestryAnchorMode::CurrentHead
        ));
        let actual_head = selected
            .head_block_id()
            .map_err(ArtifactBlockCandidateAncestryFillError::selected_state)?;
        if actual_head != self.anchor_block_id {
            return Err(
                ArtifactBlockCandidateAncestryFillError::SelectedHeadChanged {
                    expected: self.anchor_block_id,
                    actual: actual_head,
                },
            );
        }
        Ok(())
    }

    fn shape_context(&self) -> ArtifactBlockAncestryShapeContext {
        ArtifactBlockAncestryShapeContext::new(
            self.anchor_block_id,
            self.anchor_artifact_set_root,
            self.virtual_genesis_block_id,
            self.target_block_id,
        )
    }
}

impl ArtifactBlockCandidateAncestryFillPeers {
    fn validated_fallback(
        network: &StaticArtifactNetwork,
        peer_ids: &[PeerId],
    ) -> Result<Self, ArtifactBlockCandidateAncestryFillError> {
        if peer_ids.is_empty() {
            return Err(ArtifactBlockCandidateAncestryFillError::EmptyBlockPeerSet);
        }
        if peer_ids.len() > MAX_STATIC_PEERS {
            return Err(ArtifactBlockCandidateAncestryFillError::TooManyBlockPeers {
                actual: peer_ids.len(),
                maximum: MAX_STATIC_PEERS,
            });
        }

        let mut canonical_peer_ids = peer_ids.to_vec();
        canonical_peer_ids.sort_unstable();
        if let Some(peer_id) = canonical_peer_ids
            .windows(2)
            .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
        {
            return Err(ArtifactBlockCandidateAncestryFillError::DuplicateBlockPeer { peer_id });
        }
        if let Some(peer_id) = canonical_peer_ids.iter().copied().find(|peer_id| {
            network
                .swarm
                .behaviour()
                .sessions
                .peer_index(peer_id)
                .is_none()
        }) {
            return Err(ArtifactBlockCandidateAncestryFillError::UnknownBlockPeer { peer_id });
        }

        canonical_peer_ids.clone_from_slice(peer_ids);
        Ok(Self::Fallback(
            ArtifactBlockCandidateAncestryFallbackPeers {
                peer_ids: canonical_peer_ids.into_boxed_slice(),
                next_peer_index: 0,
            },
        ))
    }

    fn start_request<'store>(
        self,
        network: &mut StaticArtifactNetwork,
        state: ArtifactBlockCandidateAncestryFillState<'store>,
        block_id: ArtifactBlockId,
        last_terminal: Option<ArtifactBlockCandidateAncestryFillError>,
    ) -> Result<
        ArtifactBlockCandidateAncestryFillProgress<'store>,
        ArtifactBlockCandidateAncestryFillError,
    > {
        match self {
            Self::Direct(peer_id) => {
                if let Some(error) = last_terminal {
                    return Err(error);
                }
                let ticket = network
                    .request_block(peer_id, ArtifactBlockRequest::new(block_id))
                    .map_err(
                        |source| ArtifactBlockCandidateAncestryFillError::RequestStart {
                            block_id,
                            source,
                        },
                    )?;
                Ok(Some(ArtifactBlockCandidateAncestryFill {
                    state,
                    ticket,
                    peers: Self::Direct(peer_id),
                }))
            }
            Self::Fallback(mut peers) => loop {
                let Some(&peer_id) = peers.peer_ids.get(peers.next_peer_index) else {
                    return Err(last_terminal.unwrap_or(
                        ArtifactBlockCandidateAncestryFillError::NoRequestableBlockPeer {
                            block_id,
                        },
                    ));
                };
                peers.next_peer_index += 1;
                match network.request_block(peer_id, ArtifactBlockRequest::new(block_id)) {
                    Ok(ticket) => {
                        return Ok(Some(ArtifactBlockCandidateAncestryFill {
                            state,
                            ticket,
                            peers: Self::Fallback(peers),
                        }));
                    }
                    Err(
                        RequestStartError::AlreadyPending(_)
                        | RequestStartError::PeerDisconnected(_),
                    ) => {}
                    Err(source) => {
                        return Err(ArtifactBlockCandidateAncestryFillError::RequestStart {
                            block_id,
                            source,
                        });
                    }
                }
            },
        }
    }

    fn reset_for_parent(&mut self) {
        if let Self::Fallback(peers) = self {
            peers.next_peer_index = 0;
        }
    }
}

impl<'store> ArtifactBlockCandidateAncestryFill<'store> {
    /// Returns the exact selected anchor captured when this fill started.
    pub const fn anchor_block_id(&self) -> ArtifactBlockId {
        self.state.anchor_block_id
    }

    /// Returns the exact ancestry target selected by the caller.
    pub const fn target_block_id(&self) -> ArtifactBlockId {
        self.state.target_block_id
    }

    /// Returns the exact missing block identity awaited by the active request.
    pub const fn pending_block_id(&self) -> ArtifactBlockId {
        self.ticket.request().block_id()
    }

    /// Returns the authenticated peer expected to serve the active request.
    pub const fn pending_peer_id(&self) -> PeerId {
        self.ticket.peer_id()
    }

    /// Returns whether `event` is the exact terminal awaited by this fill.
    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        matches!(event, NetworkEvent::OutboundBlock(event) if self.ticket.accepts_event(event))
    }

    /// Cancels the fill and releases its exclusive candidate-store borrow.
    ///
    /// Every previously acknowledged insertion remains durable. Dropping the
    /// active ticket does not cancel its physical libp2p request, whose slot and
    /// permit drain through the network event loop.
    pub fn cancel(self) {}

    /// Advances the fill with its exact correlated block terminal.
    ///
    /// Current-head mode rechecks that head before a found block is shape-checked
    /// or inserted. Explicit-anchor mode instead rechecks its anchor plus every
    /// retained and pending candidate-path address before processing a terminal;
    /// unrelated selected-head advancement does not abort it. A successful
    /// insertion is acknowledged before any retained parent scan or next request.
    /// The journal is never mutated.
    pub fn on_event(
        self,
        network: &mut StaticArtifactNetwork,
        selected: &ArtifactChainJournal,
        event: NetworkEvent,
    ) -> Result<
        ArtifactBlockCandidateAncestryFillProgress<'store>,
        ArtifactBlockCandidateAncestryFillError,
    > {
        if !self.accepts_event(&event) {
            return Err(ArtifactBlockCandidateAncestryFillError::UnexpectedEvent);
        }

        let Self {
            mut state,
            ticket,
            mut peers,
        } = self;
        let NetworkEvent::OutboundBlock(event) = event else {
            unreachable!("an accepted candidate ancestry event is a block terminal")
        };
        if !ticket.belongs_to_network(network) {
            return Err(ArtifactBlockCandidateAncestryFillError::UnexpectedEvent);
        }

        let peer_id = ticket.peer_id();
        let block_id = ticket.request().block_id();
        state.require_explicit_anchor_and_path(selected, block_id)?;
        let response = match ticket
            .complete(event)
            .expect("the accepted block event matches its candidate ancestry ticket")
        {
            Ok(response) => response,
            Err(source) => {
                let retryable = matches!(
                    source.as_ref(),
                    OutboundArtifactBlockFailure::Transport(_)
                        | OutboundArtifactBlockFailure::InvalidResponse { .. }
                );
                let error = ArtifactBlockCandidateAncestryFillError::BlockRequestFailed {
                    peer_id,
                    block_id,
                    source,
                };
                if retryable {
                    return peers.start_request(network, state, block_id, Some(error));
                }
                return Err(error);
            }
        };
        let Some(block) = response.into_block() else {
            let error =
                ArtifactBlockCandidateAncestryFillError::BlockUnavailable { peer_id, block_id };
            return peers.start_request(network, state, block_id, Some(error));
        };

        if matches!(
            state.anchor_mode,
            ArtifactBlockCandidateAncestryAnchorMode::CurrentHead
        ) {
            state.require_current_head(selected)?;
        }

        let next_block_id =
            retain_ancestry_block(selected, state.shape_context(), &mut state.blocks, block)
                .map_err(ArtifactBlockCandidateAncestryFillError::from_shape)?;
        let _ = state.candidates.insert(&block).map_err(|source| {
            ArtifactBlockCandidateAncestryFillError::CandidateStoreInsert {
                block_id,
                source: Box::new(source),
            }
        })?;

        let Some(next_block_id) = next_block_id else {
            return Ok(None);
        };
        peers.reset_for_parent();
        match state.scan(selected, next_block_id)? {
            None => Ok(None),
            Some((state, block_id)) => peers.start_request(network, state, block_id, None),
        }
    }
}

impl fmt::Debug for ArtifactBlockCandidateAncestryFill<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactBlockCandidateAncestryFill")
            .field("anchor_block_id", &self.anchor_block_id())
            .field("target_block_id", &self.target_block_id())
            .field("pending_block_id", &self.pending_block_id())
            .field("pending_peer_id", &self.pending_peer_id())
            .field("retained_block_count", &self.state.blocks.len())
            .finish_non_exhaustive()
    }
}

/// Allocation-free progress after start or one exact block terminal.
///
/// `Some(fill)` means one exact missing-block request remains active. `None`
/// means the bound candidate store contains the complete checked path to the
/// captured selected anchor.
pub type ArtifactBlockCandidateAncestryFillProgress<'store> =
    Option<ArtifactBlockCandidateAncestryFill<'store>>;

/// A fail-closed durable candidate-store ancestry fill error.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactBlockCandidateAncestryFillError {
    /// The fallback mode was given no candidate block peer.
    EmptyBlockPeerSet,
    /// The fallback mode exceeded the fixed configured-peer bound.
    TooManyBlockPeers { actual: usize, maximum: usize },
    /// The fallback mode repeated one peer identity.
    DuplicateBlockPeer { peer_id: PeerId },
    /// The fallback mode named a peer outside the static configuration.
    UnknownBlockPeer { peer_id: PeerId },
    /// The candidate store and selected journal belong to different chains.
    ChainIdMismatch {
        selected: ArtifactChainId,
        candidates: ArtifactChainId,
    },
    /// The selected journal failed a required read.
    SelectedState {
        source: Box<ArtifactChainJournalError>,
    },
    /// The explicit anchor is neither virtual genesis nor a retained selected block.
    SelectedAnchorNotRetained { block_id: ArtifactBlockId },
    /// The target is the current head, virtual genesis, or another selected block.
    TargetAlreadySelected { block_id: ArtifactBlockId },
    /// The candidate store could not integrity-read one required block address.
    CandidateStoreRead {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
    /// One exact missing block request could not be started.
    RequestStart {
        block_id: ArtifactBlockId,
        source: RequestStartError,
    },
    /// No listed fallback peer could start the exact missing request.
    NoRequestableBlockPeer { block_id: ArtifactBlockId },
    /// The supplied event or driver did not belong to this fill generation.
    UnexpectedEvent,
    /// One exact missing block request failed before yielding a usable response.
    BlockRequestFailed {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
        source: Box<OutboundArtifactBlockFailure>,
    },
    /// The authenticated peer reported no block for an exact missing address.
    BlockUnavailable {
        peer_id: PeerId,
        block_id: ArtifactBlockId,
    },
    /// Current-head mode observed a different selected head after start.
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
    /// A parent address repeated within the retained path.
    RepeatedBlockId { block_id: ArtifactBlockId },
    /// The retained or pending path met selected history other than its exact anchor.
    DivergentAncestry {
        expected_anchor: ArtifactBlockId,
        encountered: ArtifactBlockId,
    },
    /// The retained path did not reach its anchor within the fixed bound.
    AncestryLimitExceeded {
        maximum: usize,
        next_block_id: ArtifactBlockId,
    },
    /// One shape-checked found block could not be durably retained.
    CandidateStoreInsert {
        block_id: ArtifactBlockId,
        source: Box<ArtifactBlockCandidateStoreError>,
    },
}

impl ArtifactBlockCandidateAncestryFillError {
    fn selected_state(source: ArtifactChainJournalError) -> Self {
        Self::SelectedState {
            source: Box::new(source),
        }
    }

    fn from_shape(error: ArtifactBlockAncestryShapeError) -> Self {
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

impl fmt::Display for ArtifactBlockCandidateAncestryFillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBlockPeerSet => {
                formatter.write_str("candidate ancestry fallback peer set is empty")
            }
            Self::TooManyBlockPeers { actual, maximum } => write!(
                formatter,
                "candidate ancestry fallback has {actual} peers, maximum is {maximum}"
            ),
            Self::DuplicateBlockPeer { peer_id } => write!(
                formatter,
                "candidate ancestry fallback repeats peer {peer_id}"
            ),
            Self::UnknownBlockPeer { peer_id } => write!(
                formatter,
                "candidate ancestry fallback peer {peer_id} is not statically configured"
            ),
            Self::ChainIdMismatch {
                selected,
                candidates,
            } => write!(
                formatter,
                "candidate store chain {candidates:?} does not match selected journal chain {selected:?}"
            ),
            Self::SelectedState { source } => write!(
                formatter,
                "candidate ancestry fill cannot use selected state: {source}"
            ),
            Self::SelectedAnchorNotRetained { block_id } => write!(
                formatter,
                "candidate ancestry fill anchor {block_id:?} is not a retained selected position"
            ),
            Self::TargetAlreadySelected { block_id } => write!(
                formatter,
                "candidate ancestry fill target {block_id:?} is already selected"
            ),
            Self::CandidateStoreRead { block_id, source } => write!(
                formatter,
                "cannot read candidate ancestry block address {block_id:?}: {source}"
            ),
            Self::RequestStart { block_id, source } => write!(
                formatter,
                "cannot request missing candidate ancestry block {block_id:?}: {source}"
            ),
            Self::NoRequestableBlockPeer { block_id } => write!(
                formatter,
                "no candidate ancestry fallback peer can request block {block_id:?}"
            ),
            Self::UnexpectedEvent => formatter.write_str(
                "network event or driver does not belong to this candidate ancestry fill",
            ),
            Self::BlockRequestFailed {
                peer_id,
                block_id,
                source,
            } => write!(
                formatter,
                "peer {peer_id} failed candidate ancestry block request {block_id:?}: {source}"
            ),
            Self::BlockUnavailable { peer_id, block_id } => write!(
                formatter,
                "peer {peer_id} has no candidate ancestry block at {block_id:?}"
            ),
            Self::SelectedHeadChanged { expected, actual } => write!(
                formatter,
                "selected head changed during candidate ancestry fill: expected {expected:?}, actual {actual:?}"
            ),
            Self::ArtifactSetRootMismatch {
                preceding_block_id,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate ancestry predecessor {preceding_block_id:?} ends at artifact-set root {expected:?}, but its child starts at {actual:?}"
            ),
            Self::RepeatedBlockId { block_id } => {
                write!(formatter, "candidate ancestry repeats block {block_id:?}")
            }
            Self::DivergentAncestry {
                expected_anchor,
                encountered,
            } => write!(
                formatter,
                "candidate ancestry expected anchor {expected_anchor:?} but encountered selected-chain context {encountered:?}"
            ),
            Self::AncestryLimitExceeded {
                maximum,
                next_block_id,
            } => write!(
                formatter,
                "candidate ancestry did not reach its anchor within {maximum} blocks; next parent is {next_block_id:?}"
            ),
            Self::CandidateStoreInsert { block_id, source } => write!(
                formatter,
                "cannot retain candidate ancestry block {block_id:?}: {source}"
            ),
        }
    }
}

impl Error for ArtifactBlockCandidateAncestryFillError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SelectedState { source } => Some(source.as_ref()),
            Self::CandidateStoreRead { source, .. } | Self::CandidateStoreInsert { source, .. } => {
                Some(source.as_ref())
            }
            Self::RequestStart { source, .. } => Some(source),
            Self::BlockRequestFailed { source, .. } => Some(source.as_ref()),
            Self::EmptyBlockPeerSet
            | Self::TooManyBlockPeers { .. }
            | Self::DuplicateBlockPeer { .. }
            | Self::UnknownBlockPeer { .. }
            | Self::ChainIdMismatch { .. }
            | Self::SelectedAnchorNotRetained { .. }
            | Self::TargetAlreadySelected { .. }
            | Self::NoRequestableBlockPeer { .. }
            | Self::UnexpectedEvent
            | Self::BlockUnavailable { .. }
            | Self::SelectedHeadChanged { .. }
            | Self::ArtifactSetRootMismatch { .. }
            | Self::RepeatedBlockId { .. }
            | Self::DivergentAncestry { .. }
            | Self::AncestryLimitExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests;
