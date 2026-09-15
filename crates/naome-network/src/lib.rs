//! Bounded authenticated artifact transport over operator-configured peers.
//!
//! TCP carries mutually authenticated Noise sessions. Yamux multiplexes artifact,
//! block, chain-head, candidate-offer, recovery, vote, and finality-proof exchanges
//! over the same fixed sessions. The lower raw peer identity owns dialing, and
//! generation-bound requests preserve peer and operation correlation.
//!
//! The caller owns the Tokio runtime and every network event loop. Acquisition
//! and serving compose explicit caller-selected targets with strictly checked
//! artifacts, candidate stores, and anchored journals. Transport receipts prove
//! neither mathematical validity nor selected history, consensus, or finality.
//! This crate starts no NAOME-owned background task and owns no journal or signer.

mod acquisition;
mod serving;
mod transport;

use acquisition::{
    block_ancestry, block_ancestry_import, block_candidate_ancestry_fill,
    block_candidate_branch_payload_fill, block_candidate_payload_fill, block_catch_up,
    block_import, head_broadcast, head_survey, peer_selection,
};
use serving::journal_service;
use transport::{
    block_transport, consensus_push, finality_exchange, head_announcement, head_transport,
    rate_limit, recovery_bundle_push, request_correlation,
};

pub use block_ancestry::{
    ArtifactBlockAncestryPull, ArtifactBlockAncestryPullError, ArtifactBlockAncestryPullProgress,
    MAX_ARTIFACT_BLOCK_ANCESTRY_BLOCKS, UnselectedArtifactBlockAncestry,
};
pub use block_ancestry_import::{
    ArtifactBlockAncestryImport, ArtifactBlockAncestryImportError,
    ArtifactBlockAncestryImportProgress, ArtifactBlockCandidateAncestryImportStartError,
};
pub use block_candidate_ancestry_fill::{
    ArtifactBlockCandidateAncestryFill, ArtifactBlockCandidateAncestryFillError,
    ArtifactBlockCandidateAncestryFillProgress,
};
pub use block_candidate_branch_payload_fill::{
    ArtifactBlockCandidateBranchPayloadFill, ArtifactBlockCandidateBranchPayloadFillError,
    ArtifactBlockCandidateBranchPayloadFillProgress,
};
pub use block_candidate_payload_fill::{
    ArtifactBlockCandidatePayloadFill, ArtifactBlockCandidatePayloadFillError,
};
pub use block_catch_up::{
    ArtifactBlockCatchUp, ArtifactBlockCatchUpError, ArtifactBlockCatchUpProgress,
};
pub use block_import::{
    ArtifactBlockImport, ArtifactBlockImportError, ArtifactBlockImportProgress,
};
pub use block_transport::{
    ArtifactBlockRequestEventMismatch, BlockRequestTicket, InboundArtifactBlockRequest,
    OutboundArtifactBlockEvent, OutboundArtifactBlockFailure,
};
pub use consensus_push::{
    AuthenticatedConsensusPushReceipt, CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
    CONSENSUS_PUSH_MAX_PROPOSAL_BYTES, CONSENSUS_PUSH_MAX_RETAINED_INBOUND_BYTES,
    CONSENSUS_PUSH_MAX_RETAINED_INBOUND_EVENTS, CONSENSUS_PUSH_MIN_PROPOSAL_BYTES,
    CONSENSUS_PUSH_VOTE_BYTES, ConsensusPushAcknowledgeError, ConsensusPushEventMismatch,
    ConsensusPushField, ConsensusPushLengthError, ConsensusPushMessage, ConsensusPushSize,
    ConsensusPushStartError, ConsensusPushStartFailure, ConsensusPushTicket, InboundConsensusPush,
    OutboundConsensusPushEvent, OutboundConsensusPushFailure, ReceivedConsensusPush,
};
pub use finality_exchange::{
    AuthenticatedFinalityProofResponse, FINALITY_PROOF_MAX_ENVELOPE_BYTES,
    FINALITY_PROOF_MAX_PAYLOAD_BYTES, FINALITY_PROOF_MAX_RETAINED_BYTES,
    FINALITY_PROOF_MIN_ENVELOPE_BYTES, FINALITY_PROOF_REQUEST_BYTES, FinalityProofEventMismatch,
    FinalityProofRequest, FinalityProofRespondError, FinalityProofResponse, FinalityProofTicket,
    InboundFinalityProofRequest, OutboundFinalityProofEvent, OutboundFinalityProofFailure,
};
pub use head_announcement::{
    ArtifactChainHeadAnnouncementEventMismatch, AuthenticatedArtifactChainHeadAnnouncementReceipt,
    HeadAnnouncementAcknowledgeError, HeadAnnouncementStartError, HeadAnnouncementTicket,
    InboundArtifactChainHeadAnnouncement, OutboundArtifactChainHeadAnnouncementEvent,
    OutboundArtifactChainHeadAnnouncementFailure,
};
pub use head_broadcast::{
    ArtifactChainHeadBroadcast, ArtifactChainHeadBroadcastEventMismatch,
    ArtifactChainHeadBroadcastPeerResult, ArtifactChainHeadBroadcastProgress,
    ArtifactChainHeadBroadcastStartError, CompletedArtifactChainHeadBroadcast,
    MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS,
};
pub use head_survey::{
    ArtifactChainHeadSurvey, ArtifactChainHeadSurveyEventMismatch,
    ArtifactChainHeadSurveyPeerResult, ArtifactChainHeadSurveyProgress,
    ArtifactChainHeadSurveyStartError, CompletedArtifactChainHeadSurvey,
};
pub use head_transport::{
    ArtifactChainHeadRequestEventMismatch, AuthenticatedArtifactChainHeadResponse,
    ChainHeadRequestTicket, InboundArtifactChainHeadRequest, OutboundArtifactChainHeadEvent,
    OutboundArtifactChainHeadFailure,
};
pub use journal_service::{JournalServiceEvent, JournalServiceRequest};
pub use libp2p::core::transport::ListenerId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
pub use recovery_bundle_push::{
    AcknowledgedRecoveryBundlePush, AuthenticatedRecoveryBundlePushReceipt,
    InboundRecoveryBundlePush, OutboundRecoveryBundlePushEvent, OutboundRecoveryBundlePushFailure,
    RECOVERY_BUNDLE_PUSH_MAX_BYTES, RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
    RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS, RecoveryBundlePushAcknowledgeError,
    RecoveryBundlePushEventMismatch, RecoveryBundlePushRequestError, RecoveryBundlePushStartError,
    RecoveryBundlePushTicket,
};

pub use transport::{
    ARTIFACT_BLOCK_IMPORT_TIMEOUT, BuildError, CONNECTION_TIMEOUT, CancellationDrainOutcome,
    DIAL_RETRY_BASE, DIAL_RETRY_MAX, INBOUND_APPLICATION_REQUEST_BURST,
    INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL, INBOUND_AUTH_BURST, INBOUND_AUTH_REFILL_INTERVAL,
    InboundArtifactRequest, ListenError, MAX_CONNECTIONS_PER_PEER,
    MAX_CONSENSUS_PUSH_STREAMS_PER_CONNECTION, MAX_EXCHANGE_STREAMS_PER_CONNECTION,
    MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION, MAX_PENDING_REQUESTS,
    MAX_RECOVERY_BUNDLE_PUSH_STREAMS_PER_CONNECTION, MAX_STATIC_PEERS,
    MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION, MAX_YAMUX_STREAMS_PER_CONNECTION, NetworkEvent,
    OutboundArtifactEvent, OutboundArtifactFailure, PeerSessionEvent, REQUEST_TIMEOUT,
    RequestStartError, RespondError, STABLE_SESSION_DURATION, StaticArtifactNetwork, StaticPeer,
    TCP_LISTEN_BACKLOG,
};

#[cfg(test)]
use transport::{codec, tests};

pub use acquisition::candidate_retention::ArtifactBlockCandidateRetentionError;
pub use acquisition::recovery_bundle_staging::{
    AcknowledgedRecoveryBundleStageError, AcknowledgedRecoveryBundleStageOutcome,
    RecoveryBundleStageSelection,
};

#[cfg(test)]
#[path = "../../../tests/support/codec_corpus.rs"]
mod codec_corpus;

pub use transport::candidate_offer::{
    CANDIDATE_OFFER_INTERVAL, CANDIDATE_OFFER_MAX_BYTES, CANDIDATE_OFFER_MAX_IDS, CandidateOffer,
    CandidateOfferError, CandidateOfferEvent, CandidateOfferFailure, CandidateOfferMismatch,
    CandidateOfferTicket, InboundCandidateOffer,
};
