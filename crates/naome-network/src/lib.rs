//! Authenticated artifact transport plus bounded untrusted peer-address routing.
//!
//! TCP carries mutually authenticated Noise sessions, Yamux provides one
//! substream per exchange, and the retained libp2p request handle plus
//! authenticated peer bind each terminal to the immutable artifact, artifact-block,
//! artifact-chain-head, or head-announcement operation that caused it. Static
//! authorization is not Sybil resistance, discovery, consensus, or artifact
//! selection.
//!
//! The endpoint with the lexicographically lower raw binary `PeerId` in each
//! configured pair owns dialing; artifact, exact-block, head-pull, and
//! head-announcement exchanges reuse that managed full-duplex session and
//! never open connections.
//!
//! A separate outbound-only [`PeerRecordBootstrapClient`] authenticates exact
//! operator-configured bootstrap endpoints and returns source-bound record
//! batches for explicit atomic admission. A separate outbound-only
//! [`LearnedPeerRecordPullClient`] accepts a bounded caller-selected set of
//! opaque store-produced candidates, authenticates each immediate identity,
//! and preserves its configured-bootstrap provenance through revalidated
//! atomic admission. A separate inbound-only
//! [`PeerRecordBootstrapResponder`] serves one operator-supplied immutable
//! canonical batch to bounded authenticated requesters. Neither swarm installs
//! the artifact protocol or converts a learned candidate into artifact authority.
//! A separate [`LocalPeerRecordIssuer`] persists one identity-bound sequence
//! watermark before returning each newly signed standard peer record. It never
//! retains the private key, discovers addresses, or publishes by itself.
//!
//! The caller owns the Tokio runtime, drives every network event loop, routes
//! correlated artifact events through exact one-payload block imports, consumes
//! exact-block terminals through their generation tickets, may durably retain
//! one exact found block as an unselected structural candidate and explicitly
//! serve it again from the caller-routed chain-scoped candidate store, may pull,
//! explicitly announce, broadcast, or survey source-bound untrusted chain heads
//! across a bounded caller-selected peer set, may retrieve one bounded
//! caller-selected and unselected block ancestry, imports one exact child or one
//! consumed ancestry, durably fills one bounded candidate-store ancestry to the
//! current head or an explicit retained selected anchor while reusing retained
//! blocks through either one exact peer or a separate bounded caller-ordered
//! fallback sequence, reconstructs and begins importing one bounded ancestry from
//! a caller-routed candidate store without block requests, or
//! composes retrieval and import into one exact-target catch-up. Every fill
//! target, import target, and fallback order remains caller-selected. The caller
//! may also validate and durably archive one exact retained direct-child
//! candidate payload through either a healthy archive hit or one exact
//! caller-selected peer request, without selecting the candidate. It may also
//! reconstruct one fully retained bounded candidate branch while retrieving
//! each missing exact committed payload from one caller-selected peer or through
//! a separate bounded caller-ordered fallback sequence with one absolute
//! deadline per missing address; every acknowledged archive prefix is durable,
//! but no partial branch snapshot is exposed. The caller also explicitly
//! accepts one bounded recovery-bundle stream, may bind its authenticated
//! immediate source plus exact selected anchor and unselected target, and may
//! stage only its fully validated unselected suffix into caller-routed candidate
//! and payload stores with independent durable prefixes. The stream receipt is
//! sent before and remains independent of staging; neither the source nor either
//! store grants selection, provenance, consensus, or finality authority. The
//! caller also explicitly
//! admits a peer-record batch and may derive one owned canonical publication
//! from exact fresh subjects retained by a peer-address store. The responder
//! never reads that peer-address store and remains immutable after construction.
//! [`StaticArtifactNetwork::next_journal_service_event`] serves authenticated
//! artifact, block, and head pulls from one borrowed journal while returning
//! announcements and every other event unchanged; it starts no background
//! task.
//! This crate starts no NAOME-owned background task and owns no
//! [`naome_storage::ArtifactChainJournal`].

mod acquisition;
mod peer_records;
mod serving;
mod transport;

use acquisition::{
    block_ancestry, block_ancestry_import, block_candidate_ancestry_fill,
    block_candidate_branch_payload_fill, block_candidate_payload_fill, block_catch_up,
    block_import, head_broadcast, head_survey, peer_selection,
};
use peer_records::{
    address_store, bootstrap, learned_pull, local_issuer, record_exchange, responder, snapshot_io,
};
use serving::journal_service;
use transport::{
    block_transport, codec, head_announcement, head_transport, rate_limit, recovery_bundle_push,
    request_correlation,
};

pub use address_store::{
    BootstrapConfigError, BootstrapPeer, BootstrapPeerError, DialCandidate,
    MAX_ADDRESSES_PER_PEER_RECORD, MAX_BOOTSTRAP_PEERS, MAX_DIAL_CANDIDATES,
    MAX_DIAL_CANDIDATES_PER_BOOTSTRAP, MAX_PEER_ADDRESS_BYTES, MAX_PEER_ADDRESS_RECORDS,
    MAX_RECORDS_PER_BOOTSTRAP, MAX_RECORDS_PER_NETWORK_GROUP, MAX_SIGNED_PEER_RECORD_BYTES,
    PEER_RECORD_TTL, PeerAddressStore, PeerAddressStoreError, PeerRecordAdmission,
    PeerRecordBatchAdmission, PeerRecordPublicationError, SignedPeerRecord, SignedPeerRecordError,
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
pub use bootstrap::{
    AuthenticatedPeerRecordBatch, PeerRecordBootstrapBuildError, PeerRecordBootstrapClient,
    PeerRecordBootstrapEvent, PeerRecordPullFailure, PeerRecordPullStartError,
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
pub use learned_pull::{
    AuthenticatedLearnedPeerRecordBatch, LearnedPeerRecordPullBuildError,
    LearnedPeerRecordPullClient, LearnedPeerRecordPullEvent, LearnedPeerRecordPullStartError,
};
pub use libp2p::core::transport::ListenerId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair};
pub use local_issuer::{LocalPeerRecordIssuer, LocalPeerRecordIssuerError};
pub use record_exchange::{
    MAX_PEER_RECORDS_PER_BATCH, PEER_RECORD_BATCH_MAX_BYTES, PEER_RECORD_PULL_REQUEST_BYTES,
    PeerRecordBatch, PeerRecordExchangeWireError, PeerRecordPullRequest,
};
pub use recovery_bundle_push::{
    AcknowledgedRecoveryBundlePush, AuthenticatedRecoveryBundlePushReceipt,
    InboundRecoveryBundlePush, OutboundRecoveryBundlePushEvent, OutboundRecoveryBundlePushFailure,
    RECOVERY_BUNDLE_PUSH_MAX_BYTES, RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_BYTES,
    RECOVERY_BUNDLE_PUSH_MAX_RETAINED_INBOUND_EVENTS, RecoveryBundlePushAcknowledgeError,
    RecoveryBundlePushEventMismatch, RecoveryBundlePushRequestError, RecoveryBundlePushStartError,
    RecoveryBundlePushTicket,
};
pub use responder::{
    PeerRecordBootstrapResponder, PeerRecordBootstrapResponderBuildError,
    PeerRecordBootstrapResponderEvent, PeerRecordBootstrapResponderFailure,
    PeerRecordBootstrapResponderListenError,
};

pub use transport::{
    ARTIFACT_BLOCK_IMPORT_TIMEOUT, BuildError, CONNECTION_TIMEOUT, CancellationDrainOutcome,
    DIAL_RETRY_BASE, DIAL_RETRY_MAX, INBOUND_APPLICATION_REQUEST_BURST,
    INBOUND_APPLICATION_REQUEST_REFILL_INTERVAL, INBOUND_AUTH_BURST, INBOUND_AUTH_REFILL_INTERVAL,
    InboundArtifactRequest, ListenError, MAX_CONNECTIONS_PER_PEER,
    MAX_EXCHANGE_STREAMS_PER_CONNECTION, MAX_HEAD_ANNOUNCEMENT_STREAMS_PER_CONNECTION,
    MAX_PENDING_REQUESTS, MAX_RECOVERY_BUNDLE_PUSH_STREAMS_PER_CONNECTION, MAX_STATIC_PEERS,
    MAX_STREAMS_PER_EXCHANGE_PER_CONNECTION, MAX_YAMUX_STREAMS_PER_CONNECTION, NetworkEvent,
    OutboundArtifactEvent, OutboundArtifactFailure, PeerSessionEvent, REQUEST_TIMEOUT,
    RequestStartError, RespondError, STABLE_SESSION_DURATION, StaticArtifactNetwork, StaticPeer,
    TCP_LISTEN_BACKLOG,
};

#[cfg(test)]
use transport::tests;

use transport::{MAX_PEER_RECORD_STREAMS_PER_CONNECTION, PEER_RECORD_IDLE_TIMEOUT, yamux_config};

pub use acquisition::candidate_retention::ArtifactBlockCandidateRetentionError;
pub use acquisition::recovery_bundle_staging::{
    AcknowledgedRecoveryBundleStageError, AcknowledgedRecoveryBundleStageOutcome,
    RecoveryBundleStageSelection,
};
