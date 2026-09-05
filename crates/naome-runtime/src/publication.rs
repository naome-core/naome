//! One publication's original custody and bounded ordered peer attempts.

use std::collections::TryReserveError;

use naome_network::{
    AuthenticatedConsensusPushReceipt, ConsensusPushMessage, ConsensusPushSize,
    ConsensusPushStartFailure, ConsensusPushTicket, MAX_STATIC_PEERS, OutboundConsensusPushFailure,
    PeerId,
};
use naome_node::{FixedValidatorNodeDeferredProposalV0, FixedValidatorNodeDriverCommandV0};
use naome_storage::{FixedValidatorSignedProposalV0, FixedValidatorSignedVoteV0};

use crate::routing::MessageRef;

/// Original typed publication and any separately retained higher-round proposal.
///
/// The released proposal token is never forwarded or silently self-admitted.
#[must_use]
pub enum FixedValidatorRuntimePublicationMessageV0 {
    Proposal {
        proposal: FixedValidatorSignedProposalV0,
        canonical_artifact_bytes: Vec<u8>,
    },
    Vote {
        vote: FixedValidatorSignedVoteV0,
        released_proposal: Option<Box<FixedValidatorNodeDeferredProposalV0>>,
    },
}

impl FixedValidatorRuntimePublicationMessageV0 {
    pub(crate) fn as_message(&self) -> MessageRef<'_> {
        match self {
            Self::Proposal {
                proposal,
                canonical_artifact_bytes,
            } => MessageRef::Proposal {
                control: proposal.canonical_proposal_control_bytes(),
                artifact: canonical_artifact_bytes,
            },
            Self::Vote { vote, .. } => MessageRef::Vote(vote.canonical_bytes()),
        }
    }

    /// Makes a fallible copy for an explicit caller-owned operation.
    /// Runtime-produced messages already satisfy driver bounds; transport checks
    /// caller-assembled messages independently. The original remains intact.
    pub fn copy_message(&self) -> Result<ConsensusPushMessage, TryReserveError> {
        self.as_message().copy_message()
    }

    pub fn size(&self) -> ConsensusPushSize {
        self.as_message().size()
    }
}

/// One peer's sole attempt, kept in the caller's configured peer order.
#[derive(Debug)]
#[must_use]
pub struct FixedValidatorRuntimePeerDeliveryV0 {
    pub(crate) peer_id: PeerId,
    pub(crate) state: FixedValidatorRuntimeDeliveryStateV0,
}

impl FixedValidatorRuntimePeerDeliveryV0 {
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub const fn state(&self) -> &FixedValidatorRuntimeDeliveryStateV0 {
        &self.state
    }
}

/// Transport outcome only. Failure can occur after the peer received the bytes.
#[derive(Debug)]
#[must_use]
pub enum FixedValidatorRuntimeDeliveryStateV0 {
    NotAttempted,
    InFlight(ConsensusPushTicket),
    Refused(ConsensusPushStartFailure),
    Failed(Box<OutboundConsensusPushFailure>),
    Received(AuthenticatedConsensusPushReceipt),
}

impl FixedValidatorRuntimeDeliveryStateV0 {
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Refused(_) | Self::Failed(_) | Self::Received(_))
    }
}

/// The sole pending or completed publication, including every original byte.
///
/// While pending, the runtime owns this value and every in-flight ticket. On
/// completion it transfers the whole value to the caller, including failed
/// attempts and the released proposal token. Taking custody is not a durable
/// outbox acknowledgement, and no outcome implies peer admission or finality.
#[must_use]
pub struct FixedValidatorRuntimePublicationV0 {
    pub(crate) message: FixedValidatorRuntimePublicationMessageV0,
    pub(crate) deliveries: [Option<FixedValidatorRuntimePeerDeliveryV0>; MAX_STATIC_PEERS],
    pub(crate) locally_admitted: bool,
}

impl FixedValidatorRuntimePublicationV0 {
    // Preserve an unrecognized command intact without allocating its error path.
    #[allow(clippy::result_large_err)]
    pub(crate) fn from_command(
        command: FixedValidatorNodeDriverCommandV0,
        peers: &[PeerId],
    ) -> Result<Self, FixedValidatorNodeDriverCommandV0> {
        let message = match command {
            FixedValidatorNodeDriverCommandV0::PublishProposal {
                proposal,
                canonical_artifact_bytes,
            } => FixedValidatorRuntimePublicationMessageV0::Proposal {
                proposal,
                canonical_artifact_bytes,
            },
            FixedValidatorNodeDriverCommandV0::PublishVote {
                vote,
                released_proposal,
            } => FixedValidatorRuntimePublicationMessageV0::Vote {
                vote,
                released_proposal,
            },
            other => return Err(other),
        };
        let deliveries = std::array::from_fn(|index| {
            peers
                .get(index)
                .map(|peer_id| FixedValidatorRuntimePeerDeliveryV0 {
                    peer_id: *peer_id,
                    state: FixedValidatorRuntimeDeliveryStateV0::NotAttempted,
                })
        });
        Ok(Self {
            message,
            deliveries,
            locally_admitted: false,
        })
    }

    pub const fn message(&self) -> &FixedValidatorRuntimePublicationMessageV0 {
        &self.message
    }

    pub fn deliveries(&self) -> impl Iterator<Item = &FixedValidatorRuntimePeerDeliveryV0> {
        self.deliveries.iter().flatten()
    }

    /// Whether ordinary local admission was attempted, including a rejection.
    pub const fn local_admission_attempted(&self) -> bool {
        self.locally_admitted
    }

    pub fn is_complete(&self) -> bool {
        self.locally_admitted
            && self
                .deliveries()
                .all(|delivery| delivery.state.is_terminal())
    }

    pub fn into_parts(
        self,
    ) -> (
        FixedValidatorRuntimePublicationMessageV0,
        [Option<FixedValidatorRuntimePeerDeliveryV0>; MAX_STATIC_PEERS],
    ) {
        (self.message, self.deliveries)
    }
}
