use std::error::Error;
use std::fmt;
use std::time::SystemTime;

use libp2p::{PeerId, identity::Keypair, noise};

use crate::address_store::{
    BootstrapPeer, DialCandidate, MAX_DIAL_CANDIDATES, PeerAddressStore, PeerAddressStoreError,
    PeerRecordBatchAdmission, compare_peer_id_bytes,
};
use crate::bootstrap::{
    AuthenticatedPeerRecordBatch, PeerRecordBootstrapClient, PeerRecordBootstrapEvent,
    PeerRecordPullFailure, PeerRecordPullStartError,
};

/// Outbound-only authenticated client for caller-selected learned-peer pulls.
///
/// The immutable inputs are opaque [`DialCandidate`] values previously
/// selected by a peer-address store. A cold pull dials only the candidate's
/// exact signed address and Noise-authenticates its self-certified peer
/// identity; a healthy connection may be reused only for that same candidate
/// identity. The client performs no automatic selection, retry, refresh,
/// redial, or publication, and a candidate grants no artifact or consensus
/// authority.
pub struct LearnedPeerRecordPullClient {
    inner: PeerRecordBootstrapClient,
    candidates: Vec<DialCandidate>,
}

impl LearnedPeerRecordPullClient {
    /// Builds one bounded outbound-only learned-peer client.
    ///
    /// Configuration rejects the ninth candidate before checking identities,
    /// then rejects the local identity, then the lowest duplicate identity.
    /// Accepted candidates are retained in canonical peer-identity order. This
    /// must run inside a Tokio runtime with I/O and time drivers enabled.
    pub fn new(
        identity: Keypair,
        candidates: impl IntoIterator<Item = DialCandidate>,
    ) -> Result<Self, LearnedPeerRecordPullBuildError> {
        let local_peer_id = identity.public().to_peer_id();
        let candidates = validate_candidates(local_peer_id, candidates)?;
        let endpoints = candidates
            .iter()
            .map(|candidate| {
                BootstrapPeer::new(candidate.peer_id(), candidate.address().clone())
                    .expect("store-produced dial candidates contain validated IP/TCP endpoints")
            })
            .collect();
        let inner = PeerRecordBootstrapClient::from_validated_bootstraps(identity, endpoints)
            .map_err(LearnedPeerRecordPullBuildError::Noise)?;
        Ok(Self { inner, candidates })
    }

    /// Returns this client's authenticated local identity.
    pub fn local_peer_id(&self) -> PeerId {
        self.inner.local_peer_id()
    }

    /// Returns the canonical immutable candidate configuration.
    pub fn candidates(&self) -> &[DialCandidate] {
        &self.candidates
    }

    /// Starts one bounded pull from an exact configured learned candidate.
    pub fn start_pull(&mut self, peer_id: PeerId) -> Result<(), LearnedPeerRecordPullStartError> {
        self.inner.start_pull(peer_id).map_err(|error| match error {
            PeerRecordPullStartError::UnknownBootstrap(peer_id) => {
                LearnedPeerRecordPullStartError::UnknownCandidate(peer_id)
            }
            PeerRecordPullStartError::AlreadyActiveOrRetained(peer_id) => {
                LearnedPeerRecordPullStartError::AlreadyActiveOrRetained(peer_id)
            }
        })
    }

    /// Waits for the next terminal learned-peer pull event.
    pub async fn next_event(&mut self) -> LearnedPeerRecordPullEvent {
        match self.inner.next_event().await {
            PeerRecordBootstrapEvent::Received(batch) => {
                let candidate = self
                    .candidate(batch.source_peer_id())
                    .expect("authenticated responses belong to configured candidates")
                    .clone();
                LearnedPeerRecordPullEvent::Received(AuthenticatedLearnedPeerRecordBatch {
                    candidate,
                    batch,
                })
            }
            PeerRecordBootstrapEvent::Failed {
                bootstrap_peer_id,
                error,
            } => {
                let candidate = self
                    .candidate(bootstrap_peer_id)
                    .expect("terminal failures belong to configured candidates")
                    .clone();
                LearnedPeerRecordPullEvent::Failed { candidate, error }
            }
        }
    }

    fn candidate(&self, peer_id: PeerId) -> Option<&DialCandidate> {
        self.candidates
            .binary_search_by(|candidate| compare_peer_id_bytes(&candidate.peer_id(), &peer_id))
            .ok()
            .map(|index| &self.candidates[index])
    }
}

fn validate_candidates(
    local_peer_id: PeerId,
    candidates: impl IntoIterator<Item = DialCandidate>,
) -> Result<Vec<DialCandidate>, LearnedPeerRecordPullBuildError> {
    let candidates = candidates.into_iter();
    let mut result = Vec::with_capacity(candidates.size_hint().0.min(MAX_DIAL_CANDIDATES));
    for candidate in candidates {
        if result.len() == MAX_DIAL_CANDIDATES {
            return Err(LearnedPeerRecordPullBuildError::TooManyCandidates {
                actual: result.len() + 1,
                maximum: MAX_DIAL_CANDIDATES,
            });
        }
        result.push(candidate);
    }
    result.sort_unstable_by(|left, right| compare_peer_id_bytes(&left.peer_id(), &right.peer_id()));
    if result
        .iter()
        .any(|candidate| candidate.peer_id() == local_peer_id)
    {
        return Err(LearnedPeerRecordPullBuildError::LocalCandidate(Box::new(
            local_peer_id,
        )));
    }
    if let Some(pair) = result
        .windows(2)
        .find(|pair| pair[0].peer_id() == pair[1].peer_id())
    {
        return Err(LearnedPeerRecordPullBuildError::DuplicateCandidate(
            Box::new(pair[0].peer_id()),
        ));
    }
    Ok(result)
}

/// One authenticated learned response bound to its exact candidate.
///
/// The response is intentionally neither cloneable nor convertible into a
/// bare batch. Its candidate slot remains occupied until consuming admission
/// or drop. Admission revalidates that the same peer, signed address,
/// configured-bootstrap provenance, and freshness at the caller-supplied
/// receipt time remain in the target store; it does not rerun candidate
/// ranking.
#[must_use]
pub struct AuthenticatedLearnedPeerRecordBatch {
    candidate: DialCandidate,
    batch: AuthenticatedPeerRecordBatch,
}

impl AuthenticatedLearnedPeerRecordBatch {
    /// Returns the exact candidate coupling the authenticated immediate peer
    /// to its configured-bootstrap provenance.
    pub const fn candidate(&self) -> &DialCandidate {
        &self.candidate
    }

    /// Returns the number of verified records in the batch.
    pub const fn record_count(&self) -> usize {
        self.batch.record_count()
    }

    /// Returns whether the learned responder supplied an empty batch.
    pub const fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// Revalidates the candidate and atomically admits the complete batch.
    pub fn admit_into(
        self,
        store: &mut PeerAddressStore,
        received_at: SystemTime,
    ) -> Result<PeerRecordBatchAdmission, PeerAddressStoreError> {
        let Self { candidate, batch } = self;
        batch.admit_learned_into(store, &candidate, received_at)
    }
}

impl fmt::Debug for AuthenticatedLearnedPeerRecordBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedLearnedPeerRecordBatch")
            .field("candidate", &self.candidate)
            .field("record_count", &self.batch.record_count())
            .finish_non_exhaustive()
    }
}

/// Failure to build one learned-peer pull client.
#[derive(Debug)]
#[non_exhaustive]
pub enum LearnedPeerRecordPullBuildError {
    /// The caller supplied more than the fixed candidate cap.
    TooManyCandidates { actual: usize, maximum: usize },
    /// One candidate is the client's own authenticated identity.
    LocalCandidate(Box<PeerId>),
    /// One candidate identity appeared more than once.
    DuplicateCandidate(Box<PeerId>),
    /// The Noise authentication configuration could not be built.
    Noise(noise::Error),
}

impl fmt::Display for LearnedPeerRecordPullBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyCandidates { actual, maximum } => write!(
                formatter,
                "learned peer-record pull has {actual} candidates; maximum is {maximum}"
            ),
            Self::LocalCandidate(peer_id) => write!(
                formatter,
                "learned peer-record candidate {peer_id} is the local identity"
            ),
            Self::DuplicateCandidate(peer_id) => write!(
                formatter,
                "learned peer-record candidate {peer_id} appears more than once"
            ),
            Self::Noise(source) => {
                write!(formatter, "cannot configure learned-peer Noise: {source}")
            }
        }
    }
}

impl Error for LearnedPeerRecordPullBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Noise(source) => Some(source),
            _ => None,
        }
    }
}

/// Failure to start one exact learned-peer pull.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LearnedPeerRecordPullStartError {
    /// The requested identity is not in this client's immutable candidates.
    UnknownCandidate(PeerId),
    /// This candidate already owns an active request or retained response.
    AlreadyActiveOrRetained(PeerId),
}

impl fmt::Display for LearnedPeerRecordPullStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCandidate(peer_id) => {
                write!(formatter, "peer {peer_id} is not a learned candidate")
            }
            Self::AlreadyActiveOrRetained(peer_id) => write!(
                formatter,
                "learned candidate {peer_id} already has an active or retained pull"
            ),
        }
    }
}

impl Error for LearnedPeerRecordPullStartError {}

/// One terminal event from the outbound-only learned-peer client.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum LearnedPeerRecordPullEvent {
    /// One verified response bound to its authenticated candidate and retained
    /// configured-bootstrap provenance.
    Received(AuthenticatedLearnedPeerRecordBatch),
    /// One exact candidate pull ended without a usable response.
    Failed {
        /// The complete candidate, including its immediate identity and
        /// configured-bootstrap provenance.
        candidate: DialCandidate,
        /// The typed terminal cause.
        error: Box<PeerRecordPullFailure>,
    },
}

#[cfg(test)]
mod tests;
