use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime};

use libp2p::futures::StreamExt;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{
    PeerId, Swarm, SwarmBuilder, connection_limits, identity::Keypair, noise, request_response, tcp,
};

use crate::address_store::{
    BootstrapConfigError, BootstrapPeer, MAX_BOOTSTRAP_PEERS, PeerAddressStore,
    PeerAddressStoreError, PeerRecordBatchAdmission, validate_bootstraps,
};
use crate::codec::{PEER_RECORD_PROTOCOL, PeerRecordCodec};
use crate::record_exchange::{PeerRecordBatch, PeerRecordPullRequest};
use crate::{CONNECTION_TIMEOUT, MAX_CONNECTIONS_PER_PEER, REQUEST_TIMEOUT, yamux_config};

const MAX_BOOTSTRAP_STREAMS_PER_CONNECTION: usize = 1;
const BOOTSTRAP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(NetworkBehaviour)]
struct Behaviour {
    limits: connection_limits::Behaviour,
    exchange: request_response::Behaviour<PeerRecordCodec>,
}

struct PendingPull {
    request_id: request_response::OutboundRequestId,
    permit: SourcePermit,
}

/// Outbound-only authenticated client for configured bootstrap record pulls.
///
/// The client owns no listener and advertises no inbound protocol. One pull
/// may be active or retained per configured bootstrap. Healthy authenticated
/// connections may be reused until their explicit finite idle timeout; the
/// client performs no automatic retry, keepalive, or managed redial.
pub struct PeerRecordBootstrapClient {
    swarm: Swarm<Behaviour>,
    bootstraps: Vec<BootstrapPeer>,
    pending: Vec<PendingPull>,
    source_slots: Arc<SourceSlots>,
}

impl PeerRecordBootstrapClient {
    /// Builds one bounded outbound-only bootstrap client.
    ///
    /// This must run inside a Tokio runtime with I/O and time drivers enabled.
    pub fn new(
        identity: Keypair,
        bootstraps: impl IntoIterator<Item = BootstrapPeer>,
    ) -> Result<Self, PeerRecordBootstrapBuildError> {
        let local_peer_id = identity.public().to_peer_id();
        let bootstraps = validate_bootstraps(local_peer_id, bootstraps)
            .map_err(PeerRecordBootstrapBuildError::BootstrapConfig)?;

        let maximum = u32::try_from(MAX_BOOTSTRAP_PEERS).expect("the bootstrap-peer cap fits u32");
        let limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(0))
                .with_max_pending_outgoing(Some(maximum))
                .with_max_established_incoming(Some(0))
                .with_max_established_outgoing(Some(maximum))
                .with_max_established(Some(maximum))
                .with_max_established_per_peer(Some(MAX_CONNECTIONS_PER_PEER)),
        );
        let exchange = request_response::Behaviour::with_codec(
            PeerRecordCodec,
            [(
                PEER_RECORD_PROTOCOL,
                request_response::ProtocolSupport::Outbound,
            )],
            request_response::Config::default()
                .with_request_timeout(REQUEST_TIMEOUT)
                .with_max_concurrent_streams(MAX_BOOTSTRAP_STREAMS_PER_CONNECTION),
        );
        let behaviour = Behaviour { limits, exchange };
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_tcp(tcp::Config::new(), noise::Config::new, || {
                yamux_config(MAX_BOOTSTRAP_STREAMS_PER_CONNECTION)
            })
            .map_err(PeerRecordBootstrapBuildError::Noise)?
            .with_behaviour(|_| behaviour)
            .expect("constructing the fixed bootstrap-client behavior is infallible")
            .with_swarm_config(|config| {
                config
                    .with_idle_connection_timeout(BOOTSTRAP_IDLE_TIMEOUT)
                    .with_max_negotiating_inbound_streams(0)
            })
            .with_connection_timeout(CONNECTION_TIMEOUT)
            .build();

        let pending = Vec::with_capacity(bootstraps.len());
        Ok(Self {
            swarm,
            bootstraps,
            pending,
            source_slots: Arc::new(SourceSlots::default()),
        })
    }

    /// Returns this client's authenticated local identity.
    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Returns the canonical immutable bootstrap configuration.
    pub fn bootstrap_peers(&self) -> &[BootstrapPeer] {
        &self.bootstraps
    }

    /// Starts one bounded pull from an exact configured bootstrap endpoint.
    pub fn start_pull(&mut self, peer_id: PeerId) -> Result<(), PeerRecordPullStartError> {
        let Some(source_index) = self
            .bootstraps
            .iter()
            .position(|bootstrap| bootstrap.peer_id() == peer_id)
        else {
            return Err(PeerRecordPullStartError::UnknownBootstrap(peer_id));
        };
        let permit = SourceSlots::try_acquire(
            &self.source_slots,
            u8::try_from(source_index).expect("the bootstrap index fits u8"),
        )
        .ok_or(PeerRecordPullStartError::AlreadyActiveOrRetained(peer_id))?;
        let connected = self.swarm.behaviour().exchange.is_connected(&peer_id);
        let request_id = if connected {
            self.swarm
                .behaviour_mut()
                .exchange
                .send_request(&peer_id, PeerRecordPullRequest)
        } else {
            let address = self.bootstraps[source_index].address().clone();
            self.swarm
                .behaviour_mut()
                .exchange
                .send_request_with_addresses(&peer_id, PeerRecordPullRequest, vec![address])
        };
        self.pending.push(PendingPull { request_id, permit });
        Ok(())
    }

    /// Waits for the next terminal bootstrap-pull event.
    pub async fn next_event(&mut self) -> PeerRecordBootstrapEvent {
        loop {
            let SwarmEvent::Behaviour(BehaviourEvent::Exchange(event)) =
                self.swarm.select_next_some().await
            else {
                continue;
            };
            if let Some(event) = self.handle_exchange_event(event) {
                return event;
            }
        }
    }

    fn handle_exchange_event(
        &mut self,
        event: request_response::Event<PeerRecordPullRequest, PeerRecordBatch>,
    ) -> Option<PeerRecordBootstrapEvent> {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                let pending = self.take_pending(request_id)?;
                let expected = self.bootstraps[pending.permit.source_index()].peer_id();
                if expected != peer {
                    return Some(PeerRecordBootstrapEvent::Failed {
                        bootstrap_peer_id: expected,
                        error: Box::new(PeerRecordPullFailure::PeerMismatch {
                            expected,
                            actual: peer,
                        }),
                    });
                }
                Some(PeerRecordBootstrapEvent::Received(
                    AuthenticatedPeerRecordBatch {
                        source_peer_id: peer,
                        batch: response,
                        permit: pending.permit,
                    },
                ))
            }
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                let pending = self.take_pending(request_id)?;
                let expected = self.bootstraps[pending.permit.source_index()].peer_id();
                let error = if expected == peer {
                    PeerRecordPullFailure::Transport(error)
                } else {
                    PeerRecordPullFailure::PeerMismatch {
                        expected,
                        actual: peer,
                    }
                };
                Some(PeerRecordBootstrapEvent::Failed {
                    bootstrap_peer_id: expected,
                    error: Box::new(error),
                })
            }
            request_response::Event::Message {
                message: request_response::Message::Request { .. },
                ..
            }
            | request_response::Event::InboundFailure { .. }
            | request_response::Event::ResponseSent { .. } => None,
        }
    }

    fn take_pending(
        &mut self,
        request_id: request_response::OutboundRequestId,
    ) -> Option<PendingPull> {
        let index = self
            .pending
            .iter()
            .position(|pending| pending.request_id == request_id)?;
        Some(self.pending.swap_remove(index))
    }

    #[cfg(test)]
    fn active_source_count(&self) -> u32 {
        self.source_slots
            .occupied
            .load(Ordering::Relaxed)
            .count_ones()
    }
}

/// One verified batch permanently bound to its Noise-authenticated source.
///
/// The value is intentionally neither cloneable nor convertible back into a
/// bare batch. Its source slot remains occupied until admission or drop.
#[must_use]
pub struct AuthenticatedPeerRecordBatch {
    source_peer_id: PeerId,
    batch: PeerRecordBatch,
    permit: SourcePermit,
}

impl AuthenticatedPeerRecordBatch {
    /// Returns the authenticated bootstrap that supplied the batch.
    pub const fn source_peer_id(&self) -> PeerId {
        self.source_peer_id
    }

    /// Returns the number of verified records in the batch.
    pub const fn record_count(&self) -> usize {
        self.batch.len()
    }

    /// Returns whether the bootstrap supplied an empty batch.
    pub const fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }

    /// Atomically admits this batch under its authenticated source identity.
    pub fn admit_into(
        self,
        store: &mut PeerAddressStore,
        received_at: SystemTime,
    ) -> Result<PeerRecordBatchAdmission, PeerAddressStoreError> {
        let Self {
            source_peer_id,
            batch,
            permit,
        } = self;
        let result = store.admit_record_batch(source_peer_id, batch, received_at);
        drop(permit);
        result
    }
}

impl fmt::Debug for AuthenticatedPeerRecordBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedPeerRecordBatch")
            .field("source_peer_id", &self.source_peer_id)
            .field("record_count", &self.batch.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct SourceSlots {
    occupied: AtomicU8,
}

impl SourceSlots {
    fn try_acquire(slots: &Arc<Self>, source_index: u8) -> Option<SourcePermit> {
        let mask = 1_u8
            .checked_shl(u32::from(source_index))
            .expect("the validated bootstrap index fits the source bitset");
        slots
            .occupied
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |occupied| {
                (occupied & mask == 0).then_some(occupied | mask)
            })
            .ok()?;
        Some(SourcePermit {
            slots: Arc::clone(slots),
            mask,
        })
    }
}

struct SourcePermit {
    slots: Arc<SourceSlots>,
    mask: u8,
}

impl SourcePermit {
    fn source_index(&self) -> usize {
        debug_assert_eq!(self.mask.count_ones(), 1);
        usize::try_from(self.mask.trailing_zeros()).expect("the source bit index fits usize")
    }
}

impl Drop for SourcePermit {
    fn drop(&mut self) {
        let previous = self.slots.occupied.fetch_and(!self.mask, Ordering::Relaxed);
        debug_assert_ne!(previous & self.mask, 0);
    }
}

/// Failure to build one bootstrap client.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordBootstrapBuildError {
    /// The local identity or configured bootstrap set was invalid.
    BootstrapConfig(BootstrapConfigError),
    /// The Noise authentication configuration could not be built.
    Noise(noise::Error),
}

impl fmt::Display for PeerRecordBootstrapBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootstrapConfig(source) => {
                write!(formatter, "invalid bootstrap config: {source}")
            }
            Self::Noise(source) => write!(formatter, "cannot configure bootstrap Noise: {source}"),
        }
    }
}

impl Error for PeerRecordBootstrapBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BootstrapConfig(source) => Some(source),
            Self::Noise(source) => Some(source),
        }
    }
}

/// Failure to start one exact bootstrap pull.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PeerRecordPullStartError {
    /// The requested identity is not in this client's immutable configuration.
    UnknownBootstrap(PeerId),
    /// This source already owns an active request or retained response.
    AlreadyActiveOrRetained(PeerId),
}

impl fmt::Display for PeerRecordPullStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBootstrap(peer_id) => {
                write!(formatter, "peer {peer_id} is not a configured bootstrap")
            }
            Self::AlreadyActiveOrRetained(peer_id) => write!(
                formatter,
                "bootstrap {peer_id} already has an active or retained pull"
            ),
        }
    }
}

impl Error for PeerRecordPullStartError {}

/// A terminal failure for one exact bootstrap pull.
#[derive(Debug)]
#[non_exhaustive]
pub enum PeerRecordPullFailure {
    /// The exact request ended in a libp2p transport failure.
    Transport(request_response::OutboundFailure),
    /// The terminal event's authenticated peer differed from the configured source.
    PeerMismatch {
        /// The operator-configured bootstrap identity.
        expected: PeerId,
        /// The authenticated identity carried by the terminal event.
        actual: PeerId,
    },
}

impl fmt::Display for PeerRecordPullFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(source) => write!(formatter, "peer-record pull failed: {source}"),
            Self::PeerMismatch { expected, actual } => write!(
                formatter,
                "peer-record terminal event came from {actual}, expected {expected}"
            ),
        }
    }
}

impl Error for PeerRecordPullFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(source) => Some(source),
            Self::PeerMismatch { .. } => None,
        }
    }
}

/// One terminal event from the outbound-only bootstrap client.
#[derive(Debug)]
#[must_use]
#[non_exhaustive]
pub enum PeerRecordBootstrapEvent {
    /// One verified response bound to its authenticated bootstrap source.
    Received(AuthenticatedPeerRecordBatch),
    /// One exact pull ended without a usable response.
    Failed {
        /// The configured bootstrap whose pull terminated.
        bootstrap_peer_id: PeerId,
        /// The typed terminal cause.
        error: Box<PeerRecordPullFailure>,
    },
}

#[cfg(test)]
mod tests;
