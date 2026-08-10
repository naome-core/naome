use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use libp2p::PeerId;
use libp2p::core::{Endpoint, Multiaddr, transport::PortUse};
use libp2p::swarm::behaviour::{FromSwarm, NetworkBehaviour, ToSwarm};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, THandler, THandlerInEvent, THandlerOutEvent, dummy,
};
use tokio::time::{Instant, Sleep, sleep_until};

#[cfg(test)]
use super::{DIAL_RETRY_BASE, DIAL_RETRY_MAX};
use super::{
    DIAL_RETRY_DELAYS, INBOUND_AUTH_BURST, INBOUND_AUTH_REFILL_INTERVAL, PeerSessionEvent,
    STABLE_SESSION_DURATION, StaticPeer,
};

pub(super) struct Behaviour {
    peers: Vec<PeerSession>,
    inbound_budget: InboundBudget,
    pending_events: VecDeque<PeerSessionEvent>,
    retry_timer: Option<Pin<Box<Sleep>>>,
}

impl Behaviour {
    pub(super) fn new(local_peer_id: PeerId, peers: impl IntoIterator<Item = StaticPeer>) -> Self {
        let now = Instant::now();
        let local_peer_bytes = local_peer_id.to_bytes();
        let mut peers = peers
            .into_iter()
            .map(|StaticPeer { peer_id, address }| {
                let owns_dial = owns_dial(&local_peer_bytes, peer_id);
                PeerSession {
                    peer_id,
                    address,
                    owns_dial,
                    failures: 0,
                    link: Link::Down {
                        retry_at: owns_dial.then_some(now),
                    },
                }
            })
            .collect::<Vec<_>>();
        peers.sort_unstable_by_key(|peer| peer.peer_id);
        Self {
            peers,
            inbound_budget: InboundBudget::new(now),
            pending_events: VecDeque::new(),
            retry_timer: None,
        }
    }

    pub(super) fn connection_status(&self, peer_id: &PeerId) -> Option<bool> {
        self.peer(peer_id)
            .map(|peer| matches!(peer.link, Link::Connected { .. }))
    }

    pub(super) fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub(super) fn peer_id_at(&self, index: usize) -> Option<PeerId> {
        self.peers.get(index).map(|peer| peer.peer_id)
    }

    pub(super) fn peer_index(&self, peer_id: &PeerId) -> Option<usize> {
        self.peers.iter().position(|peer| peer.peer_id == *peer_id)
    }

    fn peer(&self, peer_id: &PeerId) -> Option<&PeerSession> {
        self.peers.iter().find(|peer| peer.peer_id == *peer_id)
    }

    fn peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerSession> {
        self.peers.iter_mut().find(|peer| peer.peer_id == *peer_id)
    }

    fn due_peer(&self, now: Instant) -> Option<PeerId> {
        self.peers
            .iter()
            .filter_map(|peer| match peer.link {
                Link::Down {
                    retry_at: Some(retry_at),
                } if retry_at <= now => Some((peer.peer_id, retry_at)),
                _ => None,
            })
            .min_by_key(|(peer_id, retry_at)| (*retry_at, *peer_id))
            .map(|(peer_id, _)| peer_id)
    }

    fn earliest_retry(&self) -> Option<Instant> {
        self.peers
            .iter()
            .filter_map(|peer| match peer.link {
                Link::Down { retry_at } => retry_at,
                Link::Dialing { .. } | Link::Connected { .. } => None,
            })
            .min()
    }

    fn start_dial(&mut self, peer_id: PeerId) -> DialOpts {
        let peer = self.peer_mut(&peer_id).expect("a due peer is configured");
        debug_assert!(peer.owns_dial);
        debug_assert!(matches!(peer.link, Link::Down { .. }));
        let options = DialOpts::peer_id(peer_id)
            .condition(PeerCondition::DisconnectedAndNotDialing)
            .addresses(vec![peer.address.clone()])
            .build();
        peer.link = Link::Dialing {
            connection_id: options.connection_id(),
        };
        options
    }

    fn schedule_retry(&mut self, peer_id: PeerId, now: Instant, stable: bool) {
        let peer = self
            .peer_mut(&peer_id)
            .expect("only configured peers have managed sessions");
        if !peer.owns_dial {
            peer.link = Link::Down { retry_at: None };
            return;
        }
        if stable {
            peer.failures = 0;
        }
        peer.failures = peer.failures.saturating_add(1);
        let retry_at = now.checked_add(retry_delay(peer.failures));
        peer.link = Link::Down { retry_at };
        self.retry_timer = None;
    }

    fn record_established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        dialer: bool,
        now: Instant,
    ) -> bool {
        let Some(peer) = self.peer_mut(&peer_id) else {
            return false;
        };
        let correct_direction = if peer.owns_dial {
            dialer
                && matches!(
                    peer.link,
                    Link::Dialing { connection_id: expected } if expected == connection_id
                )
        } else {
            !dialer && matches!(peer.link, Link::Down { .. })
        };
        if !correct_direction {
            return false;
        }
        peer.link = Link::Connected {
            connection_id,
            connected_at: now,
        };
        self.retry_timer = None;
        true
    }

    fn record_closed(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        remaining_established: usize,
        now: Instant,
    ) -> bool {
        if remaining_established != 0 {
            return false;
        }
        let Some(peer) = self.peer(&peer_id) else {
            return false;
        };
        let Link::Connected {
            connection_id: expected,
            connected_at,
        } = peer.link
        else {
            return false;
        };
        if expected != connection_id {
            return false;
        }
        let stable = now.saturating_duration_since(connected_at) >= STABLE_SESSION_DURATION;
        self.schedule_retry(peer_id, now, stable);
        true
    }

    fn record_dial_failure(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        now: Instant,
    ) -> bool {
        let Some(peer) = self.peer(&peer_id) else {
            return false;
        };
        if !matches!(
            peer.link,
            Link::Dialing { connection_id: expected } if expected == connection_id
        ) {
            return false;
        }
        self.schedule_retry(peer_id, now, false);
        true
    }

    #[cfg(test)]
    pub(super) fn mark_connected_for_test(&mut self, peer_id: PeerId) {
        let peer = self.peer_mut(&peer_id).unwrap();
        peer.link = Link::Connected {
            connection_id: ConnectionId::new_unchecked(usize::MAX),
            connected_at: Instant::now(),
        };
    }

    #[cfg(test)]
    pub(super) fn mark_disconnected_for_test(&mut self, peer_id: PeerId) {
        assert!(self.record_closed(
            peer_id,
            ConnectionId::new_unchecked(usize::MAX),
            0,
            Instant::now(),
        ));
        self.pending_events
            .push_back(PeerSessionEvent::Disconnected { peer_id });
    }

    #[cfg(test)]
    pub(super) fn is_test_connected(&self, peer_id: &PeerId) -> bool {
        self.peer(peer_id).is_some_and(|peer| {
            matches!(
                peer.link,
                Link::Connected { connection_id, .. }
                    if connection_id == ConnectionId::new_unchecked(usize::MAX)
            )
        })
    }

    #[cfg(test)]
    pub(super) fn inbound_tokens_for_test(&self) -> u32 {
        self.inbound_budget.tokens
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = PeerSessionEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        if self.inbound_budget.try_take(Instant::now()) {
            Ok(())
        } else {
            Err(ConnectionDenied::new(SessionDenied::PreAuthenticationRate))
        }
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        let Some(peer_id) = maybe_peer else {
            return Err(ConnectionDenied::new(SessionDenied::UnmanagedDial));
        };
        let Some(peer) = self.peer(&peer_id) else {
            return Err(ConnectionDenied::new(SessionDenied::UnmanagedDial));
        };
        if !peer.owns_dial
            || !matches!(
                peer.link,
                Link::Dialing {
                    connection_id: expected,
                } if expected == connection_id
            )
        {
            return Err(ConnectionDenied::new(SessionDenied::UnmanagedDial));
        }
        Ok(Vec::new())
    }

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let Some(peer) = self.peer(&peer_id) else {
            return Err(ConnectionDenied::new(SessionDenied::UnknownPeer));
        };
        if peer.owns_dial || !matches!(peer.link, Link::Down { .. }) {
            return Err(ConnectionDenied::new(SessionDenied::WrongDirection));
        }
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        let Some(peer) = self.peer(&peer_id) else {
            return Err(ConnectionDenied::new(SessionDenied::UnknownPeer));
        };
        if !peer.owns_dial
            || !matches!(
                peer.link,
                Link::Dialing {
                    connection_id: expected,
                } if expected == connection_id
            )
        {
            return Err(ConnectionDenied::new(SessionDenied::WrongDirection));
        }
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionEstablished(established) => {
                if self.record_established(
                    established.peer_id,
                    established.connection_id,
                    established.endpoint.is_dialer(),
                    Instant::now(),
                ) {
                    self.pending_events
                        .push_back(PeerSessionEvent::Established {
                            peer_id: established.peer_id,
                        });
                }
            }
            FromSwarm::ConnectionClosed(closed) => {
                if self.record_closed(
                    closed.peer_id,
                    closed.connection_id,
                    closed.remaining_established,
                    Instant::now(),
                ) {
                    self.pending_events
                        .push_back(PeerSessionEvent::Disconnected {
                            peer_id: closed.peer_id,
                        });
                }
            }
            FromSwarm::DialFailure(failure) => {
                let Some(peer_id) = failure.peer_id else {
                    return;
                };
                if self.record_dial_failure(peer_id, failure.connection_id, Instant::now()) {
                    self.pending_events
                        .push_back(PeerSessionEvent::DialFailed { peer_id });
                }
            }
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            let now = Instant::now();
            if let Some(peer_id) = self.due_peer(now) {
                let options = self.start_dial(peer_id);
                self.retry_timer = None;
                return Poll::Ready(ToSwarm::Dial { opts: options });
            }

            if let Some(event) = self.pending_events.pop_front() {
                return Poll::Ready(ToSwarm::GenerateEvent(event));
            }

            let Some(retry_at) = self.earliest_retry() else {
                self.retry_timer = None;
                return Poll::Pending;
            };
            if self
                .retry_timer
                .as_ref()
                .is_none_or(|timer| timer.deadline() != retry_at)
            {
                self.retry_timer = Some(Box::pin(sleep_until(retry_at)));
            }
            let timer = self
                .retry_timer
                .as_mut()
                .expect("the earliest retry arms one timer");
            if timer.as_mut().poll(context).is_ready() {
                self.retry_timer = None;
                continue;
            }
            return Poll::Pending;
        }
    }
}

struct PeerSession {
    peer_id: PeerId,
    address: Multiaddr,
    owns_dial: bool,
    failures: u32,
    link: Link,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Link {
    Down {
        retry_at: Option<Instant>,
    },
    Dialing {
        connection_id: ConnectionId,
    },
    Connected {
        connection_id: ConnectionId,
        connected_at: Instant,
    },
}

fn owns_dial(local_peer_bytes: &[u8], remote_peer_id: PeerId) -> bool {
    local_peer_bytes < remote_peer_id.to_bytes().as_slice()
}

fn retry_delay(failures: u32) -> Duration {
    let index = usize::try_from(failures.saturating_sub(1)).unwrap_or(usize::MAX);
    DIAL_RETRY_DELAYS[index.min(DIAL_RETRY_DELAYS.len() - 1)]
}

struct InboundBudget {
    tokens: u32,
    last_refill: Instant,
}

impl InboundBudget {
    fn new(now: Instant) -> Self {
        Self {
            tokens: INBOUND_AUTH_BURST,
            last_refill: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let interval_nanos = INBOUND_AUTH_REFILL_INTERVAL.as_nanos();
        let intervals = elapsed.as_nanos() / interval_nanos;
        if intervals != 0 {
            let elapsed_intervals = u32::try_from(intervals).unwrap_or(u32::MAX);
            self.tokens = self
                .tokens
                .saturating_add(elapsed_intervals)
                .min(INBOUND_AUTH_BURST);
            if self.tokens == INBOUND_AUTH_BURST {
                self.last_refill = now;
            } else {
                self.last_refill += INBOUND_AUTH_REFILL_INTERVAL * elapsed_intervals;
            }
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[derive(Debug)]
enum SessionDenied {
    PreAuthenticationRate,
    UnknownPeer,
    WrongDirection,
    UnmanagedDial,
}

impl fmt::Display for SessionDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreAuthenticationRate => {
                formatter.write_str("pre-authentication connection rate exceeded")
            }
            Self::UnknownPeer => formatter.write_str("peer is not statically configured"),
            Self::WrongDirection => formatter.write_str("connection direction is not canonical"),
            Self::UnmanagedDial => formatter.write_str("outbound dial is not session-managed"),
        }
    }
}

impl Error for SessionDenied {}

#[cfg(test)]
mod tests;
