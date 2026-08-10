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
            let refill = u32::try_from(intervals).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(refill).min(INBOUND_AUTH_BURST);
            if self.tokens == INBOUND_AUTH_BURST {
                self.last_refill = now;
            } else {
                let elapsed_intervals = u32::try_from(intervals).unwrap_or(u32::MAX);
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
mod tests {
    use std::task::Waker;

    use super::*;

    fn address() -> Multiaddr {
        "/ip4/127.0.0.1/tcp/9".parse().unwrap()
    }

    fn ordered_peer_ids() -> (PeerId, PeerId) {
        let first = PeerId::random();
        let second = PeerId::random();
        if owns_dial(&first.to_bytes(), second) {
            (first, second)
        } else {
            (second, first)
        }
    }

    fn owner_behaviour() -> (Behaviour, PeerId) {
        let (owner, passive) = ordered_peer_ids();
        (
            Behaviour::new(owner, [StaticPeer::new(passive, address())]),
            passive,
        )
    }

    #[test]
    fn dial_ownership_is_antisymmetric() {
        for _ in 0..32 {
            let (lower, higher) = ordered_peer_ids();
            assert!(owns_dial(&lower.to_bytes(), higher));
            assert!(!owns_dial(&higher.to_bytes(), lower));
        }
    }

    #[test]
    fn configured_peer_indices_follow_raw_identity_order() {
        let local = PeerId::random();
        let mut hashed_bytes = vec![0x12, 0x20];
        hashed_bytes.extend_from_slice(&[0xa5; 32]);
        let hashed = PeerId::from_bytes(&hashed_bytes).unwrap();
        let mut expected = [PeerId::random(), hashed, PeerId::random()];
        assert!(!expected.contains(&local));
        expected.sort_unstable_by_key(|peer_id| peer_id.to_bytes());
        let configured = [expected[2], expected[0], expected[1]]
            .into_iter()
            .map(|peer_id| StaticPeer::new(peer_id, address()));

        let behaviour = Behaviour::new(local, configured);
        assert_eq!(behaviour.peer_count(), expected.len());
        for (index, peer_id) in expected.into_iter().enumerate() {
            assert_eq!(behaviour.peer_id_at(index), Some(peer_id));
            assert_eq!(behaviour.peer_index(&peer_id), Some(index));
        }
    }

    #[test]
    fn retry_delay_is_exponential_and_capped() {
        let seconds = (1..=9)
            .map(|failures| retry_delay(failures).as_secs())
            .collect::<Vec<_>>();
        assert_eq!(seconds, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(retry_delay(u32::MAX), DIAL_RETRY_MAX);

        let mut elapsed = Duration::ZERO;
        let attempt_seconds = (1..=8)
            .map(|failures| {
                elapsed += retry_delay(failures);
                elapsed.as_secs()
            })
            .collect::<Vec<_>>();
        assert_eq!(attempt_seconds, vec![1, 3, 7, 15, 31, 63, 123, 183]);
    }

    #[test]
    fn inbound_budget_enforces_burst_refill_and_cap() {
        let start = Instant::now();
        let mut budget = InboundBudget::new(start);
        for _ in 0..INBOUND_AUTH_BURST {
            assert!(budget.try_take(start));
        }
        assert!(!budget.try_take(start));
        assert!(!budget.try_take(start + INBOUND_AUTH_REFILL_INTERVAL / 2));
        assert!(budget.try_take(start + INBOUND_AUTH_REFILL_INTERVAL));
        assert!(!budget.try_take(start + INBOUND_AUTH_REFILL_INTERVAL));

        let later = start + Duration::from_secs(10_000);
        for _ in 0..INBOUND_AUTH_BURST {
            assert!(budget.try_take(later));
        }
        assert!(!budget.try_take(later));

        let mut full_after_idle = InboundBudget::new(start);
        for _ in 0..INBOUND_AUTH_BURST {
            assert!(full_after_idle.try_take(later));
        }
        assert!(!full_after_idle.try_take(later));

        let mut fractional = InboundBudget::new(start);
        for _ in 0..INBOUND_AUTH_BURST {
            assert!(fractional.try_take(start));
        }
        assert!(fractional.try_take(start + INBOUND_AUTH_REFILL_INTERVAL * 3 / 2));
        assert!(
            !fractional
                .try_take(start + INBOUND_AUTH_REFILL_INTERVAL * 2 - Duration::from_nanos(1))
        );
        assert!(fractional.try_take(start + INBOUND_AUTH_REFILL_INTERVAL * 2));
    }

    #[test]
    fn stale_generations_cannot_change_the_active_dial() {
        let (mut behaviour, peer_id) = owner_behaviour();
        let now = Instant::now();
        let first = behaviour.start_dial(peer_id).connection_id();
        let stale = ConnectionId::new_unchecked(usize::MAX);

        assert!(!behaviour.record_dial_failure(peer_id, stale, now));
        assert!(matches!(
            behaviour.peer(&peer_id).unwrap().link,
            Link::Dialing { connection_id } if connection_id == first
        ));
        assert!(behaviour.record_dial_failure(peer_id, first, now));
        assert_eq!(behaviour.peer(&peer_id).unwrap().failures, 1);
        assert_eq!(behaviour.due_peer(now), None);
        assert_eq!(behaviour.due_peer(now + DIAL_RETRY_BASE), Some(peer_id));

        let second = behaviour.start_dial(peer_id).connection_id();
        assert_ne!(first, second);
        assert!(!behaviour.record_dial_failure(peer_id, first, now + DIAL_RETRY_BASE));
        assert!(behaviour.record_established(peer_id, second, true, now + DIAL_RETRY_BASE));
        assert!(!behaviour.record_closed(peer_id, first, 0, now + DIAL_RETRY_BASE));
        assert!(matches!(
            behaviour.peer(&peer_id).unwrap().link,
            Link::Connected { connection_id, .. } if connection_id == second
        ));
        assert!(behaviour.record_closed(peer_id, second, 0, now + DIAL_RETRY_BASE));
    }

    #[test]
    fn only_an_exactly_stable_session_resets_backoff() {
        let (mut behaviour, peer_id) = owner_behaviour();
        let connected_at = Instant::now();
        let connection_id = ConnectionId::new_unchecked(101);
        {
            let peer = behaviour.peer_mut(&peer_id).unwrap();
            peer.failures = 4;
            peer.link = Link::Dialing { connection_id };
        }
        assert!(behaviour.record_established(peer_id, connection_id, true, connected_at));
        assert!(!behaviour.record_closed(
            peer_id,
            connection_id,
            1,
            connected_at + STABLE_SESSION_DURATION
        ));
        assert!(behaviour.record_closed(
            peer_id,
            connection_id,
            0,
            connected_at + STABLE_SESSION_DURATION - Duration::from_nanos(1)
        ));
        assert_eq!(behaviour.peer(&peer_id).unwrap().failures, 5);
        assert_eq!(
            behaviour.earliest_retry(),
            Some(
                connected_at + STABLE_SESSION_DURATION - Duration::from_nanos(1)
                    + Duration::from_secs(16)
            )
        );

        let stable_connection = ConnectionId::new_unchecked(102);
        behaviour.peer_mut(&peer_id).unwrap().link = Link::Dialing {
            connection_id: stable_connection,
        };
        let stable_since = connected_at + Duration::from_secs(120);
        assert!(behaviour.record_established(peer_id, stable_connection, true, stable_since));
        assert!(behaviour.record_closed(
            peer_id,
            stable_connection,
            0,
            stable_since + STABLE_SESSION_DURATION
        ));
        assert_eq!(behaviour.peer(&peer_id).unwrap().failures, 1);
        assert_eq!(
            behaviour.earliest_retry(),
            Some(stable_since + STABLE_SESSION_DURATION + DIAL_RETRY_BASE)
        );
    }

    #[test]
    fn canonical_direction_is_enforced_for_both_roles() {
        let (owner_id, passive_id) = ordered_peer_ids();
        let now = Instant::now();
        let connection_id = ConnectionId::new_unchecked(201);
        let mut owner = Behaviour::new(owner_id, [StaticPeer::new(passive_id, address())]);
        assert!(!owner.record_established(passive_id, connection_id, false, now));
        owner.peer_mut(&passive_id).unwrap().link = Link::Dialing { connection_id };
        assert!(owner.record_established(passive_id, connection_id, true, now));

        let mut passive = Behaviour::new(passive_id, [StaticPeer::new(owner_id, address())]);
        assert!(!passive.record_established(owner_id, connection_id, true, now));
        assert!(passive.record_established(owner_id, connection_id, false, now));
    }

    #[test]
    fn only_the_managed_owner_generation_can_open_an_outbound_connection() {
        let (owner_id, passive_id) = ordered_peer_ids();
        let mut owner = Behaviour::new(owner_id, [StaticPeer::new(passive_id, address())]);
        let unmanaged = ConnectionId::new_unchecked(301);
        assert!(
            NetworkBehaviour::handle_pending_outbound_connection(
                &mut owner,
                unmanaged,
                Some(passive_id),
                &[],
                Endpoint::Dialer,
            )
            .is_err()
        );
        let managed = owner.start_dial(passive_id).connection_id();
        assert!(
            NetworkBehaviour::handle_pending_outbound_connection(
                &mut owner,
                managed,
                Some(passive_id),
                &[],
                Endpoint::Dialer,
            )
            .is_ok()
        );

        let mut passive = Behaviour::new(passive_id, [StaticPeer::new(owner_id, address())]);
        assert!(
            NetworkBehaviour::handle_pending_outbound_connection(
                &mut passive,
                ConnectionId::new_unchecked(302),
                Some(owner_id),
                &[],
                Endpoint::Dialer,
            )
            .is_err()
        );
    }

    #[test]
    fn inbound_hook_rejects_the_ninth_pre_authentication_attempt() {
        let local = PeerId::random();
        let mut behaviour = Behaviour::new(local, []);
        let listen = address();
        let send = address();
        for index in 0..INBOUND_AUTH_BURST {
            assert!(
                NetworkBehaviour::handle_pending_inbound_connection(
                    &mut behaviour,
                    ConnectionId::new_unchecked(index as usize),
                    &listen,
                    &send,
                )
                .is_ok()
            );
        }
        assert!(
            NetworkBehaviour::handle_pending_inbound_connection(
                &mut behaviour,
                ConnectionId::new_unchecked(INBOUND_AUTH_BURST as usize),
                &listen,
                &send,
            )
            .is_err()
        );
    }

    #[test]
    fn a_due_retry_precedes_queued_observability_events() {
        let (mut behaviour, peer_id) = owner_behaviour();
        behaviour
            .pending_events
            .push_back(PeerSessionEvent::DialFailed { peer_id });
        behaviour.peer_mut(&peer_id).unwrap().link = Link::Down {
            retry_at: Some(Instant::now()),
        };
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert!(matches!(
            NetworkBehaviour::poll(&mut behaviour, &mut context),
            Poll::Ready(ToSwarm::Dial { .. })
        ));
        assert!(matches!(
            NetworkBehaviour::poll(&mut behaviour, &mut context),
            Poll::Ready(ToSwarm::GenerateEvent(PeerSessionEvent::DialFailed {
                peer_id: event_peer
            })) if event_peer == peer_id
        ));
    }
}
