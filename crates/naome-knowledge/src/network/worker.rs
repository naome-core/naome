//! One blocking state owner, with an independently polled bounded transport.
//! No mathematical state, proof checking or durable graph writes run while a
//! swarm lock is held. Overload rejects application requests or halts the node.
use super::*;
use libp2p::futures::Stream;
use std::{
    ops::{Deref, DerefMut},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, oneshot};

pub(super) struct OwnerThread {
    pub(super) thread: Option<std::thread::JoinHandle<()>>,
    pub(super) stop: Option<oneshot::Sender<()>>,
}
impl OwnerThread {
    pub(super) fn join(&mut self) -> Result<(), String> {
        self.stop.take();
        self.thread.take().map_or(Ok(()), |thread| {
            thread
                .join()
                .map_err(|_| "node state owner panicked".into())
        })
    }
}
impl Drop for OwnerThread {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub(super) struct OwnerActivity {
    busy: AtomicBool,
    started: Mutex<Instant>,
}
impl OwnerActivity {
    fn new() -> Self {
        Self {
            busy: AtomicBool::new(true),
            started: Mutex::new(Instant::now()),
        }
    }
    fn slow(&self) -> bool {
        if !self.busy.load(Ordering::Acquire) {
            return false;
        }
        let elapsed = self.started.lock().expect("owner activity lock").elapsed();
        self.busy.load(Ordering::Acquire)
            && elapsed >= crate::resources::limits().transport_busy_grace
    }
}

#[derive(Clone)]
pub(super) struct SharedSwarm {
    swarm: Arc<Mutex<Swarm<Behaviour>>>,
    changed: Arc<Notify>,
    pub(super) busy: Arc<OwnerActivity>,
    pub(super) epoch: Arc<AtomicU64>,
    grants: Arc<Mutex<PeerGrants>>,
}
#[derive(Default)]
struct PeerGrants {
    roots: BTreeMap<(PeerId, ProofId), std::sync::Weak<AtomicBool>>,
    requests: HashMap<request_response::OutboundRequestId, std::sync::Weak<AtomicBool>>,
}
impl PeerGrants {
    fn failed_request(&mut self, request: request_response::OutboundRequestId) {
        if let Some(lease) = self
            .requests
            .remove(&request)
            .and_then(|lease| lease.upgrade())
        {
            lease.store(false, Ordering::Release);
        }
    }
    fn revoke_peer(&mut self, peer: PeerId) {
        self.roots.retain(|(owner, _), lease| {
            if *owner == peer {
                if let Some(lease) = lease.upgrade() {
                    lease.store(false, Ordering::Release);
                }
                false
            } else {
                lease.strong_count() > 0
            }
        });
    }
}

pub(super) struct BehaviourGuard<'a> {
    swarm: MutexGuard<'a, Swarm<Behaviour>>,
    changed: &'a Notify,
}
impl Deref for BehaviourGuard<'_> {
    type Target = Behaviour;
    fn deref(&self) -> &Behaviour {
        self.swarm.behaviour()
    }
}
impl DerefMut for BehaviourGuard<'_> {
    fn deref_mut(&mut self) -> &mut Behaviour {
        self.swarm.behaviour_mut()
    }
}
impl Drop for BehaviourGuard<'_> {
    fn drop(&mut self) {
        self.changed.notify_one();
    }
}
impl SharedSwarm {
    pub(super) fn grant(&self, peer: PeerId, root: ProofId) -> crate::graph::PeerGrant {
        let mut grants = self.grants.lock().expect("peer grant lock");
        grants.roots.retain(|_, lease| lease.strong_count() > 0);
        if let Some(lease) = grants
            .roots
            .get(&(peer, root))
            .and_then(std::sync::Weak::upgrade)
        {
            return crate::graph::PeerGrant(lease);
        }
        let grant = crate::graph::PeerGrant::new();
        grants.roots.insert((peer, root), Arc::downgrade(&grant.0));
        grant
    }
    fn fresh_grant(&self, peer: PeerId, root: ProofId) -> crate::graph::PeerGrant {
        {
            let mut grants = self.grants.lock().expect("peer grant lock");
            if grants
                .roots
                .get(&(peer, root))
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|lease| !lease.load(Ordering::Acquire))
            {
                grants.roots.remove(&(peer, root));
            }
        }
        self.grant(peer, root)
    }
    pub(super) fn request_granted(
        &self,
        peer: PeerId,
        frame: Frame,
        grant: crate::graph::PeerGrant,
    ) -> request_response::OutboundRequestId {
        self.with(|swarm| {
            let request = swarm.behaviour_mut().exchange.send_request(&peer, frame);
            self.grants
                .lock()
                .expect("peer grant lock")
                .requests
                .insert(request, Arc::downgrade(&grant.0));
            request
        })
    }
    pub(super) fn behaviour_mut(&self) -> BehaviourGuard<'_> {
        BehaviourGuard {
            swarm: self.swarm.lock().expect("transport lock"),
            changed: &self.changed,
        }
    }
    fn with<T>(&self, action: impl FnOnce(&mut Swarm<Behaviour>) -> T) -> T {
        let result = action(&mut self.swarm.lock().expect("transport lock"));
        self.changed.notify_one();
        result
    }
    pub(super) fn connected_peers(&self) -> std::vec::IntoIter<PeerId> {
        self.with(|swarm| swarm.connected_peers().copied().collect::<Vec<_>>())
            .into_iter()
    }
    pub(super) fn is_connected(&self, peer: &PeerId) -> bool {
        self.with(|swarm| swarm.is_connected(peer))
    }
    pub(super) fn disconnect_peer_id(&self, peer: PeerId) -> Result<(), ()> {
        self.with(|swarm| swarm.disconnect_peer_id(peer))
    }
    pub(super) fn close_connection(&self, id: ConnectionId) -> bool {
        self.with(|swarm| swarm.close_connection(id))
    }
    pub(super) fn remove_listener(&self, id: libp2p::core::transport::ListenerId) -> bool {
        self.with(|swarm| swarm.remove_listener(id))
    }
    pub(super) fn listen_on(
        &self,
        address: Multiaddr,
    ) -> Result<libp2p::core::transport::ListenerId, libp2p::TransportError<std::io::Error>> {
        self.with(|swarm| swarm.listen_on(address))
    }
    pub(super) fn dial(
        &self,
        options: libp2p::swarm::dial_opts::DialOpts,
    ) -> Result<(), libp2p::swarm::DialError> {
        self.with(|swarm| swarm.dial(options))
    }
}

pub(super) struct TransportEvent {
    pub(super) event: SwarmEvent<BehaviourEvent>,
    pub(super) epoch: u64,
    pub(super) grant: Option<crate::graph::PeerGrant>,
}

pub(super) struct Transport {
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}
impl Transport {
    pub(super) fn spawn(
        swarm: Swarm<Behaviour>,
        primary_listener: libp2p::core::transport::ListenerId,
    ) -> (SharedSwarm, mpsc::Receiver<TransportEvent>, Self) {
        let shared = SharedSwarm {
            swarm: Arc::new(Mutex::new(swarm)),
            changed: Arc::new(Notify::new()),
            busy: Arc::new(OwnerActivity::new()),
            epoch: Arc::new(AtomicU64::new(0)),
            grants: Arc::new(Mutex::new(PeerGrants::default())),
        };
        let (send, events) = mpsc::channel(crate::resources::limits().transport_events);
        let (stop, mut halted) = oneshot::channel();
        let driver = shared.clone();
        let lifetime = TransportLifetime(driver.epoch.clone());
        let task = tokio::spawn(async move {
            let _lifetime = lifetime;
            loop {
                let event = tokio::select! {
                    _ = &mut halted => return Ok(()),
                    _ = driver.changed.notified() => continue,
                    event = std::future::poll_fn(|cx| {
                        std::pin::Pin::new(&mut *driver.swarm.lock().expect("transport lock")).poll_next(cx)
                    }) => event.ok_or("proof transport ended")?,
                };
                let revokes = matches!(&event, SwarmEvent::ListenerClosed { listener_id, .. } if *listener_id == primary_listener);
                {
                    let mut grants = driver.grants.lock().expect("peer grant lock");
                    match &event {
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            num_established: 0,
                            ..
                        } => grants.revoke_peer(*peer_id),
                        SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                            request_response::Event::OutboundFailure { request_id, .. },
                        )) => {
                            grants.failed_request(*request_id);
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                            request_response::Event::Message {
                                message: request_response::Message::Response { request_id, .. },
                                ..
                            },
                        )) => {
                            grants.requests.remove(request_id);
                        }
                        _ => {}
                    }
                }
                let incompatible = if let SwarmEvent::Behaviour(BehaviourEvent::Discovery(
                    discovery::BehaviourEvent::Identify(libp2p::identify::Event::Received {
                        peer_id,
                        info,
                        ..
                    }),
                )) = &event
                {
                    let swarm = driver.swarm.lock().expect("transport lock");
                    let book = swarm.behaviour().gate.0.lock();
                    discovery::identified_kind(*peer_id, info, false, &book.relays).is_none()
                } else {
                    false
                };
                if incompatible
                    && let SwarmEvent::Behaviour(BehaviourEvent::Discovery(
                        discovery::BehaviourEvent::Identify(libp2p::identify::Event::Received {
                            peer_id,
                            ..
                        }),
                    )) = &event
                {
                    driver
                        .grants
                        .lock()
                        .expect("peer grant lock")
                        .revoke_peer(*peer_id);
                }
                if revokes {
                    driver
                        .epoch
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                            epoch.checked_add(1).filter(|next| *next != u64::MAX)
                        })
                        .map_err(|_| "transport epoch exhausted")?;
                }
                // Do not let slow checking retain unlimited inbound channels.
                // Busy is a retryable protocol error; transport keeps progressing.
                // Metadata offers fit the same bounded handoff and may wait
                // for the owner. Refusing every one-shot hint while checking
                // would lose work even when queue capacity remains available.
                let queued_offer = matches!(&event, SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                    request_response::Event::Message { message: request_response::Message::Request { request, .. }, .. }
                )) if matches!(&request.message.body, Body::Offer { .. }));
                if driver.busy.slow()
                    && !queued_offer
                    && let SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                        request_response::Event::Message {
                            message: request_response::Message::Request { channel, .. },
                            ..
                        },
                    )) = event
                {
                    let _ = driver.behaviour_mut().exchange.send_response(
                        channel,
                        Frame::new(Body::Error {
                            reason: "node state owner busy".into(),
                        }),
                    );
                    continue;
                }
                // Capture authority before queuing. A later disconnect/failure
                // revokes this exact lease even while the owner is checking.
                let grant = match &event {
                    SwarmEvent::Behaviour(BehaviourEvent::Exchange(
                        request_response::Event::Message { peer, message, .. },
                    )) => {
                        let body = match message {
                            request_response::Message::Request { request, .. } => {
                                &request.message.body
                            }
                            request_response::Message::Response { response, .. } => {
                                &response.message.body
                            }
                        };
                        match body {
                            Body::Offer { metadata } | Body::Description { metadata } => {
                                crate::object::id_bytes(&metadata.proof_id)
                                    .ok()
                                    .map(|id| driver.fresh_grant(*peer, ProofId::from_bytes(id)))
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                let epoch = driver.epoch.load(Ordering::Acquire);
                send.try_send(TransportEvent {
                    event,
                    epoch,
                    grant,
                })
                .map_err(|_| "bounded transport event queue exhausted")?;
            }
        });
        (
            shared,
            events,
            Self {
                stop: Some(stop),
                task: Some(task),
            },
        )
    }
    pub(super) async fn shutdown(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.task.take() {
            Some(task) => task
                .await
                .map_err(|e| format!("transport task failed: {e}"))?,
            None => Ok(()),
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// Mark every actual poll, including a future that performs synchronous work
// before returning Pending. Waiting for a policy/provider does not stay busy.
pub(super) async fn while_polled<T>(
    busy: Arc<OwnerActivity>,
    future: impl std::future::Future<Output = T>,
) -> T {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(move |cx| {
        struct Clear<'a>(&'a OwnerActivity);
        impl Drop for Clear<'_> {
            fn drop(&mut self) {
                self.0.busy.store(false, Ordering::Release);
            }
        }
        *busy.started.lock().expect("owner activity lock") = Instant::now();
        busy.busy.store(true, Ordering::Release);
        let _clear = Clear(&busy);
        future.as_mut().poll(cx)
    })
    .await
}

// Queue overflow, task errors, cancellation and normal shutdown all revoke
// authority, even when the owner is still inside a slow checker or commit.
struct TransportLifetime(Arc<AtomicU64>);
impl Drop for TransportLifetime {
    fn drop(&mut self) {
        // MAX is terminal and can never authorize a subsequently built guard.
        self.0.store(u64::MAX, Ordering::Release);
    }
}

#[derive(Default)]
pub(super) struct PublishedStatus {
    pub(super) count: AtomicUsize,
    pub(super) ready: AtomicBool,
}

pub(super) struct Controls {
    stop: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}
impl Controls {
    pub(super) fn spawn(
        control: Option<Arc<crate::runtime::Control>>,
        status: Arc<PublishedStatus>,
    ) -> Self {
        let (stop, mut halt) = oneshot::channel();
        let task = tokio::spawn(async move {
            let Some(control) = control else {
                return Ok(());
            };
            let mut pending = libp2p::futures::stream::FuturesUnordered::new();
            let mut stopping = false;
            let mut stop_watch = Some(control.stop_watch());
            let mut deadline = None;
            loop {
                if stopping && pending.is_empty() {
                    return Ok(());
                }
                tokio::select! {
                    _ = &mut halt, if !stopping => {
                        stopping = true; deadline = Some(tokio::time::Instant::now() + crate::resources::limits().control_timeout);
                    },
                    _ = crate::runtime::requested_stop(&mut stop_watch), if !stopping => {
                        stopping = true; deadline = Some(tokio::time::Instant::now() + crate::resources::limits().control_timeout);
                    },
                    _ = async {
                        match deadline { Some(until) => tokio::time::sleep_until(until).await,
                            None => std::future::pending().await }
                    }, if stopping => return Ok(()),
                    stream = control.accept(), if !stopping && pending.len() < crate::resources::limits().control_clients => {
                        let stream = stream?;
                        let control = control.clone();
                        let count = status.count.load(Ordering::Acquire);
                        let ready = status.ready.load(Ordering::Acquire);
                        pending.push(async move { control.respond(stream, count, ready).await });
                    },
                    response = pending.next(), if !pending.is_empty() => {
                        if let Some(Err(error)) = response { emit(json!({"event":"control_rejected", "error":error})); }
                    },
                }
            }
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }
    pub(super) async fn shutdown(&mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.task.take() {
            Some(task) => task
                .await
                .map_err(|e| format!("control task failed: {e}"))?,
            None => Ok(()),
        }
    }
}
impl Drop for Controls {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_and_request_revocation_leave_unrelated_roots_and_node_lifetime_valid() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let root_a = crate::graph::PeerGrant::new();
        let root_b = crate::graph::PeerGrant::new();
        let mut grants = PeerGrants::default();
        grants.roots.insert(
            (peer_a, ProofId::from_bytes([1; 32])),
            Arc::downgrade(&root_a.0),
        );
        grants.roots.insert(
            (peer_b, ProofId::from_bytes([2; 32])),
            Arc::downgrade(&root_b.0),
        );
        let lifetime = Arc::new(AtomicU64::new(0));
        let local = crate::graph::CommitGuard::new(lifetime.clone(), 0, None, None);
        grants.revoke_peer(peer_b);
        assert!(root_a.check().is_ok());
        assert_eq!(root_b.check().unwrap_err(), crate::Error::StaleAuthority);
        assert!(local.check().is_ok());
        let mut exchange = request_response::Behaviour::with_codec(
            Codec::default(),
            [(PROTOCOL, request_response::ProtocolSupport::Full)],
            request_response::Config::default(),
        );
        let request = exchange.send_request(&peer_a, Frame::new(Body::Missing));
        grants.requests.insert(request, Arc::downgrade(&root_a.0));
        grants.failed_request(request);
        assert_eq!(root_a.check().unwrap_err(), crate::Error::StaleAuthority);
        assert!(local.check().is_ok());
    }
}
