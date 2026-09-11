//! Binds codec clones to the Noise-authenticated peer before any frame is read.
//!
//! request_response clones its codec synchronously when constructing a handler.
//! The factory scope supplies that peer once; subsequent handler/stream clones
//! retain the immutable binding. An unbound codec refuses all decoding.
use super::*;
use libp2p::core::{Endpoint, transport::PortUse};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, THandler, THandlerInEvent, THandlerOutEvent,
    behaviour::{FromSwarm, ToSwarm},
};
use std::{
    ops::{Deref, DerefMut},
    sync::RwLock,
    task::{Context, Poll},
};

pub(super) struct DecodeLanes {
    pub admitted: RwLock<HashSet<PeerId>>,
    pub factory_peer: RwLock<Option<PeerId>>,
    pub validators: Arc<InboundRetentionBudget>,
    pub observers: Arc<InboundRetentionBudget>,
}
impl DecodeLanes {
    pub fn budget(&self, peer: PeerId) -> std::io::Result<Arc<InboundRetentionBudget>> {
        let admitted = self
            .admitted
            .read()
            .map_err(|_| std::io::Error::other("membership admission poisoned"))?;
        Ok(Arc::clone(if admitted.contains(&peer) {
            &self.validators
        } else {
            &self.observers
        }))
    }
}

pub(super) struct PeerExchange {
    inner: request_response::Behaviour<MembershipCodec>,
    lanes: Arc<DecodeLanes>,
}
impl PeerExchange {
    pub fn new(
        inner: request_response::Behaviour<MembershipCodec>,
        lanes: Arc<DecodeLanes>,
    ) -> Self {
        Self { inner, lanes }
    }
    fn bind(&self, peer: Option<PeerId>) -> Result<(), ConnectionDenied> {
        *self.lanes.factory_peer.write().map_err(|_| {
            ConnectionDenied::new(std::io::Error::other("membership codec factory poisoned"))
        })? = peer;
        Ok(())
    }
}
impl Deref for PeerExchange {
    type Target = request_response::Behaviour<MembershipCodec>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for PeerExchange {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl NetworkBehaviour for PeerExchange {
    type ConnectionHandler =
        <request_response::Behaviour<MembershipCodec> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <request_response::Behaviour<MembershipCodec> as NetworkBehaviour>::ToSwarm;
    fn handle_pending_inbound_connection(
        &mut self,
        id: ConnectionId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(id, local, remote)
    }
    fn handle_pending_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: Option<PeerId>,
        addresses: &[Multiaddr],
        role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner
            .handle_pending_outbound_connection(id, peer, addresses, role)
    }
    fn handle_established_inbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        local: &Multiaddr,
        remote: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.bind(Some(peer))?;
        let result = self
            .inner
            .handle_established_inbound_connection(id, peer, local, remote);
        self.bind(None)?;
        result
    }
    fn handle_established_outbound_connection(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        address: &Multiaddr,
        role: Endpoint,
        port: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.bind(Some(peer))?;
        let result = self
            .inner
            .handle_established_outbound_connection(id, peer, address, role, port);
        self.bind(None)?;
        result
    }
    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        self.inner.on_swarm_event(event);
    }
    fn on_connection_handler_event(
        &mut self,
        peer: PeerId,
        id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner.on_connection_handler_event(peer, id, event);
    }
    fn poll(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(context)
    }
}
