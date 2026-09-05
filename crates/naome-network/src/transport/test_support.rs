//! Test-only observations and synthetic terminals; live transport ownership stays private.
use super::*;
use libp2p::request_response::{Event, Message, OutboundRequestId};
use naome_protocol::{
    block_exchange::ArtifactBlockRequest,
    chain_head_announcement::ArtifactChainHeadAnnouncement,
    chain_head_exchange::{ArtifactChainHeadRequest, ArtifactChainHeadResponse},
};

impl StaticArtifactNetwork {
    pub(crate) fn pending_count_for_test(&self) -> usize {
        self.pending.len()
    }
    pub(crate) fn active_permit_count_for_test(&self) -> usize {
        self.pending_budget.active.load(Ordering::Relaxed)
    }
    pub(crate) fn has_pending_block_for_test(&self) -> bool {
        self.pending
            .keys()
            .any(|key| matches!(key, ExchangeRequestId::Block(_)))
    }
    pub(crate) fn has_pending_artifact_for_test(&self) -> bool {
        self.pending
            .keys()
            .any(|key| matches!(key, ExchangeRequestId::Artifact(_)))
    }
    pub(crate) fn remove_pending_block_for_test(&mut self, id: OutboundRequestId) -> bool {
        self.pending.remove(&ExchangeRequestId::Block(id)).is_some()
    }
    pub(crate) fn mark_connected_for_test(&mut self, peer: PeerId) {
        self.swarm
            .behaviour_mut()
            .sessions
            .mark_connected_for_test(peer);
    }
    pub(crate) fn mark_disconnected_for_test(&mut self, peer: PeerId) {
        self.swarm
            .behaviour_mut()
            .sessions
            .mark_disconnected_for_test(peer);
    }
    pub(crate) fn hold_pending_permits_for_test(&self, count: usize) -> Vec<PendingPermit> {
        (0..count)
            .map(|_| PendingBudget::try_acquire(&self.pending_budget).unwrap())
            .collect()
    }
    pub(crate) fn application_tokens_for_test(&self) -> u32 {
        self.inbound_application_request_budget.tokens()
    }
    pub(crate) fn exhaust_application_budget_for_test(&mut self, now: Instant) {
        self.inbound_application_request_budget.exhaust(now);
    }
    pub(crate) fn handle_artifact_exchange_event_for_test(
        &mut self,
        event: Event<ArtifactRequest, ArtifactResponse>,
    ) -> Option<NetworkEvent> {
        self.handle_artifact_exchange_event(event)
    }
    pub(crate) fn handle_head_exchange_event_for_test(
        &mut self,
        event: Event<ArtifactChainHeadRequest, ArtifactChainHeadResponse>,
    ) -> Option<NetworkEvent> {
        self.handle_head_exchange_event(event)
    }
}
impl StaticArtifactNetwork {
    pub(crate) fn pending_block_for_peer_for_test(
        &self,
        peer: PeerId,
    ) -> Option<(OutboundRequestId, ArtifactBlockRequest)> {
        self.pending
            .iter()
            .find_map(|(id, pending)| match (id, pending) {
                (ExchangeRequestId::Block(id), PendingRequest::Block(pending))
                    if self.pending_peer_id(pending.peer_index) == peer =>
                {
                    Some((*id, pending.request))
                }
                _ => None,
            })
    }
}
impl StaticArtifactNetwork {
    pub(crate) fn pending_artifact_for_peer_for_test(
        &self,
        peer: PeerId,
    ) -> Option<(OutboundRequestId, ArtifactRequest)> {
        self.pending
            .iter()
            .find_map(|(id, pending)| match (id, pending) {
                (ExchangeRequestId::Artifact(id), PendingRequest::Artifact(pending))
                    if self.pending_peer_id(pending.peer_index) == peer =>
                {
                    Some((*id, pending.request))
                }
                _ => None,
            })
    }
}
impl StaticArtifactNetwork {
    pub(crate) fn pending_head_for_peer_for_test(
        &self,
        peer: PeerId,
    ) -> Option<(OutboundRequestId, ArtifactChainHeadRequest)> {
        self.pending
            .iter()
            .find_map(|(id, pending)| match (id, pending) {
                (ExchangeRequestId::Head(id), PendingRequest::Head(pending))
                    if self.pending_peer_id(pending.peer_index) == peer =>
                {
                    Some((*id, pending.request))
                }
                _ => None,
            })
    }
}
impl StaticArtifactNetwork {
    pub(crate) fn pending_announcement_for_peer_for_test(
        &self,
        peer: PeerId,
    ) -> Option<(OutboundRequestId, ArtifactChainHeadAnnouncement)> {
        self.pending
            .iter()
            .find_map(|(id, pending)| match (id, pending) {
                (ExchangeRequestId::Announcement(id), PendingRequest::Announcement(pending))
                    if self.pending_peer_id(pending.peer_index) == peer =>
                {
                    Some((*id, pending.announcement))
                }
                _ => None,
            })
    }
}
impl StaticArtifactNetwork {
    pub(crate) fn handle_block_exchange_event_for_test(
        &mut self,
        event: Event<ArtifactBlockRequest, Vec<u8>>,
    ) -> Option<NetworkEvent> {
        let event = match event {
            Event::Message {
                peer,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
            } => {
                let response = codec::ArtifactBlockWireResponse::new(response);
                Event::Message {
                    peer,
                    connection_id,
                    message: Message::Response {
                        request_id,
                        response,
                    },
                }
            }
            Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            },
            _ => panic!("the test helper injects only outbound terminals"),
        };
        self.handle_block_exchange_event(event)
    }
}
impl StaticArtifactNetwork {
    pub(crate) fn handle_head_announcement_event_for_test(
        &mut self,
        event: Event<ArtifactChainHeadAnnouncement, ()>,
    ) -> Option<NetworkEvent> {
        let event = match event {
            Event::Message {
                peer,
                connection_id,
                message:
                    Message::Response {
                        request_id,
                        response: (),
                    },
            } => {
                let response = codec::ArtifactChainHeadAnnouncementReceipt;
                Event::Message {
                    peer,
                    connection_id,
                    message: Message::Response {
                        request_id,
                        response,
                    },
                }
            }
            Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            } => Event::OutboundFailure {
                peer,
                connection_id,
                request_id,
                error,
            },
            _ => panic!("the test helper injects only outbound terminals"),
        };
        self.handle_head_announcement_event(event)
    }
}
impl InboundArtifactRequest {
    pub(crate) fn is_channel_open_for_test(&self) -> bool {
        self.channel.is_open()
    }
}

impl StaticArtifactNetwork {
    pub(crate) fn take_due_artifact_request_deadline_for_test(
        &mut self,
        now: Instant,
    ) -> Option<NetworkEvent> {
        self.take_due_artifact_request_deadline(now)
    }
}
