//! Atomic request batches with transport-owned permits and enqueue order.

use super::*;
use naome_protocol::{
    chain_head_announcement::ArtifactChainHeadAnnouncement,
    chain_head_exchange::ArtifactChainHeadRequest,
};

pub(crate) enum BatchStartError {
    RequestStart(RequestStartError),
    InsufficientCapacity { available: usize },
}

impl StaticArtifactNetwork {
    pub(crate) fn start_chain_head_request_batch(
        &mut self,
        peer_ids: &[PeerId],
        request: ArtifactChainHeadRequest,
    ) -> Result<Vec<ChainHeadRequestTicket>, BatchStartError> {
        let mut peer_indices = [0; MAX_STATIC_PEERS];
        for (&peer_id, peer_index) in peer_ids.iter().zip(&mut peer_indices) {
            let transport_connected = self.swarm.behaviour().head_exchange.is_connected(&peer_id);
            *peer_index = self
                .preflight_request(peer_id, transport_connected)
                .map_err(BatchStartError::RequestStart)?;
        }

        let permits = PendingBudget::try_acquire_many(&self.pending_budget, peer_ids.len())
            .map_err(|available| BatchStartError::InsufficientCapacity { available })?;
        let mut peers = Vec::with_capacity(peer_ids.len());
        for ((&peer_index, &peer_id), permit) in peer_indices[..peer_ids.len()]
            .iter()
            .zip(peer_ids)
            .zip(permits.into_iter().flatten())
        {
            peers.push(self.enqueue_chain_head_request(peer_index, peer_id, request, permit));
        }

        Ok(peers)
    }
    pub(crate) fn start_head_announcement_batch(
        &mut self,
        peer_ids: &[PeerId],
        announcement: ArtifactChainHeadAnnouncement,
    ) -> Result<Vec<HeadAnnouncementTicket>, BatchStartError> {
        let mut peer_indices = [0; MAX_ARTIFACT_CHAIN_HEAD_BROADCAST_PEERS];
        for (&peer_id, peer_index) in peer_ids.iter().zip(&mut peer_indices) {
            let transport_connected = self
                .swarm
                .behaviour()
                .head_announcement
                .is_connected(&peer_id);
            *peer_index = self
                .preflight_request(peer_id, transport_connected)
                .map_err(BatchStartError::RequestStart)?;
        }

        let permits = PendingBudget::try_acquire_many(&self.pending_budget, peer_ids.len())
            .map_err(|available| BatchStartError::InsufficientCapacity { available })?;
        let mut peers = Vec::with_capacity(peer_ids.len());
        for ((&peer_index, &peer_id), permit) in peer_indices[..peer_ids.len()]
            .iter()
            .zip(peer_ids)
            .zip(permits.into_iter().flatten())
        {
            peers.push(self.enqueue_head_announcement(peer_index, peer_id, announcement, permit));
        }

        Ok(peers)
    }
}
