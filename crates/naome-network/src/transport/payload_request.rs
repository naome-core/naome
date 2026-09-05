//! Opaque payload request custody, cancellation, and exact terminal correlation.

use super::*;
use libp2p::request_response::OutboundRequestId;
use naome_proof::ArtifactId;

pub(crate) struct ArtifactPayloadRequest {
    control: Option<Arc<ArtifactRequestControl>>,
    peer_id: PeerId,
    request: ArtifactRequest,
    request_id: OutboundRequestId,
    attempted_peers: u8,
}

pub(crate) struct ArtifactPayloadRequestStarter {
    control: Arc<ArtifactRequestControl>,
    request: ArtifactRequest,
}

impl ArtifactPayloadRequest {
    fn new_controlled_request(
        network: &StaticArtifactNetwork,
        artifact_id: ArtifactId,
    ) -> (Arc<ArtifactRequestControl>, ArtifactRequest) {
        let deadline = tokio::time::Instant::now()
            .checked_add(ARTIFACT_BLOCK_IMPORT_TIMEOUT)
            .expect("the fixed artifact-payload deadline fits Tokio Instant");
        let control = Arc::new(ArtifactRequestControl::new(
            Arc::clone(&network.pending_budget),
            deadline,
        ));
        (control, ArtifactRequest::new(artifact_id))
    }

    pub(crate) fn start_direct(
        network: &mut StaticArtifactNetwork,
        peer_id: PeerId,
        artifact_id: ArtifactId,
    ) -> Result<Self, RequestStartError> {
        let (control, request) = Self::new_controlled_request(network, artifact_id);
        let request_id = network.request_controlled_artifact(peer_id, request, &control)?;
        Ok(Self {
            control: Some(control),
            peer_id,
            request,
            request_id,
            attempted_peers: 0,
        })
    }

    pub(crate) fn start(
        network: &mut StaticArtifactNetwork,
        preferred_peer_id: PeerId,
        artifact_id: ArtifactId,
    ) -> Result<Self, ArtifactAttemptSelectionError> {
        let (control, request) = Self::new_controlled_request(network, artifact_id);
        let mut attempted_peers = 0;
        let (peer_id, request_id) = start_next_artifact_attempt(
            network,
            preferred_peer_id,
            request,
            &control,
            &mut attempted_peers,
        )?;
        Ok(Self {
            control: Some(control),
            peer_id,
            request,
            request_id,
            attempted_peers,
        })
    }

    fn control(&self) -> &Arc<ArtifactRequestControl> {
        self.control
            .as_ref()
            .expect("an active artifact payload request retains its control")
    }

    pub(crate) fn belongs_to_network(&self, network: &StaticArtifactNetwork) -> bool {
        Arc::ptr_eq(&self.control().network_budget, &network.pending_budget)
    }

    pub(crate) fn accepts_event(&self, event: &OutboundArtifactEvent) -> bool {
        crate::request_correlation::RequestCorrelation::new(
            self.request_id,
            self.peer_id,
            &self.request,
        )
        .matches(
            crate::request_correlation::RequestCorrelation::new(
                event.request_id,
                event.peer_id,
                &event.request,
            ),
            self.control(),
            &event.control,
        )
    }

    pub(crate) fn deadline_expired(&self) -> bool {
        tokio::time::Instant::now() >= self.control().deadline
    }

    pub(crate) fn into_starter(mut self) -> ArtifactPayloadRequestStarter {
        let control = self
            .control
            .take()
            .expect("an active artifact payload request retains its control");
        ArtifactPayloadRequestStarter {
            control,
            request: self.request,
        }
    }

    pub(crate) fn try_next(
        mut self,
        network: &mut StaticArtifactNetwork,
    ) -> Result<Self, ArtifactAttemptSelectionError> {
        let (peer_id, request_id) = start_next_artifact_attempt(
            network,
            self.peer_id,
            self.request,
            self.control
                .as_ref()
                .expect("an active block import retains artifact-request control"),
            &mut self.attempted_peers,
        )?;
        self.peer_id = peer_id;
        self.request_id = request_id;
        Ok(self)
    }

    pub(crate) const fn artifact_id(&self) -> ArtifactId {
        self.request.artifact_id()
    }

    pub(crate) const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub(crate) fn disarm(&mut self) {
        self.control = None;
    }
}

impl ArtifactPayloadRequestStarter {
    pub(crate) fn new(network: &StaticArtifactNetwork, artifact_id: ArtifactId) -> Self {
        let (control, request) =
            ArtifactPayloadRequest::new_controlled_request(network, artifact_id);
        Self { control, request }
    }

    pub(crate) fn deadline_expired(&self) -> bool {
        tokio::time::Instant::now() >= self.control.deadline
    }

    pub(crate) fn start(
        &self,
        network: &mut StaticArtifactNetwork,
        peer_id: PeerId,
    ) -> Result<ArtifactPayloadRequest, RequestStartError> {
        let request_id =
            network.request_controlled_artifact(peer_id, self.request, &self.control)?;
        Ok(ArtifactPayloadRequest {
            control: Some(Arc::clone(&self.control)),
            peer_id,
            request: self.request,
            request_id,
            attempted_peers: 0,
        })
    }
}

impl Drop for ArtifactPayloadRequest {
    fn drop(&mut self) {
        if let Some(control) = &self.control {
            control.cancel();
        }
    }
}

impl fmt::Debug for ArtifactPayloadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactPayloadRequest")
            .field("peer_id", &self.peer_id)
            .field("request", &self.request)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

pub(crate) enum ArtifactAttemptSelectionError {
    NoEligiblePeer,
    RequestStart(RequestStartError),
}

fn start_next_artifact_attempt(
    network: &mut StaticArtifactNetwork,
    preferred_peer_id: PeerId,
    request: ArtifactRequest,
    control: &Arc<ArtifactRequestControl>,
    attempted_peers: &mut u8,
) -> Result<(PeerId, OutboundRequestId), ArtifactAttemptSelectionError> {
    let (preferred_index, peer_count) = {
        let sessions = &network.swarm.behaviour().sessions;
        let preferred_index = sessions.peer_index(&preferred_peer_id).ok_or(
            ArtifactAttemptSelectionError::RequestStart(RequestStartError::UnknownPeer(
                preferred_peer_id,
            )),
        )?;
        (preferred_index, sessions.peer_count())
    };

    for position in 0..peer_count {
        let index = if position == 0 {
            preferred_index
        } else {
            let ordered = position - 1;
            if ordered < preferred_index {
                ordered
            } else {
                ordered + 1
            }
        };
        let bit = 1_u8
            .checked_shl(u32::try_from(index).expect("the peer index fits u32"))
            .expect("the static peer count fits one attempted-peer mask");
        if *attempted_peers & bit != 0 {
            continue;
        }
        *attempted_peers |= bit;

        let peer_id = network
            .swarm
            .behaviour()
            .sessions
            .peer_id_at(index)
            .expect("the configured peer index remains stable");
        match network.request_controlled_artifact(peer_id, request, control) {
            Ok(request_id) => return Ok((peer_id, request_id)),
            Err(RequestStartError::AlreadyPending(_) | RequestStartError::PeerDisconnected(_)) => {}
            Err(source) => return Err(ArtifactAttemptSelectionError::RequestStart(source)),
        }
    }

    Err(ArtifactAttemptSelectionError::NoEligiblePeer)
}
