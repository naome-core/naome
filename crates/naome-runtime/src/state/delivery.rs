use super::*;
use naome_consensus::state::StatePublication;
use naome_protocol::state_exchange::StateRequest;
use sha2::{Digest, Sha256};

fn ordinary_parallel_body(body: &StateRequestBody) -> bool {
    matches!(
        body,
        StateRequestBody::Proposal(_) | StateRequestBody::Vote(_) | StateRequestBody::TimeReport(_)
    )
}

impl StateRuntime {
    fn queued_action_deliveries(&self) -> usize {
        self.outbox
            .iter()
            .filter(|delivery| matches!(&delivery.body, StateRequestBody::UserAction(_)))
            .count()
            + self
                .flights
                .iter()
                .filter(|flight| matches!(&flight.delivery.body, StateRequestBody::UserAction(_)))
                .count()
    }
    fn request_id(&self, body: &StateRequestBody) -> Result<[u8; 32]> {
        let maximum = self
            .state()?
            .genesis()
            .profile()
            .limits()
            .transport_frame_bytes as usize;
        let request = StateRequest::new(self.context, body.clone(), maximum)
            .map_err(|error| StateRuntimeError::Rejected(error.to_string()))?;
        Ok(Sha256::digest(request.to_wire_bytes()).into())
    }
    // The caller retries failed starts. Keep their error typed as a unit so a
    // busy roster does not format discarded peer IDs on every flush.
    fn send_request(
        &mut self,
        peer: PeerId,
        body: StateRequestBody,
    ) -> std::result::Result<StateTicket, ()> {
        let handoff = matches!(
            &body,
            StateRequestBody::Offer(_)
                | StateRequestBody::CandidateOffer(_)
                | StateRequestBody::Agreement(_)
                | StateRequestBody::ReadySignature(_)
                | StateRequestBody::TerminalSignature(_)
                | StateRequestBody::Finalized(_)
        );
        if self.recovery_clients.contains(&peer) {
            // The owner may have authenticated to either current or prepared
            // listener. Send only bounded handoff evidence on the lane that
            // holds that owner's grant; a recovery identity gains no vote.
            if let Some(active) = self.network.active_mut()
                && let Ok(ticket) = active.request_recovery_evidence_to_owner(peer, body.clone())
            {
                return Ok(ticket);
            }
            if let Some(staged) = self.network.staged_mut()
                && let Ok(ticket) = staged.request_recovery_evidence_to_owner(peer, body.clone())
            {
                return Ok(ticket);
            }
            if let Some(recovery) = self.network.recovery_mut()
                && let Ok(ticket) = recovery.request_recovery_evidence_to_owner(peer, body)
            {
                return Ok(ticket);
            }
            return Err(());
        }
        // A candidate retains its advertised key while moving from the
        // parent courier lane to the prepared lane. Its first agreement must
        // reach that courier: it cannot open the prepared listener until it
        // has verified the agreement. Fresh incumbent keys have no parent
        // binding and continue to use the prepared lane below.
        if matches!(&body, StateRequestBody::Agreement(_))
            && let Some(active) = self.network.active_mut()
            && active.is_configured_peer(&peer)
        {
            if !active.has_connected_static_session(&peer) {
                return Err(());
            }
            return active.request_state(peer, body).map_err(|_| ());
        }
        if (handoff || self.network.active().is_none())
            && let Some(staged) = self.network.staged_mut()
            && staged.is_configured_peer(&peer)
        {
            if !staged.has_connected_static_session(&peer) {
                return Err(());
            }
            return staged.request_state(peer, body).map_err(|_| ());
        }
        if self.recovery_authenticated.contains(&peer)
            && self.network.active().is_none()
            && let Some(recovery) = self.network.recovery_mut()
        {
            return recovery.request_recovery_state(peer, body).map_err(|_| ());
        }
        let active = self.network.active_mut().ok_or(())?;
        if !active.has_connected_static_session(&peer) {
            return Err(());
        }
        active.request_state(peer, body).map_err(|_| ())
    }
    pub(super) fn enqueue(&mut self, peer: PeerId, body: StateRequestBody) -> Result<()> {
        self.enqueue_with_id(peer, body, None)
    }
    fn enqueue_with_id(
        &mut self,
        peer: PeerId,
        body: StateRequestBody,
        prepared_id: Option<[u8; 32]>,
    ) -> Result<()> {
        if self.disabled.contains(&peer) {
            return Ok(());
        }
        let state = self.state()?;
        let capacity = state.genesis().profile().limits().transport_buffer_frames as usize;
        let height = state.height();
        if matches!(&body, StateRequestBody::Finalized(_))
            && self.network.active().is_some()
            && self.confirmed_parent.get(&peer) == Some(&height)
        {
            // An accepted offer was checked against this exact selected
            // parent by the peer. Its already-durable finality need not
            // occupy the serial proof delivery slot to that peer again.
            return Ok(());
        }
        if matches!(&body, StateRequestBody::UserAction(_)) {
            // Candidate couriers have no ordinary relay authority. Keep most
            // of the bounded queue available for consensus and sealing even
            // when all sixteen local action slots are occupied.
            let queued_actions = self.queued_action_deliveries();
            if self.node.position()?.is_none() || queued_actions >= (capacity / 4).max(1) {
                return Ok(());
            }
        }
        let id = match prepared_id {
            Some(id) => id,
            None => self.request_id(&body)?,
        };
        if self.sent.contains(&(peer, id))
            || self.acknowledged.contains(&(peer, id))
            || self.outbox.iter().any(|d| d.peer == peer && d.id == id)
            || self
                .flights
                .iter()
                .any(|f| f.delivery.peer == peer && f.delivery.id == id)
        {
            return Ok(());
        }
        // Replace a superseded unsent clock report in place. Moving it to the
        // back on every tick can starve time certification behind recurring
        // finality/history traffic when network latency exceeds the tick period.
        // The retained position preserves fairness without increasing capacity.
        if matches!(&body, StateRequestBody::TimeReport(_))
            && let Some(queued) = self
                .outbox
                .iter_mut()
                .find(|d| d.peer == peer && matches!(&d.body, StateRequestBody::TimeReport(_)))
        {
            *queued = Delivery {
                peer,
                body,
                id,
                height,
                queued_at: queued.queued_at,
            };
            return Ok(());
        }
        let delivery_capacity = capacity.max(
            (self.peers.len() + self.handoff_peers.len())
                .saturating_mul(8)
                .saturating_add(64),
        );
        if self.outbox.len() + self.flights.len() >= delivery_capacity {
            return Ok(());
        }
        self.outbox.push_back(Delivery {
            peer,
            body,
            id,
            height,
            queued_at: Instant::now(),
        });
        Ok(())
    }
    pub(super) fn remember_acknowledged(&mut self, delivery: &Delivery) -> Result<()> {
        // These immutable frames have already passed the remote acceptance
        // path. Replay them after a session change, rather than every second
        // while the same bounded connection is still finishing the seal.
        // Actions remain on periodic retry: their pending admission is volatile.
        if !matches!(
            delivery.body,
            StateRequestBody::Offer(_)
                | StateRequestBody::CandidateOffer(_)
                | StateRequestBody::Agreement(_)
                | StateRequestBody::ReadySignature(_)
                | StateRequestBody::TerminalSignature(_)
                | StateRequestBody::Finalized(_)
                | StateRequestBody::Proposal(_)
                | StateRequestBody::Vote(_)
        ) {
            return Ok(());
        }
        let id = (delivery.peer, delivery.id);
        if !self.acknowledged.contains(&id) {
            // Each slot can use current and prepared identities. This
            // bounded hash cache owns no message payload or transport permit.
            let maximum = self
                .state()?
                .genesis()
                .profile()
                .limits()
                .transport_buffer_frames as usize
                * (self.peers.len() + self.handoff_peers.len()).max(4);
            while self.acknowledged.len() >= maximum {
                self.acknowledged.pop_front();
            }
            self.acknowledged.push_back(id);
        }
        Ok(())
    }
    /// The remote runtime accepts an Offer only after verifying its signed
    /// current authority, head, and state commitment. Keep this proof only
    /// for configured selected peers; recovery and prepared peers still need
    /// explicit finality while they catch up.
    pub(super) fn remember_confirmed_parent(&mut self, delivery: &Delivery) -> Result<()> {
        if !matches!(&delivery.body, StateRequestBody::Offer(_))
            || delivery.height != self.state()?.height()
            || !self.peers.contains(&delivery.peer)
            || self.recovery_clients.contains(&delivery.peer)
            || self.recovery_authenticated.contains(&delivery.peer)
            || !self
                .network
                .active()
                .is_some_and(|network| network.is_configured_peer(&delivery.peer))
        {
            return Ok(());
        }
        self.confirmed_parent.insert(delivery.peer, delivery.height);
        self.outbox.retain(|queued| {
            !(queued.peer == delivery.peer
                && queued.height == delivery.height
                && matches!(
                    &queued.body,
                    StateRequestBody::Finalized(_) | StateRequestBody::History { .. }
                ))
        });
        Ok(())
    }
    pub(super) fn current_proposer_peer(&self) -> Result<Option<PeerId>> {
        let Some(proposer) = self.node.current_proposer_key()? else {
            return Ok(None);
        };
        let Some(keys) = self
            .state()?
            .authority()
            .units()
            .iter()
            .filter_map(|unit| unit.keys())
            .find(|keys| keys.consensus() == proposer.as_bytes())
        else {
            return Ok(None);
        };
        let peer = naome_network::state_peer_id(*keys.transport())
            .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
        Ok(self.peers.contains(&peer).then_some(peer))
    }
    pub(super) fn broadcast(&mut self, body: StateRequestBody) -> Result<()> {
        if self.network.active().is_none() || self.peers.is_empty() {
            return Ok(());
        }
        let id = self.request_id(&body)?;
        self.broadcast_with_id(body, id)
    }
    fn broadcast_with_id(&mut self, body: StateRequestBody, id: [u8; 32]) -> Result<()> {
        if self.network.active().is_none() || self.peers.is_empty() {
            return Ok(());
        }
        if matches!(&body, StateRequestBody::UserAction(_)) {
            let count = self.peers.len();
            let limit = (self
                .state()?
                .genesis()
                .profile()
                .limits()
                .transport_buffer_frames as usize
                / 4)
            .max(1);
            // The selected proposer can make an admitted action useful in this
            // round. Give it the first bounded delivery slot before rotating
            // the remaining couriers; this changes only transport order.
            let proposer = self.current_proposer_peer()?;
            if let Some(peer) = proposer {
                self.enqueue_with_id(peer, body.clone(), Some(id))?;
            }
            for _ in 0..count {
                if self.queued_action_deliveries() >= limit {
                    break;
                }
                let index = self.action_peer_cursor % count;
                let peer = self.peers[index];
                self.action_peer_cursor = (index + 1) % count;
                if Some(peer) == proposer {
                    continue;
                }
                self.enqueue_with_id(peer, body.clone(), Some(id))?;
            }
            return Ok(());
        }
        // A wire request has one identity across all recipients. The peer is
        // kept separately in each bounded delivery and acknowledgement key.
        // Gather peers already holding this exact request once. Repeated
        // publication retries must not scan the whole outbox for every peer.
        let already_scheduled: BTreeSet<_> = self
            .outbox
            .iter()
            .filter(|delivery| delivery.id == id)
            .map(|delivery| delivery.peer)
            .chain(
                self.flights
                    .iter()
                    .filter(|flight| flight.delivery.id == id)
                    .map(|flight| flight.delivery.peer),
            )
            .chain(
                self.sent
                    .iter()
                    .filter(|(_, sent_id)| *sent_id == id)
                    .map(|(peer, _)| *peer),
            )
            .chain(
                self.acknowledged
                    .iter()
                    .filter(|(_, accepted_id)| *accepted_id == id)
                    .map(|(peer, _)| *peer),
            )
            .collect();
        for peer in self.peers.clone() {
            if !already_scheduled.contains(&peer) {
                self.enqueue_with_id(peer, body.clone(), Some(id))?;
            }
        }
        Ok(())
    }
    pub(super) fn broadcast_handoff(&mut self, body: StateRequestBody) -> Result<()> {
        let old_lane = self.network.active().is_some();
        let prepared_evidence = matches!(
            &body,
            StateRequestBody::Agreement(_) | StateRequestBody::ReadySignature(_)
        );
        let mut peers = if old_lane {
            self.peers.clone()
        } else {
            Vec::new()
        };
        peers.extend(self.handoff_peers.iter().copied().filter(|peer| {
            !old_lane
                || !prepared_evidence
                // A selected candidate first learns the agreement through
                // its configured parent courier. Its prepared listener does
                // not exist until that agreement has been accepted.
                || (matches!(&body, StateRequestBody::Agreement(_))
                    && self
                        .network
                        .active()
                        .is_some_and(|active| active.is_configured_peer(peer)))
                || self
                    .network
                    .staged()
                    .is_some_and(|staged| staged.has_connected_static_session(peer))
        }));
        peers.extend(self.recovery_authenticated.iter().copied());
        peers.extend(self.recovery_clients.iter().copied());
        peers.sort();
        peers.dedup();
        let mut id = None;
        for peer in peers {
            if self
                .network
                .active()
                .is_some_and(|net| net.local_peer_id() == peer)
                || self
                    .network
                    .staged()
                    .is_some_and(|net| net.local_peer_id() == peer)
                || self
                    .network
                    .recovery()
                    .is_some_and(|net| net.local_peer_id() == peer)
            {
                continue;
            }
            let prepared_id = match id {
                Some(id) => id,
                None => {
                    let prepared_id = self.request_id(&body)?;
                    id = Some(prepared_id);
                    prepared_id
                }
            };
            self.enqueue_with_id(peer, body.clone(), Some(prepared_id))?;
        }
        Ok(())
    }
    pub(super) fn enqueue_publications(&mut self) -> Result<()> {
        let next_height = self.state()?.height().checked_add(1);
        if self
            .node
            .handoff_agreement()
            .is_some_and(|agreement| next_height == Some(agreement.seal_context().height()))
        {
            // The durable agreement carries the proposal and its complete
            // outgoing quorum. Peers can verify it directly. Retrying ordinary
            // round traffic now only delays READY and TERMINAL on the same
            // bounded peer connection, where sealing remains serial.
            self.outbox.retain(|delivery| {
                !matches!(
                    delivery.body,
                    StateRequestBody::Proposal(_)
                        | StateRequestBody::Vote(_)
                        | StateRequestBody::TimeReport(_)
                )
            });
            return Ok(());
        }
        if self.network.active().is_none() || self.peers.is_empty() {
            self.publication_cache.clear();
            return Ok(());
        }
        let mut next_cache = Vec::new();
        for publication in self.node.publications()? {
            let (body, id) = match self
                .publication_cache
                .iter()
                .find(|(cached, _, _)| cached == &publication)
            {
                Some((_, body, id)) => (body.clone(), *id),
                None => {
                    let body = match &publication {
                        StatePublication::Proposal(p) => StateRequestBody::Proposal(
                            p.encode().map_err(StateNodeError::from)?.into(),
                        ),
                        StatePublication::Vote(v) => StateRequestBody::Vote(v.encode().into()),
                    };
                    let id = self.request_id(&body)?;
                    (body, id)
                }
            };
            self.broadcast_with_id(body.clone(), id)?;
            next_cache.push((publication, body, id));
        }
        self.publication_cache = next_cache;
        Ok(())
    }
    pub(super) fn enqueue_latest_finality(&mut self) -> Result<()> {
        let height = self.state()?.height();
        if height > 0 {
            let proof = self.node.finality_bytes(height)?;
            // The sole holder of a complete seal may become vacant in the
            // selected successor. Its fresh recovery identity must still
            // deliver that public proof to peers preparing the same record.
            self.broadcast_handoff(StateRequestBody::Finalized(proof.into()))?;
        }
        Ok(())
    }
    pub(super) fn enqueue_period_offers(&mut self) -> Result<()> {
        if let Some(offer) = self
            .next_custody
            .as_ref()
            .and_then(StatePeriodCustody::offer)
        {
            self.broadcast_handoff(StateRequestBody::Offer(offer.encode().into()))?;
        }
        if let Some(offer) = self
            .next_custody
            .as_ref()
            .and_then(StatePeriodCustody::candidate_offer)
        {
            self.broadcast_handoff(StateRequestBody::CandidateOffer(offer.encode().into()))?;
        }
        Ok(())
    }
    pub(super) fn enqueue_periodic(&mut self) -> Result<()> {
        // Retry exact completed signatures and actions on a bounded interval.
        // Their authoritative bytes remain in the node/history or caller queue.
        let now = Instant::now();
        if now.duration_since(self.last_rebroadcast) >= Duration::from_secs(1) {
            self.sent.clear();
            self.last_rebroadcast = now;
        }
        if self.state()?.terminated() {
            return self.enqueue_latest_finality();
        }
        // Relay admitted actions before recurring repair and handoff copies.
        // Otherwise a full bounded outbox can keep a timely ballot local until
        // its certified voting window has closed. The cursor shares capacity
        // between retained actions without changing their admission priority.
        let mut actions: Vec<_> = self
            .pending
            .values()
            .map(|op| Arc::<[u8]>::from(op.encode()))
            .collect();
        if !actions.is_empty() {
            let length = actions.len();
            actions.rotate_left(self.action_cursor % length);
            self.action_cursor = (self.action_cursor + 1) % length;
        }
        for bytes in actions {
            self.broadcast(StateRequestBody::UserAction(bytes))?;
        }
        // A healthy owner already has durable fresh custody at this height.
        // Deliver its exact offer before recurring repair copies so a proposer
        // can include it within the bounded preparation grace interval.
        if self.network.active().is_none() {
            // A returning owner's offer names its selected parent. Peers
            // behind that parent need the sealed proof before the offer.
            self.enqueue_latest_finality()?;
        }
        self.enqueue_period_offers()?;
        if let Some(agreement) = self.node.handoff_agreement() {
            self.broadcast_handoff(StateRequestBody::Agreement(
                agreement.encode().map_err(StateNodeError::from)?.into(),
            ))?;
        }
        // Every signer retries its own durable evidence. Flooding every
        // collected signature through every peer multiplies delivery work by
        // the roster size again and can starve READY behind old requests.
        if let Some(terminal) = self.node.local_terminal_signature().cloned() {
            self.broadcast_handoff(StateRequestBody::TerminalSignature(
                terminal.encode().into(),
            ))?;
        }
        if let Some(ready) = self.node.local_ready_signature().cloned() {
            self.broadcast_handoff(StateRequestBody::ReadySignature(ready.encode().into()))?;
        }
        if self.network.active().is_some() {
            self.enqueue_latest_finality()?;
        }
        self.enqueue_publications()?;
        let next_height = self.state()?.height().checked_add(1);
        if self
            .node
            .handoff_agreement()
            .is_none_or(|agreement| next_height != Some(agreement.seal_context().height()))
            && let Some(report) = &self.own_time
        {
            self.broadcast(StateRequestBody::TimeReport(report.clone()))?;
        }
        let from = self
            .state()?
            .height()
            .checked_add(1)
            .ok_or(StateRuntimeError::Configuration("height overflow"))?;
        // One record can consume almost the whole transport envelope. Each
        // returned frame is verified and durably selected before requesting next.
        let history_peers = if self.network.active().is_some() {
            self.peers.clone()
        } else if self.network.staged().is_some() {
            self.handoff_peers.clone()
        } else {
            Vec::new()
        };
        for peer in history_peers {
            if self
                .network
                .staged()
                .is_some_and(|net| net.local_peer_id() == peer)
            {
                continue;
            }
            if self.network.active().is_some()
                && self.confirmed_parent.get(&peer) == Some(&self.state()?.height())
                && self.last_selected_at.elapsed() < Duration::from_secs(5)
            {
                // An accepted offer proves this peer has our parent. Defer
                // speculative empty history only during healthy progress;
                // a stalled height resumes repair after the fixed bound.
                continue;
            }
            self.enqueue(
                peer,
                StateRequestBody::History {
                    from,
                    max_records: 1,
                },
            )?;
        }
        Ok(())
    }
    pub(super) fn flush(&mut self) -> Result<()> {
        self.expire_proof_fetches();
        let mut deferred_serial = BTreeSet::new();
        for fetch in &mut self.proof_fetches {
            if fetch.outcome.is_none() && fetch.ticket.is_none() {
                // Transient disconnected/already-pending capacity retries are
                // bounded by this fetch's fixed overall deadline.
                if let Some(active) = self.network.active_mut() {
                    match active.request_state(
                        fetch.peer,
                        StateRequestBody::Proof {
                            proof_id: fetch.proof,
                        },
                    ) {
                        Ok(ticket) => fetch.ticket = Some(ticket),
                        Err(naome_network::StateStartError::Transport(
                            naome_network::RequestStartError::AlreadyPending(_),
                        )) => {
                            // The proof tried first; do not let an ordinary
                            // second flight leapfrog it during this flush.
                            deferred_serial.insert(fetch.peer);
                        }
                        Err(_) => {}
                    }
                }
            }
        }

        // An authenticated roster can fill the bounded queue with offers and
        // speculative history before its quorum is ready. Deliver current
        // agreement, seal and consensus frames first; otherwise large rosters
        // can exhaust signing rounds while old repair requests occupy every
        // flight. Aging still moves ordinary work ahead of fresh repair.
        // Stable sorting preserves FIFO order within each class.
        let now = Instant::now();
        let retired = self.network.active().is_none();
        self.outbox.make_contiguous().sort_by_key(|delivery| {
            if retired && matches!(delivery.body, StateRequestBody::Finalized(_)) {
                0
            } else if matches!(delivery.body, StateRequestBody::Agreement(_)) {
                1
            } else if matches!(delivery.body, StateRequestBody::TerminalSignature(_)) {
                2
            } else if matches!(
                delivery.body,
                StateRequestBody::ReadySignature(_) | StateRequestBody::Finalized(_)
            ) {
                3
            } else if matches!(
                delivery.body,
                StateRequestBody::Proposal(_) | StateRequestBody::Vote(_)
            ) {
                4
            } else if matches!(
                delivery.body,
                StateRequestBody::UserAction(_)
                    | StateRequestBody::Offer(_)
                    | StateRequestBody::CandidateOffer(_)
                    | StateRequestBody::TimeReport(_)
            ) {
                5
            } else if now.duration_since(delivery.queued_at) >= Duration::from_secs(2) {
                6
            } else if matches!(delivery.body, StateRequestBody::History { .. }) {
                8
            } else {
                7
            }
        });
        let attempts = self.outbox.len();
        for _ in 0..attempts {
            let Some(delivery) = self.outbox.pop_front() else {
                break;
            };
            if delivery.height != self.state()?.height() {
                continue;
            }
            let mut same_peer = self
                .flights
                .iter()
                .filter(|flight| flight.delivery.peer == delivery.peer);
            let first = same_peer.next();
            let has_second = same_peer.next().is_some();
            let static_peer = self
                .network
                .active()
                .is_some_and(|network| network.is_configured_peer(&delivery.peer))
                || self
                    .network
                    .staged()
                    .is_some_and(|network| network.is_configured_peer(&delivery.peer));
            let ordinary_pair = first
                .is_some_and(|flight| ordinary_parallel_body(&flight.delivery.body))
                && !has_second
                && static_peer
                && !deferred_serial.contains(&delivery.peer)
                && ordinary_parallel_body(&delivery.body);
            if self.disabled.contains(&delivery.peer) || (first.is_some() && !ordinary_pair) {
                // A serial item encountered earlier in priority order must
                // not be leapfrogged by a second ordinary request this pass.
                if first.is_some() && !ordinary_parallel_body(&delivery.body) {
                    deferred_serial.insert(delivery.peer);
                }
                self.outbox.push_back(delivery);
                continue;
            }
            match self.send_request(delivery.peer, delivery.body.clone()) {
                Ok(ticket) => self.flights.push(Flight { delivery, ticket }),
                Err(_) => self.outbox.push_back(delivery),
            }
        }
        Ok(())
    }
}
