use super::*;
use naome_consensus::state::StatePublication;
use naome_protocol::state_exchange::{StateContext, StateRequest};
use sha2::{Digest, Sha256};

impl StateRuntime {
    fn enqueue(&mut self, peer: PeerId, body: StateRequestBody) -> Result<()> {
        if self.disabled.contains(&peer) {
            return Ok(());
        }
        let state = self.state()?;
        let maximum = state.genesis().profile().limits().transport_frame_bytes as usize;
        let capacity = state.genesis().profile().limits().transport_buffer_frames as usize;
        let height = state.height();
        let context = StateContext::new(
            *state.genesis().id().as_bytes(),
            *state.genesis().profile().id().as_bytes(),
        );
        let request = StateRequest::new(context, body.clone(), maximum)
            .map_err(|e| StateRuntimeError::Rejected(e.to_string()))?;
        let id: [u8; 32] = Sha256::digest(request.to_wire_bytes()).into();
        if self.sent.contains(&(peer, id))
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
            };
            return Ok(());
        }
        if self.outbox.len() + self.flights.len() >= capacity {
            return Ok(());
        }
        self.outbox.push_back(Delivery {
            peer,
            body,
            id,
            height,
        });
        Ok(())
    }
    fn broadcast(&mut self, body: StateRequestBody) -> Result<()> {
        for peer in self.peers.clone() {
            self.enqueue(peer, body.clone())?;
        }
        Ok(())
    }
    pub(super) fn enqueue_publications(&mut self) -> Result<()> {
        for publication in self.node.publications()? {
            let body = match publication {
                StatePublication::Proposal(p) => {
                    StateRequestBody::Proposal(p.encode().map_err(StateNodeError::from)?.into())
                }
                StatePublication::Vote(v) => StateRequestBody::Vote(v.encode().into()),
            };
            self.broadcast(body)?;
        }
        Ok(())
    }
    pub(super) fn enqueue_latest_finality(&mut self) -> Result<()> {
        let height = self.state()?.height();
        if height > 0 {
            let proof = self.node.finality_bytes(height)?;
            self.broadcast(StateRequestBody::Finalized(proof.into()))?;
        }
        Ok(())
    }
    pub(super) fn enqueue_periodic(&mut self) -> Result<()> {
        // Retry exact completed signatures and actions on a bounded interval.
        // Their authoritative bytes remain in the node/history or caller queue.
        self.sent.clear();
        self.enqueue_latest_finality()?;
        self.enqueue_publications()?;
        if let Some(report) = &self.own_time {
            self.broadcast(StateRequestBody::TimeReport(report.clone()))?;
        }
        let from = self
            .state()?
            .height()
            .checked_add(1)
            .ok_or(StateRuntimeError::Configuration("height overflow"))?;
        // One record can consume almost the whole transport envelope. Each
        // returned frame is verified and durably selected before requesting next.
        for peer in self.peers.clone() {
            self.enqueue(
                peer,
                StateRequestBody::History {
                    from,
                    max_records: 1,
                },
            )?;
        }
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
        Ok(())
    }
    pub(super) fn flush(&mut self) -> Result<()> {
        self.expire_proof_fetches();
        for fetch in &mut self.proof_fetches {
            if fetch.outcome.is_none() && fetch.ticket.is_none() {
                // Transient disconnected/already-pending capacity retries are
                // bounded by this fetch's fixed overall deadline.
                if let Ok(ticket) = self.network.request_state(
                    fetch.peer,
                    StateRequestBody::Proof {
                        proof_id: fetch.proof,
                    },
                ) {
                    fetch.ticket = Some(ticket);
                }
            }
        }

        let attempts = self.outbox.len();
        for _ in 0..attempts {
            let Some(delivery) = self.outbox.pop_front() else {
                break;
            };
            if delivery.height != self.state()?.height() {
                continue;
            }
            if self.disabled.contains(&delivery.peer)
                || self
                    .flights
                    .iter()
                    .any(|f| f.delivery.peer == delivery.peer)
            {
                self.outbox.push_back(delivery);
                continue;
            }
            match self
                .network
                .request_state(delivery.peer, delivery.body.clone())
            {
                Ok(ticket) => self.flights.push(Flight { delivery, ticket }),
                Err(_) => self.outbox.push_back(delivery),
            }
        }
        Ok(())
    }
}
