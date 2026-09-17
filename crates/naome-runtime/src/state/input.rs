use super::*;
use naome_ledger::time::SignedTimeReport;
use naome_network::NetworkEvent;
use naome_protocol::state_exchange::{
    ResearchHistoryItem, ResearchRejection, ResearchResponseBody,
};
use naome_storage::state::ResearchAppendOutcome;

impl ResearchRuntime {
    pub(super) fn network_event(&mut self, event: NetworkEvent) -> Result<ResearchRuntimeEvent> {
        match event {
            NetworkEvent::InboundResearch(inbound) => {
                let peer = inbound.peer_id();
                let body = inbound.request().body().clone();
                let (response, event) = match self.request_body(&body) {
                    Ok(response) => (response, ResearchRuntimeEvent::Network),
                    Err(error) if is_rejection(&error) => (
                        ResearchResponseBody::Rejected(ResearchRejection::Invalid),
                        ResearchRuntimeEvent::Rejected {
                            peer,
                            reason: error.to_string(),
                        },
                    ),
                    Err(error) => return Err(error),
                };
                // A dropped/broken response channel does not undo an anchored
                // finality or make queued user input into a finalized receipt.
                let _ = self.network.respond_research(inbound, response);
                Ok(event)
            }
            NetworkEvent::OutboundResearch(event) => {
                self.expire_proof_fetches();
                if let Some(index) = self.proof_fetches.iter().position(|fetch| {
                    fetch
                        .ticket
                        .as_ref()
                        .is_some_and(|ticket| ticket.accepts_event(&event))
                }) {
                    let ticket = self.proof_fetches[index]
                        .ticket
                        .take()
                        .expect("matching proof ticket");
                    match ticket.complete(event) {
                        Ok(Ok(received)) => {
                            let body = received.response().body();
                            let outcome = self.validate_proof_fetch_response(index, body);
                            if matches!(body, ResearchResponseBody::Busy) {
                                // Retain the original deadline when retrying.
                                self.expire_proof_fetches();
                            } else {
                                self.proof_fetches[index].outcome = Some(outcome);
                            }
                        }
                        Ok(Err(error)) => {
                            self.proof_fetches[index].outcome =
                                Some(Err(format!("proof transport failed: {error:?}")))
                        }
                        Err(mismatch) => {
                            let (ticket, _event) = mismatch.into_parts();
                            self.proof_fetches[index].ticket = Some(ticket);
                            return Err(ResearchRuntimeError::Transport(
                                "proof ticket correlation mismatch".into(),
                            ));
                        }
                    }
                    return Ok(ResearchRuntimeEvent::Network);
                }
                let Some(index) = self
                    .flights
                    .iter()
                    .position(|f| f.ticket.accepts_event(&event))
                else {
                    return Ok(ResearchRuntimeEvent::Network);
                };
                let Flight { delivery, ticket } = self.flights.swap_remove(index);
                let received = match ticket.complete(event) {
                    Ok(Ok(received)) => received,
                    Ok(Err(_)) => {
                        if delivery.height == self.state()?.height() {
                            self.outbox.push_back(delivery);
                        }
                        return Ok(ResearchRuntimeEvent::Network);
                    }
                    Err(mismatch) => {
                        let (ticket, _event) = mismatch.into_parts();
                        self.flights.push(Flight { delivery, ticket });
                        return Err(ResearchRuntimeError::Transport(
                            "research ticket correlation mismatch".into(),
                        ));
                    }
                };
                let peer = delivery.peer;
                self.sent.insert((peer, delivery.id));
                match received.response().body() {
                    ResearchResponseBody::History(items) => {
                        for item in items {
                            match self.receive_finality(&item.evidence) {
                                Ok(_) => {}
                                Err(error) if is_rejection(&error) => {
                                    return Ok(ResearchRuntimeEvent::Rejected {
                                        peer,
                                        reason: error.to_string(),
                                    });
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    ResearchResponseBody::Busy => {
                        self.sent.remove(&(peer, delivery.id));
                        if delivery.height == self.state()?.height() {
                            self.outbox.push_back(delivery);
                        }
                    }
                    _ => {}
                }
                // `received` releases the transport byte/pending permit here.
                Ok(ResearchRuntimeEvent::Network)
            }
            NetworkEvent::ListenerError { error, .. } => {
                Err(ResearchRuntimeError::Transport(error.to_string()))
            }
            NetworkEvent::ListenerClosed {
                reason: Err(error), ..
            } => Err(ResearchRuntimeError::Transport(error.to_string())),
            _ => Ok(ResearchRuntimeEvent::Network),
        }
    }
    pub(super) fn validate_proof_fetch_response(
        &self,
        index: usize,
        body: &ResearchResponseBody,
    ) -> std::result::Result<Vec<u8>, String> {
        let fetch = &self.proof_fetches[index];
        match body {
            ResearchResponseBody::Proof {
                proof_id,
                certificate,
            } if *proof_id == fetch.proof => {
                let state = self.state().map_err(|e| e.to_string())?;
                if certificate.len() > state.genesis().profile().limits().certificate_bytes as usize
                {
                    return Err("remote proof exceeds certificate bound".into());
                }
                let selected = state
                    .library()
                    .lookup(*proof_id)
                    .ok_or("requested proof is not selected")?;
                if selected.canonical_bytes() != certificate.as_ref() {
                    return Err("remote proof differs from selected verified certificate".into());
                }
                Ok(certificate.to_vec())
            }
            ResearchResponseBody::Unavailable => Err("remote proof unavailable".into()),
            ResearchResponseBody::Rejected(reason) => {
                Err(format!("remote proof request rejected: {reason:?}"))
            }
            ResearchResponseBody::Busy => Err("remote proof peer busy".into()),
            _ => Err("remote proof response does not match request".into()),
        }
    }
    fn request_body(&mut self, body: &ResearchRequestBody) -> Result<ResearchResponseBody> {
        match body {
            ResearchRequestBody::Handshake => Ok(ResearchResponseBody::Ready),
            ResearchRequestBody::TimeReport(bytes) => {
                let report = SignedTimeReport::decode(bytes)?;
                report.verify(
                    self.state()?.genesis(),
                    self.state()?.head(),
                    self.state()?
                        .height()
                        .checked_add(1)
                        .ok_or(ResearchRuntimeError::Configuration("height overflow"))?,
                )?;
                if self
                    .time_reports
                    .get(&report.validator())
                    .is_none_or(|old| report.utc_seconds() > old.utc_seconds())
                {
                    self.time_reports.insert(report.validator(), report);
                }
                Ok(ResearchResponseBody::Accepted)
            }
            ResearchRequestBody::UserAction(bytes) => {
                let operation = SignedOperation::decode(bytes)?;
                self.submit_operation(operation)?;
                Ok(ResearchResponseBody::Accepted)
            }
            ResearchRequestBody::Proposal(bytes) => {
                self.node.accept_proposal(bytes)?;
                if !self.work_ready
                    && self
                        .node
                        .position()?
                        .is_some_and(|p| p.2 == ResearchPhase::Proposal)
                {
                    self.phase_started = Instant::now();
                }
                self.work_ready = true;
                Ok(ResearchResponseBody::Accepted)
            }
            ResearchRequestBody::Vote(bytes) => {
                self.node.accept_vote(bytes)?;
                Ok(ResearchResponseBody::Accepted)
            }
            ResearchRequestBody::Finalized(bytes) => {
                self.receive_finality(bytes)?;
                Ok(ResearchResponseBody::Accepted)
            }
            ResearchRequestBody::History { from, max_records } => {
                let head = self.state()?.height();
                let maximum = self
                    .state()?
                    .genesis()
                    .profile()
                    .limits()
                    .transport_frame_bytes as usize;
                let mut used = 106usize;
                let mut records = Vec::new();
                for offset in 0..u64::from(*max_records) {
                    let height = from
                        .checked_add(offset)
                        .ok_or(ResearchRuntimeError::Rejected(
                            "history range overflow".into(),
                        ))?;
                    if height > head {
                        break;
                    }
                    let evidence = self.node.finality_bytes(height)?;
                    if used
                        .checked_add(12 + evidence.len())
                        .is_none_or(|n| n > maximum)
                    {
                        break;
                    }
                    used += 12 + evidence.len();
                    records.push(ResearchHistoryItem {
                        height,
                        evidence: evidence.into(),
                    });
                }
                Ok(ResearchResponseBody::History(records))
            }
            ResearchRequestBody::Proof { proof_id } => {
                Ok(self.state()?.library().lookup(*proof_id).map_or(
                    ResearchResponseBody::Unavailable,
                    |proof| ResearchResponseBody::Proof {
                        proof_id: *proof_id,
                        certificate: proof.canonical_bytes().into(),
                    },
                ))
            }
        }
    }
    fn receive_finality(&mut self, bytes: &[u8]) -> Result<ResearchAppendOutcome> {
        let before = self.state()?.height();
        let result = self.node.accept_finality(bytes)?;
        if self.state()?.height() != before {
            self.on_height()?;
        }
        Ok(result)
    }
}
fn is_rejection(error: &ResearchRuntimeError) -> bool {
    matches!(
        error,
        ResearchRuntimeError::Rejected(_)
            | ResearchRuntimeError::Node(ResearchNodeError::Rejected(_))
    )
}
