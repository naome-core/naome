use super::*;
use naome_consensus::state::{SealRole, SealSignature};
use naome_ledger::time::SignedTimeReport;
use naome_network::NetworkEvent;
use naome_protocol::state_exchange::{StateHistoryItem, StateRejection, StateResponseBody};
use naome_storage::state::StateAppendOutcome;

impl StateRuntime {
    pub(super) fn network_event(
        &mut self,
        event: NetworkEvent,
        lane: naome_network::StateLane,
    ) -> Result<StateRuntimeEvent> {
        match event {
            NetworkEvent::RecoveryConnected {
                peer_id,
                initiated_by_us,
                ..
            } => {
                if self.all_remote_slots_disabled()? {
                    return Ok(StateRuntimeEvent::Network);
                }
                if initiated_by_us {
                    self.start_recovery_challenge(peer_id);
                }
                Ok(StateRuntimeEvent::Network)
            }
            NetworkEvent::RecoveryAuthenticated { peer_id, owner } => {
                if !self.recovery_owner_disabled(owner)? {
                    self.recovery_clients.insert(peer_id);
                }
                Ok(StateRuntimeEvent::Network)
            }
            NetworkEvent::RecoveryDisconnected { peer_id }
            | NetworkEvent::RecoveryAuthTimeout { peer_id } => {
                self.recovery_authenticated.remove(&peer_id);
                self.recovery_clients.remove(&peer_id);
                self.recovery_flights
                    .retain(|flight| flight.peer != peer_id);
                // A recovery transport may discard its pending tickets while
                // closing a bounded session. Drop matching runtime deliveries
                // too, or their old tickets can block all later handoff
                // attempts to the same fresh identity after reauthentication.
                self.flights
                    .retain(|flight| flight.delivery.peer != peer_id);
                self.outbox.retain(|delivery| delivery.peer != peer_id);
                self.sent.retain(|(peer, _)| *peer != peer_id);
                self.acknowledged.retain(|(peer, _)| *peer != peer_id);
                self.confirmed_parent.remove(&peer_id);
                Ok(StateRuntimeEvent::Network)
            }
            NetworkEvent::PeerSession(
                naome_network::PeerSessionEvent::Established { peer_id }
                | naome_network::PeerSessionEvent::Disconnected { peer_id },
            ) => {
                self.sent.retain(|(peer, _)| *peer != peer_id);
                self.acknowledged.retain(|(peer, _)| *peer != peer_id);
                self.confirmed_parent.remove(&peer_id);
                Ok(StateRuntimeEvent::Network)
            }
            NetworkEvent::InboundState(inbound) => {
                let peer = inbound.peer_id();
                let blocked_recovery_owner = inbound
                    .recovery_owner()
                    .map(|owner| self.recovery_owner_disabled(owner))
                    .transpose()?
                    .unwrap_or(false);
                if inbound.recovery_owner().is_some() && !blocked_recovery_owner {
                    // The network has verified the owner's challenge response.
                    // This connection can receive the same bounded handoff
                    // evidence as an ordinary peer without voting authority.
                    self.recovery_clients.insert(peer);
                }
                let body = inbound.request().body().clone();
                let (response, event) = match if blocked_recovery_owner {
                    Err(StateRuntimeError::Rejected(
                        "simulated authority slot disabled".into(),
                    ))
                } else {
                    self.request_body(&body)
                } {
                    Ok(response) => (response, StateRuntimeEvent::Network),
                    Err(error) if is_rejection(&error) => (
                        StateResponseBody::Rejected(StateRejection::Invalid),
                        StateRuntimeEvent::Rejected {
                            peer,
                            reason: error.to_string(),
                        },
                    ),
                    Err(error) => return Err(error),
                };
                // A dropped/broken response channel does not undo an anchored
                // finality or make queued user input into a finalized receipt.
                let network = match lane {
                    naome_network::StateLane::Active => self.network.active_mut(),
                    naome_network::StateLane::Handoff => self.network.staged_mut(),
                    naome_network::StateLane::Recovery => self.network.recovery_mut(),
                };
                if let Some(network) = network {
                    let _ = network.respond_state(inbound, response);
                }
                Ok(event)
            }
            NetworkEvent::OutboundState(event) => {
                if let Some(index) = self
                    .recovery_flights
                    .iter()
                    .position(|flight| flight.ticket.accepts_event(&event))
                {
                    return self.handle_recovery_outbound(index, event);
                }
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
                            if matches!(body, StateResponseBody::Busy) {
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
                            return Err(StateRuntimeError::Transport(
                                "proof ticket correlation mismatch".into(),
                            ));
                        }
                    }
                    return Ok(StateRuntimeEvent::Network);
                }
                let Some(index) = self
                    .flights
                    .iter()
                    .position(|f| f.ticket.accepts_event(&event))
                else {
                    return Ok(StateRuntimeEvent::Network);
                };
                let Flight { delivery, ticket } = self.flights.swap_remove(index);
                let received = match ticket.complete(event) {
                    Ok(Ok(received)) => received,
                    Ok(Err(_)) => {
                        if delivery.height == self.state()?.height() {
                            self.outbox.push_back(delivery);
                        }
                        return Ok(StateRuntimeEvent::Network);
                    }
                    Err(mismatch) => {
                        let (ticket, _event) = mismatch.into_parts();
                        self.flights.push(Flight { delivery, ticket });
                        return Err(StateRuntimeError::Transport(
                            "research ticket correlation mismatch".into(),
                        ));
                    }
                };
                let peer = delivery.peer;
                self.sent.insert((peer, delivery.id));
                match received.response().body() {
                    StateResponseBody::Accepted => {
                        self.remember_acknowledged(&delivery)?;
                        self.remember_confirmed_parent(&delivery)?;
                    }
                    StateResponseBody::History(items) => {
                        for item in items {
                            match self.receive_finality(&item.evidence) {
                                Ok(_) => {}
                                Err(error) if is_rejection(&error) => {
                                    return Ok(StateRuntimeEvent::Rejected {
                                        peer,
                                        reason: error.to_string(),
                                    });
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                    StateResponseBody::Busy => {
                        self.sent.remove(&(peer, delivery.id));
                        if delivery.height == self.state()?.height() {
                            self.outbox.push_back(delivery);
                        }
                    }
                    _ => {}
                }
                // `received` releases the transport byte/pending permit here.
                Ok(StateRuntimeEvent::Network)
            }
            NetworkEvent::ListenerError { error, .. } => {
                Err(StateRuntimeError::Transport(error.to_string()))
            }
            NetworkEvent::ListenerClosed {
                reason: Err(error), ..
            } => Err(StateRuntimeError::Transport(error.to_string())),
            _ => Ok(StateRuntimeEvent::Network),
        }
    }
    pub(super) fn validate_proof_fetch_response(
        &self,
        index: usize,
        body: &StateResponseBody,
    ) -> std::result::Result<Vec<u8>, String> {
        let fetch = &self.proof_fetches[index];
        match body {
            StateResponseBody::Proof {
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
            StateResponseBody::Unavailable => Err("remote proof unavailable".into()),
            StateResponseBody::Rejected(reason) => {
                Err(format!("remote proof request rejected: {reason:?}"))
            }
            StateResponseBody::Busy => Err("remote proof peer busy".into()),
            _ => Err("remote proof response does not match request".into()),
        }
    }
    pub(super) fn request_body(&mut self, body: &StateRequestBody) -> Result<StateResponseBody> {
        match body {
            StateRequestBody::Handshake => Ok(StateResponseBody::Ready),
            StateRequestBody::TimeReport(bytes) => {
                let report = SignedTimeReport::decode(bytes)?;
                report.verify(
                    self.state()?.genesis(),
                    self.state()?.authority(),
                    self.state()?.head(),
                    self.state()?
                        .height()
                        .checked_add(1)
                        .ok_or(StateRuntimeError::Configuration("height overflow"))?,
                )?;
                if self
                    .time_reports
                    .get(&report.validator())
                    .is_none_or(|old| report.utc_seconds() > old.utc_seconds())
                {
                    self.time_reports.insert(report.validator(), report);
                }
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::UserAction(bytes) => {
                let operation = SignedOperation::decode(bytes)?;
                self.submit_operation(operation)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::Proposal(bytes) => {
                self.node.accept_proposal(bytes)?;
                if !self.work_ready
                    && self
                        .node
                        .position()?
                        .is_some_and(|p| p.2 == StatePhase::Proposal)
                {
                    self.phase_started = Instant::now();
                }
                self.work_ready = true;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::Vote(bytes) => {
                self.node.accept_vote(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::Offer(bytes) => {
                self.accept_offer(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::CandidateOffer(bytes) => {
                self.accept_candidate_offer(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::RecoveryChallenge | StateRequestBody::RecoveryHello(_) => Err(
                StateRuntimeError::Rejected("recovery lane not authenticated".into()),
            ),
            StateRequestBody::PendingAgreement { height } => {
                let bytes = self
                    .node
                    .handoff_agreement()
                    .filter(|agreement| agreement.seal_context().height() == *height)
                    .map(|agreement| agreement.encode().map(|bytes| bytes.into()))
                    .transpose()
                    .map_err(StateNodeError::from)?;
                Ok(StateResponseBody::Agreement(bytes))
            }
            StateRequestBody::Agreement(bytes) => {
                self.node.accept_agreement(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::ReadySignature(bytes) => {
                if SealSignature::decode(bytes)
                    .map_err(StateNodeError::from)?
                    .role()
                    != SealRole::Ready
                {
                    return Err(StateRuntimeError::Rejected(
                        "READY frame has wrong seal role".into(),
                    ));
                }
                self.node.accept_seal_signature(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::TerminalSignature(bytes) => {
                if SealSignature::decode(bytes)
                    .map_err(StateNodeError::from)?
                    .role()
                    != SealRole::Terminal
                {
                    return Err(StateRuntimeError::Rejected(
                        "TERMINAL frame has wrong seal role".into(),
                    ));
                }
                self.node.accept_seal_signature(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::Finalized(bytes) => {
                self.receive_finality(bytes)?;
                Ok(StateResponseBody::Accepted)
            }
            StateRequestBody::History { from, max_records } => {
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
                        .ok_or(StateRuntimeError::Rejected("history range overflow".into()))?;
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
                    records.push(StateHistoryItem {
                        height,
                        evidence: evidence.into(),
                    });
                }
                Ok(StateResponseBody::History(records))
            }
            StateRequestBody::Proof { proof_id } => {
                Ok(self.state()?.library().lookup(*proof_id).map_or(
                    StateResponseBody::Unavailable,
                    |proof| StateResponseBody::Proof {
                        proof_id: *proof_id,
                        certificate: proof.canonical_bytes().into(),
                    },
                ))
            }
        }
    }
    pub(super) fn receive_finality(&mut self, bytes: &[u8]) -> Result<StateAppendOutcome> {
        let before = self.state()?.height();
        let result = self.node.accept_finality(bytes)?;
        if self.state()?.height() != before {
            self.on_height()?;
        }
        Ok(result)
    }
}
pub(super) fn is_rejection(error: &StateRuntimeError) -> bool {
    matches!(
        error,
        StateRuntimeError::Rejected(_) | StateRuntimeError::Node(StateNodeError::Rejected(_))
    )
}
