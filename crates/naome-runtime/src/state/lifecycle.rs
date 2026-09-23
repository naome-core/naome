use super::*;
use naome_chain::StateRecord;
use naome_ledger::AccountId;
use naome_network::{Keypair, state_peer_id};
use zeroize::Zeroizing;

pub(super) fn candidate_still_live(
    state: &LedgerState,
    family: naome_ledger::ResolutionId,
) -> bool {
    state.join_queue().contains(&family)
        && !state.consumed_claims().contains(&family)
        && state
            .join_intent(family)
            .is_some_and(|entry| entry.expires() > state.time())
}

pub(super) fn fresh_recovery_key(selected: &LedgerState) -> Result<SigningKey> {
    for _ in 0..4 {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *seed)
            .map_err(|_| StateRuntimeError::Configuration("recovery entropy unavailable"))?;
        let key = SigningKey::from_bytes(&seed);
        let public = key.verifying_key().to_bytes();
        if !selected.used_period_keys().contains(&public)
            && !selected
                .accounts()
                .values()
                .any(|account| account == &public)
        {
            return Ok(key);
        }
    }
    Err(StateRuntimeError::Configuration(
        "fresh recovery identity unavailable",
    ))
}

pub(super) fn attach_recovery_network(
    pair: &mut StateTransportPair,
    selected: &LedgerState,
    key: &SigningKey,
) -> Result<()> {
    let peer = state_peer_id(key.verifying_key().to_bytes())
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
    if let Some(existing) = pair.recovery() {
        if existing.local_peer_id() != peer {
            return Err(StateRuntimeError::Configuration(
                "recovery identity differs from setup",
            ));
        }
        return Ok(());
    }
    let mut seed = Zeroizing::new(key.to_bytes());
    let identity = Keypair::ed25519_from_bytes(&mut *seed)
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
    let network = StateNetwork::new_recovery_only(identity, selected)
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
    pair.attach_recovery(network)
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))
}

/// Preserve late archive catch-up after the finite run has retired every
/// authority key. The stable address now serves only owner-authenticated
/// recovery through a fresh Noise identity, including after cold restart.
pub(super) fn listen_terminal_recovery(
    pair: &mut StateTransportPair,
    primary_endpoint: &str,
    bind: Option<SocketAddr>,
) -> Result<()> {
    let address = match bind {
        Some(address) => address,
        None => primary_endpoint
            .parse()
            .map_err(|_| StateRuntimeError::Configuration("invalid recovery endpoint"))?,
    };
    pair.recovery_mut()
        .ok_or(StateRuntimeError::Configuration(
            "terminal recovery missing",
        ))?
        .listen_on(listen_address(address)?)
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
    Ok(())
}

impl StateRuntime {
    pub(super) fn recovery_owner_disabled(&self, owner: AccountId) -> Result<bool> {
        Ok(self
            .state()?
            .authority()
            .owner(owner)
            .is_some_and(|unit| self.disabled_slots.contains(&unit.slot())))
    }
    pub(super) fn all_remote_slots_disabled(&self) -> Result<bool> {
        if !self.config.allow_simulation_controls || self.disabled_slots.is_empty() {
            return Ok(false);
        }
        let local = self
            .handoff_setup
            .as_ref()
            .map(|setup| AccountId::for_key(setup.owner_key.verifying_key().as_bytes()));
        let remote: Vec<_> = self
            .state()?
            .authority()
            .units()
            .iter()
            .filter(|unit| Some(unit.owner()) != local)
            .collect();
        Ok(!remote.is_empty()
            && remote
                .iter()
                .all(|unit| self.disabled_slots.contains(&unit.slot())))
    }

    /// Probe explicit stable endpoints only after ordinary progress stalls.
    /// Recovery grants history access but never creates a validator vote.
    pub(super) fn probe_recovery(&mut self) -> Result<()> {
        if self.state()?.terminated() || self.all_remote_slots_disabled()? {
            return Ok(());
        }
        let now = Instant::now();
        let probe_interval = if self.network.active().is_some() {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(1)
        };
        if now.duration_since(self.last_recovery_probe) < probe_interval
            || (self.network.active().is_some()
                && now.duration_since(self.last_selected_at) < Duration::from_secs(5))
        {
            return Ok(());
        }
        self.last_recovery_probe = now;
        let from = self
            .state()?
            .height()
            .checked_add(1)
            .ok_or(StateRuntimeError::Configuration("height overflow"))?;
        for peer in self.recovery_authenticated.clone() {
            if self
                .recovery_flights
                .iter()
                .any(|flight| flight.peer == peer)
            {
                continue;
            }
            if let Some(network) = self.network.recovery_mut()
                && let Ok(ticket) = network.request_recovery_state(
                    peer,
                    StateRequestBody::History {
                        from,
                        max_records: 1,
                    },
                )
            {
                self.recovery_flights.push(RecoveryFlight {
                    peer,
                    stage: RecoveryStage::History,
                    ticket,
                });
            }
        }
        let Some(setup) = &self.handoff_setup else {
            return Ok(());
        };
        // Try the currently selected keyed listeners before stable fallback
        // addresses. The older endpoint of a rotating slot may be closed.
        let mut endpoints: Vec<_> = self
            .state()?
            .authority()
            .units()
            .iter()
            .filter_map(|unit| unit.keys().map(|keys| keys.endpoint().to_owned()))
            .collect();
        endpoints.retain(|endpoint| {
            endpoint != &setup.primary_endpoint && endpoint != &setup.handoff_endpoint
        });
        endpoints.sort();
        endpoints.dedup();
        let mut fallback = setup.recovery_endpoints.clone();
        fallback.retain(|endpoint| {
            endpoint != &setup.primary_endpoint && endpoint != &setup.handoff_endpoint
        });
        fallback.sort();
        fallback.dedup();
        for endpoint in fallback {
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        if endpoints.is_empty() {
            return Ok(());
        }
        self.recovery_cursor %= endpoints.len();
        // The transport itself caps simultaneous recovery connections at two.
        // Try two distinct stable addresses each second so a rotated listener
        // or dead address cannot delay one-record-at-a-time catch-up for a
        // whole endpoint cycle.
        for _ in 0..endpoints.len().min(2) {
            let endpoint = &endpoints[self.recovery_cursor];
            self.recovery_cursor = (self.recovery_cursor + 1) % endpoints.len();
            if let Some(network) = self.network.recovery_mut() {
                let result = network.dial_recovery(endpoint);
                if matches!(result, Err(naome_network::RecoveryDialError::Capacity)) {
                    break;
                }
            }
        }
        Ok(())
    }

    pub(super) fn start_recovery_challenge(&mut self, peer: PeerId) {
        if self
            .recovery_flights
            .iter()
            .any(|flight| flight.peer == peer)
        {
            return;
        }
        let ticket = self.network.recovery_mut().and_then(|network| {
            network
                .request_recovery_state(peer, StateRequestBody::RecoveryChallenge)
                .ok()
        });
        if let Some(ticket) = ticket {
            self.recovery_flights.push(RecoveryFlight {
                peer,
                stage: RecoveryStage::Challenge,
                ticket,
            });
        } else {
            self.abandon_recovery_peer(peer);
        }
    }

    fn abandon_recovery_peer(&mut self, peer: PeerId) {
        self.recovery_authenticated.remove(&peer);
        self.recovery_clients.remove(&peer);
        self.recovery_flights.retain(|flight| flight.peer != peer);
        if let Some(network) = self.network.recovery_mut() {
            network.disconnect_recovery_peer(peer);
        }
    }

    pub(super) fn handle_recovery_outbound(
        &mut self,
        index: usize,
        event: naome_network::StateEvent,
    ) -> Result<StateRuntimeEvent> {
        let flight = self.recovery_flights.swap_remove(index);
        let peer = flight.peer;
        let response = match flight.ticket.complete(event) {
            Ok(Ok(received)) => received.response().body().clone(),
            Ok(Err(_)) => {
                self.abandon_recovery_peer(peer);
                return Ok(StateRuntimeEvent::Network);
            }
            Err(_) => {
                return Err(StateRuntimeError::Transport(
                    "recovery ticket correlation mismatch".into(),
                ));
            }
        };
        match (flight.stage, response) {
            (
                RecoveryStage::Challenge,
                naome_protocol::state_exchange::StateResponseBody::RecoveryNonce(nonce),
            ) => {
                let setup = self
                    .handoff_setup
                    .as_ref()
                    .ok_or(StateRuntimeError::Configuration("recovery setup missing"))?;
                let key = setup
                    .recovery_key
                    .as_ref()
                    .ok_or(StateRuntimeError::Configuration("recovery key missing"))?;
                let context = self
                    .network
                    .state_context()
                    .ok_or(StateRuntimeError::Configuration("recovery context missing"))?;
                let hello =
                    naome_network::RecoveryHello::sign(context, peer, nonce, &setup.owner_key, key);
                let ticket = self.network.recovery_mut().and_then(|network| {
                    network
                        .request_recovery_state(
                            peer,
                            StateRequestBody::RecoveryHello(hello.encode().to_vec().into()),
                        )
                        .ok()
                });
                if let Some(ticket) = ticket {
                    self.recovery_flights.push(RecoveryFlight {
                        peer,
                        stage: RecoveryStage::Hello,
                        ticket,
                    });
                } else {
                    self.abandon_recovery_peer(peer);
                }
            }
            (RecoveryStage::Hello, naome_protocol::state_exchange::StateResponseBody::Accepted) => {
                self.recovery_authenticated.insert(peer);
                let from = self
                    .state()?
                    .height()
                    .checked_add(1)
                    .ok_or(StateRuntimeError::Configuration("height overflow"))?;
                if let Some(network) = self.network.recovery_mut()
                    && let Ok(ticket) = network.request_recovery_state(
                        peer,
                        StateRequestBody::History {
                            from,
                            max_records: 1,
                        },
                    )
                {
                    self.recovery_flights.push(RecoveryFlight {
                        peer,
                        stage: RecoveryStage::History,
                        ticket,
                    });
                }
            }
            (
                RecoveryStage::History,
                naome_protocol::state_exchange::StateResponseBody::History(items),
            ) => {
                let empty = items.is_empty();
                for item in items {
                    // Every item is independently authenticated against the
                    // selected historical parent before installation.
                    match self.receive_finality(&item.evidence) {
                        Ok(_) => {}
                        Err(error) if super::input::is_rejection(&error) => {
                            self.abandon_recovery_peer(peer);
                            return Ok(StateRuntimeEvent::Rejected {
                                peer,
                                reason: error.to_string(),
                            });
                        }
                        Err(error) => return Err(error),
                    }
                }
                // An ordinary selected validator can use its static lanes for
                // handoff. Do not hold a scarce recovery connection after a
                // peer confirms there is no missing history. A vacant owner
                // with a prepared offer may ask for a pending agreement; a
                // retired outgoing signer needs this lane to deliver its
                // durable TERMINAL even without an incoming offer.
                if empty
                    && !self.node.local_terminal_saved()
                    && (self.network.active().is_some()
                        || self
                            .next_custody
                            .as_ref()
                            .and_then(StatePeriodCustody::offer)
                            .is_none())
                {
                    self.abandon_recovery_peer(peer);
                    return Ok(StateRuntimeEvent::Network);
                }
                if self.node.handoff_agreement().is_none()
                    && self
                        .next_custody
                        .as_ref()
                        .and_then(StatePeriodCustody::offer)
                        .is_some()
                {
                    let height = self
                        .state()?
                        .height()
                        .checked_add(1)
                        .ok_or(StateRuntimeError::Configuration("height overflow"))?;
                    if let Some(network) = self.network.recovery_mut()
                        && let Ok(ticket) = network.request_recovery_state(
                            peer,
                            StateRequestBody::PendingAgreement { height },
                        )
                    {
                        self.recovery_flights.push(RecoveryFlight {
                            peer,
                            stage: RecoveryStage::PendingAgreement,
                            ticket,
                        });
                    }
                }
            }
            (
                RecoveryStage::PendingAgreement,
                naome_protocol::state_exchange::StateResponseBody::Agreement(Some(bytes)),
            ) => {
                if let Err(error) = self.node.accept_agreement(&bytes) {
                    if matches!(error, StateNodeError::Rejected(_)) {
                        self.abandon_recovery_peer(peer);
                        return Ok(StateRuntimeEvent::Rejected {
                            peer,
                            reason: error.to_string(),
                        });
                    }
                    return Err(StateRuntimeError::Node(error));
                }
            }
            (
                RecoveryStage::PendingAgreement,
                naome_protocol::state_exchange::StateResponseBody::Agreement(None),
            ) => {}
            (
                RecoveryStage::History | RecoveryStage::PendingAgreement,
                naome_protocol::state_exchange::StateResponseBody::Busy,
            ) => {}
            _ => {
                self.abandon_recovery_peer(peer);
            }
        }
        Ok(StateRuntimeEvent::Network)
    }
    /// Advance the selected agreement through durable incoming preparation and
    /// outgoing retirement. No provisional child can become a live signer here.
    pub(super) fn advance_handoff(&mut self) -> Result<()> {
        if self.state()?.terminated() {
            return Ok(());
        }
        let Some(agreement) = self.node.handoff_agreement().cloned() else {
            return Ok(());
        };
        let parent = self.state()?.clone();
        let record = StateRecord::decode(agreement.proposal().record_bytes(), parent.genesis())?;
        self.prepare_handoff_network(&parent, &record, &agreement)?;

        if let Some(custody) = &self.next_custody {
            let local_key = custody.consensus_key().verifying_key().to_bytes();
            if agreement.incoming().consensus_unit(&local_key).is_some()
                && self.network.staged().is_some()
            {
                let ready = self.node.sign_local_ready(custody.consensus_key())?;
                self.broadcast_handoff(StateRequestBody::ReadySignature(ready.encode().into()))?;
            }
        }

        if self.node.ready_signatures().len() >= 3
            && self.node.position()?.is_some()
            && !self.node.local_terminal_saved()
        {
            self.node.sign_local_terminal()?;
        }
        if self.node.local_terminal_saved() && !self.node.local_terminal_released() {
            self.retire_outgoing()?;
            let terminal = self.node.release_local_terminal()?;
            self.broadcast_handoff(StateRequestBody::TerminalSignature(
                terminal.encode().into(),
            ))?;
        }
        Ok(())
    }

    fn prepare_handoff_network(
        &mut self,
        parent: &LedgerState,
        record: &StateRecord,
        agreement: &naome_consensus::state::StateAgreement,
    ) -> Result<()> {
        if self.network.staged().is_some() {
            if self
                .network
                .staged()
                .and_then(StateNetwork::state_authority_id)
                != Some(agreement.incoming().id())
            {
                return Err(StateRuntimeError::Configuration(
                    "restored handoff transport authority mismatch",
                ));
            }
            if self
                .network
                .active()
                .zip(self.network.staged())
                .is_some_and(|(active, staged)| active.local_peer_id() == staged.local_peer_id())
            {
                if self.node.signer_key().is_some() {
                    return Err(StateRuntimeError::Configuration(
                        "active validator reused staged transport key",
                    ));
                }
                self.network.retire_old();
                self.flights.clear();
            }
            self.handoff_peers = handoff_peer_ids(agreement, record)?;
            return Ok(());
        }
        let Some(custody) = &self.next_custody else {
            return Ok(());
        };
        let local_transport = custody.transport_key().verifying_key().to_bytes();
        let offered = record
            .handoff_plan()
            .offers()
            .iter()
            .any(|offer| offer.keys().transport() == &local_transport)
            || record
                .handoff_plan()
                .candidate()
                .is_some_and(|offer| offer.keys().transport() == &local_transport);
        if !offered {
            return Ok(());
        }
        let mut seed = Zeroizing::new(custody.transport_key().to_bytes());
        let identity = Keypair::ed25519_from_bytes(&mut *seed)
            .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
        let mut staged = StateNetwork::new_staged(
            identity,
            parent,
            record.handoff_plan(),
            record.time_certificate(),
        )
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
        if staged.state_authority_id() != Some(agreement.incoming().id()) {
            return Err(StateRuntimeError::Configuration(
                "staged authority differs from agreement",
            ));
        }
        let setup = self
            .handoff_setup
            .as_ref()
            .ok_or(StateRuntimeError::Configuration("handoff setup missing"))?;
        let bind = if custody
            .offer()
            .is_some_and(|offer| offer.keys().endpoint() == setup.primary_endpoint)
            || custody
                .candidate_offer()
                .is_some_and(|offer| offer.keys().endpoint() == setup.primary_endpoint)
        {
            setup.primary_listen_address
        } else {
            setup.handoff_listen_address
        };
        let listen = match bind {
            Some(address) => listen_address(address)?,
            None => staged
                .state_listen_address()
                .ok_or(StateRuntimeError::Configuration("staged endpoint missing"))?
                .clone(),
        };
        if self
            .network
            .active()
            .is_some_and(|active| active.local_peer_id() == staged.local_peer_id())
        {
            // A queued candidate's courier uses the same registered key and
            // endpoint that becomes its prepared handoff identity. Release
            // that listener before binding the prepared lane.
            if self.node.signer_key().is_some() {
                return Err(StateRuntimeError::Configuration(
                    "active validator reused staged transport key",
                ));
            }
            self.network.retire_old();
            self.flights.clear();
        }
        staged
            .listen_on(listen)
            .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
        self.network
            .stage(staged)
            .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
        self.handoff_peers = handoff_peer_ids(agreement, record)?;
        self.apply_slot_disables()?;
        Ok(())
    }

    /// The old Noise sessions and locally controlled secret files are gone
    /// before the saved TERMINAL signature leaves the private journal.
    fn retire_outgoing(&mut self) -> Result<()> {
        self.network.retire_old();
        self.flights.clear();
        self.outbox.clear();
        self.sent.clear();
        self.acknowledged.clear();
        self.recovery_clients.clear();
        self.proof_fetches
            .iter_mut()
            .for_each(|fetch| fetch.ticket = None);
        // The public retirement audit reopens the custody journal. Release
        // this runtime's file lock before doing that read and deleting the
        // selected period's local secret.
        self.current_custody.take();
        if let Some(parent_height) = self.node.signer_parent_height()? {
            let setup = self
                .handoff_setup
                .as_ref()
                .ok_or(StateRuntimeError::Configuration("handoff setup missing"))?;
            if parent_height == 0 {
                retire_file(&setup.initial_consensus_key_path)?;
                retire_file(&setup.initial_transport_key_path)?;
            } else {
                self.node.retire_selected_custody(
                    &setup.custody_directory,
                    &setup.custody_anchor_directory,
                    &setup.owner_key,
                )?;
            }
        }
        Ok(())
    }

    /// Install only the successor already selected by durable sealed history.
    pub(super) fn activate_selected_period(&mut self) -> Result<()> {
        let selected = self.state()?.clone();
        let Some(setup) = &self.handoff_setup else {
            return Ok(());
        };
        // Every ticket belongs to a transport from the outgoing period. A
        // successful seal may already have retired the active lane, leaving
        // only staged tickets; retaining them would suppress new requests to
        // the same peer IDs after the staged lane becomes ordinary transport.
        self.flights.clear();
        self.proof_fetches
            .iter_mut()
            .for_each(|fetch| fetch.ticket = None);
        let setup_owner = setup.owner_key.clone();
        let signer_dir = setup.signer_directory.clone();
        let signer_anchor = setup.signer_anchor_directory.clone();
        let custody_dir = setup.custody_directory.clone();
        let custody_anchor = setup.custody_anchor_directory.clone();
        let handoff_dir = setup.handoff_directory.clone();
        let handoff_anchor = setup.handoff_anchor_directory.clone();
        let primary_endpoint = setup.primary_endpoint.clone();
        let handoff_endpoint = setup.handoff_endpoint.clone();
        let primary_bind = setup.primary_listen_address;
        let handoff_bind = setup.handoff_listen_address;
        let candidate_family = setup.candidate_family;
        let recovery_key = setup
            .recovery_key
            .clone()
            .ok_or(StateRuntimeError::Configuration("recovery key missing"))?;

        if self.network.active().is_some() {
            self.retire_outgoing()?;
        }
        if selected.terminated() {
            if let Some(custody) = self.next_custody.take() {
                custody.retire()?;
            } else {
                StatePeriodCustody::retire_terminal_selected(
                    &custody_dir,
                    &custody_anchor,
                    self.node.history(),
                    &setup_owner,
                )?;
            }
            let mut seed = Zeroizing::new(recovery_key.to_bytes());
            let identity = Keypair::ed25519_from_bytes(&mut *seed)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let recovery = StateNetwork::new_recovery_only(identity, &selected)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            self.network = StateTransportPair::from_recovery(recovery)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            listen_terminal_recovery(&mut self.network, &primary_endpoint, primary_bind)?;
            self.peers.clear();
            self.handoff_peers.clear();
            self.offers.clear();
            self.candidate_offers.clear();
            self.refresh_slot_proof_fetches()?;
            return Ok(());
        }
        let owner = AccountId::for_key(setup_owner.verifying_key().as_bytes());
        let local_unit = selected.authority().owner(owner);
        let selected_custody = if local_unit.is_some_and(|unit| unit.keys().is_some()) {
            match self.next_custody.take() {
                Some(custody) => Some(custody),
                None => StatePeriodCustody::open_for_selected(
                    &custody_dir,
                    &custody_anchor,
                    self.node.history(),
                    &setup_owner,
                )?,
            }
        } else {
            if let Some(unselected) = self.next_custody.take() {
                if unselected.candidate_offer().is_some() {
                    // The custody store verifies that this exact imported
                    // pair still belongs to a live queued claim before it
                    // can be reused for the new selected parent.
                    unselected.abandon_unselected_candidate(&selected)?;
                } else {
                    unselected.retire()?;
                }
            }
            None
        };
        if local_unit.is_some_and(|unit| unit.keys().is_some()) && selected_custody.is_none() {
            return Err(StateRuntimeError::Configuration(
                "selected local custody missing",
            ));
        }
        if let Some(custody) = selected_custody {
            let selected_keys =
                local_unit
                    .and_then(|unit| unit.keys())
                    .ok_or(StateRuntimeError::Configuration(
                        "selected local keys missing",
                    ))?;
            if custody.consensus_key().verifying_key().to_bytes() != *selected_keys.consensus()
                || custody.transport_key().verifying_key().to_bytes() != *selected_keys.transport()
            {
                return Err(StateRuntimeError::Configuration(
                    "selected local custody differs from authority",
                ));
            }
            if !self.network.try_promote_selected(&selected) {
                let mut seed = Zeroizing::new(custody.transport_key().to_bytes());
                let identity = Keypair::ed25519_from_bytes(&mut *seed)
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
                let active = StateNetwork::new_for_parent(identity, &selected)
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
                let endpoint = selected_keys.endpoint();
                let bind = if endpoint == primary_endpoint {
                    primary_bind
                } else {
                    handoff_bind
                };
                let listen = match bind {
                    Some(address) => listen_address(address)?,
                    None => active
                        .state_listen_address()
                        .ok_or(StateRuntimeError::Configuration("active endpoint missing"))?
                        .clone(),
                };
                // A different selected roster needs fresh static sessions.
                self.network = StateTransportPair::new(active)
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
                self.network
                    .active_mut()
                    .expect("selected network installed")
                    .listen_on(listen)
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            }
            self.current_custody = Some(custody);
        } else if let Some(family) =
            candidate_family.filter(|family| candidate_still_live(&selected, *family))
        {
            let candidate = StatePeriodCustody::stage_candidate(
                &custody_dir,
                &custody_anchor,
                &selected,
                family,
                &setup_owner,
            )?;
            let mut seed = Zeroizing::new(candidate.transport_key().to_bytes());
            let identity = Keypair::ed25519_from_bytes(&mut *seed)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let active = StateNetwork::new_for_parent(identity, &selected)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let endpoint = candidate
                .candidate_offer()
                .ok_or(StateRuntimeError::Configuration("candidate offer missing"))?
                .keys()
                .endpoint();
            let bind = if endpoint == primary_endpoint {
                primary_bind
            } else {
                handoff_bind
            };
            let listen = match bind {
                Some(address) => listen_address(address)?,
                None => active
                    .state_listen_address()
                    .ok_or(StateRuntimeError::Configuration(
                        "candidate endpoint missing",
                    ))?
                    .clone(),
            };
            self.network = StateTransportPair::new(active)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            self.network
                .active_mut()
                .expect("candidate network installed")
                .listen_on(listen)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            self.next_custody = Some(candidate);
        } else {
            let mut seed = Zeroizing::new(recovery_key.to_bytes());
            let identity = Keypair::ed25519_from_bytes(&mut *seed)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            let recovery = StateNetwork::new_recovery_only(identity, &selected)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
            self.network = StateTransportPair::from_recovery(recovery)
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?;
        }
        attach_recovery_network(&mut self.network, &selected, &recovery_key)?;
        self.apply_slot_disables()?;
        self.handoff_peers.clear();
        self.peers = selected
            .authority()
            .units()
            .iter()
            .filter_map(|unit| unit.keys())
            .map(|keys| {
                state_peer_id(*keys.transport())
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        if let Some(active) = self.network.active() {
            self.peers.retain(|peer| *peer != active.local_peer_id());
        } else {
            self.peers.clear();
        }
        self.refresh_slot_proof_fetches()?;
        if selected.terminated() {
            return Ok(());
        }
        let next_height = selected
            .height()
            .checked_add(1)
            .ok_or(StateRuntimeError::Configuration("height overflow"))?;
        let journal = StateHandoffJournal::open_or_create(
            &handoff_dir,
            &handoff_anchor,
            selected.genesis().clone(),
            next_height,
            self.node.maximum_round(),
            self.node.history(),
        )?;
        if let Some(custody) = self.current_custody.as_mut() {
            let signer = custody.open_or_create_selected_signer(
                &signer_dir,
                &signer_anchor,
                self.node.history(),
                self.node.maximum_round(),
            )?;
            self.node.install_selected_signer(signer, journal)?;
        } else {
            self.node.install_observer_period(journal)?;
        }
        let endpoint = local_unit.map(|unit| {
            if unit
                .keys()
                .is_some_and(|keys| keys.endpoint() == primary_endpoint)
            {
                handoff_endpoint
            } else {
                primary_endpoint
            }
        });
        self.offers.clear();
        self.candidate_offers.clear();
        if let Some((unit, endpoint)) = local_unit.zip(endpoint) {
            self.next_custody = Some(StatePeriodCustody::stage_offer(
                &custody_dir,
                &custody_anchor,
                &selected,
                unit.id(),
                &setup_owner,
                endpoint,
            )?);
        }
        if let Some(offer) = self
            .next_custody
            .as_ref()
            .and_then(StatePeriodCustody::offer)
        {
            self.accept_offer(&offer.encode())?;
        }
        if let Some(offer) = self
            .next_custody
            .as_ref()
            .and_then(StatePeriodCustody::candidate_offer)
        {
            self.accept_candidate_offer(&offer.encode())?;
        }
        Ok(())
    }
}

fn handoff_peer_ids(
    agreement: &naome_consensus::state::StateAgreement,
    record: &StateRecord,
) -> Result<Vec<PeerId>> {
    let mut peers = Vec::new();
    for unit in agreement.incoming().units() {
        if let Some(keys) = unit.keys() {
            peers.push(
                state_peer_id(*keys.transport())
                    .map_err(|error| StateRuntimeError::Transport(error.to_string()))?,
            );
        }
    }
    for offer in record.handoff_plan().offers() {
        peers.push(
            state_peer_id(*offer.keys().transport())
                .map_err(|error| StateRuntimeError::Transport(error.to_string()))?,
        );
    }
    peers.sort();
    peers.dedup();
    Ok(peers)
}

pub(super) fn listen_address(address: SocketAddr) -> Result<naome_network::Multiaddr> {
    let family = if address.is_ipv4() { "ip4" } else { "ip6" };
    format!("/{family}/{}/tcp/{}", address.ip(), address.port())
        .parse()
        .map_err(|_| StateRuntimeError::Configuration("invalid handoff bind address"))
}

fn retire_file(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StateRuntimeError::Transport(error.to_string())),
    }
    let directory = path
        .parent()
        .ok_or(StateRuntimeError::Configuration("key directory missing"))?;
    std::fs::File::open(directory)
        .and_then(|dir| dir.sync_all())
        .map_err(|error| StateRuntimeError::Transport(error.to_string()))
}
