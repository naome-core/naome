//! Cancellation-safe ownership and deterministic event-loop ordering.

use naome_consensus::{FixedValidatorLockPhaseV0, FixedValidatorProposalSourceV0};
use naome_network::{
    MAX_STATIC_PEERS, NetworkEvent, OutboundConsensusPushEvent, PeerId, StaticArtifactNetwork,
};
use naome_node::{
    FixedValidatorNodeCurrentRoundFinalityInboxDrainV0, FixedValidatorNodeCurrentRoundInboxDrainV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
    FixedValidatorNodeDriverAdmissionOutcomeV0 as AdmissionOutcome,
    FixedValidatorNodeDriverCommandV0 as Command, FixedValidatorNodeDriverEventV0 as DriverEvent,
    FixedValidatorNodeDriverProposalAuthoringOutcomeV0 as AuthoringOutcome,
    FixedValidatorNodeDriverStepOutcomeV0 as StepOutcome, FixedValidatorNodeDriverV0 as Driver,
    FixedValidatorNodeHigherRoundInboxDrainV0, FixedValidatorNodePhaseTimeoutV0,
};
use tokio::time::{Instant, sleep_until};

use crate::routing::{MessageRef, PreparedAdmission};
use crate::{
    FixedValidatorRuntimeAdmissionReportV0 as AdmissionReport,
    FixedValidatorRuntimeAdmissionResultV0 as AdmissionResult,
    FixedValidatorRuntimeCreateErrorV0 as CreateError,
    FixedValidatorRuntimeCreateFailureV0 as CreateFailure,
    FixedValidatorRuntimeDeliveryStateV0 as DeliveryState, FixedValidatorRuntimeEventV0 as Event,
    FixedValidatorRuntimeFailureV0 as Failure, FixedValidatorRuntimeInputSourceV0 as InputSource,
    FixedValidatorRuntimePartsV0 as Parts, FixedValidatorRuntimePublicationV0 as Publication,
    FixedValidatorRuntimeRoutingErrorV0 as RoutingError,
    FixedValidatorRuntimeTimeoutsV0 as Timeouts, FixedValidatorRuntimeTimerV0 as Timer,
};

/// One process-local driver/network owner with bounded publication backpressure.
///
/// Each `next_event` returns at most one visible result. Dropping its borrowed
/// future preserves all stored custody; it does not cancel a transport request.
/// Only the caller may dispose of returned events or tear down this owner. No
/// inbox is silently drained, no failed send is retried, and publication waits
/// prevent a second signed publication from being released by this owner.
#[must_use]
pub struct FixedValidatorRuntimeV0<'node> {
    driver: Option<Driver<'node>>,
    network: StaticArtifactNetwork,
    peers: Vec<PeerId>,
    timeouts: Timeouts,
    timer: Option<Timer>,
    pending_arm: Option<FixedValidatorNodePhaseTimeoutV0>,
    publication: Option<Publication>,
    pending_network_event: Option<NetworkEvent>,
    failed_admission: Option<AdmissionReport>,
    step_yielded: bool,
    rejected_due_ticket: Option<FixedValidatorNodePhaseTimeoutV0>,
}

impl<'node> FixedValidatorRuntimeV0<'node> {
    /// Preflights every peer and the complete driver-local round ceiling before
    /// assuming custody. Rejection returns all inputs without any driver step.
    pub fn new(
        driver: Driver<'node>,
        network: StaticArtifactNetwork,
        peers: Vec<PeerId>,
        timeouts: Timeouts,
    ) -> Result<Self, Box<CreateError<'node>>> {
        let reason = Self::preflight(&driver, &network, &peers, timeouts);
        if let Some(reason) = reason {
            return Err(Box::new(CreateError {
                driver,
                network,
                peers,
                timeouts,
                reason,
            }));
        }
        Ok(Self {
            driver: Some(driver),
            network,
            peers,
            timeouts,
            timer: None,
            pending_arm: None,
            publication: None,
            pending_network_event: None,
            failed_admission: None,
            step_yielded: false,
            rejected_due_ticket: None,
        })
    }

    fn preflight(
        driver: &Driver<'_>,
        network: &StaticArtifactNetwork,
        peers: &[PeerId],
        timeouts: Timeouts,
    ) -> Option<CreateFailure> {
        if peers.len() > MAX_STATIC_PEERS {
            return Some(CreateFailure::TooManyPeers {
                actual: peers.len(),
                maximum: MAX_STATIC_PEERS,
            });
        }
        for (index, peer) in peers.iter().enumerate() {
            if peers[..index].contains(peer) {
                return Some(CreateFailure::DuplicatePeer(*peer));
            }
            if !network.is_configured_peer(peer) {
                return Some(CreateFailure::UnconfiguredPeer(*peer));
            }
        }
        let now = Instant::now();
        for phase in [
            FixedValidatorLockPhaseV0::Proposal,
            FixedValidatorLockPhaseV0::Prevote,
            FixedValidatorLockPhaseV0::Precommit,
        ] {
            match timeouts.duration(phase, driver.inclusive_maximum_round()) {
                Err(error) => return Some(CreateFailure::Timing(error)),
                Ok(duration) if now.checked_add(duration).is_none() => {
                    return Some(CreateFailure::Timing(
                        crate::FixedValidatorRuntimeTimingErrorV0::DeadlineOverflow,
                    ));
                }
                Ok(_) => {}
            }
        }
        None
    }

    /// Read-only driver diagnostics; no mutable signer or scope is exposed.
    pub fn driver(&self) -> Option<&Driver<'node>> {
        self.driver.as_ref()
    }
    pub const fn timer(&self) -> Option<Timer> {
        self.timer
    }
    pub fn local_peer_id(&self) -> PeerId {
        self.network.local_peer_id()
    }
    pub fn pending_publication(&self) -> Option<&Publication> {
        self.publication.as_ref()
    }
    pub fn failed_admission(&self) -> Option<&AdmissionReport> {
        self.failed_admission.as_ref()
    }

    /// Explicitly transfers every retained higher-round input and clears only
    /// that inbox's blocking state. The same deadline becomes observable again
    /// if the higher block previously rejected its due ticket; it is not reset.
    /// All other driver and runtime custody stays owned here.
    /// Returns `None` without mutation when no driver survives.
    pub fn drain_inbox_and_reset(&mut self) -> Option<FixedValidatorNodeHigherRoundInboxDrainV0> {
        let (driver, drained) = self.driver.take()?.drain_inbox_and_reset().into_parts();
        self.driver = Some(*driver);
        self.step_yielded = false;
        self.rejected_due_ticket = None;
        Some(drained)
    }

    /// Explicitly transfers every retained current proposal and prevote and
    /// clears only current-voting blocking. Re-enables ordinary classification
    /// without changing the due fence, deadline, other inboxes, or publication.
    /// Returns `None` without mutation when no driver survives.
    pub fn drain_current_inbox_and_reset(
        &mut self,
    ) -> Option<FixedValidatorNodeCurrentRoundInboxDrainV0> {
        let (driver, drained) = self
            .driver
            .take()?
            .drain_current_inbox_and_reset()
            .into_parts();
        self.driver = Some(*driver);
        self.step_yielded = false;
        Some(drained)
    }

    /// Explicitly transfers every retained current-finality input and clears
    /// only its capacity state. Re-enables ordinary classification while all
    /// other driver and runtime custody, including the deadline, stays intact.
    /// Returns `None` without mutation when no driver survives.
    pub fn drain_current_finality_inbox_and_reset(
        &mut self,
    ) -> Option<FixedValidatorNodeCurrentRoundFinalityInboxDrainV0> {
        let (driver, drained) = self
            .driver
            .take()?
            .drain_current_finality_inbox_and_reset()
            .into_parts();
        self.driver = Some(*driver);
        self.step_yielded = false;
        Some(drained)
    }

    /// Explicitly transfers every retained nil precommit and clears only that
    /// inbox's capacity state. Re-enables ordinary classification while all
    /// other driver and runtime custody, including the deadline, stays intact.
    /// Returns `None` without mutation when no driver survives.
    pub fn drain_current_nil_precommit_inbox_and_reset(
        &mut self,
    ) -> Option<FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0> {
        let (driver, drained) = self
            .driver
            .take()?
            .drain_current_nil_precommit_inbox_and_reset()
            .into_parts();
        self.driver = Some(*driver);
        self.step_yielded = false;
        Some(drained)
    }

    /// Polls transport once without admitting input, observing a timer, stepping
    /// the driver, or starting a send. At most one returned network event is
    /// buffered. This can service queued receipts while the caller holds driver
    /// work; only the peer's correlated receipt proves transport completion.
    pub async fn poll_transport_once(&mut self) -> crate::FixedValidatorRuntimeTransportPollV0 {
        use crate::FixedValidatorRuntimeTransportPollV0 as Outcome;
        use std::{future::Future, task::Poll};
        if self.pending_network_event.is_some() {
            return Outcome::InputSlotOccupied;
        }
        let event = std::future::poll_fn(|cx| {
            let mut future = std::pin::pin!(self.network.next_event());
            Poll::Ready(match future.as_mut().poll(cx) {
                Poll::Ready(event) => Some(event),
                Poll::Pending => None,
            })
        })
        .await;
        if let Some(event) = event {
            self.pending_network_event = Some(event);
            Outcome::BufferedEvent
        } else {
            Outcome::PolledPending
        }
    }

    /// Explicitly transfers every surviving owner; queued sends are not cancelled.
    pub fn into_parts(self) -> Parts<'node> {
        Parts {
            driver: self.driver,
            network: self.network,
            peers: self.peers,
            timeouts: self.timeouts,
            timer: self.timer,
            pending_arm: self.pending_arm,
            publication: self.publication,
            pending_network_event: self.pending_network_event,
            failed_admission: self.failed_admission,
            step_yielded: self.step_yielded,
            rejected_due_ticket: self.rejected_due_ticket,
        }
    }

    fn arm(&mut self) -> Event<'node> {
        let ticket = self.pending_arm.expect("one exact arm is retained");
        match Timer::new(ticket, Instant::now(), self.timeouts) {
            Ok(timer) => {
                self.pending_arm = None;
                self.timer = Some(timer);
                self.rejected_due_ticket = None;
                Event::TimerArmed(timer)
            }
            Err(error) => Event::TimingRejected(error),
        }
    }

    fn discard_superseded_deadline(&mut self) {
        let active = self.driver.as_ref().and_then(Driver::active_timeout);
        if self
            .timer
            .is_some_and(|timer| Some(timer.ticket()) != active)
        {
            self.timer = None;
        }
        if self.rejected_due_ticket != active {
            self.rejected_due_ticket = None;
        }
    }

    /// Authors only the caller's explicit direct source through the existing
    /// driver gate. Runtime backpressure or an observed deadline returns the
    /// source intact. Once forwarded, the existing driver consumes the source
    /// on every outcome, including retained-work and semantic rejection.
    pub fn author_proposal(&mut self, source: FixedValidatorProposalSourceV0) -> Event<'node> {
        let Some(driver) = self.driver.as_ref() else {
            return Event::AuthoringUnavailable(source);
        };
        if self.publication.is_some()
            || self.pending_arm.is_some()
            || self.pending_network_event.is_some()
            || self.timer.is_none()
            || driver.has_pending_command()
            || driver.timeout_is_due()
            || self
                .timer
                .is_some_and(|timer| Instant::now() >= timer.deadline())
        {
            return Event::AuthoringBusy(source);
        }
        let driver = self.driver.take().unwrap();
        match driver.author_proposal(source) {
            Ok(AuthoringOutcome::Authored { driver }) => {
                self.driver = Some(*driver);
                Event::ProposalAuthored
            }
            Ok(
                AuthoringOutcome::CommandPending { driver }
                | AuthoringOutcome::StepWorkPending { driver },
            ) => {
                self.driver = Some(*driver);
                Event::AuthoringStepWorkPending
            }
            Ok(AuthoringOutcome::Rejected { driver, rejection }) => {
                self.driver = Some(*driver);
                Event::ProposalRejected(rejection)
            }
            Ok(AuthoringOutcome::SignerStopped(halt)) => {
                Event::Fatal(Box::new(Failure::ProposalSignerStopped(halt)))
            }
            Ok(other) => Event::UnsupportedAuthoring(Box::new(other)),
            Err(error) => Event::Fatal(Box::new(Failure::Step(error))),
        }
    }

    fn step_driver(&mut self) -> Option<Event<'node>> {
        self.step_yielded = false;
        let driver = self.driver.take().expect("live owner has one driver");
        let outcome = match driver.step() {
            Ok(outcome) => outcome,
            Err(error) => return Some(Event::Fatal(Box::new(Failure::Step(error)))),
        };
        let event = match outcome {
            StepOutcome::Command { driver, command } => {
                self.driver = Some(*driver);
                match command {
                    Command::ArmPhaseTimeout(ticket) => {
                        self.pending_arm = Some(ticket);
                        self.arm()
                    }
                    command => match Publication::from_command(command, &self.peers) {
                        Ok(publication) if self.publication.is_none() => {
                            let size = publication.message().size();
                            self.publication = Some(publication);
                            Event::PublicationPrepared(size)
                        }
                        Ok(_) => {
                            unreachable!("only the successor arm can follow an owned publication")
                        }
                        Err(command) => Event::UnsupportedCommand(command),
                    },
                }
            }
            StepOutcome::Transitioned { driver } => {
                let position = driver.position();
                let phase = driver.phase();
                self.driver = Some(*driver);
                Event::Transitioned { position, phase }
            }
            StepOutcome::Finality { driver, selection } => {
                self.driver = Some(*driver);
                Event::Finality(selection)
            }
            StepOutcome::Idle { driver } => {
                self.driver = Some(*driver);
                return None;
            }
            StepOutcome::Blocked { driver, reason } => {
                self.step_yielded = true;
                self.driver = Some(*driver);
                Event::DriverBlocked(reason)
            }
            StepOutcome::Rejected { driver, rejection } => {
                self.step_yielded = true;
                self.driver = Some(*driver);
                Event::DriverRejected(rejection)
            }
            StepOutcome::SignerStopped(halt) => {
                Event::Fatal(Box::new(Failure::VoteSignerStopped(halt)))
            }
            StepOutcome::FinalityStopped(halt) => {
                Event::Fatal(Box::new(Failure::FinalityStopped(halt)))
            }
            other => Event::UnsupportedStep(Box::new(other)),
        };
        self.discard_superseded_deadline();
        Some(event)
    }

    fn start_next_peer(&mut self) -> Option<Event<'node>> {
        let publication = self.publication.as_mut().unwrap();
        let delivery = publication
            .deliveries
            .iter_mut()
            .flatten()
            .find(|delivery| matches!(delivery.state, DeliveryState::NotAttempted))?;
        let message = match publication.message.copy_message() {
            Ok(message) => message,
            Err(error) => return Some(Event::ReservationFailed(error)),
        };
        let peer_id = delivery.peer_id;
        let started = match self.network.push_consensus(peer_id, message) {
            Ok(ticket) => {
                delivery.state = DeliveryState::InFlight(ticket);
                true
            }
            Err(error) => {
                let (_, reason) = error.into_parts();
                delivery.state = DeliveryState::Refused(reason);
                false
            }
        };
        Some(Event::PeerAttempted { peer_id, started })
    }

    fn complete_peer(&mut self, event: OutboundConsensusPushEvent) -> Event<'node> {
        let delivery = self.publication.as_mut().and_then(|publication| {
            publication.deliveries.iter_mut().flatten().find(|delivery| {
                matches!(&delivery.state, DeliveryState::InFlight(ticket) if ticket.accepts_event(&event))
            })
        });
        let Some(delivery) = delivery else {
            return Event::Network(NetworkEvent::OutboundConsensusPush(event));
        };
        let DeliveryState::InFlight(ticket) =
            std::mem::replace(&mut delivery.state, DeliveryState::NotAttempted)
        else {
            unreachable!("matched an in-flight ticket")
        };
        let received = match ticket.complete(event) {
            Ok(Ok(receipt)) => {
                delivery.state = DeliveryState::Received(receipt);
                true
            }
            Ok(Err(error)) => {
                delivery.state = DeliveryState::Failed(error);
                false
            }
            Err(mismatch) => {
                let (ticket, event) = mismatch.into_parts();
                delivery.state = DeliveryState::InFlight(ticket);
                return Event::Network(NetworkEvent::OutboundConsensusPush(event));
            }
        };
        Event::PeerCompleted {
            peer_id: delivery.peer_id,
            received,
        }
    }

    fn observe_due(&mut self) -> Event<'node> {
        let ticket = self.timer.expect("one deadline is being observed").ticket();
        let driver = self
            .driver
            .take()
            .expect("one live driver owns the deadline");
        match driver.admit_event(DriverEvent::TimeoutDue(ticket)) {
            Ok(AdmissionOutcome::Admitted {
                driver,
                disposition,
            }) => {
                self.driver = Some(*driver);
                self.timer = None;
                self.step_yielded = false;
                self.rejected_due_ticket = None;
                Event::TimerDue {
                    ticket,
                    result: Ok(disposition),
                }
            }
            Ok(AdmissionOutcome::Rejected {
                driver, rejection, ..
            }) => {
                self.driver = Some(*driver);
                // This monotone higher-inbox block already denies every ordinary
                // voting input. Preserve the expired deadline but permit strict
                // finality escape admission without continuously re-yielding it.
                if matches!(
                    *rejection,
                    naome_node::FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(_)
                ) {
                    self.rejected_due_ticket = Some(ticket);
                }
                Event::TimerDue {
                    ticket,
                    result: Err(rejection),
                }
            }
            Ok(other) => Event::UnsupportedAdmission(Box::new(other)),
            Err(error) => Event::Fatal(Box::new(Failure::Admission(error))),
        }
    }

    fn apply_prepared(
        &mut self,
        prepared: PreparedAdmission,
        mut report: AdmissionReport,
    ) -> Event<'node> {
        for (index, (event, route)) in prepared.events.into_iter().zip(prepared.routes).enumerate()
        {
            let (Some(event), Some(route)) = (event, route) else {
                continue;
            };
            let driver = self
                .driver
                .take()
                .expect("admission owns the sole live driver");
            let result = match driver.admit_event(event) {
                Ok(AdmissionOutcome::Admitted {
                    driver,
                    disposition,
                }) => {
                    self.driver = Some(*driver);
                    Ok(disposition)
                }
                Ok(AdmissionOutcome::Rejected {
                    driver, rejection, ..
                }) => {
                    self.driver = Some(*driver);
                    Err(rejection)
                }
                Ok(other) => {
                    self.failed_admission = Some(report);
                    return Event::UnsupportedAdmission(Box::new(other));
                }
                Err(error) => {
                    self.failed_admission = Some(report);
                    return Event::Fatal(Box::new(Failure::Admission(error)));
                }
            };
            self.step_yielded = false;
            report.results[index] = Some(AdmissionResult { route, result });
            // No step or timer observation occurs between the two admissions.
        }
        report.completed = true;
        Event::Admission(Box::new(report))
    }

    fn admit_local_publication(&mut self) -> Event<'node> {
        let driver = self.driver.as_ref().unwrap();
        let publication = self.publication.as_mut().unwrap();
        let prepared = publication
            .message
            .as_message()
            .prepare(driver.context(), driver.position());
        if let Err(RoutingError::Reservation(error)) = prepared {
            return Event::ReservationFailed(error);
        }
        publication.locally_admitted = true;
        let mut report = AdmissionReport {
            source: InputSource::LocalPublication,
            receipt_queued: None,
            input: None,
            results: [None, None],
            routing_error: None,
            completed: false,
        };
        match prepared {
            Ok(prepared) => self.apply_prepared(prepared, report),
            Err(error) => {
                report.routing_error = Some(error);
                Event::Admission(Box::new(report))
            }
        }
    }

    fn handle_network_event(&mut self, event: NetworkEvent) -> Event<'node> {
        let inbound = match event {
            NetworkEvent::InboundConsensusPush(inbound) => inbound,
            NetworkEvent::OutboundConsensusPush(event) => return self.complete_peer(event),
            other => return Event::Network(other),
        };
        let driver = self
            .driver
            .as_ref()
            .expect("network input requires the live owner");
        let prepared =
            MessageRef::from(inbound.message()).prepare(driver.context(), driver.position());
        if let Err(RoutingError::Reservation(error)) = prepared {
            return Event::UnacknowledgedInput { inbound, error };
        }
        // Copy reservation precedes receipt transfer; closed channels still
        // return the exact source and original input allocations.
        let (received, receipt_queued) = match self.network.acknowledge_consensus_push(inbound) {
            Ok(received) => (received, true),
            Err(error) => (error.into_received(), false),
        };
        let (peer_id, input) = received.into_parts();
        let mut report = AdmissionReport {
            source: InputSource::Peer(peer_id),
            receipt_queued: Some(receipt_queued),
            input: Some(input),
            results: [None, None],
            routing_error: None,
            completed: false,
        };
        match prepared {
            Ok(prepared) => self.apply_prepared(prepared, report),
            Err(error) => {
                report.routing_error = Some(error);
                Event::Admission(Box::new(report))
            }
        }
    }

    /// Advances pending commands and retained driver work before observing new
    /// input. A ready exact timer wins a tie with a newly obtained network event.
    /// One publication backpressures further driver transitions until its local
    /// admission and each one-shot peer attempt have completed and transferred.
    pub async fn next_event(&mut self) -> Event<'node> {
        if self.driver.is_none() {
            return Event::DriverUnavailable;
        }
        if self.pending_arm.is_some() {
            return self.arm();
        }
        if self.publication.is_some() {
            if self.driver.as_ref().unwrap().has_pending_command() {
                return self
                    .step_driver()
                    .expect("a pending command transfers without an idle step");
            }
            if !self.publication.as_ref().unwrap().locally_admitted {
                return self.admit_local_publication();
            }
            if self.publication.as_ref().unwrap().is_complete() {
                return Event::PublicationComplete(Box::new(self.publication.take().unwrap()));
            }
            if self.pending_network_event.is_none()
                && let Some(event) = self.start_next_peer()
            {
                return event;
            }
            let event = match self.poll_network_or_due().await {
                Ok(event) => event,
                Err(event) => return event,
            };
            return self.handle_network_event(event);
        }
        if (self.driver.as_ref().unwrap().has_pending_command() || !self.step_yielded)
            && let Some(event) = self.step_driver()
        {
            return event;
        }
        let driver = self.driver.as_ref().unwrap();
        if self.timer.is_none()
            && !driver.timeout_is_due()
            && let Some(ticket) = driver.active_timeout()
        {
            self.pending_arm = Some(ticket);
            return self.arm();
        }
        match self.poll_network_or_due().await {
            Ok(event) => self.handle_network_event(event),
            Err(event) => event,
        }
    }

    fn observable_timer(&self) -> Option<Timer> {
        self.timer
            .filter(|timer| Some(timer.ticket()) != self.rejected_due_ticket)
    }

    async fn poll_network_or_due(&mut self) -> Result<NetworkEvent, Event<'node>> {
        if self
            .observable_timer()
            .is_some_and(|timer| Instant::now() >= timer.deadline())
        {
            return Err(self.observe_due());
        }
        let event = if let Some(event) = self.pending_network_event.take() {
            event
        } else if let Some(timer) = self.observable_timer() {
            tokio::select! {
                biased;
                _ = sleep_until(timer.deadline()) => return Err(self.observe_due()),
                event = self.network.next_event() => event,
            }
        } else {
            self.network.next_event().await
        };
        // The clock may have crossed its deadline during network polling.
        if self
            .observable_timer()
            .is_some_and(|timer| Instant::now() >= timer.deadline())
        {
            self.pending_network_event = Some(event);
            return Err(self.observe_due());
        }
        Ok(event)
    }
}
