//! One volatile proof owner: one bounded pass, or explicit periodic following.
use super::{Result, config, report};
use naome_consensus::{ConsensusHeight, UnverifiedFixedConsensusProposalRouteV0};
use naome_network::{
    ConsensusPushMessage, FinalityProofRequest, FinalityProofResponse, FinalityProofTicket,
    OutboundFinalityProofEvent, OutboundFinalityProofFailure, PeerId, RequestStartError,
};
use naome_runtime::{
    FixedValidatorRuntimeEventV0 as Event,
    FixedValidatorRuntimeFinalityProofRequestErrorV0 as RequestError,
    FixedValidatorRuntimeProofRefusalV0 as Refusal, FixedValidatorRuntimeV0 as Runtime,
};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct ProofSync {
    id: u64,
    peer: PeerId,
    count: u64,
    interval: Option<Duration>,
    state: State,
}

enum State {
    Waiting(Instant),
    Active(Pass),
}

struct Pass {
    next: u64,
    last: u64,
    completed: u64,
    deadline: Instant,
    ticket: Option<FinalityProofTicket>,
}

struct Failure {
    code: &'static str,
    retry: bool,
}
impl Failure {
    fn retry(code: &'static str) -> Self {
        Self { code, retry: true }
    }
    fn stop(code: &'static str) -> Self {
        Self { code, retry: false }
    }
}

impl ProofSync {
    fn peer(peer: &str, count: u64) -> Result<PeerId> {
        if !(1..=16).contains(&count) {
            return Err("sync_count");
        }
        peer.parse().map_err(|_| "peer_id")
    }

    pub fn start(id: u64, peer: &str, count: u64, runtime: &mut Runtime<'_>) -> Result<Self> {
        let peer = Self::peer(peer, count)?;
        let pass = Pass::start(peer, count, runtime).map_err(|failure| failure.code)?;
        Ok(Self {
            id,
            peer,
            count,
            interval: None,
            state: State::Active(pass),
        })
    }

    pub fn follow(
        id: u64,
        peer: &str,
        count: u64,
        millis: &str,
        runtime: &Runtime<'_>,
    ) -> Result<Self> {
        let peer = Self::peer(peer, count)?;
        let millis = config::decimal::<u64>(millis).map_err(|_| "follow_interval")?;
        if millis == 0 {
            return Err("follow_interval");
        }
        let interval = Duration::from_millis(millis);
        let due = Instant::now()
            .checked_add(interval)
            .ok_or("follow_deadline_overflow")?;
        if !runtime.is_configured_peer(&peer) {
            return Err("follow_peer_not_configured");
        }
        runtime.driver().ok_or("driver_unavailable")?;
        Ok(Self {
            id,
            peer,
            count,
            interval: Some(interval),
            state: State::Waiting(due),
        })
    }

    pub fn active(&self) -> bool {
        matches!(self.state, State::Active(_))
    }

    pub fn deadline(&self) -> Instant {
        match &self.state {
            State::Waiting(due) => *due,
            State::Active(pass) => pass.deadline,
        }
    }

    pub fn status(&self) -> Value {
        let mut status = match &self.state {
            State::Active(pass) => {
                json!({"id": self.id, "peer_id": self.peer.to_string(), "next_height": pass.next.to_string(), "last_height": pass.last.to_string(), "completed": pass.completed.to_string()})
            }
            State::Waiting(_) => {
                json!({"id": self.id, "peer_id": self.peer.to_string(), "state": "waiting"})
            }
        };
        if let Some(interval) = self.interval {
            status["following"] = json!(true);
            status["interval_millis"] = json!(interval.as_millis().to_string());
            status["count"] = json!(self.count);
            if self.active() {
                status["state"] = json!("active");
            }
        }
        status
    }

    fn pass_stopped(&self, reason: &'static str, output: &report::Output) -> Result<()> {
        output.emit(
            json!({"event":"sync_stopped", "id":self.id, "reason":reason, "job":self.status()}),
        )
    }

    pub fn stopped(&self, reason: &'static str, output: &report::Output) -> Result<()> {
        self.pass_stopped(reason, output)?;
        if self.interval.is_some() {
            output.emit(json!({"event":"follow_stopped", "id":self.id, "reason":reason, "job":self.status()}))?;
        }
        Ok(())
    }

    fn finish(mut self, failure: Option<Failure>, output: &report::Output) -> Result<Option<Self>> {
        if let Some(failure) = &failure {
            self.pass_stopped(failure.code, output)?;
        }
        let reason = failure
            .as_ref()
            .map_or("pass_completed", |failure| failure.code);
        if let Some(interval) = self.interval {
            if failure.as_ref().is_none_or(|failure| failure.retry) {
                if let Some(due) = Instant::now().checked_add(interval) {
                    // Dropping the old pass also disposes its exact outstanding
                    // ticket. A late terminal cannot satisfy the next generation.
                    self.state = State::Waiting(due);
                    output.emit(json!({"event":"follow_waiting", "id":self.id, "reason":reason, "job":self.status()}))?;
                    return Ok(Some(self));
                }
                self.stopped("follow_deadline_overflow", output)?;
            } else {
                output.emit(json!({"event":"follow_stopped", "id":self.id, "reason":reason, "job":self.status()}))?;
            }
        }
        Ok(None)
    }

    pub fn changed(&self, runtime: &Runtime<'_>) -> bool {
        match &self.state {
            State::Waiting(_) => false,
            State::Active(pass) => runtime
                .driver()
                .is_none_or(|driver| driver.position().height().value() != pass.next),
        }
    }

    pub fn head_changed(self, output: &report::Output) -> Result<Option<Self>> {
        self.finish(Some(Failure::retry("sync_head_changed")), output)
    }

    pub fn accepts(&self, event: &OutboundFinalityProofEvent) -> bool {
        match &self.state {
            State::Waiting(_) => false,
            State::Active(pass) => pass
                .ticket
                .as_ref()
                .is_some_and(|ticket| ticket.accepts_event(event)),
        }
    }

    pub fn elapsed(
        mut self,
        runtime: &mut Runtime<'_>,
        acquiring: bool,
        output: &report::Output,
    ) -> Result<Option<Self>> {
        if self.active() {
            return self.finish(Some(Failure::retry("network_deadline")), output);
        }
        if acquiring {
            return self.finish(Some(Failure::retry("sources_busy")), output);
        }
        match Pass::start(self.peer, self.count, runtime) {
            Ok(pass) => {
                self.state = State::Active(pass);
                output.emit(
                    json!({"event":"sync_pass_started", "id":self.id, "job":self.status()}),
                )?;
                Ok(Some(self))
            }
            Err(failure) => self.finish(Some(failure), output),
        }
    }

    /// Only ordinary runtime scheduling transfers the child arm. Neither a
    /// follower tick nor a successful proof steps the driver internally.
    pub fn successor(
        mut self,
        runtime: &mut Runtime<'_>,
        output: &report::Output,
    ) -> Result<Option<Self>> {
        let State::Active(pass) = &mut self.state else {
            return Ok(Some(self));
        };
        let failure = if Instant::now() >= pass.deadline {
            Some(Failure::retry("network_deadline"))
        } else if pass.ticket.is_none() {
            pass.request(self.peer, runtime).err()
        } else {
            None
        };
        match failure {
            Some(failure) => self.finish(Some(failure), output),
            None => Ok(Some(self)),
        }
    }

    pub fn complete<'node>(
        mut self,
        event: OutboundFinalityProofEvent,
        runtime: &mut Runtime<'node>,
        output: &report::Output,
        supply_missing_proposal: bool,
    ) -> Result<(Option<Self>, Option<Event<'node>>)> {
        let failure = if Instant::now() >= self.deadline() {
            Some(Failure::retry("network_deadline"))
        } else if self.changed(runtime) {
            Some(Failure::retry("sync_head_changed"))
        } else {
            None
        };
        if let Some(failure) = failure {
            return Ok((self.finish(Some(failure), output)?, None));
        }
        let State::Active(pass) = &mut self.state else {
            return Err("sync_correlation");
        };
        let ticket = pass.ticket.take().ok_or("sync_correlation")?;
        let response = ticket.complete(event).map_err(|_| "sync_correlation")?;
        let response = match response {
            Ok(response) => response,
            Err(error) => {
                let failure = match *error {
                    _ if error.is_invalid_response() => Failure::stop("transport_failure"),
                    OutboundFinalityProofFailure::Transport(_) => {
                        Failure::retry("transport_failure")
                    }
                    _ => Failure::stop("transport_failure"),
                };
                return Ok((self.finish(Some(failure), output)?, None));
            }
        };
        let FinalityProofResponse::Found {
            canonical_envelope,
            canonical_artifact,
        } = response.into_response()
        else {
            return Ok((
                self.finish(Some(Failure::retry("unavailable")), output)?,
                None,
            ));
        };
        // Preserve one bounded raw proposal only for the autonomous owner.
        // Queueing it below never counts as verified proof or finality progress.
        let proposal = supply_missing_proposal.then(|| {
            UnverifiedFixedConsensusProposalRouteV0::proposal_control_from_envelope(
                &canonical_envelope,
            )
            .map(|canonical_proposal| ConsensusPushMessage::Proposal {
                canonical_proposal,
                canonical_artifact: canonical_artifact.clone(),
            })
        });
        let event = match runtime.commit_finality_envelope(&canonical_envelope, canonical_artifact)
        {
            Ok(event) => event,
            Err((reason, _payload)) => {
                let failure = match reason {
                    Refusal::Busy => Failure::retry("proof_backpressure"),
                    Refusal::DriverUnavailable => Failure::stop("proof_backpressure"),
                };
                return Ok((self.finish(Some(failure), output)?, None));
            }
        };
        if !matches!(&event, Event::Finality(_)) {
            if matches!(&event, Event::CurrentFinalityUnresolved)
                && let Some(Ok(proposal)) = proposal
            {
                let queued = runtime.queue_input(proposal).is_ok();
                output
                    .emit(json!({"event":"sync_proposal_input", "id":self.id, "queued":queued}))?;
            }
            let failure = if matches!(
                &event,
                Event::ExplicitCommandPending | Event::CurrentFinalityUnresolved
            ) {
                Failure::retry("proof_not_committed")
            } else {
                Failure::stop("proof_not_committed")
            };
            return Ok((self.finish(Some(failure), output)?, Some(event)));
        }
        pass.completed += 1;
        output.emit(json!({"event":"sync_progress", "id":self.id, "height":pass.next.to_string(), "completed":pass.completed.to_string()}))?;
        if pass.next == pass.last {
            output.emit(json!({"event":"sync_completed", "id":self.id, "completed":pass.completed.to_string(), "last_height":pass.last.to_string()}))?;
            return Ok((self.finish(None, output)?, Some(event)));
        }
        pass.next += 1;
        if Instant::now() >= pass.deadline {
            return Ok((
                self.finish(Some(Failure::retry("network_deadline")), output)?,
                Some(event),
            ));
        }
        Ok((Some(self), Some(event)))
    }
}

impl Pass {
    fn start(
        peer: PeerId,
        count: u64,
        runtime: &mut Runtime<'_>,
    ) -> std::result::Result<Self, Failure> {
        let driver = runtime
            .driver()
            .ok_or_else(|| Failure::stop("driver_unavailable"))?;
        let next = driver.position().height().value();
        let last = next
            .checked_add(count - 1)
            .ok_or_else(|| Failure::stop("sync_height_overflow"))?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(120))
            .ok_or_else(|| Failure::stop("sync_deadline_overflow"))?;
        let mut pass = Self {
            next,
            last,
            completed: 0,
            deadline,
            ticket: None,
        };
        pass.request(peer, runtime)?;
        Ok(pass)
    }

    fn request(
        &mut self,
        peer: PeerId,
        runtime: &mut Runtime<'_>,
    ) -> std::result::Result<(), Failure> {
        let driver = runtime
            .driver()
            .ok_or_else(|| Failure::stop("driver_unavailable"))?;
        if driver.position().height().value() != self.next {
            return Err(Failure::retry("sync_head_changed"));
        }
        let request = FinalityProofRequest::new(driver.context(), ConsensusHeight::new(self.next))
            .ok_or_else(|| Failure::stop("sync_height"))?;
        self.ticket = Some(
            runtime
                .request_finality_proof(peer, request)
                .map_err(|error| match error {
                    RequestError::Refused(Refusal::Busy)
                    | RequestError::Network(
                        RequestStartError::AlreadyPending(_)
                        | RequestStartError::PeerDisconnected(_)
                        | RequestStartError::GlobalLimit { .. },
                    ) => Failure::retry("sync_request_start"),
                    _ => Failure::stop("sync_request_start"),
                })?,
        );
        Ok(())
    }
}
