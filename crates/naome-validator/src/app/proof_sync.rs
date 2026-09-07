//! One volatile caller-selected proof catch-up job. The runtime owns authority.
use super::{Result, report};
use naome_consensus::ConsensusHeight;
use naome_network::{
    FinalityProofRequest, FinalityProofResponse, FinalityProofTicket, OutboundFinalityProofEvent,
    PeerId,
};
use naome_runtime::{FixedValidatorRuntimeEventV0 as Event, FixedValidatorRuntimeV0 as Runtime};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct ProofSync {
    id: u64,
    peer: PeerId,
    next: u64,
    last: u64,
    completed: u64,
    deadline: Instant,
    ticket: Option<FinalityProofTicket>,
}
impl ProofSync {
    pub fn start(id: u64, peer: &str, count: u64, runtime: &mut Runtime<'_>) -> Result<Self> {
        if !(1..=16).contains(&count) {
            return Err("sync_count");
        }
        let peer = peer.parse().map_err(|_| "peer_id")?;
        let driver = runtime.driver().ok_or("driver_unavailable")?;
        let next = driver.position().height().value();
        let last = next.checked_add(count - 1).ok_or("sync_height_overflow")?;
        // The bounded archive profile uses this same whole-job network budget.
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(120))
            .ok_or("sync_deadline_overflow")?;
        let mut job = Self {
            id,
            peer,
            next,
            last,
            completed: 0,
            deadline,
            ticket: None,
        };
        job.request(runtime)?;
        Ok(job)
    }
    fn request(&mut self, runtime: &mut Runtime<'_>) -> Result<()> {
        let driver = runtime.driver().ok_or("driver_unavailable")?;
        if driver.position().height().value() != self.next {
            return Err("sync_head_changed");
        }
        let request = FinalityProofRequest::new(driver.context(), ConsensusHeight::new(self.next))
            .ok_or("sync_height")?;
        self.ticket = Some(
            runtime
                .request_finality_proof(self.peer, request)
                .map_err(|_| "sync_request_start")?,
        );
        Ok(())
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn status(&self) -> Value {
        json!({"id": self.id, "peer_id": self.peer.to_string(), "next_height": self.next.to_string(), "last_height": self.last.to_string(), "completed": self.completed.to_string()})
    }
    pub fn stopped(&self, reason: &'static str, output: &report::Output) -> Result<()> {
        output.emit(
            json!({"event": "sync_stopped", "id": self.id, "reason": reason, "job": self.status()}),
        )
    }
    pub fn changed(&self, runtime: &Runtime<'_>) -> bool {
        runtime
            .driver()
            .is_none_or(|driver| driver.position().height().value() != self.next)
    }
    pub fn accepts(&self, event: &OutboundFinalityProofEvent) -> bool {
        self.ticket
            .as_ref()
            .is_some_and(|ticket| ticket.accepts_event(event))
    }
    /// A successful proof queues a child arm. Start its successor only after
    /// ordinary runtime scheduling transfers that arm, never by stepping here.
    pub fn successor(&mut self, runtime: &mut Runtime<'_>) -> Result<()> {
        if Instant::now() >= self.deadline {
            return Err("network_deadline");
        }
        if self.ticket.is_none() {
            self.request(runtime)?;
        }
        Ok(())
    }
    pub fn complete<'node>(
        mut self,
        event: OutboundFinalityProofEvent,
        runtime: &mut Runtime<'node>,
        output: &report::Output,
    ) -> Result<(Option<Self>, Option<Event<'node>>)> {
        let reason = if Instant::now() >= self.deadline {
            Some("network_deadline")
        } else if self.changed(runtime) {
            Some("sync_head_changed")
        } else {
            None
        };
        if let Some(reason) = reason {
            self.stopped(reason, output)?;
            return Ok((None, None));
        }
        let ticket = self.ticket.take().ok_or("sync_correlation")?;
        let response = ticket.complete(event).map_err(|_| "sync_correlation")?;
        let Ok(response) = response else {
            self.stopped("transport_failure", output)?;
            return Ok((None, None));
        };
        let FinalityProofResponse::Found {
            canonical_envelope,
            canonical_artifact,
        } = response.into_response()
        else {
            self.stopped("unavailable", output)?;
            return Ok((None, None));
        };
        let event = match runtime.commit_finality_envelope(&canonical_envelope, canonical_artifact)
        {
            Ok(event) => event,
            Err(_) => {
                self.stopped("proof_backpressure", output)?;
                return Ok((None, None));
            }
        };
        if !matches!(event, Event::Finality(_)) {
            self.stopped("proof_not_committed", output)?;
            return Ok((None, Some(event)));
        }
        self.completed += 1;
        output.emit(json!({"event": "sync_progress", "id": self.id, "height": self.next.to_string(), "completed": self.completed.to_string()}))?;
        if self.next == self.last {
            output.emit(json!({"event": "sync_completed", "id": self.id, "completed": self.completed.to_string(), "last_height": self.last.to_string()}))?;
            return Ok((None, Some(event)));
        }
        self.next += 1;
        // No new request may follow a synchronous commit that outlasted the budget.
        if Instant::now() >= self.deadline {
            self.stopped("network_deadline", output)?;
            return Ok((None, Some(event)));
        }
        Ok((Some(self), Some(event)))
    }
}
