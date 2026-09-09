//! Explicit, volatile authorization to try one height's caller-selected source.

use naome_chain::ArtifactBlockId;
use naome_consensus::{
    ConsensusPosition, FixedValidatorLockPhaseV0, FixedValidatorProposalIntentErrorV0,
};
use naome_node::FixedValidatorNodeProposalAuthoringRejectionV0 as Rejection;
use naome_runtime::{FixedValidatorRuntimeEventV0 as Event, FixedValidatorRuntimeV0 as Runtime};
use serde_json::{Value, json};

use super::{Result, acquisition, report, sources::Sources};

pub(super) struct ProposalJob {
    id: u64,
    height: u64,
    target: ArtifactBlockId,
    round: Option<ConsensusPosition>,
    finished_round: bool,
    state: &'static str,
}

pub(super) enum Step {
    Waiting,
    Stopped,
    Fatal,
}

impl ProposalJob {
    pub fn start(id: u64, target: &str, runtime: &Runtime<'_>) -> Result<Self> {
        let target = acquisition::block(target)?;
        let driver = runtime.driver().ok_or("proposal_unavailable")?;
        Ok(Self {
            id,
            height: driver.position().height().value(),
            target,
            round: None,
            finished_round: false,
            state: "waiting",
        })
    }

    pub fn needs_sources(&self) -> bool {
        self.state == "source_unavailable"
    }

    pub fn target(&self) -> ArtifactBlockId {
        self.target
    }

    pub fn status(&self) -> Value {
        json!({"id": self.id, "height": self.height.to_string(),
            "target": report::hex(self.target.as_bytes()), "state": self.state,
            "round": self.round.map(|position| position.round().value().to_string()),
            "round_complete": self.finished_round})
    }

    pub fn changed(&self, runtime: &Runtime<'_>) -> Option<&'static str> {
        match runtime.driver() {
            None => Some("runtime_unavailable"),
            Some(driver) if driver.position().height().value() != self.height => {
                Some("height_changed")
            }
            _ => None,
        }
    }

    pub fn stopped(&self, reason: &'static str, output: &report::Output) -> Result<()> {
        output.emit(json!({"event": "proposal_job_stopped", "id": self.id,
            "reason": reason, "job": self.status()}))
    }

    fn waiting(&mut self, state: &'static str, output: &report::Output) -> Result<Step> {
        if self.state != state {
            self.state = state;
            output.emit(json!({"event": "proposal_job_waiting", "id": self.id,
                "job": self.status()}))?;
        }
        Ok(Step::Waiting)
    }

    /// At most one bounded attempt between ordinary session polls. No sleep,
    /// transport poll, source acquisition, custody disposal, or signing bypass.
    pub fn advance(
        &mut self,
        runtime: &mut Runtime<'_>,
        sources: &mut Sources,
        output: &report::Output,
        local_failure_is_fatal: bool,
    ) -> Result<Step> {
        if let Some(reason) = self.changed(runtime) {
            self.stopped(reason, output)?;
            return Ok(Step::Stopped);
        }
        let driver = runtime.driver().unwrap();
        let position = driver.position();
        if self.round != Some(position) {
            self.round = Some(position);
            self.finished_round = false;
            // Starting a job never substitutes its candidate for an already
            // completed manual or recovered proposal in this exact round.
            let history = match driver.publication_history() {
                Ok(history) => history,
                Err(_) => {
                    self.stopped("publication_history", output)?;
                    return Ok(if local_failure_is_fatal {
                        Step::Fatal
                    } else {
                        Step::Stopped
                    });
                }
            };
            self.finished_round = history.entries().any(|entry| {
                entry.position() == position && entry.phase() == FixedValidatorLockPhaseV0::Proposal
            });
        }
        if self.finished_round {
            return self.waiting("round_complete", output);
        }
        if driver.phase() != FixedValidatorLockPhaseV0::Proposal {
            return self.waiting("proposal_phase", output);
        }
        let mut event = runtime.author_candidate_backed_fresh_proposal(
            &mut sources.candidates,
            &mut sources.payloads,
            self.target,
        );
        // The sealed authoring coordinator reports this before any candidate
        // lookup. Its retained value is the sole alternative, including when
        // its payload is absent; absence never falls back to the fresh target.
        if matches!(&event, Event::ProposalRejected(rejection)
            if matches!(rejection.as_ref(), Rejection::Proposal(error)
                if matches!(error.as_ref(), FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired)))
        {
            event = runtime.author_payload_store_backed_retained_proposal(&mut sources.payloads);
        }
        match &event {
            Event::StoreAuthoringBusy => return self.waiting("runtime_busy", output),
            Event::AuthoringStepWorkPending => return self.waiting("driver_work", output),
            Event::ProposalRejected(rejection)
                if matches!(
                    rejection.as_ref(),
                    Rejection::CandidateUnavailable { .. } | Rejection::PayloadUnavailable { .. }
                ) =>
            {
                return self.waiting("source_unavailable", output);
            }
            Event::ProposalRejected(rejection) => match rejection.as_ref() {
                Rejection::Proposal(error)
                    if matches!(
                        error.as_ref(),
                        FixedValidatorProposalIntentErrorV0::NotScheduledProposer { .. }
                    ) =>
                {
                    self.finished_round = true;
                    return self.waiting("not_scheduled", output);
                }
                Rejection::Proposal(error)
                    if matches!(
                        error.as_ref(),
                        FixedValidatorProposalIntentErrorV0::WrongPhase { .. }
                    ) =>
                {
                    return self.waiting("proposal_phase", output);
                }
                _ => {}
            },
            _ => {}
        }
        let authored = matches!(event, Event::ProposalAuthored);
        let source_fatal = local_failure_is_fatal
            && matches!(&event,
            Event::ProposalRejected(rejection) if matches!(rejection.as_ref(),
                Rejection::CandidateStore(_) | Rejection::PayloadStore(_)
                | Rejection::CandidateChainMismatch { .. }));
        let (outcome, fatal) = report::event(event);
        let fatal = fatal || source_fatal;
        if authored {
            self.finished_round = true;
            self.state = "authored";
        }
        output.emit(json!({"event": "proposal_job_attempt", "id": self.id,
            "job": self.status(), "outcome": outcome}))?;
        if authored {
            Ok(Step::Waiting)
        } else {
            self.stopped(
                if fatal {
                    "authoring_fatal"
                } else {
                    "authoring_rejected"
                },
                output,
            )?;
            Ok(if fatal { Step::Fatal } else { Step::Stopped })
        }
    }
}
