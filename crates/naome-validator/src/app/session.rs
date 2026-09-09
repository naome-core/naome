use std::path::Path;

use naome_network::NetworkEvent;
use naome_runtime::{FixedValidatorRuntimeEventV0 as Event, FixedValidatorRuntimeV0 as Runtime};
use serde_json::{Value, json};
use tokio::{signal::unix::Signal, sync::mpsc};

use super::{
    Result,
    acquisition::{self, Acquisition},
    commands,
    input::{Command, Input},
    proof_sync::ProofSync,
    proposal_job::{ProposalJob, Step as ProposalStep},
    provider, report, source_provider,
    sources::Sources,
    supervisor::Supervisor,
};

type Stop = (&'static str, bool);

pub(super) struct Session<'io, 'node> {
    pub supervisor: Option<Supervisor>,
    pub input_closed: bool,
    pub proposal_job: Option<ProposalJob>,
    pub runtime: Runtime<'node>,
    pub proof_sync: Option<ProofSync>,
    pub acquiring: bool,
    pub base: &'io Path,
    pub output: &'io report::Output,
    pub input: mpsc::Receiver<Input>,
    pub interrupt: Signal,
    pub terminate: Signal,
    pub serve_finality_proofs: bool,
    pub serve_artifact_sources: bool,
}

enum Poll<'node> {
    WakeSupervisor,
    Command(Command),
    Runtime(Event<'node>),
    Stop(Stop),
}

impl<'node> Session<'_, 'node> {
    pub async fn run(mut self, mut sources: Option<Sources>) -> Result<(Value, bool)> {
        let (reason, success) = loop {
            if let Some(command) = self.supervise()? {
                let started = match sources.as_mut() {
                    Some(sources) => Acquisition::start(command, &mut self.runtime, sources, true),
                    None => Err("sources_disabled"),
                };
                match started {
                    Ok(job) => {
                        self.acquiring = true;
                        let outcome = self.run_acquisition(0, job).await;
                        self.acquiring = false;
                        if let Some(stop) = outcome? {
                            break stop;
                        }
                    }
                    Err(code) => {
                        self.output
                            .emit(json!({"event":"supervisor_acquisition_waiting", "code":code}))?;
                        if code == "source_candidate_store" || code == "source_local_store" {
                            return Err(code);
                        }
                    }
                }
            }
            if let Some(mut job) = self.proposal_job.take() {
                match sources.as_mut() {
                    Some(sources) => match job.advance(
                        &mut self.runtime,
                        sources,
                        self.output,
                        self.supervisor.is_some(),
                    )? {
                        ProposalStep::Waiting => self.proposal_job = Some(job),
                        ProposalStep::Stopped => {
                            if let Some(supervisor) = self.supervisor.as_mut() {
                                supervisor.fresh_stopped = true;
                                supervisor.stopped_target = Some(job.target());
                            }
                        }
                        ProposalStep::Fatal => break ("proposal_job_fatal", false),
                    },
                    None => job.stopped("sources_disabled", self.output)?,
                }
            }
            let stop = match self.poll().await? {
                Poll::WakeSupervisor => None,
                Poll::Command(Command::ProposeHeight { id, target }) => {
                    if self.proposal_job.is_some() {
                        self.rejected(id, "proposal_busy")?;
                    } else if sources.is_none() {
                        self.rejected(id, "sources_disabled")?;
                    } else {
                        match ProposalJob::start(id, &target, &self.runtime) {
                            Ok(job) => {
                                self.result(
                                    id,
                                    json!({"event": "proposal_job_started", "job": job.status()}),
                                )?;
                                self.proposal_job = Some(job);
                            }
                            Err(code) => self.rejected(id, code)?,
                        }
                    }
                    None
                }
                Poll::Command(command) if command.starts_acquisition() => {
                    let id = command.id();
                    let started = match sources.as_mut() {
                        Some(sources) => {
                            Acquisition::start(command, &mut self.runtime, sources, false)
                        }
                        None => Err("sources_disabled"),
                    };
                    match started {
                        Ok(job) => {
                            self.acquiring = true;
                            let result = self.run_acquisition(id, job).await;
                            self.acquiring = false;
                            result?
                        }
                        Err(code) => {
                            self.rejected(id, code)?;
                            None
                        }
                    }
                }
                Poll::Command(Command::SourcesStatus { id }) => {
                    self.result(id, sources.as_ref().map_or_else(
                        || json!({"event": "sources_status", "enabled": false, "acquisition": null}),
                        Sources::status,
                    ))?;
                    None
                }
                Poll::Command(Command::CancelAcquisition { id }) => {
                    self.result(
                        id,
                        json!({"event": "acquisition_cancelled", "active": false}),
                    )?;
                    None
                }
                Poll::Command(Command::AuthorCandidate { id, target }) => {
                    let event = match sources.as_mut() {
                        Some(sources) => acquisition::block(&target).map(|target| {
                            self.runtime.author_candidate_backed_fresh_proposal(
                                &mut sources.candidates,
                                &mut sources.payloads,
                                target,
                            )
                        }),
                        None => Err("sources_disabled"),
                    };
                    self.authoring_result(id, event)?
                }
                Poll::Command(Command::AuthorStoredRetained { id }) => {
                    let event = sources.as_mut().ok_or("sources_disabled").map(|sources| {
                        self.runtime
                            .author_payload_store_backed_retained_proposal(&mut sources.payloads)
                    });
                    self.authoring_result(id, event)?
                }
                Poll::Command(command) => self.command(command, sources.as_mut())?,
                Poll::Runtime(event) => self.event(event, sources.as_mut())?,
                Poll::Stop(stop) => Some(stop),
            };
            if let Some(stop) = stop {
                break stop;
            }
        };
        if let Some(job) = self.proof_sync.take() {
            job.stopped(reason, self.output)?;
        }
        if let Some(job) = self.proposal_job.take() {
            job.stopped(reason, self.output)?;
        }
        self.input.close();
        // Both source handles and the runtime die inside the awaited signing
        // callback. The outer owner emits this summary only after all drop.
        Ok((
            report::stopped(self.runtime, reason, self.input.len()),
            success,
        ))
    }

    async fn run_acquisition(&mut self, id: u64, mut job: Acquisition<'_>) -> Result<Option<Stop>> {
        if job.complete() {
            self.result(
                id,
                json!({"event": "acquisition_complete", "job": job.status()}),
            )?;
            return Ok(None);
        }
        self.result(
            id,
            json!({"event": "acquisition_started", "job": job.status()}),
        )?;
        loop {
            let stop = match self.poll().await? {
                Poll::WakeSupervisor => None,
                Poll::Runtime(Event::Network(event)) if job.accepts_event(&event) => {
                    let prior = job.status();
                    job = match job.advance(&mut self.runtime, event) {
                        Ok(job) => job,
                        Err(code) => {
                            self.output.emit(json!({"event": "acquisition_failed", "id": id, "code": code, "job": prior}))?;
                            if self.supervisor.is_some()
                                && matches!(code, "source_candidate_store" | "source_local_store")
                            {
                                return Err(code);
                            }
                            return Ok(None);
                        }
                    };
                    let complete = job.complete();
                    self.output.emit(json!({"event": if complete { "acquisition_complete" } else { "acquisition_progress" }, "id": id, "job": job.status()}))?;
                    if complete {
                        return Ok(None);
                    }
                    None
                }
                Poll::Command(Command::SourcesStatus { id: status_id }) => {
                    self.result(
                        status_id,
                        json!({"event": "sources_status", "enabled": true,
                        "acquisition": {"id": id, "job": job.status()}}),
                    )?;
                    None
                }
                Poll::Command(Command::CancelAcquisition { id: cancel_id }) => {
                    let status = job.status();
                    job.cancel();
                    self.result(cancel_id, json!({"event": "acquisition_cancelled", "active": true, "acquisition_id": id}))?;
                    self.output
                        .emit(json!({"event": "acquisition_cancelled", "id": id, "job": status}))?;
                    return Ok(None);
                }
                Poll::Command(command) if command.needs_idle_sources() => {
                    self.rejected(command.id(), "sources_busy")?;
                    None
                }
                Poll::Command(command) => self.command(command, None)?,
                Poll::Runtime(event) => self.event(event, None)?,
                Poll::Stop(stop) => Some(stop),
            };
            if let Some(stop) = stop {
                let status = job.status();
                job.cancel();
                self.output.emit(json!({"event": "acquisition_cancelled", "id": id, "reason": stop.0, "job": status}))?;
                return Ok(Some(stop));
            }
        }
    }

    fn supervise(&mut self) -> Result<Option<Command>> {
        let Some(supervisor) = self.supervisor.as_mut() else {
            return Ok(None);
        };
        let Some(driver) = self.runtime.driver() else {
            return Err("supervisor_driver_unavailable");
        };
        let height = driver.position().height().value();
        if supervisor.height != Some(height) {
            self.proposal_job = None;
            supervisor.height = Some(height);
            supervisor.acquire_payloads = false;
            supervisor.fresh_stopped = false;
            supervisor.stopped_target = None;
            self.output
                .emit(json!({"event":"supervisor_height", "height":height.to_string()}))?;
        }
        let index = usize::try_from(height - 1).map_err(|_| "supervisor_height")?;
        let head = driver
            .selected_artifact_history()
            .selected_head_block_id()
            .map_err(|_| "supervisor_selected_history")?;
        let parent_matches = index == 0 || supervisor.targets.get(index - 1) == Some(&head);
        let target = driver
            .retained_proposal_block()
            .map(|b| b.id())
            .or_else(|| {
                if parent_matches && !supervisor.fresh_stopped {
                    supervisor.targets.get(index).copied()
                } else {
                    None
                }
            })
            .filter(|target| Some(*target) != supervisor.stopped_target);
        if let Some(target) = target
            && self
                .proposal_job
                .as_ref()
                .is_none_or(|job| job.target() != target)
        {
            self.proposal_job = Some(ProposalJob::start(
                0,
                &report::hex(target.as_bytes()),
                &self.runtime,
            )?);
        }
        if tokio::time::Instant::now() < supervisor.due {
            return Ok(None);
        }
        supervisor.postpone()?;
        if self.proof_sync.is_some() || self.acquiring {
            return Ok(None);
        }
        supervisor.next_is_sync = !supervisor.next_is_sync;
        if supervisor.next_is_sync
            || !self
                .proposal_job
                .as_ref()
                .is_some_and(ProposalJob::needs_sources)
        {
            let peer = supervisor.peer(0);
            match ProofSync::start(0, &peer, 1, &mut self.runtime) {
                Ok(job) => self.proof_sync = Some(job),
                Err(code) => self.output.emit(
                    json!({"event":"supervisor_sync_waiting", "code":code, "peer_id":peer}),
                )?,
            }
            return Ok(None);
        }
        let Some(target) = target else {
            return Ok(None);
        };
        let peer_id = supervisor.peer(if supervisor.acquire_payloads { 2 } else { 1 });
        let target = report::hex(target.as_bytes());
        self.output.emit(json!({"event":"supervisor_acquisition_selected", "peer_id":peer_id,
            "target":target, "kind":if supervisor.acquire_payloads { "payloads" } else { "ancestry" }}))?;
        let command = if supervisor.acquire_payloads {
            Command::AcquirePayloads {
                id: 0,
                target,
                peer_id,
                max_blocks: supervisor.acquisition_blocks,
            }
        } else {
            Command::AcquireAncestry {
                id: 0,
                target,
                peer_id,
            }
        };
        supervisor.acquire_payloads = !supervisor.acquire_payloads;
        Ok(Some(command))
    }

    async fn poll(&mut self) -> Result<Poll<'node>> {
        loop {
            if let Some(reason) = self
                .proposal_job
                .as_ref()
                .and_then(|job| job.changed(&self.runtime))
            {
                self.proposal_job
                    .take()
                    .unwrap()
                    .stopped(reason, self.output)?;
            }
            if self
                .proof_sync
                .as_ref()
                .is_some_and(|job| job.changed(&self.runtime))
            {
                self.proof_sync = self.proof_sync.take().unwrap().head_changed(self.output)?;
            }
            let deadline = self.proof_sync.as_ref().map(ProofSync::deadline);
            let supervisor_due = self
                .supervisor
                .as_ref()
                .filter(|_| !self.acquiring)
                .map(|s| s.due);
            let polled = tokio::select! {
                _ = async { if let Some(due) = supervisor_due { tokio::time::sleep_until(due).await } else { std::future::pending::<()>().await } } => Poll::WakeSupervisor,
                _ = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await } else { std::future::pending::<()>().await } } => {
                    self.proof_sync = self.proof_sync.take().unwrap().elapsed(&mut self.runtime, self.acquiring, self.output)?;
                    continue;
                },
                _ = self.output.failed() => return Err("output_write"),
                _ = self.interrupt.recv() => Poll::Stop(("sigint", true)),
                _ = self.terminate.recv() => Poll::Stop(("sigterm", true)),
                input = self.input.recv(), if !self.input_closed => match input {
                    Some(Input::Line(bytes)) => match Command::parse(&bytes) {
                        Ok(command) => Poll::Command(command),
                        Err(_) => {
                            self.output.emit(json!({"event": "command_rejected", "id": null, "code": "command_schema"}))?;
                            continue;
                        }
                    },
                    Some(Input::End("eof")) | None if self.supervisor.is_some() => {
                        self.input_closed = true;
                        continue;
                    },
                    Some(Input::End(reason)) => Poll::Stop((reason, reason == "eof")),
                    None => Poll::Stop(("input_closed", false)),
                },
                event = self.runtime.next_event() => Poll::Runtime(event),
            };
            if let Some(polled) = self.handle_sync(polled)? {
                return Ok(polled);
            }
        }
    }

    fn handle_sync(&mut self, polled: Poll<'node>) -> Result<Option<Poll<'node>>> {
        match polled {
            Poll::Command(command) if self.supervisor.is_some() && !matches!(&command,
                Command::Status { .. } | Command::SourcesStatus { .. } | Command::ProposalStatus { .. }
                | Command::SyncStatus { .. } | Command::Shutdown { .. }) => {
                self.rejected(command.id(), "supervisor_owns_work")?;
            }
            Poll::Command(Command::ProposalStatus { id }) => self.result(
                id, json!({"event": "proposal_job_status", "job": self.proposal_job.as_ref().map(ProposalJob::status)})
            )?,
            Poll::Command(Command::CancelProposal { id }) => {
                let job = self.proposal_job.take();
                self.result(id, json!({"event": "proposal_job_cancelled", "job": job.as_ref().map(ProposalJob::status)}))?;
                if let Some(job) = job {
                    job.stopped("cancelled", self.output)?;
                }
            }
            Poll::Command(command) if command.authors_proposal() && self.proposal_job.is_some() => {
                self.rejected(command.id(), "proposal_busy")?;
            }
            Poll::Command(Command::FollowFinality { id, peer_id, count, interval_millis }) => {
                if self.proof_sync.is_some() {
                    self.rejected(id, "sync_busy")?;
                } else {
                    match ProofSync::follow(id, &peer_id, count, &interval_millis, &self.runtime) {
                        Ok(job) => {
                            self.result(id, json!({"event":"follow_started", "job":job.status()}))?;
                            self.proof_sync = Some(job);
                        },
                        Err(code) => self.rejected(id, code)?,
                    }
                }
            }
            Poll::Command(Command::SyncFinality { id, peer_id, count }) => {
                if self.proof_sync.is_some() || self.acquiring {
                    self.rejected(id, "sync_busy")?;
                } else {
                    match ProofSync::start(id, &peer_id, count, &mut self.runtime) {
                        Ok(job) => {
                            self.result(id, json!({"event": "sync_started", "job": job.status()}))?;
                            self.proof_sync = Some(job);
                        }
                        Err(code) => self.rejected(id, code)?,
                    }
                }
            }
            Poll::Command(Command::SyncStatus { id }) => self.result(
                id, json!({"event": "sync_status", "job": self.proof_sync.as_ref().map(ProofSync::status)})
            )?,
            Poll::Command(Command::CancelSync { id }) => {
                let job = self.proof_sync.take();
                self.result(id, json!({"event": "sync_cancelled", "job": job.as_ref().map(ProofSync::status)}))?;
                if let Some(job) = job {
                    job.stopped("cancelled", self.output)?;
                }
            }
            Poll::Command(command) if command.starts_acquisition() && self.proof_sync.as_ref().is_some_and(ProofSync::active) => {
                self.rejected(command.id(), "sync_busy")?;
            }
            Poll::Runtime(Event::Network(NetworkEvent::OutboundFinalityProof(event))) => {
                if self.proof_sync.as_ref().is_some_and(|job| job.accepts(&event)) {
                    let (job, event) = self.proof_sync.take().unwrap().complete(event, &mut self.runtime, self.output, self.supervisor.is_some())?;
                    self.proof_sync = job;
                    if let Some(event) = event {
                        return Ok(Some(Poll::Runtime(event)));
                    }
                } else {
                    self.output.emit(json!({"event": "sync_response_discarded", "peer_id": event.peer_id().to_string(), "height": event.request().height().value().to_string()}))?;
                }
            }
            Poll::Runtime(event @ Event::TimerArmed(_)) => {
                if let Some(job) = self.proof_sync.take() {
                    self.proof_sync = job.successor(&mut self.runtime, self.output)?;
                }
                return Ok(Some(Poll::Runtime(event)));
            }
            other => return Ok(Some(other)),
        }
        Ok(None)
    }

    fn command(&mut self, command: Command, sources: Option<&mut Sources>) -> Result<Option<Stop>> {
        let id = command.id();
        let shutdown = matches!(command, Command::Shutdown { .. });
        match commands::execute(command, self.base, &mut self.runtime, sources) {
            Ok((outcome, fatal)) => {
                self.result(id, outcome)?;
                if fatal {
                    return Ok(Some(("command_fatal", false)));
                }
            }
            Err(code) => self.rejected(id, code)?,
        }
        Ok(shutdown.then_some(("shutdown", true)))
    }

    fn authoring_result(&mut self, id: u64, event: Result<Event<'node>>) -> Result<Option<Stop>> {
        match event {
            Ok(event) => {
                let (outcome, fatal) = report::event(event);
                self.result(id, outcome)?;
                Ok(fatal.then_some(("command_fatal", false)))
            }
            Err(code) => {
                self.rejected(id, code)?;
                Ok(None)
            }
        }
    }

    fn event(
        &mut self,
        event: Event<'node>,
        sources: Option<&mut Sources>,
    ) -> Result<Option<Stop>> {
        let (mut event, fatal) = match event {
            Event::Network(NetworkEvent::InboundFinalityProof(inbound))
                if self.serve_finality_proofs =>
            {
                provider::respond(&mut self.runtime, inbound)
            }
            Event::Network(NetworkEvent::InboundBlockRequest(inbound))
                if self.serve_artifact_sources =>
            {
                (
                    source_provider::block(&mut self.runtime, inbound, sources),
                    false,
                )
            }
            Event::Network(NetworkEvent::InboundArtifactRequest(inbound))
                if self.serve_artifact_sources =>
            {
                (
                    source_provider::artifact(&mut self.runtime, inbound, sources),
                    false,
                )
            }
            event => report::event(event),
        };
        if event["event"] == "finality" {
            event["state"] = report::status(&self.runtime);
        }
        let fatal = fatal
            || (self.supervisor.is_some()
                && event["event"] == "source_response_failed"
                && matches!(
                    event["reason"].as_str(),
                    Some("candidate_store" | "payload_store")
                ));
        self.output.emit(event)?;
        Ok(fatal.then_some(("runtime_fatal", false)))
    }

    fn result(&self, id: u64, outcome: Value) -> Result<()> {
        self.output
            .emit(json!({"event": "command_result", "id": id, "outcome": outcome}))
    }

    fn rejected(&self, id: u64, code: &'static str) -> Result<()> {
        self.output
            .emit(json!({"event": "command_rejected", "id": id, "code": code}))
    }
}
