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
    provider, report, source_provider,
    sources::Sources,
};

type Stop = (&'static str, bool);

pub(super) struct Session<'io, 'node> {
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
    Command(Command),
    Runtime(Event<'node>),
    Stop(Stop),
}

impl<'node> Session<'_, 'node> {
    pub async fn run(mut self, mut sources: Option<Sources>) -> Result<(Value, bool)> {
        let (reason, success) = loop {
            let stop = match self.poll().await? {
                Poll::Command(command) if command.starts_acquisition() => {
                    let id = command.id();
                    let started = match sources.as_mut() {
                        Some(sources) => Acquisition::start(command, &mut self.runtime, sources),
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
                Poll::Runtime(Event::Network(event)) if job.accepts_event(&event) => {
                    let prior = job.status();
                    job = match job.advance(&mut self.runtime, event) {
                        Ok(job) => job,
                        Err(code) => {
                            self.output.emit(json!({"event": "acquisition_failed", "id": id, "code": code, "job": prior}))?;
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

    async fn poll(&mut self) -> Result<Poll<'node>> {
        loop {
            if self
                .proof_sync
                .as_ref()
                .is_some_and(|job| job.changed(&self.runtime))
            {
                self.proof_sync
                    .take()
                    .unwrap()
                    .stopped("sync_head_changed", self.output)?;
            }
            let deadline = self.proof_sync.as_ref().map(ProofSync::deadline);
            let polled = tokio::select! {
                _ = async { if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await } else { std::future::pending::<()>().await } } => {
                    self.proof_sync.take().unwrap().stopped("network_deadline", self.output)?;
                    continue;
                },
                _ = self.output.failed() => return Err("output_write"),
                _ = self.interrupt.recv() => Poll::Stop(("sigint", true)),
                _ = self.terminate.recv() => Poll::Stop(("sigterm", true)),
                input = self.input.recv() => match input {
                    Some(Input::Line(bytes)) => match Command::parse(&bytes) {
                        Ok(command) => Poll::Command(command),
                        Err(_) => {
                            self.output.emit(json!({"event": "command_rejected", "id": null, "code": "command_schema"}))?;
                            continue;
                        }
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
            Poll::Command(command) if command.starts_acquisition() && self.proof_sync.is_some() => {
                self.rejected(command.id(), "sync_busy")?;
            }
            Poll::Runtime(Event::Network(NetworkEvent::OutboundFinalityProof(event))) => {
                if self.proof_sync.as_ref().is_some_and(|job| job.accepts(&event)) {
                    let (job, event) = self.proof_sync.take().unwrap().complete(event, &mut self.runtime, self.output)?;
                    self.proof_sync = job;
                    if let Some(event) = event {
                        return Ok(Some(Poll::Runtime(event)));
                    }
                } else {
                    self.output.emit(json!({"event": "sync_response_discarded", "peer_id": event.peer_id().to_string(), "height": event.request().height().value().to_string()}))?;
                }
            }
            Poll::Runtime(event @ Event::TimerArmed(_)) => {
                if let Some(job) = self.proof_sync.as_mut()
                    && let Err(reason) = job.successor(&mut self.runtime) {
                    self.proof_sync.take().unwrap().stopped(reason, self.output)?;
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
