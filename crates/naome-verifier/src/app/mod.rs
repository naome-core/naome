use std::{env, path::PathBuf, process::ExitCode};

use serde_json::json;
use tokio::{
    runtime::Builder,
    signal::unix::{SignalKind, signal},
};

mod archive;
mod commands;
mod config;
mod files;
mod input;
mod report;

type Result<T> = std::result::Result<T, &'static str>;

struct Stopped {
    reason: &'static str,
    success: bool,
}

pub(super) fn main() -> ExitCode {
    let Ok(output) = report::Output::start() else {
        return ExitCode::FAILURE;
    };
    // run owns and drops the journal, executor and input receiver before any
    // final flush or claim that its locks have been released.
    let (summary, success) = match run(&output) {
        Ok(stopped) => (
            json!({"event": "stopped", "reason": stopped.reason, "locks_released": true}),
            stopped.success,
        ),
        Err(code) => {
            if code.starts_with("output_") {
                return ExitCode::FAILURE;
            }
            (
                json!({"event": "error", "code": code, "locks_released": true}),
                false,
            )
        }
    };
    if output.finish(summary).is_ok() && success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(output: &report::Output) -> Result<Stopped> {
    let mut args = env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or("usage_config_path")?);
    if args.next().is_some() {
        return Err("usage_config_path");
    }
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "executor")?
        .block_on(run_async(path, output))
}

async fn run_async(path: PathBuf, output: &report::Output) -> Result<Stopped> {
    let mut config = config::Prepared::load(&path)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal_registration")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal_registration")?;
    let mut input = input::start()?;
    let mut archive = config
        .network
        .take()
        .map(archive::Prepared::start)
        .transpose()?;
    let mut journal = config.provision()?;
    let state = report::status(&journal)?;
    if journal.halt().map_err(|_| "finality_state")?.is_some() {
        output.emit(json!({"event": "halted", "state": state}))?;
        return Ok(Stopped {
            reason: "finality_halted",
            success: false,
        });
    }
    output.emit(json!({"event": "ready", "state": state}))?;
    let stopped = loop {
        tokio::select! {
            biased;
            _ = interrupt.recv() => break Stopped { reason: "sigint", success: true },
            _ = terminate.recv() => break Stopped { reason: "sigterm", success: true },
            _ = output.failed() => return Err("output_write"),
            work = next_work(&mut input, &mut archive) => match work {
                Work::Network(event) => {
                    if archive.as_mut().expect("network work requires an archive").handle(event, &mut journal, output)? {
                        break Stopped { reason: "finality_halted", success: false };
                    }
                }
                Work::Deadline => archive.as_mut().expect("deadline requires an archive").elapsed(&journal, output)?,
                Work::Input(Some(input::Input::Line(bytes))) => {
                    let command = match input::Command::parse(&bytes) {
                        Ok(command) => command,
                        Err(_) => {
                            output.emit(json!({"event": "command_rejected", "id": null, "code": "command_schema"}))?;
                            continue;
                        }
                    };
                    let id = command.id();
                    let shutdown = matches!(command, input::Command::Shutdown { .. });
                    let executed = match (&mut archive, command) {
                        (Some(archive), input::Command::Sync { id, peer_id, count }) =>
                            archive.start_sync(id, &peer_id, count, &journal).map(|outcome| (outcome, false)),
                        (Some(archive), input::Command::FollowFinality { id, peer_id, count, interval_millis }) =>
                            archive.follow(id, &peer_id, count, &interval_millis, &journal).map(|outcome| (outcome, false)),
                        (Some(archive), command @ input::Command::Status { .. }) =>
                            commands::execute(command, &config.base, &mut journal).map(|(mut outcome, halted)| {
                                outcome["sync"] = archive.status();
                                (outcome, halted)
                            }),
                        (Some(archive), input::Command::CancelSync { .. }) =>
                            archive.cancel().map(|outcome| (outcome, false)),
                        (Some(archive), input::Command::Import { .. }) if archive.active() =>
                            Err(commands::Failure::Rejected("sync_busy")),
                        (_, command) => commands::execute(command, &config.base, &mut journal),
                    };
                    match executed {
                        Ok((outcome, halted)) => {
                            output.emit(json!({"event": "command_result", "id": id, "outcome": outcome}))?;
                            if halted { break Stopped { reason: "finality_halted", success: false }; }
                        }
                        Err(commands::Failure::Rejected(code)) => {
                            output.emit(json!({"event": "command_rejected", "id": id, "code": code}))?;
                        }
                        Err(commands::Failure::Fatal(code)) => {
                            output.emit(json!({"event": "command_failed", "id": id, "code": code, "strict_restart_required": true}))?;
                            break Stopped { reason: code, success: false };
                        }
                    }
                    if shutdown { break Stopped { reason: "shutdown", success: true }; }
                }
                Work::Input(Some(input::Input::End(reason))) => break Stopped { reason, success: reason == "eof" },
                Work::Input(None) => break Stopped { reason: "input_closed", success: false },
            },
        }
    };
    input.close();
    Ok(stopped)
}

// Only one event is held by the owner; keep it inline instead of allocating
// for every network event merely to shrink the input/deadline variants.
#[allow(clippy::large_enum_variant)]
enum Work {
    Input(Option<input::Input>),
    Network(naome_network::NetworkEvent),
    Deadline,
}

async fn next_work(
    input: &mut tokio::sync::mpsc::Receiver<input::Input>,
    archive: &mut Option<archive::Archive>,
) -> Work {
    let Some(archive) = archive else {
        return Work::Input(input.recv().await);
    };
    let deadline = archive.deadline();
    tokio::select! {
        biased;
        _ = async {
            if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; }
            else { std::future::pending::<()>().await; }
        } => Work::Deadline,
        work = async {
            // Neither a stream of local commands nor inbound requests gets a
            // permanent priority. Signals/output failure retain the outer gate.
            tokio::select! {
                input = input.recv() => Work::Input(input),
                event = archive.network.next_event() => Work::Network(event),
            }
        } => work,
    }
}
