use std::{env, path::PathBuf, process::ExitCode};

use serde_json::json;
use tokio::{
    runtime::Builder,
    signal::unix::{SignalKind, signal},
};

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
    let config = config::Prepared::load(&path)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal_registration")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal_registration")?;
    let mut input = input::start()?;
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
            input = input.recv() => match input {
                Some(input::Input::Line(bytes)) => {
                    let command = match input::Command::parse(&bytes) {
                        Ok(command) => command,
                        Err(_) => {
                            output.emit(json!({"event": "command_rejected", "id": null, "code": "command_schema"}))?;
                            continue;
                        }
                    };
                    let id = command.id();
                    let shutdown = matches!(command, input::Command::Shutdown { .. });
                    match commands::execute(command, &config.base, &mut journal) {
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
                Some(input::Input::End(reason)) => break Stopped { reason, success: reason == "eof" },
                None => break Stopped { reason: "input_closed", success: false },
            },
        }
    };
    input.close();
    Ok(stopped)
}
