use std::{env, path::PathBuf, process::ExitCode};

use naome_node::{FixedValidatorNodeDriverV0, FixedValidatorNodeStartupV0};
use naome_runtime::FixedValidatorRuntimeV0;
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

pub(super) fn main() -> ExitCode {
    let Ok(output) = report::Output::start() else {
        return ExitCode::FAILURE;
    };
    match run(&output) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            // Never format parsing errors or configuration/source bytes.
            // A stopped report already describes process_stopped. An output
            // failure must not start a second bounded flush on the same sink.
            if code != "process_stopped" && !code.starts_with("output_") {
                let _ = output.finish(json!({"event": "error", "code": code}));
            }
            ExitCode::FAILURE
        }
    }
}

fn run(output: &report::Output) -> Result<()> {
    let mut args = env::args_os().skip(1);
    let path = PathBuf::from(args.next().ok_or("usage_config_path")?);
    if args.next().is_some() {
        return Err("usage_config_path");
    }
    let executor = Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "executor")?;
    executor.block_on(run_async(path, output))
}

async fn run_async(path: PathBuf, output: &report::Output) -> Result<()> {
    let mut config = config::Config::load(&path)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "signal_registration")?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|_| "signal_registration")?;
    let mut input = input::start()?;
    let signing_key = config.signing_key.take().ok_or("signing_key_missing")?;
    let ready = match config.mode {
        config::Mode::Create => config
            .provision()
            .create(signing_key)
            .map_err(|_| "startup_create")?,
        config::Mode::Open => match config
            .provision()
            .open(signing_key)
            .map_err(|_| "startup_open")?
        {
            FixedValidatorNodeStartupV0::Ready(ready) => *ready,
            FixedValidatorNodeStartupV0::FinalityStopped(_) => {
                return Err("startup_finality_stopped");
            }
            FixedValidatorNodeStartupV0::SignerStopped(_) => return Err("startup_signer_stopped"),
            FixedValidatorNodeStartupV0::PendingPreparation(_) => {
                return Err("startup_pending_vote");
            }
            FixedValidatorNodeStartupV0::PendingProposal(_) => {
                return Err("startup_pending_proposal");
            }
        },
    };
    let (summary, success) = ready.run_with_signing_session_async(async move |scope| {
        let driver = FixedValidatorNodeDriverV0::new(scope, config.higher, config.current, config.finality, config.nil_precommit, config.driver_max_round).map_err(|_| "driver_create")?;
        let mut network = config.network;
        network.listen_on(config.listen).map_err(|_| "listen_start")?;
        let mut runtime = FixedValidatorRuntimeV0::new(driver, network, config.targets, config.timeouts).map_err(|_| "runtime_create")?;
        output.emit(json!({"event": "ready", "state": report::status(&runtime)}))?;
        let (reason, success) = loop {
            tokio::select! {
                _ = interrupt.recv() => break ("sigint", true),
                _ = terminate.recv() => break ("sigterm", true),
                input = input.recv() => match input {
                    Some(input::Input::Line(bytes)) => {
                        let command = match serde_json::from_slice::<input::Command>(&bytes) {
                            Ok(command) => command,
                            Err(_) => { output.emit(json!({"event": "command_rejected", "id": null, "code": "command_schema"}))?; continue; },
                        };
                        let id = command.id();
                        let shutdown = matches!(command, input::Command::Shutdown { .. });
                        match commands::execute(command, &config.base, &mut runtime) {
                            Ok((outcome, fatal)) => {
                                output.emit(json!({"event": "command_result", "id": id, "outcome": outcome}))?;
                                if fatal { break ("command_fatal", false); }
                            },
                            Err(code) => output.emit(json!({"event": "command_rejected", "id": id, "code": code}))?,
                        }
                        if shutdown { break ("shutdown", true); }
                    },
                    Some(input::Input::End(reason)) => break (reason, reason == "eof"),
                    None => break ("input_closed", false),
                },
                event = runtime.next_event() => {
                    let (mut event, fatal) = report::event(event);
                    if event["event"] == "finality" { event["state"] = report::status(&runtime); }
                    output.emit(event)?;
                    if fatal { break ("runtime_fatal", false); }
                },
            }
        };
        input.close();
        Ok::<_, &'static str>((report::stopped(runtime, reason, input.len()), success))
    }).await.map_err(|_| "signing_session")??;
    // The outer future has finished: both anchored journal owners are dropped.
    output.finish(summary)?;
    if success {
        Ok(())
    } else {
        Err("process_stopped")
    }
}
