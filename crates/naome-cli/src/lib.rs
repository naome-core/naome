//! Shared command entry point for the canonical trusted NAOME state machine.

mod archive;
mod output;

#[cfg(unix)]
mod app;

/// Independently replays a public archive without opening signing or node state.
pub fn verify_archive(
    genesis: &std::path::Path,
    directory: &std::path::Path,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    archive::verify(genesis, directory)
}

/// Read-only verifier process interface. Operator commands are never dispatched.
pub fn run_verifier_args(args: Vec<String>) -> std::process::ExitCode {
    match args.first().map(String::as_str) {
        None | Some("help" | "--help") => {
            let _ = output::message(
                output::Stream::Out,
                "Usage: naome-verifier verify GENESIS EXPORT_DIRECTORY",
                std::time::Duration::from_secs(2),
            );
            std::process::ExitCode::SUCCESS
        }
        Some("verify") if args.len() == 3 => {
            match verify_archive(
                std::path::Path::new(&args[1]),
                std::path::Path::new(&args[2]),
            ) {
                Ok(report) => {
                    if output::report(&report.to_string()).is_ok() {
                        std::process::ExitCode::SUCCESS
                    } else {
                        std::process::ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    let _ = output::message(
                        output::Stream::Error,
                        &format!("naome-verifier: {error}"),
                        std::time::Duration::from_millis(250),
                    );
                    std::process::ExitCode::FAILURE
                }
            }
        }
        _ => {
            let _ = output::message(
                output::Stream::Error,
                "naome-verifier only supports: verify GENESIS EXPORT_DIRECTORY",
                std::time::Duration::from_millis(250),
            );
            std::process::ExitCode::FAILURE
        }
    }
}

/// Validator-only interface. No legacy or operator command can create custody.
#[cfg(unix)]
pub fn run_validator_args(args: Vec<String>) -> std::process::ExitCode {
    match args.first().map(String::as_str) {
        None | Some("help" | "--help") => {
            let _ = output::message(
                output::Stream::Out,
                "Usage: naome-validator start CONFIG",
                std::time::Duration::from_secs(2),
            );
            std::process::ExitCode::SUCCESS
        }
        Some("start") if args.len() == 2 => run_args(args),
        _ => {
            let _ = output::message(
                output::Stream::Error,
                "naome-validator only supports: start CONFIG",
                std::time::Duration::from_millis(250),
            );
            std::process::ExitCode::FAILURE
        }
    }
}

/// Runs canonical-state commands with the program name already removed.
#[cfg(unix)]
pub fn run_args(args: Vec<String>) -> std::process::ExitCode {
    let result = (|| -> app::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(app::run(args))
    })();
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _ = output::message(
                output::Stream::Error,
                &format!("naome: {error}"),
                std::time::Duration::from_millis(250),
            );
            std::process::ExitCode::FAILURE
        }
    }
}

/// Runs canonical-state commands from the process argument vector.
#[cfg(unix)]
pub fn main() -> std::process::ExitCode {
    run_args(std::env::args().skip(1).collect())
}

#[cfg(not(unix))]
pub fn main() -> std::process::ExitCode {
    eprintln!("naome: validator operation requires Unix durable signing support");
    std::process::ExitCode::FAILURE
}
