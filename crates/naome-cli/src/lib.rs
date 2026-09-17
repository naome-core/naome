//! Shared command entry point for the canonical trusted NAOME state machine.

#[cfg(unix)]
mod app;

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
            eprintln!("naome: {error}");
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
