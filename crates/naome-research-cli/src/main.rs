//! Command line operation of a separately initialized trusted research run.

#[cfg(unix)]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        app::main()
    }
    #[cfg(not(unix))]
    {
        eprintln!("naome-research: validator operation requires Unix durable signing support");
        std::process::ExitCode::FAILURE
    }
}
