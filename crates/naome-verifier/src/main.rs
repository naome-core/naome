//! Keyless ownership of an independently verified, anchored finality history.

#[cfg(unix)]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        app::main()
    }
    #[cfg(not(unix))]
    {
        eprintln!("naome-verifier: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
