//! Independently verified, anchored finality history without consensus signing.

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
