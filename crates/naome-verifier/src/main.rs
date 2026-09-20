//! Independent, keyless verification of the canonical complete-state history.
fn main() -> std::process::ExitCode {
    #[cfg(any(unix, windows))]
    {
        naome_cli::run_verifier_args(std::env::args().skip(1).collect())
    }
    #[cfg(not(any(unix, windows)))]
    {
        eprintln!("naome-verifier: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
