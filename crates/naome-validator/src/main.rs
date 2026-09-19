//! Canonical full-state validator; initialization belongs to `naome setup`.
fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        naome_cli::run_validator_args(std::env::args().skip(1).collect())
    }
    #[cfg(not(unix))]
    {
        eprintln!("naome-validator: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
