//! Explicit local process ownership for the existing fixed-validator V0 runtime.

#[cfg(unix)]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        app::main()
    }
    #[cfg(not(unix))]
    {
        eprintln!("naome-validator: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
