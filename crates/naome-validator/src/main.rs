//! Explicit local process ownership for the existing fixed-validator V0 runtime.

#[cfg(unix)]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.first().is_some_and(|arg| arg == "state") {
            return naome_cli::run_args(args.into_iter().skip(1).collect());
        }
        app::main()
    }
    #[cfg(not(unix))]
    {
        eprintln!("naome-validator: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
