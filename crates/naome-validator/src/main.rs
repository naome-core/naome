//! Canonical state validator entry point, with V0 retirement still in progress.

#[cfg(unix)]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.is_empty()
            || args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "start" | "help" | "--help"))
        {
            return naome_cli::run_args(args);
        }
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
