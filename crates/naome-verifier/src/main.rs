//! Independently verified, anchored finality history without consensus signing.

#[cfg(any(unix, windows))]
mod app;

// The narrow Windows token wrapper relies on native heap alignment. Keep its
// allocator explicit; this executable does not impersonate another identity.
#[cfg(windows)]
#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

fn main() -> std::process::ExitCode {
    #[cfg(any(unix, windows))]
    {
        #[cfg(unix)]
        let args: Vec<_> = std::env::args().skip(1).collect();
        #[cfg(unix)]
        if args.first().is_some_and(|arg| arg == "state") {
            let state_args: Vec<_> = args.into_iter().skip(1).collect();
            if state_args.first().is_some_and(|arg| arg == "verify") {
                return naome_cli::run_args(state_args);
            }
            eprintln!("naome-verifier: state only supports independent offline verification");
            return std::process::ExitCode::FAILURE;
        }
        app::main()
    }
    #[cfg(not(any(unix, windows)))]
    {
        eprintln!("naome-verifier: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
