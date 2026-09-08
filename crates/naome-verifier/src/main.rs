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
        app::main()
    }
    #[cfg(not(any(unix, windows)))]
    {
        eprintln!("naome-verifier: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
