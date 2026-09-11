//! Operator tools for an explicitly bounded, disposable fixed-validator devnet.
#[cfg(unix)]
mod app;

fn main() -> std::process::ExitCode {
    #[cfg(unix)]
    {
        match app::run() {
            Ok(value) => {
                println!("{value}");
                std::process::ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("naome-devnet: {error}");
                std::process::ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(unix))]
    {
        eprintln!("naome-devnet: unsupported_platform");
        std::process::ExitCode::FAILURE
    }
}
