//! Native graceful termination feeds the same owner teardown as input shutdown.

use super::Result;

#[cfg(unix)]
pub(super) struct Signals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(windows)]
pub(super) struct Signals {
    interrupt: tokio::signal::windows::CtrlC,
    terminate: tokio::signal::windows::CtrlBreak,
}

impl Signals {
    pub(super) fn new() -> Result<Self> {
        #[cfg(unix)]
        let signals = {
            use tokio::signal::unix::{SignalKind, signal};
            Self {
                interrupt: signal(SignalKind::interrupt()).map_err(|_| "signal_registration")?,
                terminate: signal(SignalKind::terminate()).map_err(|_| "signal_registration")?,
            }
        };
        #[cfg(windows)]
        let signals = Self {
            interrupt: tokio::signal::windows::ctrl_c().map_err(|_| "signal_registration")?,
            terminate: tokio::signal::windows::ctrl_break().map_err(|_| "signal_registration")?,
        };
        Ok(signals)
    }

    pub(super) async fn receive(&mut self) -> &'static str {
        #[cfg(unix)]
        let reasons = ["sigint", "sigterm"];
        #[cfg(windows)]
        let reasons = ["ctrl_c", "ctrl_break"];
        tokio::select! {
            biased;
            _ = self.interrupt.recv() => reasons[0],
            _ = self.terminate.recv() => reasons[1],
        }
    }
}
