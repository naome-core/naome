//! Bounded diagnostics. Writer threads own bytes, never state or signing keys.
use std::{
    io::{self, Write},
    sync::mpsc,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::sync::Arc;

pub(crate) type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy)]
pub(crate) enum Stream {
    Out,
    Error,
}
struct Frame {
    bytes: Vec<u8>,
    acknowledged: Option<mpsc::SyncSender<()>>,
}
pub(crate) struct Output {
    sender: mpsc::SyncSender<Frame>,
    #[cfg(unix)]
    failed: Arc<tokio::sync::Notify>,
}
impl Output {
    pub(crate) fn start(stream: Stream) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Frame>(32);
        #[cfg(unix)]
        let failed = Arc::new(tokio::sync::Notify::new());
        #[cfg(unix)]
        let writer_failed = Arc::clone(&failed);
        std::thread::Builder::new()
            .name("naome-output".into())
            .spawn(move || {
                let mut writer: Box<dyn Write> = match stream {
                    Stream::Out => Box::new(io::stdout().lock()),
                    Stream::Error => Box::new(io::stderr().lock()),
                };
                for frame in receiver {
                    if writer
                        .write_all(&frame.bytes)
                        .and_then(|()| writer.flush())
                        .is_err()
                    {
                        #[cfg(unix)]
                        writer_failed.notify_one();
                        break;
                    }
                    if let Some(acknowledged) = frame.acknowledged {
                        let _ = acknowledged.try_send(());
                    }
                }
            })?;
        Ok(Self {
            sender,
            #[cfg(unix)]
            failed,
        })
    }
    #[cfg(unix)]
    pub(crate) async fn failed(&self) {
        self.failed.notified().await;
    }
    pub(crate) fn line(&self, value: &str) -> Result<()> {
        self.line_bounded(value, 16_384)
    }
    fn report_line(&self, value: &str) -> Result<()> {
        self.line_bounded(value, 3 * 1024 * 1024)
    }
    fn line_bounded(&self, value: &str, maximum: usize) -> Result<()> {
        if value.len() > maximum {
            return Err("diagnostic output limit".into());
        }
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(b'\n');
        self.sender
            .try_send(Frame {
                bytes,
                acknowledged: None,
            })
            .map_err(|_| "diagnostic output backpressure".into())
    }
    // Call only after durable owners have dropped. Never join a stalled writer.
    pub(crate) fn finish_until(&self, deadline: Instant) -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Frame {
                bytes: Vec::new(),
                acknowledged: Some(sender),
            })
            .map_err(|_| "diagnostic output backpressure")?;
        receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "diagnostic output flush timed out".into())
    }
}
/// One-shot process output with a bounded wait, including startup errors.
pub(crate) fn message(stream: Stream, value: &str, budget: Duration) -> Result<()> {
    let output = Output::start(stream)?;
    output.line(value)?;
    output.finish_until(Instant::now() + budget)
}

/// Complete checked status reports are bounded separately from diagnostic
/// events: at most 8192 passive claims, 256 accounts, four endpoint strings and
/// one active attempt fit within the same 3 MiB bound as local control replies.
pub(crate) fn report(value: &str) -> Result<()> {
    let output = Output::start(Stream::Out)?;
    output.report_line(value)?;
    output.finish_until(Instant::now() + Duration::from_secs(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_report_preserves_every_bounded_claim_and_registered_account() {
        let limits = naome_ledger::profile::Limits::default();
        let maximum = limits.run_records;
        // Conservatively allow one claim per record at the profile ceiling. IDs and
        // ordinals have their full serialized widths; no report truncation.
        let claims = (0..maximum)
            .map(|n| {
                serde_json::json!({
                    "family": format!("{n:064x}"), "author": "ff".repeat(32), "ordinal": u64::MAX,
                })
            })
            .collect::<Vec<_>>();
        let accounts = (0..limits.registered_accounts).map(|n| serde_json::json!({
            "account":format!("{n:064x}"), "balance_atoms":u128::MAX.to_string(), "next_nonce":u64::MAX,
        })).collect::<Vec<_>>();
        let body = serde_json::json!({"claims":claims,"accounts":accounts,"registered_accounts":limits.registered_accounts,"remaining_account_slots":0,"registration_available":false}).to_string();
        assert!(body.len() > 16_384);
        assert!(body.len() < 3 * 1024 * 1024);
        let (sender, receiver) = mpsc::sync_channel(2);
        let output = Output {
            sender,
            #[cfg(unix)]
            failed: Arc::new(tokio::sync::Notify::new()),
        };
        assert!(output.line(&body).is_err());
        output.report_line(&body).unwrap();
        let frame = receiver.recv().unwrap();
        assert_eq!(frame.bytes, format!("{body}\n").into_bytes());
        let recovered: serde_json::Value = serde_json::from_slice(&frame.bytes).unwrap();
        assert_eq!(
            recovered["claims"].as_array().unwrap().len(),
            maximum as usize
        );
        assert_eq!(
            recovered["accounts"].as_array().unwrap().len(),
            limits.registered_accounts as usize
        );
    }
}
