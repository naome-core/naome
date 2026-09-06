use std::{
    io::{self, Write},
    sync::{Arc, mpsc},
    time::Duration,
};

use naome_storage::{
    FixedValidatorAnchoredFinalityJournalV0 as Journal, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityRecordV0,
};
use serde_json::{Value, json};
use tokio::sync::Notify;

use super::Result;

struct Frame {
    bytes: Vec<u8>,
    acknowledged: Option<mpsc::SyncSender<()>>,
}

pub(super) struct Output {
    sender: mpsc::SyncSender<Frame>,
    failed: Arc<Notify>,
}

impl Output {
    pub fn start() -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Frame>(32);
        let failed = Arc::new(Notify::new());
        let writer_failed = Arc::clone(&failed);
        // A stalled pipe retains only bounded report bytes, never authority.
        std::thread::Builder::new()
            .name("verifier-output".into())
            .spawn(move || {
                let mut stdout = io::stdout().lock();
                for frame in receiver {
                    if stdout
                        .write_all(&frame.bytes)
                        .and_then(|()| stdout.flush())
                        .is_err()
                    {
                        // One stored permit also covers failure before the
                        // journal owner starts waiting, including idle stdin.
                        writer_failed.notify_one();
                        break;
                    }
                    if let Some(acknowledged) = frame.acknowledged {
                        let _ = acknowledged.try_send(());
                    }
                }
            })
            .map_err(|_| "output_thread")?;
        Ok(Self { sender, failed })
    }

    pub async fn failed(&self) {
        self.failed.notified().await;
    }

    pub fn emit(&self, value: Value) -> Result<()> {
        self.send(value, None)
    }

    fn send(&self, value: Value, acknowledged: Option<mpsc::SyncSender<()>>) -> Result<()> {
        let mut bytes = serde_json::to_vec(&value).map_err(|_| "output_encode")?;
        if bytes.len() > 16_384 {
            return Err("output_limit");
        }
        bytes.push(b'\n');
        self.sender
            .try_send(Frame {
                bytes,
                acknowledged,
            })
            .map_err(|_| "output_backpressure")
    }

    // Called only after journal ownership has ended. Never join a blocked
    // writer, and never repeat a failed final flush on the same output sink.
    pub fn finish(&self, value: Value) -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.send(value, Some(sender))?;
        receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "output_flush")
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn halt(halt: FixedValidatorFinalityHaltV0) -> Value {
    json!({
        "kind": format!("{:?}", halt.kind()), "height": halt.height().value().to_string(),
        "first_ancestry": hex(halt.first_ancestry().as_bytes()),
        "first_envelope_id": hex(halt.first_envelope_id().as_bytes()),
        "second_ancestry": hex(halt.second_ancestry().as_bytes()),
        "second_envelope_id": hex(halt.second_envelope_id().as_bytes()),
        "state_id": hex(halt.state_id().as_bytes()),
    })
}

pub(super) fn status(journal: &Journal) -> Result<Value> {
    let state_id = journal.state_id().map_err(|_| "finality_state")?;
    let halted = journal.halt().map_err(|_| "finality_state")?;
    let head = if halted.is_some() {
        Value::Null
    } else {
        let head = journal.head().map_err(|_| "finality_state")?;
        json!({
            "height": head.verified_height().map_or(0, |h| h.value()).to_string(),
            "ancestry_id": hex(head.ancestry_id().as_bytes()),
            "artifact_block_id": hex(head.artifact_snapshot().head_block_id().as_bytes()),
            "artifact_set_root": hex(head.artifact_snapshot().artifact_set_root().as_bytes()),
        })
    };
    Ok(json!({
        "chain_id": hex(journal.context().chain_id().as_bytes()),
        "genesis_id": hex(journal.context().genesis_id().as_bytes()),
        "protocol_version": journal.context().protocol_version().value(),
        "fixed_set_id": hex(journal.fixed_agreement_set_id().as_bytes()),
        "finality_max_round": journal.replay_limit().max_round().to_string(),
        "state_id": hex(state_id.as_bytes()), "head": head, "halt": halted.map(halt),
    }))
}

pub(super) fn record(record: &FixedValidatorFinalityRecordV0) -> Value {
    let value = record.value();
    json!({
        "height": record.position().height().value().to_string(),
        "round": record.position().round().value().to_string(),
        "ancestry_id": hex(value.ancestry_id().as_bytes()),
        "envelope_id": hex(record.envelope_id().as_bytes()),
        "artifact_block_id": hex(value.artifact_block().id().as_bytes()),
        "state_id": hex(record.state_id().as_bytes()),
        "envelope_bytes": record.canonical_envelope_bytes().len(),
        "payload_bytes": record.canonical_artifact_bytes().len(),
    })
}
