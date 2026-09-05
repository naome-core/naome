use std::{
    io::{self, Write},
    sync::mpsc,
    time::Duration,
};

use naome_network::{NetworkEvent, PeerSessionEvent};
use naome_node::FixedValidatorNodeDriverV0;
use naome_runtime::{
    FixedValidatorRuntimeDeliveryStateV0 as Delivery, FixedValidatorRuntimeEventV0 as Event,
    FixedValidatorRuntimeFailureV0 as Failure, FixedValidatorRuntimeInputSourceV0 as InputSource,
    FixedValidatorRuntimePublicationMessageV0 as Message,
    FixedValidatorRuntimePublicationV0 as Publication, FixedValidatorRuntimeV0 as Runtime,
};
use serde_json::{Value, json};

use super::Result;

struct Frame {
    bytes: Vec<u8>,
    acknowledged: Option<mpsc::SyncSender<()>>,
}

pub(super) struct Output(mpsc::SyncSender<Frame>);

impl Output {
    pub fn start() -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Frame>(32);
        // This thread owns only bounded report bytes. A stalled stdout reader
        // cannot block the signing executor or prevent journal-owner drop.
        std::thread::Builder::new()
            .name("validator-output".into())
            .spawn(move || {
                let mut stdout = io::stdout().lock();
                for frame in receiver {
                    if stdout
                        .write_all(&frame.bytes)
                        .and_then(|()| stdout.flush())
                        .is_err()
                    {
                        break;
                    }
                    if let Some(ack) = frame.acknowledged {
                        let _ = ack.try_send(());
                    }
                }
            })
            .map_err(|_| "output_thread")?;
        Ok(Self(sender))
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
        self.0
            .try_send(Frame {
                bytes,
                acknowledged,
            })
            .map_err(|_| "output_backpressure")
    }

    /// Only called after journal owners have dropped. Never join a writer that
    /// may be blocked on the user's pipe; final flush has a bounded wait.
    pub fn finish(&self, value: Value) -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.send(value, Some(sender))?;
        receiver
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "output_flush")
    }
}

pub(super) fn driver(driver: Option<&FixedValidatorNodeDriverV0<'_>>) -> Value {
    let Some(driver) = driver else {
        return Value::Null;
    };
    json!({
        "height": driver.position().height().value().to_string(),
        "round": driver.position().round().value().to_string(),
        "phase": format!("{:?}", driver.phase()),
        "head": driver.selected_artifact_history().selected_head_block_id().ok().map(|id| hex(id.as_bytes())),
        "higher_inbox": driver.inbox_len(), "current_inbox": driver.current_inbox_len(),
        "finality_inbox": driver.current_finality_inbox_len(), "nil_precommit_inbox": driver.current_nil_precommit_inbox_len(),
        "pending_command": driver.has_pending_command(), "timeout_due": driver.timeout_is_due(),
    })
}

pub(super) fn publication(publication: &Publication) -> Value {
    json!({
        "size": format!("{:?}", publication.message().size()),
        "local_admission_attempted": publication.local_admission_attempted(),
        "released_proposal": matches!(publication.message(), Message::Vote { released_proposal: Some(_), .. }),
        "deliveries": publication.deliveries().map(|delivery| json!({
            "peer": delivery.peer_id().to_string(),
            "state": match delivery.state() {
                Delivery::NotAttempted => "not_attempted", Delivery::InFlight(_) => "in_flight",
                Delivery::Refused(_) => "refused", Delivery::Failed(_) => "failed", Delivery::Received(_) => "received",
            },
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn status(runtime: &Runtime<'_>) -> Value {
    json!({ "driver": driver(runtime.driver()), "timer": runtime.timer().is_some(), "publication": runtime.pending_publication().map(publication) })
}

pub(super) fn stopped(runtime: Runtime<'_>, reason: &str, queued_commands: usize) -> Value {
    let parts = runtime.into_parts();
    // These are disposal diagnostics, not a persisted recovery/outbox record.
    json!({
        "event": "stopped", "reason": reason, "locks_released": true,
        "discarded": {
            "driver": driver(parts.driver.as_ref()), "publication": parts.publication.as_ref().map(publication),
            "timer": parts.timer.is_some(), "pending_arm": parts.pending_arm.is_some(),
            "network_event": parts.pending_network_event.is_some(), "caller_input": parts.pending_caller_input.is_some(),
            "failed_admission": parts.failed_admission.is_some(), "rejected_due_ticket": parts.rejected_due_ticket.is_some(),
            "queued_operator_frames": queued_commands, "unacknowledged_stdin_discarded": true,
        },
    })
}

pub(super) fn event(event: Event<'_>) -> (Value, bool) {
    let mut fatal = false;
    let value = match event {
        Event::TimerArmed(timer) => {
            json!({"event": "timer_armed", "phase": format!("{:?}", timer.ticket().phase())})
        }
        Event::TimerDue { result, .. } => json!({"event": "timer_due", "admitted": result.is_ok()}),
        Event::Transitioned { position, phase } => {
            json!({"event": "transitioned", "height": position.height().value().to_string(), "round": position.round().value().to_string(), "phase": format!("{phase:?}")})
        }
        Event::Finality(_) => json!({"event": "finality"}),
        Event::PublicationPrepared(size) => {
            json!({"event": "publication_prepared", "size": format!("{size:?}")})
        }
        Event::PeerAttempted { peer_id, started } => {
            json!({"event": "peer_attempted", "peer": peer_id.to_string(), "started": started})
        }
        Event::PeerCompleted { peer_id, received } => {
            json!({"event": "peer_completed", "peer": peer_id.to_string(), "received": received})
        }
        Event::PublicationComplete(value) => {
            json!({"event": "publication_complete", "disposed": publication(&value)})
        }
        Event::Admission(report) => {
            json!({"event": "admission", "source": match report.source { InputSource::LocalPublication => json!({"kind": "local_publication"}), InputSource::CallerInput => json!({"kind": "caller"}), InputSource::Peer(peer) => json!({"kind": "peer", "peer": peer.to_string()}) }, "receipt_queued": report.receipt_queued, "all_admitted": report.all_admitted(), "routing_error": report.routing_error.is_some(), "routes": report.results.iter().flatten().map(|result| json!({"route": format!("{:?}", result.route), "admitted": result.result.is_ok()})).collect::<Vec<_>>() })
        }
        Event::Network(NetworkEvent::Listening { address }) => {
            json!({"event": "listening", "address": address.to_string()})
        }
        Event::Network(NetworkEvent::PeerSession(event)) => {
            json!({"event": "peer_session", "peer": event.peer_id().to_string(), "state": match event { PeerSessionEvent::Established { .. } => "established", PeerSessionEvent::DialFailed { .. } => "dial_failed", PeerSessionEvent::Disconnected { .. } => "disconnected", _ => "unsupported" }})
        }
        Event::Network(
            NetworkEvent::ListenerError { .. } | NetworkEvent::ListenerClosed { .. },
        ) => {
            fatal = true;
            json!({"event": "listener_failed"})
        }
        Event::Network(_) => json!({"event": "network_event_discarded"}),
        Event::DriverBlocked(_) => json!({"event": "driver_blocked"}),
        Event::DriverRejected(_) => json!({"event": "driver_rejected"}),
        Event::ProposalAuthored => json!({"event": "proposal_authored"}),
        Event::ProposalRejected(_) => json!({"event": "proposal_rejected"}),
        Event::AuthoringBusy(_) | Event::StoreAuthoringBusy => json!({"event": "authoring_busy"}),
        Event::AuthoringStepWorkPending => json!({"event": "authoring_step_work_pending"}),
        Event::ExplicitCommandPending => json!({"event": "explicit_command_pending"}),
        Event::CurrentFinalityUnresolved => json!({"event": "current_finality_unresolved"}),
        Event::HigherEvidenceUnresolved => json!({"event": "higher_evidence_unresolved"}),
        Event::HigherRoundAdvanceRejected(_) => json!({"event": "higher_round_rejected"}),
        Event::CurrentRoundFinalityRejected(_) => {
            json!({"event": "current_round_finality_rejected"})
        }
        Event::LowerRoundFinalityRejected(_) => json!({"event": "lower_round_finality_rejected"}),
        Event::CandidateBackedFinalityRejected(_) => {
            json!({"event": "candidate_finality_rejected"})
        }
        Event::LowerRoundPreselectionConflictRejected(_) => {
            json!({"event": "lower_round_conflict_rejected"})
        }
        Event::CurrentRoundPreselectionConflictRejected(_) => {
            json!({"event": "current_round_conflict_rejected"})
        }
        // Fail closed on lost driver, allocation/timing failure or future
        // authority-bearing variants. No implicit replay, drain or repair.
        Event::UnacknowledgedInput { .. } | Event::ReservationFailed(_) => {
            fatal = true;
            json!({"event": "allocation_failed"})
        }
        Event::TimingRejected(_) => {
            fatal = true;
            json!({"event": "timing_failed"})
        }
        Event::Fatal(error) => {
            fatal = true;
            match *error {
                Failure::FinalityStopped(stopped) => {
                    let halt = stopped.finality_halt();
                    json!({"event": "finality_stopped", "kind": format!("{:?}", halt.kind()),
                        "height": halt.height().value().to_string(),
                        "first_ancestry": hex(halt.first_ancestry().as_bytes()),
                        "second_ancestry": hex(halt.second_ancestry().as_bytes()),
                        "finality_state_id": hex(halt.state_id().as_bytes()),
                        "signer_finality_state_id": hex(stopped.signer_stop().finality_state_id().as_bytes())})
                }
                Failure::HistoricalFinalityConflict(_) => {
                    json!({"event": "proof_failed", "operation": "historical_finality_conflict", "strict_restart_required": true})
                }
                Failure::LowerRoundPreselectionConflict(_) => {
                    json!({"event": "proof_failed", "operation": "lower_round_conflict", "strict_restart_required": true})
                }
                Failure::CurrentRoundPreselectionConflict(_) => {
                    json!({"event": "proof_failed", "operation": "current_round_conflict", "strict_restart_required": true})
                }
                _ => json!({"event": "driver_unavailable"}),
            }
        }
        Event::DriverUnavailable
        | Event::AuthoringUnavailable(_)
        | Event::StoreAuthoringUnavailable => {
            fatal = true;
            json!({"event": "driver_unavailable"})
        }
        _ => {
            fatal = true;
            json!({"event": "unsupported_runtime_event"})
        }
    };
    (value, fatal)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
