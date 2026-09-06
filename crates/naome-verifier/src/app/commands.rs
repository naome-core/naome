use std::path::Path;

use naome_consensus::{
    ConsensusHeight, ConsensusRound, ConsensusValueV0, VerifiedFixedConsensusTransitionV0,
};
use naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
use naome_storage::{
    FixedValidatorAnchoredFinalityJournalV0 as Journal,
    FixedValidatorFinalityCommitOutcomeV0 as Commit,
};
use serde_json::{Value, json};

use super::{files, input::Command, report};

pub(super) enum Failure {
    Rejected(&'static str),
    Fatal(&'static str),
}

pub(super) fn execute(
    command: Command,
    base: &Path,
    journal: &mut Journal,
) -> std::result::Result<(Value, bool), Failure> {
    use Failure::{Fatal, Rejected};
    match command {
        Command::Status { .. } => Ok((
            json!({"kind": "status", "state": report::status(journal).map_err(Fatal)?}),
            false,
        )),
        Command::Record { height, .. } => {
            if height == 0 {
                return Err(Rejected("record_height"));
            }
            let record = journal
                .finality_record(ConsensusHeight::new(height))
                .map_err(|_| Fatal("finality_state"))?
                .ok_or(Rejected("record_unavailable"))?;
            Ok((
                json!({"kind": "record", "record": report::record(record)}),
                false,
            ))
        }
        Command::Shutdown { .. } => Ok((json!({"kind": "shutdown"}), false)),
        Command::Import {
            envelope_file,
            payload_file,
            ..
        } => {
            let envelope = files::bytes(
                &base.join(envelope_file),
                VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH,
            )
            .map_err(Rejected)?;
            if envelope.len() < VerifiedFixedConsensusTransitionV0::MIN_BYTE_LENGTH {
                return Err(Rejected("envelope_length"));
            }
            // The prefix supplies only untrusted routing. In particular, an
            // already selected value must still verify the COMPLETE evidence.
            let route =
                ConsensusValueV0::from_canonical_bytes(&envelope[..ConsensusValueV0::BYTE_LENGTH])
                    .map_err(|_| Rejected("envelope_value"))?;
            if route.context() != journal.context() {
                return Err(Rejected("envelope_context"));
            }
            let parent = journal
                .parent_for_height(route.height())
                .map_err(|_| Fatal("finality_state"))?
                .ok_or(Rejected("parent_unavailable"))?;
            let payload = files::bytes(&base.join(payload_file), ARTIFACT_PAYLOAD_MAX_BYTES)
                .map_err(Rejected)?;
            let transition = parent
                .decode_and_verify_envelope_with_round_limit(
                    &envelope,
                    payload,
                    ConsensusRound::new(journal.replay_limit().max_round()),
                )
                .map_err(|_| Rejected("proof_verification"))?;
            // From this point on, errors can follow durable journal writes.
            // They must end ownership; no failed commit is an unchanged-state
            // rejection, and no report precedes the anchor acknowledgement.
            let committed = journal
                .commit_verified(transition)
                .map_err(|_| Fatal("finality_commit"))?;
            let (outcome, halted) = match committed {
                Commit::Finalized {
                    position,
                    ancestry_id,
                    envelope_id,
                    state_id,
                } => (
                    json!({"kind": "finalized", "height": position.height().value().to_string(),
                        "round": position.round().value().to_string(), "ancestry_id": report::hex(ancestry_id.as_bytes()),
                        "envelope_id": report::hex(envelope_id.as_bytes()), "state_id": report::hex(state_id.as_bytes())}),
                    false,
                ),
                Commit::AlreadyFinalized {
                    height,
                    ancestry_id,
                    retained_envelope_id,
                    state_id,
                } => (
                    json!({"kind": "already_finalized", "height": height.value().to_string(),
                        "ancestry_id": report::hex(ancestry_id.as_bytes()),
                        "retained_envelope_id": report::hex(retained_envelope_id.as_bytes()),
                        "state_id": report::hex(state_id.as_bytes())}),
                    false,
                ),
                Commit::Halted(halt) => {
                    (json!({"kind": "halted", "halt": report::halt(halt)}), true)
                }
            };
            Ok((outcome, halted))
        }
    }
}
