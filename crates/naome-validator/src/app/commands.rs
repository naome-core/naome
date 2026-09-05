use std::path::{Path, PathBuf};

use naome_chain::{ARTIFACT_BLOCK_BYTES, ArtifactBlock};
use naome_consensus::{
    ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget,
    FixedValidatorProposalSourceV0 as Source, MAX_ACTIVE_VALIDATORS, ProposalSigningRoot,
    VerifiedFixedConsensusTransitionV0, VerifiedPrecommitCertificateV0,
    VerifiedQuorumCertificateV0,
};
use naome_network::{
    CONSENSUS_PUSH_MAX_PAYLOAD_BYTES, CONSENSUS_PUSH_MAX_PROPOSAL_BYTES, CONSENSUS_PUSH_VOTE_BYTES,
    ConsensusPushMessage,
};
use naome_runtime::{
    FixedValidatorRuntimeEventV0 as Event, FixedValidatorRuntimeProofRefusalV0 as Refusal,
    FixedValidatorRuntimeV0 as Runtime,
};
use serde_json::{Value, json};

use super::{
    Result, config, files,
    input::{Command, InboxClass, ProposalVoteFiles, VoteRole, VoteTarget},
    report,
};

pub(super) fn execute(
    command: Command,
    base: &Path,
    runtime: &mut Runtime<'_>,
) -> Result<(Value, bool)> {
    let input = match command {
        Command::DiscardInbox { inbox, .. } => {
            let discarded_items = match inbox {
                InboxClass::Higher => runtime.drain_inbox_and_reset().map(discard),
                InboxClass::Current => runtime.drain_current_inbox_and_reset().map(discard),
                InboxClass::Finality => runtime
                    .drain_current_finality_inbox_and_reset()
                    .map(discard),
                InboxClass::NilPrecommit => runtime
                    .drain_current_nil_precommit_inbox_and_reset()
                    .map(discard),
            }
            .ok_or("driver_unavailable")?;
            return Ok((
                json!({"event": "inbox_discarded", "inbox": inbox,
                    "discarded_items": discarded_items, "state": report::status(runtime)}),
                false,
            ));
        }
        Command::AuthorFresh {
            block_file,
            payload_file,
            ..
        } => {
            let artifact_block = ArtifactBlock::from_canonical_bytes(&files::bytes(
                &base.join(block_file),
                ARTIFACT_BLOCK_BYTES,
            )?)
            .map_err(|_| "block_decode")?;
            let canonical_artifact_bytes =
                files::bytes(&base.join(payload_file), CONSENSUS_PUSH_MAX_PAYLOAD_BYTES)?;
            return Ok(report::event(runtime.author_proposal(Source::Fresh {
                artifact_block,
                canonical_artifact_bytes,
            })));
        }
        Command::AuthorRetained { payload_file, .. } => {
            let canonical_artifact_bytes =
                files::bytes(&base.join(payload_file), CONSENSUS_PUSH_MAX_PAYLOAD_BYTES)?;
            return Ok(report::event(runtime.author_proposal(
                Source::RetainedValid {
                    canonical_artifact_bytes,
                },
            )));
        }
        Command::SubmitVote { vote_file, .. } => ConsensusPushMessage::Vote {
            canonical_vote: files::bytes(&base.join(vote_file), CONSENSUS_PUSH_VOTE_BYTES)?,
        },
        Command::SubmitProposal {
            control_file,
            payload_file,
            ..
        } => ConsensusPushMessage::Proposal {
            canonical_proposal: files::bytes(
                &base.join(control_file),
                CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
            )?,
            canonical_artifact: files::bytes(
                &base.join(payload_file),
                CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
            )?,
        },
        Command::AdvanceHigherQuorum {
            certificate_file, ..
        } => {
            let certificate = files::bytes(
                &base.join(certificate_file),
                VerifiedQuorumCertificateV0::MAX_BYTE_LENGTH,
            )?;
            let outcome = runtime.advance_to_higher_round_quorum(&certificate);
            return Ok(proof_outcome(outcome, runtime, 0));
        }
        Command::AdvanceHigherVotes {
            evidence_round,
            role,
            target,
            vote_files,
            ..
        } => {
            let role = match role {
                VoteRole::Prevote => ConsensusVoteRole::Prevote,
                VoteRole::Precommit => ConsensusVoteRole::Precommit,
            };
            let target = match target {
                VoteTarget::Nil {} => ConsensusVoteTarget::Nil,
                VoteTarget::Proposal { root } => {
                    ConsensusVoteTarget::Proposal(ProposalSigningRoot::from_bytes(
                        config::hex32(&root).map_err(|_| "proof_root")?,
                    ))
                }
            };
            let votes = read_votes(base, &vote_files)?;
            let refs = vote_refs(&votes);
            let outcome = runtime.advance_to_higher_round_vote_batch(
                &refs,
                ConsensusRound::new(evidence_round),
                role,
                target,
            );
            return Ok(proof_outcome(outcome, runtime, 0));
        }
        Command::HaltHistoricalEnvelope {
            envelope_file,
            payload_file,
            ..
        } => {
            let envelope = files::bytes(
                &base.join(envelope_file),
                VerifiedFixedConsensusTransitionV0::MAX_BYTE_LENGTH,
            )?;
            let payload = files::bytes(&base.join(payload_file), CONSENSUS_PUSH_MAX_PAYLOAD_BYTES)?;
            let outcome = runtime
                .commit_historical_finality_conflict(&envelope, payload)
                .map_err(|(reason, _payload)| reason);
            return Ok(proof_outcome(outcome, runtime, 1));
        }
        Command::HaltHistoricalVotes {
            evidence_round,
            proof,
            ..
        } => {
            check_vote_count(&proof.vote_files)?;
            let proof = read_proposal_votes(base, proof)?;
            let refs = vote_refs(&proof.votes);
            let outcome = runtime
                .commit_historical_finality_conflict_vote_batch(
                    &proof.control,
                    proof.payload,
                    &refs,
                    ConsensusRound::new(evidence_round),
                )
                .map_err(|(reason, _payload)| reason);
            return Ok(proof_outcome(outcome, runtime, 1));
        }
        Command::FinalizeCurrentQuorum {
            control_file,
            payload_file,
            certificate_file,
            ..
        } => {
            let control =
                files::bytes(&base.join(control_file), CONSENSUS_PUSH_MAX_PROPOSAL_BYTES)?;
            let payload = files::bytes(&base.join(payload_file), CONSENSUS_PUSH_MAX_PAYLOAD_BYTES)?;
            let certificate = files::bytes(
                &base.join(certificate_file),
                VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH,
            )?;
            let outcome = runtime
                .commit_current_round_finality(&control, payload, &certificate)
                .map_err(|(reason, _payload)| reason);
            return Ok(proof_outcome(outcome, runtime, 1));
        }
        Command::FinalizeCurrentVotes { proof, .. } => {
            check_vote_count(&proof.vote_files)?;
            let proof = read_proposal_votes(base, proof)?;
            let refs = vote_refs(&proof.votes);
            let outcome = runtime
                .commit_current_round_finality_vote_batch(&proof.control, proof.payload, &refs)
                .map_err(|(reason, _payload)| reason);
            return Ok(proof_outcome(outcome, runtime, 1));
        }
        Command::FinalizeLowerQuorum {
            control_file,
            payload_file,
            certificate_file,
            ..
        } => {
            let control =
                files::bytes(&base.join(control_file), CONSENSUS_PUSH_MAX_PROPOSAL_BYTES)?;
            let payload = files::bytes(&base.join(payload_file), CONSENSUS_PUSH_MAX_PAYLOAD_BYTES)?;
            let certificate = files::bytes(
                &base.join(certificate_file),
                VerifiedPrecommitCertificateV0::MAX_BYTE_LENGTH,
            )?;
            let outcome = runtime
                .commit_lower_round_finality(&control, payload, &certificate)
                .map_err(|(reason, _payload)| reason);
            return Ok(proof_outcome(outcome, runtime, 1));
        }
        Command::FinalizeLowerVotes {
            evidence_round,
            proof,
            ..
        } => {
            check_vote_count(&proof.vote_files)?;
            let proof = read_proposal_votes(base, proof)?;
            let refs = vote_refs(&proof.votes);
            let outcome = runtime
                .commit_lower_round_finality_vote_batch(
                    &proof.control,
                    proof.payload,
                    &refs,
                    ConsensusRound::new(evidence_round),
                )
                .map_err(|(reason, _payload)| reason);
            return Ok(proof_outcome(outcome, runtime, 1));
        }
        Command::HaltCurrentConflict { first, second, .. } => {
            check_vote_count(&first.vote_files)?;
            check_vote_count(&second.vote_files)?;
            let first = read_proposal_votes(base, first)?;
            let second = read_proposal_votes(base, second)?;
            let first_refs = vote_refs(&first.votes);
            let second_refs = vote_refs(&second.votes);
            let outcome = runtime
                .commit_current_round_preselection_conflict_vote_batches(
                    &first.control,
                    first.payload,
                    &first_refs,
                    &second.control,
                    second.payload,
                    &second_refs,
                )
                .map_err(|(reason, _first, _second)| reason);
            return Ok(proof_outcome(outcome, runtime, 2));
        }
        Command::HaltLowerConflict {
            evidence_round,
            first,
            second,
            ..
        } => {
            // Bound both batches before opening either proof's source files.
            check_vote_count(&first.vote_files)?;
            check_vote_count(&second.vote_files)?;
            let first = read_proposal_votes(base, first)?;
            let second = read_proposal_votes(base, second)?;
            let first_refs = vote_refs(&first.votes);
            let second_refs = vote_refs(&second.votes);
            let outcome = runtime
                .commit_lower_round_preselection_conflict_vote_batches(
                    &first.control,
                    first.payload,
                    &first_refs,
                    &second.control,
                    second.payload,
                    &second_refs,
                    ConsensusRound::new(evidence_round),
                )
                .map_err(|(reason, _first, _second)| reason);
            return Ok(proof_outcome(outcome, runtime, 2));
        }
        Command::Status { .. } => return Ok((report::status(runtime), false)),
        Command::Shutdown { .. } => return Ok((json!({"event": "shutdown_requested"}), false)),
    };
    runtime
        .queue_input(input)
        .map_err(|_| "input_queue_refused")?;
    Ok((json!({"event": "input_queued"}), false))
}

fn discard(inbox: impl ExactSizeIterator) -> usize {
    let count = inbox.len();
    drop(inbox);
    count
}

fn check_vote_count(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() || paths.len() > MAX_ACTIVE_VALIDATORS {
        return Err("proof_vote_count");
    }
    Ok(())
}

fn read_votes(base: &Path, paths: &[PathBuf]) -> Result<Vec<Vec<u8>>> {
    check_vote_count(paths)?;
    paths
        .iter()
        .map(|path| {
            let bytes = files::bytes(&base.join(path), CONSENSUS_PUSH_VOTE_BYTES)?;
            if bytes.len() != CONSENSUS_PUSH_VOTE_BYTES {
                return Err("proof_vote_length");
            }
            Ok(bytes)
        })
        .collect()
}

fn vote_refs(votes: &[Vec<u8>]) -> Vec<&[u8]> {
    votes.iter().map(Vec::as_slice).collect()
}

struct ProposalVotes {
    control: Vec<u8>,
    payload: Vec<u8>,
    votes: Vec<Vec<u8>>,
}

fn read_proposal_votes(base: &Path, proof: ProposalVoteFiles) -> Result<ProposalVotes> {
    Ok(ProposalVotes {
        control: files::bytes(
            &base.join(proof.control_file),
            CONSENSUS_PUSH_MAX_PROPOSAL_BYTES,
        )?,
        payload: files::bytes(
            &base.join(proof.payload_file),
            CONSENSUS_PUSH_MAX_PAYLOAD_BYTES,
        )?,
        votes: read_votes(base, &proof.vote_files)?,
    })
}

fn proof_outcome(
    outcome: std::result::Result<Event<'_>, Refusal>,
    runtime: &Runtime<'_>,
    payloads: usize,
) -> (Value, bool) {
    let (mut value, fatal) = match outcome {
        Ok(event) => report::event(event),
        Err(reason) => (
            json!({"event": "proof_refused", "refunded_payloads_discarded": payloads, "reason": match reason {
                Refusal::Busy => "busy", Refusal::DriverUnavailable => "driver_unavailable",
            }}),
            matches!(reason, Refusal::DriverUnavailable),
        ),
    };
    // A command is one attempt. Refunded payloads are discarded, never retried.
    value["state"] = report::status(runtime);
    (value, fatal)
}
