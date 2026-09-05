use std::path::Path;

use naome_chain::{ARTIFACT_BLOCK_BYTES, ArtifactBlock};
use naome_consensus::FixedValidatorProposalSourceV0 as Source;
use naome_network::{
    CONSENSUS_PUSH_MAX_PAYLOAD_BYTES, CONSENSUS_PUSH_MAX_PROPOSAL_BYTES, CONSENSUS_PUSH_VOTE_BYTES,
    ConsensusPushMessage,
};
use naome_runtime::FixedValidatorRuntimeV0 as Runtime;
use serde_json::{Value, json};

use super::{Result, files, input::Command, report};

pub(super) fn execute(
    command: Command,
    base: &Path,
    runtime: &mut Runtime<'_>,
) -> Result<(Value, bool)> {
    let input = match command {
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
        Command::Status { .. } => return Ok((report::status(runtime), false)),
        Command::Shutdown { .. } => return Ok((json!({"event": "shutdown_requested"}), false)),
    };
    runtime
        .queue_input(input)
        .map_err(|_| "input_queue_refused")?;
    Ok((json!({"event": "input_queued"}), false))
}
