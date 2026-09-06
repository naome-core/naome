use naome_chain::ArtifactBlockId;
use naome_network::{
    ArtifactBlockCandidateAncestryFill, ArtifactBlockCandidateAncestryFillError as AncestryError,
    ArtifactBlockCandidateBranchPayloadFillProgress as PayloadProgress, MAX_STATIC_PEERS,
    NetworkEvent, PeerId,
};
use naome_runtime::{
    FixedValidatorRuntimeAcquisitionStartErrorV0 as StartError,
    FixedValidatorRuntimeAncestryFillAdvanceErrorV0 as AncestryAdvanceError,
    FixedValidatorRuntimePayloadFillAdvanceErrorV0 as PayloadAdvanceError,
    FixedValidatorRuntimeV0 as Runtime,
};
use naome_storage::CandidateBranchReconstructionLimits;
use serde_json::{Value, json};

use super::{Result, config, input::Command, sources::Sources};

pub(super) struct Acquisition<'store> {
    target: ArtifactBlockId,
    phase: Phase<'store>,
}

enum Phase<'store> {
    Ancestry(Option<ArtifactBlockCandidateAncestryFill<'store>>),
    Payload(PayloadProgress<'store>),
}

enum Peers {
    Direct(PeerId),
    Fallback(Vec<PeerId>),
}

impl Acquisition<'_> {
    pub fn start<'store>(
        command: Command,
        runtime: &mut Runtime<'_>,
        sources: &'store mut Sources,
    ) -> Result<Acquisition<'store>> {
        let (target, anchor, peers, blocks) = match command {
            Command::AcquireAncestry {
                target, peer_id, ..
            } => (target, None, Peers::Direct(peer(&peer_id)?), None),
            Command::AcquireAncestryFallback {
                target, peer_ids, ..
            } => (target, None, fallback(peer_ids)?, None),
            Command::AcquireAnchoredAncestry {
                target,
                anchor,
                peer_id,
                ..
            } => (
                target,
                Some(block(&anchor)?),
                Peers::Direct(peer(&peer_id)?),
                None,
            ),
            Command::AcquireAnchoredAncestryFallback {
                target,
                anchor,
                peer_ids,
                ..
            } => (target, Some(block(&anchor)?), fallback(peer_ids)?, None),
            Command::AcquirePayloads {
                target,
                peer_id,
                max_blocks,
                ..
            } => (
                target,
                None,
                Peers::Direct(peer(&peer_id)?),
                Some(max_blocks),
            ),
            Command::AcquirePayloadsFallback {
                target,
                peer_ids,
                max_blocks,
                ..
            } => (target, None, fallback(peer_ids)?, Some(max_blocks)),
            _ => return Err("acquisition_command"),
        };
        let target = block(&target)?;
        let phase = if let Some(blocks) = blocks {
            let limit = CandidateBranchReconstructionLimits::new(
                usize::try_from(blocks).map_err(|_| "source_block_limit")?,
            )
            .map_err(|_| "source_block_limit")?;
            let progress = match peers {
                Peers::Direct(peer) => runtime.start_artifact_block_candidate_branch_payload_fill(
                    &mut sources.candidates,
                    &mut sources.payloads,
                    peer,
                    target,
                    limit,
                ),
                Peers::Fallback(peers) => runtime
                    .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                        &mut sources.candidates,
                        &mut sources.payloads,
                        &peers,
                        target,
                        limit,
                    ),
            }
            .map_err(start_error)?;
            Phase::Payload(progress)
        } else {
            let progress = match (anchor, peers) {
                (None, Peers::Direct(peer)) => runtime.start_artifact_block_candidate_ancestry_fill(
                    &mut sources.candidates, peer, target,
                ),
                (None, Peers::Fallback(peers)) => runtime.start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                    &mut sources.candidates, &peers, target,
                ),
                (Some(anchor), Peers::Direct(peer)) => runtime.start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                    &mut sources.candidates, peer, anchor, target,
                ),
                (Some(anchor), Peers::Fallback(peers)) => runtime.start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                    &mut sources.candidates, &peers, anchor, target,
                ),
            }.map_err(start_error)?;
            Phase::Ancestry(progress)
        };
        Ok(Acquisition { target, phase })
    }

    pub fn complete(&self) -> bool {
        matches!(
            self.phase,
            Phase::Ancestry(None) | Phase::Payload(PayloadProgress::Complete(_))
        )
    }

    pub fn status(&self) -> Value {
        let mut value = json!({"target": hex(self.target.as_bytes()), "complete": self.complete()});
        match &self.phase {
            Phase::Ancestry(progress) => {
                value["kind"] = json!("ancestry");
                if let Some(progress) = progress {
                    value["anchor"] = json!(hex(progress.anchor_block_id().as_bytes()));
                    value["pending_block"] = json!(hex(progress.pending_block_id().as_bytes()));
                    value["peer"] = json!(progress.pending_peer_id().to_string());
                }
            }
            Phase::Payload(progress) => {
                value["kind"] = json!("payloads");
                match progress {
                    PayloadProgress::AwaitingResponse(progress) => {
                        value["pending_block"] = json!(hex(progress.pending_block_id().as_bytes()));
                        value["pending_artifact"] =
                            json!(hex(progress.pending_artifact_id().as_bytes()));
                        value["peer"] = json!(progress.pending_peer_id().to_string());
                    }
                    PayloadProgress::Complete(branch) => {
                        value["anchor"] = json!(hex(branch.anchor_block_id().as_bytes()));
                        value["validated_blocks"] = json!(branch.block_count());
                    }
                }
            }
        }
        value
    }

    pub fn accepts_event(&self, event: &NetworkEvent) -> bool {
        match &self.phase {
            Phase::Ancestry(Some(progress)) => progress.accepts_event(event),
            Phase::Payload(PayloadProgress::AwaitingResponse(progress)) => {
                progress.accepts_event(event)
            }
            _ => false,
        }
    }

    pub fn advance(self, runtime: &mut Runtime<'_>, event: NetworkEvent) -> Result<Self> {
        let phase = match self.phase {
            Phase::Ancestry(Some(progress)) => Phase::Ancestry(
                runtime
                    .advance_artifact_block_candidate_ancestry_fill(progress, event)
                    .map_err(|error| match *error {
                        AncestryAdvanceError::Operation(error) => ancestry_error(&error),
                        AncestryAdvanceError::Refused {
                            progress, event, ..
                        } => {
                            // An explicit process attempt ends on refusal. The
                            // refunded owners are disposed without resubmission.
                            progress.cancel();
                            drop(event);
                            "source_advance_refused"
                        }
                    })?,
            ),
            Phase::Payload(PayloadProgress::AwaitingResponse(progress)) => Phase::Payload(
                runtime
                    .advance_artifact_block_candidate_branch_payload_fill(progress, event)
                    .map_err(|error| match *error {
                        PayloadAdvanceError::Operation(_) => "source_payload_failure",
                        PayloadAdvanceError::Refused {
                            progress, event, ..
                        } => {
                            progress.cancel();
                            drop(event);
                            "source_advance_refused"
                        }
                    })?,
            ),
            _ => return Err("acquisition_complete"),
        };
        Ok(Self {
            target: self.target,
            phase,
        })
    }

    pub fn cancel(self) {
        match self.phase {
            Phase::Ancestry(Some(progress)) => progress.cancel(),
            Phase::Payload(PayloadProgress::AwaitingResponse(progress)) => progress.cancel(),
            _ => {}
        }
    }
}

fn start_error(error: StartError) -> &'static str {
    match error {
        StartError::DriverUnavailable => "driver_unavailable",
        StartError::Ancestry(error) => ancestry_error(&error),
        StartError::Payload(_) => "source_payload_failure",
    }
}

fn ancestry_error(error: &AncestryError) -> &'static str {
    match error {
        AncestryError::SelectedHeadChanged { .. } => "source_selected_head_changed",
        AncestryError::CandidateStoreRead { .. } | AncestryError::CandidateStoreInsert { .. } => {
            "source_candidate_store"
        }
        AncestryError::RequestStart { .. } | AncestryError::NoRequestableBlockPeer { .. } => {
            "source_request_start"
        }
        AncestryError::BlockUnavailable { .. } => "source_block_unavailable",
        _ => "source_ancestry_failure",
    }
}

pub(super) fn block(value: &str) -> Result<ArtifactBlockId> {
    config::hex32(value)
        .map(ArtifactBlockId::from_bytes)
        .map_err(|_| "source_block_id")
}

fn peer(value: &str) -> Result<PeerId> {
    value.parse().map_err(|_| "source_peer_id")
}

fn fallback(values: Vec<String>) -> Result<Peers> {
    if values.is_empty() || values.len() > MAX_STATIC_PEERS {
        return Err("source_peer_count");
    }
    values
        .iter()
        .map(|value| peer(value))
        .collect::<Result<Vec<_>>>()
        .map(Peers::Fallback)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
