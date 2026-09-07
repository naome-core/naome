//! Explicit store disclosure; serving grants no selected-history authority.
use naome_network::{InboundArtifactBlockRequest, InboundArtifactRequest, RespondError};
use naome_runtime::FixedValidatorRuntimeV0 as Runtime;
use serde_json::{Value, json};

use super::sources::Sources;

pub(super) fn block(
    runtime: &mut Runtime<'_>,
    inbound: InboundArtifactBlockRequest,
    sources: Option<&mut Sources>,
) -> Value {
    let peer = inbound.peer_id().to_string();
    let address = super::report::hex(inbound.request().block_id().as_bytes());
    let busy = sources.is_none();
    let result = match sources {
        Some(sources) => {
            runtime.respond_block_from_candidate_store(inbound, &mut sources.candidates)
        }
        None => runtime.respond_block_unavailable(inbound),
    };
    report("block", peer, address, busy, result)
}

pub(super) fn artifact(
    runtime: &mut Runtime<'_>,
    inbound: InboundArtifactRequest,
    sources: Option<&mut Sources>,
) -> Value {
    let peer = inbound.peer_id().to_string();
    let address = super::report::hex(inbound.request().artifact_id().as_bytes());
    let busy = sources.is_none();
    let result = match sources {
        Some(sources) => {
            runtime.respond_artifact_from_payload_store(inbound, &mut sources.payloads)
        }
        None => runtime.respond_artifact_unavailable(inbound),
    };
    report("payload", peer, address, busy, result)
}

fn report(
    kind: &str,
    peer: String,
    address: String,
    busy: bool,
    result: std::result::Result<(), RespondError>,
) -> Value {
    match result {
        Ok(()) => {
            json!({"event":"source_response_queued", "kind":kind, "peer":peer, "address":address, "sources_busy":busy})
        }
        Err(error) => {
            let reason = match error {
                RespondError::CandidateStore(_) => "candidate_store",
                RespondError::PayloadStore(_) => "payload_store",
                RespondError::ChannelClosed => "channel_closed",
                RespondError::RateLimited => "rate_limited",
                _ => "unsupported_response",
            };
            // Source poisoning retains the existing source-local failure
            // boundary. It does not silently revoke independent signing state.
            json!({"event":"source_response_failed", "kind":kind, "peer":peer, "address":address, "reason":reason})
        }
    }
}
