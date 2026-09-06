use naome_network::{FinalityProofRespondError, InboundFinalityProofRequest};
use naome_runtime::{
    FixedValidatorRuntimeFinalityProofResponseErrorV0 as ResponseError, FixedValidatorRuntimeV0,
};
use serde_json::{Value, json};

pub(super) fn respond(
    runtime: &mut FixedValidatorRuntimeV0<'_>,
    inbound: InboundFinalityProofRequest,
) -> (Value, bool) {
    let peer = inbound.peer_id().to_string();
    let height = inbound.request().height().value().to_string();
    match runtime.respond_finality_proof_from_selected_history(inbound) {
        Ok(()) => (
            json!({"event": "proof_response_queued", "peer": peer, "height": height}),
            false,
        ),
        Err(error) => {
            let (reason, fatal) = match error {
                ResponseError::DriverUnavailable(_) => ("driver_unavailable", true),
                ResponseError::Response(FinalityProofRespondError::Journal(_)) => {
                    ("finality_history", true)
                }
                ResponseError::Response(FinalityProofRespondError::Transport(_)) => {
                    ("transport", false)
                }
                ResponseError::Response(FinalityProofRespondError::RetentionLimit) => {
                    ("retention_limit", false)
                }
                ResponseError::Response(FinalityProofRespondError::Allocation) => {
                    ("allocation", false)
                }
                ResponseError::Response(FinalityProofRespondError::InvalidLengths) => {
                    ("proof_lengths", false)
                }
                ResponseError::Response(_) => ("unsupported_response", true),
            };
            (
                json!({"event": "proof_response_failed", "peer": peer, "height": height, "reason": reason}),
                fatal,
            )
        }
    }
}
