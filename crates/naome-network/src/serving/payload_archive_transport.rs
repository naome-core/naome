//! Caller-routed serving from one canonical artifact-payload archive.

use naome_protocol::artifact_exchange::{ARTIFACT_RESPONSE_MAX_BYTES, ArtifactResponse};
use naome_storage::CanonicalArtifactPayloadStore;

use super::{InboundArtifactRequest, RespondError, StaticArtifactNetwork};

impl StaticArtifactNetwork {
    /// Serves one statically authorized Noise-authenticated artifact request from
    /// a caller-routed payload archive.
    ///
    /// The archive is Foundation-scoped rather than chain-scoped, and the wire
    /// request carries no chain identity. The caller must therefore decide
    /// explicitly whether this request may read this archive. Explicit caller
    /// routing may retransmit bytes retained from another source, but this method
    /// retains no source provenance and never selects a recipient, falls back from
    /// selected journal serving, or starts an automatic relay policy, task, or
    /// schedule.
    ///
    /// Archive health and exact local presence are checked before the response
    /// channel and shared inbound budget. A present payload is integrity-read
    /// only after those resource gates, so a rate-limited request cannot force an
    /// artifact-sized disk read. An integrity failure remains a typed archive
    /// error and is never translated to `Unavailable`.
    ///
    /// A found response contains the exact archived tagged canonical bytes, but
    /// serving them does not recreate their original checked context or establish
    /// chain membership, current validity, availability, selection, consensus,
    /// finality, economics, or peer trust. Every receiver must strictly validate
    /// the bytes against its own target state.
    pub fn respond_artifact_from_payload_store(
        &mut self,
        inbound: InboundArtifactRequest,
        payloads: &mut CanonicalArtifactPayloadStore,
    ) -> Result<(), RespondError> {
        let artifact_id = inbound.request().artifact_id();
        let is_retained = payloads
            .contains(artifact_id)
            .map_err(RespondError::PayloadStore)?;

        self.respond_artifact_with(inbound, || {
            let bytes = if is_retained {
                payloads
                    .get(artifact_id)
                    .map_err(RespondError::PayloadStore)?
                    .expect("an exclusively borrowed payload archive retains its indexed address")
                    .into_canonical_artifact_bytes()
                    .into_vec()
            } else {
                Vec::new()
            };
            debug_assert!(bytes.len() <= ARTIFACT_RESPONSE_MAX_BYTES);
            let response = ArtifactResponse::from_wire_bytes(bytes)
                .expect("an archived canonical artifact obeys the payload byte limit");
            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests;
