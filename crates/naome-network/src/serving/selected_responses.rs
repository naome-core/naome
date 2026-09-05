//! Journal and candidate-store lookup adapters for typed transport responses.

use crate::*;
use naome_protocol::artifact_exchange::{ARTIFACT_RESPONSE_MAX_BYTES, ArtifactResponse};
use naome_storage::{ArtifactBlockCandidateStore, ArtifactChainJournal};

impl StaticArtifactNetwork {
    /// Serves one authenticated block request from the healthy local journal.
    ///
    /// A found response performs one bounded canonical encoding because
    /// rust-libp2p must own the response until its asynchronous write ends.
    pub fn respond_block_from_journal(
        &mut self,
        inbound: InboundArtifactBlockRequest,
        journal: &ArtifactChainJournal,
    ) -> Result<(), RespondError> {
        let block = journal
            .block(inbound.request().block_id())
            .map_err(RespondError::Journal)?;
        self.respond_block_value(inbound, block)
    }

    /// Serves one authenticated block request from a caller-routed candidate store.
    ///
    /// The request carries no chain identity: the caller must supply the
    /// intended chain-scoped store. A failed integrity read is reported rather
    /// than translated to `Unavailable`; serving never inserts, replaces,
    /// promotes, or deletes a candidate.
    pub fn respond_block_from_candidate_store(
        &mut self,
        inbound: InboundArtifactBlockRequest,
        store: &mut ArtifactBlockCandidateStore,
    ) -> Result<(), RespondError> {
        let block = store
            .get(inbound.request().block_id())
            .map_err(RespondError::CandidateStore)?;
        self.respond_block_value(inbound, block.as_ref())
    }

    /// Serves one authenticated request from the healthy local journal.
    ///
    /// One bounded artifact-sized copy is required because rust-libp2p owns the
    /// response until its asynchronous stream write completes. The journal is
    /// not borrowed across that write.
    pub fn respond_artifact_from_journal(
        &mut self,
        inbound: InboundArtifactRequest,
        journal: &ArtifactChainJournal,
    ) -> Result<(), RespondError> {
        let response_bytes = journal
            .artifact(inbound.request().artifact_id())
            .map_err(RespondError::Journal)?
            .map(|record| record.canonical_artifact_bytes());
        self.respond_artifact_with(inbound, || {
            let bytes = response_bytes.map_or_else(Vec::new, <[u8]>::to_vec);
            debug_assert!(bytes.len() <= ARTIFACT_RESPONSE_MAX_BYTES);
            let response = ArtifactResponse::from_wire_bytes(bytes)
                .expect("retained canonical artifact obeys the certificate limit");
            Ok(response)
        })
    }

    /// Serves one authenticated chain-head request from the healthy local journal.
    pub fn respond_chain_head_from_journal(
        &mut self,
        inbound: InboundArtifactChainHeadRequest,
        journal: &ArtifactChainJournal,
    ) -> Result<(), RespondError> {
        let head_block_id = journal.head_block_id().map_err(RespondError::Journal)?;
        let head_bytes = (journal.chain_id() == inbound.request().chain_id())
            .then_some(head_block_id)
            .map(|block_id| *block_id.as_bytes());
        self.respond_chain_head_value(inbound, head_bytes)
    }
}
