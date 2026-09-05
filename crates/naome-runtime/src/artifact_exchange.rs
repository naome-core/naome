//! Explicit source acquisition and responses on the runtime's existing network.

use std::{error::Error, fmt};

use naome_chain::ArtifactBlockId;
use naome_network::{
    ArtifactBlockCandidateAncestryFill as Ancestry,
    ArtifactBlockCandidateAncestryFillError as AncestryError,
    ArtifactBlockCandidateAncestryFillProgress as AncestryProgress,
    ArtifactBlockCandidateBranchPayloadFill as Payload,
    ArtifactBlockCandidateBranchPayloadFillError as PayloadError,
    ArtifactBlockCandidateBranchPayloadFillProgress as PayloadProgress,
    ConsensusPushAcknowledgeError, InboundArtifactBlockRequest, InboundArtifactRequest,
    InboundConsensusPush, NetworkEvent, PeerId, ReceivedConsensusPush, RespondError,
    StaticArtifactNetwork,
};
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBranchReconstructionLimits,
    CanonicalArtifactPayloadStore, SelectedArtifactHistory,
};

use super::FixedValidatorRuntimeV0;

/// No lower acquisition operation ran and no caller-owned input was consumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeAcquisitionRefusalV0 {
    DriverUnavailable,
    OtherNetwork,
    UnexpectedEvent,
}

/// A refused start or the unchanged lower operation's typed failure.
#[derive(Debug)]
pub enum FixedValidatorRuntimeAcquisitionStartErrorV0 {
    DriverUnavailable,
    Ancestry(Box<AncestryError>),
    Payload(Box<PayloadError>),
}

impl fmt::Display for FixedValidatorRuntimeAcquisitionStartErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "runtime artifact acquisition did not start: {self:?}")
    }
}

impl Error for FixedValidatorRuntimeAcquisitionStartErrorV0 {}

/// Preflight refunds both exact owners; a delegated error retains its existing
/// consuming and durable-prefix semantics.
#[must_use]
#[derive(Debug)]
#[allow(
    clippy::large_enum_variant,
    reason = "the returned error is already boxed; refund both original owners in one allocation"
)]
pub enum FixedValidatorRuntimeAncestryFillAdvanceErrorV0<'store> {
    Refused {
        reason: FixedValidatorRuntimeAcquisitionRefusalV0,
        progress: Ancestry<'store>,
        event: NetworkEvent,
    },
    Operation(AncestryError),
}

/// Preflight refunds both exact owners; no partial reconstructed snapshot is
/// exposed after a delegated payload failure.
#[derive(Debug)]
#[must_use]
#[allow(
    clippy::large_enum_variant,
    reason = "the returned error is already boxed; refund both original owners in one allocation"
)]
pub enum FixedValidatorRuntimePayloadFillAdvanceErrorV0<'store> {
    Refused {
        reason: FixedValidatorRuntimeAcquisitionRefusalV0,
        progress: Payload<'store>,
        event: NetworkEvent,
    },
    Operation(PayloadError),
}

type StartError = FixedValidatorRuntimeAcquisitionStartErrorV0;
type Refusal = FixedValidatorRuntimeAcquisitionRefusalV0;
type AncestryAdvanceError<'store> = FixedValidatorRuntimeAncestryFillAdvanceErrorV0<'store>;
type PayloadAdvanceError<'store> = FixedValidatorRuntimePayloadFillAdvanceErrorV0<'store>;

impl FixedValidatorRuntimeV0<'_> {
    fn acquisition_parts(
        &mut self,
    ) -> Result<(&mut StaticArtifactNetwork, &dyn SelectedArtifactHistory), StartError> {
        let driver = self.driver.as_ref().ok_or(StartError::DriverUnavailable)?;
        Ok((&mut self.network, driver.selected_artifact_history()))
    }

    /// Starts only the caller-selected direct ancestry fill. The history borrow
    /// ends with this call; normal runtime polling may continue between steps.
    pub fn start_artifact_block_candidate_ancestry_fill<'store>(
        &mut self,
        candidates: &'store mut ArtifactBlockCandidateStore,
        peer: PeerId,
        target: ArtifactBlockId,
    ) -> Result<AncestryProgress<'store>, StartError> {
        let (network, selected) = self.acquisition_parts()?;
        network
            .start_artifact_block_candidate_ancestry_fill(selected, candidates, peer, target)
            .map_err(|error| StartError::Ancestry(Box::new(error)))
    }

    /// Preserves the caller's exact optional fallback order and all lower gates.
    pub fn start_artifact_block_candidate_ancestry_fill_with_peer_fallback<'store>(
        &mut self,
        candidates: &'store mut ArtifactBlockCandidateStore,
        peers: &[PeerId],
        target: ArtifactBlockId,
    ) -> Result<AncestryProgress<'store>, StartError> {
        let (network, selected) = self.acquisition_parts()?;
        network
            .start_artifact_block_candidate_ancestry_fill_with_peer_fallback(
                selected, candidates, peers, target,
            )
            .map_err(|error| StartError::Ancestry(Box::new(error)))
    }

    /// Starts at one exact caller-selected retained anchor, including genesis.
    pub fn start_artifact_block_candidate_ancestry_fill_from_selected_anchor<'store>(
        &mut self,
        candidates: &'store mut ArtifactBlockCandidateStore,
        peer: PeerId,
        anchor: ArtifactBlockId,
        target: ArtifactBlockId,
    ) -> Result<AncestryProgress<'store>, StartError> {
        let (network, selected) = self.acquisition_parts()?;
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor(
                selected, candidates, peer, anchor, target,
            )
            .map_err(|error| StartError::Ancestry(Box::new(error)))
    }

    /// Combines only the existing explicit anchor and caller-ordered fallback.
    pub fn start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback<
        'store,
    >(
        &mut self,
        candidates: &'store mut ArtifactBlockCandidateStore,
        peers: &[PeerId],
        anchor: ArtifactBlockId,
        target: ArtifactBlockId,
    ) -> Result<AncestryProgress<'store>, StartError> {
        let (network, selected) = self.acquisition_parts()?;
        network
            .start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(
                selected, candidates, peers, anchor, target,
            )
            .map_err(|error| StartError::Ancestry(Box::new(error)))
    }

    /// Starts a separate payload phase against the history visible at this call.
    /// Store hits still undergo complete reconstruction and validation.
    pub fn start_artifact_block_candidate_branch_payload_fill<'store>(
        &mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &'store mut CanonicalArtifactPayloadStore,
        peer: PeerId,
        target: ArtifactBlockId,
        limits: CandidateBranchReconstructionLimits,
    ) -> Result<PayloadProgress<'store>, StartError> {
        let (network, selected) = self.acquisition_parts()?;
        network
            .start_artifact_block_candidate_branch_payload_fill(
                selected, candidates, payloads, peer, target, limits,
            )
            .map_err(|error| StartError::Payload(Box::new(error)))
    }

    /// Preserves the existing per-payload deadline and exact fallback order.
    pub fn start_artifact_block_candidate_branch_payload_fill_with_peer_fallback<'store>(
        &mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &'store mut CanonicalArtifactPayloadStore,
        peers: &[PeerId],
        target: ArtifactBlockId,
        limits: CandidateBranchReconstructionLimits,
    ) -> Result<PayloadProgress<'store>, StartError> {
        let (network, selected) = self.acquisition_parts()?;
        network
            .start_artifact_block_candidate_branch_payload_fill_with_peer_fallback(
                selected, candidates, payloads, peers, target, limits,
            )
            .map_err(|error| StartError::Payload(Box::new(error)))
    }

    /// Advances only an exact original-network terminal. A refused call refunds
    /// the workflow and event; delegated failures consume them as before.
    pub fn advance_artifact_block_candidate_ancestry_fill<'store>(
        &mut self,
        progress: Ancestry<'store>,
        event: NetworkEvent,
    ) -> Result<AncestryProgress<'store>, Box<AncestryAdvanceError<'store>>> {
        let reason = if self.driver.is_none() {
            Some(Refusal::DriverUnavailable)
        } else if !progress.belongs_to_network(&self.network) {
            Some(Refusal::OtherNetwork)
        } else if !progress.accepts_event(&event) {
            Some(Refusal::UnexpectedEvent)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Box::new(AncestryAdvanceError::Refused {
                reason,
                progress,
                event,
            }));
        }
        let driver = self.driver.as_ref().expect("acquisition preflight");
        progress
            .on_event(&mut self.network, driver.selected_artifact_history(), event)
            .map_err(|error| Box::new(AncestryAdvanceError::Operation(error)))
    }

    /// Continues the captured artifact snapshot without admitting it into the
    /// driver's current consensus context or altering runtime scheduling.
    pub fn advance_artifact_block_candidate_branch_payload_fill<'store>(
        &mut self,
        progress: Payload<'store>,
        event: NetworkEvent,
    ) -> Result<PayloadProgress<'store>, Box<PayloadAdvanceError<'store>>> {
        let reason = if self.driver.is_none() {
            Some(Refusal::DriverUnavailable)
        } else if !progress.belongs_to_network(&self.network) {
            Some(Refusal::OtherNetwork)
        } else if !progress.accepts_event(&event) {
            Some(Refusal::UnexpectedEvent)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Box::new(PayloadAdvanceError::Refused {
                reason,
                progress,
                event,
            }));
        }
        progress
            .on_event(&mut self.network, event)
            .map_err(|error| Box::new(PayloadAdvanceError::Operation(error)))
    }

    /// Explicitly serves one request from the caller's exact candidate store.
    /// This changes no driver, timer, input, or publication marker.
    pub fn respond_block_from_candidate_store(
        &mut self,
        inbound: InboundArtifactBlockRequest,
        candidates: &mut ArtifactBlockCandidateStore,
    ) -> Result<(), RespondError> {
        self.network
            .respond_block_from_candidate_store(inbound, candidates)
    }

    /// Explicitly serves one request from the caller's exact payload archive,
    /// retaining the existing integrity checks, resource gates, and errors.
    pub fn respond_artifact_from_payload_store(
        &mut self,
        inbound: InboundArtifactRequest,
        payloads: &mut CanonicalArtifactPayloadStore,
    ) -> Result<(), RespondError> {
        self.network
            .respond_artifact_from_payload_store(inbound, payloads)
    }

    /// Queues only a transport receipt for a caller-held inbound handle and
    /// returns its exact source and bytes, including on a closed channel. Any
    /// later caller queueing requires ordinary admission and is CallerInput.
    pub fn acknowledge_consensus_push(
        &mut self,
        inbound: InboundConsensusPush,
    ) -> Result<ReceivedConsensusPush, Box<ConsensusPushAcknowledgeError>> {
        self.network.acknowledge_consensus_push(inbound)
    }
}
