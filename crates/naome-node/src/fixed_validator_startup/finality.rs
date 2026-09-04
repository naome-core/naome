use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_consensus::{
    ConsensusAncestryId, ConsensusEnvelopeId, ConsensusEnvelopeVerifyError, ConsensusHeight,
    ConsensusPosition, ConsensusProposalVerifyError, ConsensusRound,
    FixedConsensusBoundedSeparateFinalityVerifyError, FixedConsensusBranchV0,
    FixedConsensusPrecommitBatchSealErrorV0, FixedConsensusRoundV0,
    OwnedVerifiedFixedConsensusTransitionV0, ProposerSelectionError,
};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, CandidateBackedFinalityErrorV0,
    CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityCommitOutcomeV0,
    FixedValidatorFinalityConflictSignerStopOutcomeV0, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityJournalStateIdV0,
    FixedValidatorVoteSafetyJournalErrorV0, commit_candidate_backed_anchored_finality_conflict_v0,
    commit_candidate_backed_anchored_finality_v0,
};

use super::candidate_backed_proposal::{
    CandidateBackedProposalSourceErrorV0, load_candidate_backed_proposal_payload,
};
use super::{FixedValidatorNodeFinalityStoppedV0, FixedValidatorNodeSigningScopeV0};

/// Nonterminal selected-finality result paired with continued signing authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeFinalitySelectionV0 {
    /// One new direct child and its exact evidence became durable.
    Finalized {
        position: ConsensusPosition,
        ancestry_id: ConsensusAncestryId,
        envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
    /// One exact caller-selected retained candidate became durable.
    CandidateBackedFinalized {
        target: ArtifactBlockId,
        position: ConsensusPosition,
        ancestry_id: ConsensusAncestryId,
        envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
    /// The exact value was already selected; no durable byte changed.
    AlreadyFinalized {
        height: ConsensusHeight,
        ancestry_id: ConsensusAncestryId,
        retained_envelope_id: ConsensusEnvelopeId,
        state_id: FixedValidatorFinalityJournalStateIdV0,
    },
}

/// Result of coupling one verified finality transition to the local signer.
#[must_use]
pub enum FixedValidatorNodeFinalityOutcomeV0<'node> {
    /// Finality remains operable and the returned scope is aligned to its head.
    Continues {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        selection: FixedValidatorNodeFinalitySelectionV0,
    },
    /// A durable sibling conflict stopped both finality and the signer.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

/// Explicit round-routing metadata for one exact finality vote batch.
///
/// This value keeps the caller-selected evidence round distinct from the
/// inclusive local work ceiling. Construction performs no validation and
/// grants no evidence or finality authority; each consuming ingress enforces
/// its own signer-relative and persisted-ceiling policy before input work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeFinalityRoundRouteV0 {
    evidence_round: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
}

impl FixedValidatorNodeFinalityRoundRouteV0 {
    /// Names the exact caller-routed evidence round and inclusive work ceiling.
    pub const fn new(
        evidence_round: ConsensusRound,
        inclusive_maximum_round: ConsensusRound,
    ) -> Self {
        Self {
            evidence_round,
            inclusive_maximum_round,
        }
    }

    /// Returns the caller-routed round every proposal and vote must authenticate.
    pub const fn evidence_round(self) -> ConsensusRound {
        self.evidence_round
    }

    /// Returns the inclusive caller-local sequential work ceiling.
    pub const fn inclusive_maximum_round(self) -> ConsensusRound {
        self.inclusive_maximum_round
    }
}

/// Result of admitting exact-current-round evidence into node-owned finality.
///
/// A rejection returns the unchanged signing scope because no finality or signer
/// effect occurred. Once the proposal and supplied or batch-constructed
/// precommit certificate produce an owned sealed transition, the existing
/// consuming finality outcome is retained without reinterpretation.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'node> {
    /// The sealed transition reached the existing finality coordinator.
    Finality(FixedValidatorNodeFinalityOutcomeV0<'node>),
    /// Caller-supplied evidence was rejected before any state change.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>,
    },
}

/// Result of admitting two exact-current proofs into the neutral halt path.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0<'node> {
    /// Both proofs became one durable finality halt and signer stop.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
    /// One proof was rejected before any finality or signer effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>,
    },
}

/// A pre-effect exact-current-round finality rejection.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundFinalityRejectionV0 {
    /// Reconstructing the signer's exact round would exceed caller policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// Complete proposal-control or artifact-payload admission failed.
    Proposal(Box<ConsensusProposalVerifyError>),
    /// The supplied certificate could not seal the admitted proposal.
    PrecommitCertificate(Box<ConsensusEnvelopeVerifyError>),
    /// The exact caller-routed signed-precommit batch could not seal the proposal.
    PrecommitBatch(Box<FixedConsensusPrecommitBatchSealErrorV0>),
    /// The first paired proposal-control or artifact payload was rejected.
    FirstProposal(Box<ConsensusProposalVerifyError>),
    /// The first paired precommit certificate was rejected.
    FirstPrecommitCertificate(Box<ConsensusEnvelopeVerifyError>),
    /// The second paired proposal-control or artifact payload was rejected.
    SecondProposal(Box<ConsensusProposalVerifyError>),
    /// The second paired precommit certificate was rejected.
    SecondPrecommitCertificate(Box<ConsensusEnvelopeVerifyError>),
}

impl fmt::Display for FixedValidatorNodeCurrentRoundFinalityRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "current-round finality requires {required:?}, above caller-local ceiling {maximum:?}"
            ),
            Self::Proposal(source) => {
                write!(
                    formatter,
                    "current-round finality proposal was rejected: {source}"
                )
            }
            Self::PrecommitCertificate(source) => write!(
                formatter,
                "current-round finality precommit certificate was rejected: {source}"
            ),
            Self::PrecommitBatch(source) => write!(
                formatter,
                "current-round finality precommit batch was rejected: {source}"
            ),
            Self::FirstProposal(source) => write!(
                formatter,
                "first current-round paired proposal was rejected: {source}"
            ),
            Self::FirstPrecommitCertificate(source) => write!(
                formatter,
                "first current-round paired precommit certificate was rejected: {source}"
            ),
            Self::SecondProposal(source) => write!(
                formatter,
                "second current-round paired proposal was rejected: {source}"
            ),
            Self::SecondPrecommitCertificate(source) => write!(
                formatter,
                "second current-round paired precommit certificate was rejected: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeCurrentRoundFinalityRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Proposal(source) => Some(source.as_ref()),
            Self::PrecommitCertificate(source) => Some(source.as_ref()),
            Self::PrecommitBatch(source) => Some(source.as_ref()),
            Self::FirstProposal(source) | Self::SecondProposal(source) => Some(source.as_ref()),
            Self::FirstPrecommitCertificate(source) | Self::SecondPrecommitCertificate(source) => {
                Some(source.as_ref())
            }
            Self::RoundWorkLimitExceeded { .. } => None,
        }
    }
}

/// A fatal exact-current-round finality coordination failure.
///
/// Every variant consumes the signing scope. Pre-effect node coherence and the
/// persisted finality work ceiling are fatal rather than caller rejections. A
/// nested finality error preserves the existing commit and signer-handoff
/// classification after an owned sealed transition has been created.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeCurrentRoundFinalityErrorV0 {
    /// The node-owned signer and branch do not name the same next height.
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    /// The signer's exact node-owned branch round could not be reconstructed.
    Round(ProposerSelectionError),
    /// The signer is above the node-owned finality journal's durable ceiling.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// Sealed evidence reached the existing consuming finality coordinator.
    Finality(Box<FixedValidatorNodeFinalityErrorV0>),
}

impl fmt::Display for FixedValidatorNodeCurrentRoundFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            } => write!(
                formatter,
                "signer position {signer:?} differs from node branch next height {branch_next_height:?}"
            ),
            Self::Round(source) => write!(
                formatter,
                "current node finality round could not be reconstructed: {source}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Finality(source) => {
                write!(
                    formatter,
                    "current-round finality coordination failed: {source}"
                )
            }
        }
    }
}

impl Error for FixedValidatorNodeCurrentRoundFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Finality(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. } | Self::FinalityRoundLimitExceeded { .. } => {
                None
            }
        }
    }
}

/// Result of admitting strictly lower-round evidence into node-owned finality.
///
/// A rejection returns the unchanged signing scope because certificate routing,
/// bounded round derivation, proposal admission, and certificate verification
/// completed without a finality or signer effect. Once complete verification
/// produces an owned sealed transition, the existing consuming finality outcome
/// is retained without reinterpretation.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeLowerRoundFinalityOutcomeV0<'node> {
    /// The sealed transition reached the existing finality coordinator.
    Finality(FixedValidatorNodeFinalityOutcomeV0<'node>),
    /// Caller-supplied evidence was rejected before any state change.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeLowerRoundFinalityRejectionV0>,
    },
}

/// Result of admitting two strictly lower-round proofs into the neutral halt path.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0<'node> {
    /// Both proofs became one durable finality halt and signer stop.
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
    /// Caller-supplied evidence was rejected before any finality or signer effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0>,
    },
}

/// A pre-effect strictly lower-round paired-finality rejection.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0 {
    /// The first complete proof was rejected by the lower-round boundary.
    First(Box<FixedValidatorNodeLowerRoundFinalityRejectionV0>),
    /// The second complete proof was rejected by the lower-round boundary.
    Second(Box<FixedValidatorNodeLowerRoundFinalityRejectionV0>),
    /// The independently authenticated proofs do not name one exact position.
    PositionMismatch {
        first: ConsensusPosition,
        second: ConsensusPosition,
    },
}

/// A pre-effect strictly lower-round finality rejection.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeLowerRoundFinalityRejectionV0 {
    /// The certificate does not name a round below the current signer round.
    NotEarlierThanSigner {
        evidence: ConsensusRound,
        signer: ConsensusRound,
    },
    /// Reconstructing the certificate's exact round would exceed caller policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// Certificate routing or complete branch-relative verification failed.
    Evidence(Box<FixedConsensusBoundedSeparateFinalityVerifyError>),
    /// The exact caller-routed signed-precommit batch could not seal the proposal.
    PrecommitBatch(Box<FixedConsensusPrecommitBatchSealErrorV0>),
}

impl fmt::Display for FixedValidatorNodeLowerRoundFinalityRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEarlierThanSigner { evidence, signer } => write!(
                formatter,
                "lower-round finality evidence at {evidence:?} is not earlier than signer round {signer:?}"
            ),
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "lower-round finality requires {required:?}, above caller-local ceiling {maximum:?}"
            ),
            Self::Evidence(source) => {
                write!(
                    formatter,
                    "lower-round finality evidence was rejected: {source}"
                )
            }
            Self::PrecommitBatch(source) => write!(
                formatter,
                "lower-round finality precommit batch was rejected: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeLowerRoundFinalityRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Evidence(source) => Some(source.as_ref()),
            Self::PrecommitBatch(source) => Some(source.as_ref()),
            Self::NotEarlierThanSigner { .. } | Self::RoundWorkLimitExceeded { .. } => None,
        }
    }
}

impl fmt::Display for FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::First(source) => {
                write!(
                    formatter,
                    "first lower-round paired proof was rejected: {source}"
                )
            }
            Self::Second(source) => write!(
                formatter,
                "second lower-round paired proof was rejected: {source}"
            ),
            Self::PositionMismatch { first, second } => write!(
                formatter,
                "lower-round paired proofs name different positions: {first:?} and {second:?}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::First(source) | Self::Second(source) => Some(source.as_ref()),
            Self::PositionMismatch { .. } => None,
        }
    }
}

/// Result of candidate-backed exact signed-precommit-batch finality admission.
///
/// Every rejection returns the unchanged node signing scope because no sealed
/// transition reached finality. Once complete source, proposal, and batch
/// verification produces that transition, the existing consuming finality and
/// signer-height handoff contract applies unchanged.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeCandidateBackedFinalityOutcomeV0<'node> {
    /// The sealed candidate-backed transition reached the existing coordinator.
    Finality(FixedValidatorNodeFinalityOutcomeV0<'node>),
    /// Caller-routed input or source state was rejected before any node effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeCandidateBackedFinalityRejectionV0>,
    },
}

/// A pre-effect candidate-backed exact-precommit-batch rejection.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeCandidateBackedFinalityRejectionV0 {
    /// The caller requested a work ceiling above the persisted finality ceiling.
    RoundWorkLimitExceedsFinality {
        requested: ConsensusRound,
        finality: ConsensusRound,
    },
    /// The explicit evidence round exceeds the caller-local work ceiling.
    EvidenceRoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The candidate store belongs to another artifact chain.
    CandidateChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// Exact candidate lookup or integrity verification failed.
    CandidateStore(Box<ArtifactBlockCandidateStoreError>),
    /// The exact caller-selected candidate is not retained.
    CandidateUnavailable { target: ArtifactBlockId },
    /// The proposal embeds another block than the caller-selected target.
    ProposalTargetMismatch {
        expected: ArtifactBlockId,
        actual: ArtifactBlockId,
    },
    /// The retained candidate bytes differ from the proposal's exact block.
    CandidateBlockMismatch { target: ArtifactBlockId },
    /// Exact payload lookup or integrity verification failed.
    PayloadStore(Box<CanonicalArtifactPayloadStoreError>),
    /// The retained candidate's exact committed payload is unavailable.
    PayloadUnavailable { target: ArtifactBlockId },
    /// Complete proposal-control or artifact-payload admission failed.
    Proposal(Box<ConsensusProposalVerifyError>),
    /// The exact signed-precommit batch could not seal the admitted proposal.
    PrecommitBatch(Box<FixedConsensusPrecommitBatchSealErrorV0>),
}

impl fmt::Display for FixedValidatorNodeCandidateBackedFinalityRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoundWorkLimitExceedsFinality {
                requested,
                finality,
            } => write!(
                formatter,
                "candidate-backed finality work ceiling {requested:?} exceeds persisted finality ceiling {finality:?}"
            ),
            Self::EvidenceRoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "candidate-backed finality evidence round {required:?} exceeds caller-local ceiling {maximum:?}"
            ),
            Self::CandidateChainMismatch { expected, actual } => write!(
                formatter,
                "candidate store chain mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateStore(source) => source.fmt(formatter),
            Self::CandidateUnavailable { target } => {
                write!(formatter, "candidate {target:?} is not retained")
            }
            Self::ProposalTargetMismatch { expected, actual } => write!(
                formatter,
                "proposal target mismatch: expected {expected:?}, actual {actual:?}"
            ),
            Self::CandidateBlockMismatch { target } => write!(
                formatter,
                "retained candidate {target:?} differs from the proposal block"
            ),
            Self::PayloadStore(source) => source.fmt(formatter),
            Self::PayloadUnavailable { target } => {
                write!(
                    formatter,
                    "payload for candidate {target:?} is not retained"
                )
            }
            Self::Proposal(source) => write!(
                formatter,
                "candidate-backed finality proposal was rejected: {source}"
            ),
            Self::PrecommitBatch(source) => write!(
                formatter,
                "candidate-backed finality precommit batch was rejected: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeCandidateBackedFinalityRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CandidateStore(source) => Some(source.as_ref()),
            Self::PayloadStore(source) => Some(source.as_ref()),
            Self::Proposal(source) => Some(source.as_ref()),
            Self::PrecommitBatch(source) => Some(source.as_ref()),
            Self::RoundWorkLimitExceedsFinality { .. }
            | Self::EvidenceRoundWorkLimitExceeded { .. }
            | Self::CandidateChainMismatch { .. }
            | Self::CandidateUnavailable { .. }
            | Self::ProposalTargetMismatch { .. }
            | Self::CandidateBlockMismatch { .. }
            | Self::PayloadUnavailable { .. } => None,
        }
    }
}

/// A consuming candidate-backed exact-precommit-batch finality failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeCandidateBackedFinalityErrorV0 {
    /// The exact caller-routed evidence round could not be reconstructed.
    Round(ProposerSelectionError),
    /// Sealed evidence reached the existing consuming finality coordinator.
    Finality(Box<FixedValidatorNodeFinalityErrorV0>),
}

impl fmt::Display for FixedValidatorNodeCandidateBackedFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Round(source) => write!(
                formatter,
                "candidate-backed finality round could not be reconstructed: {source}"
            ),
            Self::Finality(source) => write!(
                formatter,
                "candidate-backed batch finality coordination failed: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeCandidateBackedFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Finality(source) => Some(source.as_ref()),
        }
    }
}

/// A fatal strictly lower-round finality coordination failure.
///
/// Every variant consumes the signing scope. Node coherence and the persisted
/// finality work ceiling are checked before caller evidence. A nested finality
/// error preserves the existing commit and signer-handoff classification after
/// an owned sealed transition has been created.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeLowerRoundFinalityErrorV0 {
    /// The node-owned signer and branch do not name the same next height.
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    /// The exact node-owned branch round could not be reconstructed.
    Round(ProposerSelectionError),
    /// The signer is above the node-owned finality journal's durable ceiling.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// Sealed evidence reached the existing consuming finality coordinator.
    Finality(Box<FixedValidatorNodeFinalityErrorV0>),
}

impl fmt::Display for FixedValidatorNodeLowerRoundFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            } => write!(
                formatter,
                "signer position {signer:?} differs from node branch next height {branch_next_height:?}"
            ),
            Self::Round(source) => write!(
                formatter,
                "lower-round node finality position could not be reconstructed: {source}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Finality(source) => {
                write!(
                    formatter,
                    "lower-round finality coordination failed: {source}"
                )
            }
        }
    }
}

impl Error for FixedValidatorNodeLowerRoundFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Finality(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. } | Self::FinalityRoundLimitExceeded { .. } => {
                None
            }
        }
    }
}

/// A fail-closed live finality-to-signer coordination failure.
///
/// Every variant consumes the node signing scope. When a variant carries a
/// selection or halt, that finality result is already durable and must not be
/// interpreted as rolled back; strict restart is the only recovery classifier.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeFinalityErrorV0 {
    /// The sealed-transition finality commit rejected or has ambiguous durability.
    Commit(Box<FixedValidatorFinalityJournalErrorV0>),
    /// Candidate verification or its finality commit failed.
    CandidateBackedFinality(Box<CandidateBackedFinalityErrorV0>),
    /// Finality succeeded but could not issue its exact signer-height authority.
    SignerHeightAuthority {
        selection: Box<FixedValidatorNodeFinalitySelectionV0>,
        source: Box<FixedValidatorFinalityJournalErrorV0>,
    },
    /// Finality succeeded but the signer could not durably prepare its child lineage.
    SignerHeightPrepare {
        selection: Box<FixedValidatorNodeFinalitySelectionV0>,
        source: Box<FixedValidatorVoteSafetyJournalErrorV0>,
    },
    /// Both journals were anchored but live signer publication failed.
    SignerHeightAcknowledge {
        selection: Box<FixedValidatorNodeFinalitySelectionV0>,
        source: Box<FixedValidatorVoteSafetyJournalErrorV0>,
    },
    /// Finality halted but could not issue its exact signer-stop authority.
    SignerStopAuthority {
        halt: Box<FixedValidatorFinalityHaltV0>,
        source: Box<FixedValidatorFinalityJournalErrorV0>,
    },
    /// Finality halted but the signer stop could not be durably completed.
    SignerStop {
        halt: Box<FixedValidatorFinalityHaltV0>,
        source: Box<FixedValidatorVoteSafetyJournalErrorV0>,
    },
}

impl fmt::Display for FixedValidatorNodeFinalityErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Commit(source) => write!(formatter, "node finality commit failed: {source}"),
            Self::CandidateBackedFinality(source) => {
                write!(
                    formatter,
                    "node candidate-backed finality commit failed: {source}"
                )
            }
            Self::SignerHeightAuthority { selection, source } => write!(
                formatter,
                "node finality result {selection:?} could not issue signer-height authority: {source}"
            ),
            Self::SignerHeightPrepare { selection, source } => write!(
                formatter,
                "node finality result {selection:?} could not prepare the signer height: {source}"
            ),
            Self::SignerHeightAcknowledge { selection, source } => write!(
                formatter,
                "node finality result {selection:?} could not publish the anchored signer height: {source}"
            ),
            Self::SignerStopAuthority { halt, source } => write!(
                formatter,
                "node finality halt {halt:?} could not issue signer-stop authority: {source}"
            ),
            Self::SignerStop { halt, source } => write!(
                formatter,
                "node finality halt {halt:?} could not stop the signer: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeFinalityErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Commit(source)
            | Self::SignerHeightAuthority { source, .. }
            | Self::SignerStopAuthority { source, .. } => Some(source.as_ref()),
            Self::CandidateBackedFinality(source) => Some(source.as_ref()),
            Self::SignerHeightPrepare { source, .. }
            | Self::SignerHeightAcknowledge { source, .. }
            | Self::SignerStop { source, .. } => Some(source.as_ref()),
        }
    }
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Finalizes one exact-current-round proposal from its separate messages.
    ///
    /// The caller supplies complete proposal-control bytes, the owned canonical
    /// artifact payload, one precommit certificate, and an inclusive local work
    /// ceiling. The signer's position selects the sole branch round; no session
    /// readiness or phase condition is inferred, so already pending signer work
    /// cannot suppress otherwise valid finality. Caller-cap, proposal, payload,
    /// certificate, and exact-round mismatch failures preserve the unchanged
    /// scope. Node coherence and the persisted finality ceiling remain fatal.
    /// Once sealing succeeds, the existing consuming finality and signer-handoff
    /// contract applies unchanged.
    pub fn commit_current_round_finality(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_precommit_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeCurrentRoundFinalityErrorV0,
    > {
        commit_current_round_finality_with_precommits(
            self,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            CurrentRoundPrecommitInputV0::CanonicalCertificate(canonical_precommit_certificate),
            inclusive_maximum_round,
        )
    }

    /// Commits two exact-current proposal proofs as one neutral terminal halt.
    ///
    /// Both triples are independently admitted and sealed against one derived
    /// current round before any durable effect. Rejection of either triple
    /// returns the unchanged scope. Once the paired finality append begins,
    /// every failure is fatal and strict anchored reopen is the only classifier.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_current_round_preselection_conflict(
        self,
        first_canonical_proposal_control_bytes: &[u8],
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_precommit_certificate: &[u8],
        second_canonical_proposal_control_bytes: &[u8],
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_precommit_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0<'node>,
        FixedValidatorNodeCurrentRoundFinalityErrorV0,
    > {
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        let signer_position = self.signing_session.position();
        let round = match current_round_for_finality(
            &self.branch,
            signer_position,
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(round) => round,
            Err(CurrentRoundFinalityRoundErrorV0::Rejected(rejection)) => {
                return Ok(current_round_preselection_conflict_rejected(
                    self, rejection,
                ));
            }
            Err(CurrentRoundFinalityRoundErrorV0::Fatal(error)) => return Err(error),
        };
        let first_proposal = match round.decode_and_verify_proposal_control(
            first_canonical_proposal_control_bytes,
            first_canonical_artifact_bytes,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                return Ok(current_round_preselection_conflict_rejected(
                    self,
                    FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstProposal(Box::new(
                        source,
                    )),
                ));
            }
        };
        let first = match first_proposal
            .seal_with_precommit_certificate(first_canonical_precommit_certificate)
        {
            Ok(transition) => transition.into_owned(),
            Err(source) => {
                drop(round);
                return Ok(current_round_preselection_conflict_rejected(
                    self,
                    FixedValidatorNodeCurrentRoundFinalityRejectionV0::FirstPrecommitCertificate(
                        Box::new(source),
                    ),
                ));
            }
        };
        let second_proposal = match round.decode_and_verify_proposal_control(
            second_canonical_proposal_control_bytes,
            second_canonical_artifact_bytes,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                return Ok(current_round_preselection_conflict_rejected(
                    self,
                    FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondProposal(Box::new(
                        source,
                    )),
                ));
            }
        };
        let second = match second_proposal
            .seal_with_precommit_certificate(second_canonical_precommit_certificate)
        {
            Ok(transition) => transition.into_owned(),
            Err(source) => {
                drop(round);
                return Ok(current_round_preselection_conflict_rejected(
                    self,
                    FixedValidatorNodeCurrentRoundFinalityRejectionV0::SecondPrecommitCertificate(
                        Box::new(source),
                    ),
                ));
            }
        };
        drop(round);

        let Self {
            finality,
            branch: _,
            signing_session,
        } = self;
        let halt = finality
            .commit_verified_preselection_conflict(first, second)
            .map_err(|source| {
                FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(Box::new(
                    FixedValidatorNodeFinalityErrorV0::Commit(Box::new(source)),
                ))
            })?;
        let stopped =
            stop_after_finality_halt(finality, signing_session, halt).map_err(|source| {
                FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(Box::new(source))
            })?;
        Ok(
            FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(Box::new(
                stopped,
            )),
        )
    }

    /// Finalizes one exact-current-round proposal from an exact precommit batch.
    ///
    /// Proposal admission precedes all-or-nothing quorum construction. Every
    /// supplied vote must authenticate the node-derived current round,
    /// precommit role, and admitted proposal root. The batch is not observed,
    /// filtered, retained, grouped, or selected, and all pre-sealing rejection
    /// returns the unchanged signing scope.
    pub fn commit_current_round_finality_vote_batch(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_signed_precommits: &[&[u8]],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeCurrentRoundFinalityErrorV0,
    > {
        commit_current_round_finality_with_precommits(
            self,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            CurrentRoundPrecommitInputV0::ExactSignedVotes(canonical_signed_precommits),
            inclusive_maximum_round,
        )
    }

    /// Finalizes one strictly earlier-round proposal from its separate messages.
    ///
    /// The caller supplies complete proposal-control bytes, the owned canonical
    /// artifact payload, one precommit certificate, and an inclusive local work
    /// ceiling. Strict certificate framing supplies only an unauthenticated
    /// routing position; it must name this branch's next height and a round
    /// strictly below the signer's current round before the complete proposal,
    /// payload, producer, snapshot, and certificate are verified together.
    /// Caller evidence rejection preserves the unchanged scope. Node coherence
    /// and the persisted finality ceiling remain fatal. Once verification
    /// succeeds, the existing consuming finality and signer-handoff contract
    /// applies unchanged.
    pub fn commit_lower_round_finality(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_precommit_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeLowerRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeLowerRoundFinalityErrorV0,
    > {
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        let signer_position = self.signing_session.position();
        lower_round_finality_preflight(&self.branch, signer_position, finality_maximum_round)?;

        let transition = match verify_lower_round_finality_inputs(
            &self.branch,
            signer_position.round(),
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            canonical_precommit_certificate,
            inclusive_maximum_round,
        ) {
            Ok(transition) => transition,
            Err(LowerRoundFinalityVerifyFailureV0::Fatal(source)) => {
                return Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Round(source));
            }
            Err(LowerRoundFinalityVerifyFailureV0::Rejected(rejection)) => {
                return Ok(lower_round_finality_rejected(self, rejection));
            }
        };

        self.commit_verified_finality(transition)
            .map(FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality)
            .map_err(|source| {
                FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(Box::new(source))
            })
    }

    /// Commits two strictly earlier-round proposal proofs as one neutral halt.
    ///
    /// Each complete triple independently passes the existing bounded lower-
    /// round verifier before their authenticated positions are compared. Any
    /// rejection returns the unchanged scope without a write. Only one exact
    /// shared position may enter the existing paired finality append and signer-
    /// stop sequence; caller order grants no root or winner preference.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lower_round_preselection_conflict(
        self,
        first_canonical_proposal_control_bytes: &[u8],
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_precommit_certificate: &[u8],
        second_canonical_proposal_control_bytes: &[u8],
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_precommit_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0<'node>,
        FixedValidatorNodeLowerRoundFinalityErrorV0,
    > {
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        let signer_position = self.signing_session.position();
        lower_round_finality_preflight(&self.branch, signer_position, finality_maximum_round)?;

        let first = match verify_lower_round_finality_inputs(
            &self.branch,
            signer_position.round(),
            first_canonical_proposal_control_bytes,
            first_canonical_artifact_bytes,
            first_canonical_precommit_certificate,
            inclusive_maximum_round,
        ) {
            Ok(transition) => transition,
            Err(LowerRoundFinalityVerifyFailureV0::Fatal(source)) => {
                return Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Round(source));
            }
            Err(LowerRoundFinalityVerifyFailureV0::Rejected(rejection)) => {
                return Ok(lower_round_preselection_conflict_rejected(
                    self,
                    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::First(Box::new(
                        rejection,
                    )),
                ));
            }
        };
        let second = match verify_lower_round_finality_inputs(
            &self.branch,
            signer_position.round(),
            second_canonical_proposal_control_bytes,
            second_canonical_artifact_bytes,
            second_canonical_precommit_certificate,
            inclusive_maximum_round,
        ) {
            Ok(transition) => transition,
            Err(LowerRoundFinalityVerifyFailureV0::Fatal(source)) => {
                return Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Round(source));
            }
            Err(LowerRoundFinalityVerifyFailureV0::Rejected(rejection)) => {
                return Ok(lower_round_preselection_conflict_rejected(
                    self,
                    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::Second(Box::new(
                        rejection,
                    )),
                ));
            }
        };
        let first_position = first.position();
        let second_position = second.position();
        if first_position != second_position {
            return Ok(lower_round_preselection_conflict_rejected(
                self,
                FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0::PositionMismatch {
                    first: first_position,
                    second: second_position,
                },
            ));
        }

        let Self {
            finality,
            branch: _,
            signing_session,
        } = self;
        let halt = finality
            .commit_verified_preselection_conflict(first, second)
            .map_err(|source| {
                FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(Box::new(
                    FixedValidatorNodeFinalityErrorV0::Commit(Box::new(source)),
                ))
            })?;
        let stopped =
            stop_after_finality_halt(finality, signing_session, halt).map_err(|source| {
                FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(Box::new(source))
            })?;
        Ok(
            FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(Box::new(
                stopped,
            )),
        )
    }

    /// Finalizes one explicitly routed strictly earlier-round proposal from an
    /// exact signed-precommit batch.
    ///
    /// The route's evidence round is bounded metadata only. It must be below
    /// the signer round and within the route's caller-local work ceiling before
    /// sequential derivation begins; the admitted proposal and every signed
    /// precommit must then independently authenticate that exact derived
    /// position. The batch is never filtered, retained, grouped, or selected.
    /// Every pre-sealing rejection returns the unchanged scope.
    pub fn commit_lower_round_finality_vote_batch(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_signed_precommits: &[&[u8]],
        route: FixedValidatorNodeFinalityRoundRouteV0,
    ) -> Result<
        FixedValidatorNodeLowerRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeLowerRoundFinalityErrorV0,
    > {
        let evidence_round = route.evidence_round();
        let inclusive_maximum_round = route.inclusive_maximum_round();
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        let signer_position = self.signing_session.position();
        lower_round_finality_preflight(&self.branch, signer_position, finality_maximum_round)?;
        if evidence_round >= signer_position.round() {
            return Ok(lower_round_finality_rejected(
                self,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                    evidence: evidence_round,
                    signer: signer_position.round(),
                },
            ));
        }
        if evidence_round > inclusive_maximum_round {
            return Ok(lower_round_finality_rejected(
                self,
                FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                    required: evidence_round,
                    maximum: inclusive_maximum_round,
                },
            ));
        }
        let round = derive_finality_round(&self.branch, evidence_round)
            .map_err(FixedValidatorNodeLowerRoundFinalityErrorV0::Round)?;
        let proposal = match round.decode_and_verify_proposal_control(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                return Ok(lower_round_finality_rejected(
                    self,
                    FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(Box::new(
                        FixedConsensusBoundedSeparateFinalityVerifyError::Proposal(source),
                    )),
                ));
            }
        };
        let transition = match proposal.seal_with_precommit_vote_batch(canonical_signed_precommits)
        {
            Ok(transition) => transition.into_owned(),
            Err(source) => {
                drop(round);
                return Ok(lower_round_finality_rejected(
                    self,
                    FixedValidatorNodeLowerRoundFinalityRejectionV0::PrecommitBatch(Box::new(
                        source,
                    )),
                ));
            }
        };
        drop(round);

        self.commit_verified_finality(transition)
            .map(FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality)
            .map_err(|source| {
                FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(Box::new(source))
            })
    }

    /// Consumes one sealed transition and couples its finality result to the signer.
    ///
    /// A new child returns a replacement scope only after both anchored journals
    /// advance and signer memory reaches the child's round zero. Same selected-
    /// value replay returns the unchanged aligned scope without writes. A distinct
    /// sibling returns only terminal evidence after the exact finality stop is
    /// anchored into the signer. Every error consumes the scope.
    pub fn commit_verified_finality(
        self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
    ) -> Result<FixedValidatorNodeFinalityOutcomeV0<'node>, FixedValidatorNodeFinalityErrorV0> {
        self.commit_verified_finality_with_origin(transition, FinalityTransitionOriginV0::Direct)
    }

    fn commit_verified_finality_with_origin(
        self,
        transition: OwnedVerifiedFixedConsensusTransitionV0,
        origin: FinalityTransitionOriginV0,
    ) -> Result<FixedValidatorNodeFinalityOutcomeV0<'node>, FixedValidatorNodeFinalityErrorV0> {
        let Self {
            finality,
            branch,
            signing_session,
        } = self;
        let outcome = finality
            .commit_verified(transition)
            .map_err(|source| FixedValidatorNodeFinalityErrorV0::Commit(Box::new(source)))?;
        match outcome {
            FixedValidatorFinalityCommitOutcomeV0::Finalized {
                position,
                ancestry_id,
                envelope_id,
                state_id,
            } => {
                let selection = match origin {
                    FinalityTransitionOriginV0::Direct => {
                        FixedValidatorNodeFinalitySelectionV0::Finalized {
                            position,
                            ancestry_id,
                            envelope_id,
                            state_id,
                        }
                    }
                    FinalityTransitionOriginV0::CandidateBacked(target) => {
                        FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
                            target,
                            position,
                            ancestry_id,
                            envelope_id,
                            state_id,
                        }
                    }
                };
                continue_after_finalized(finality, signing_session, position, selection)
            }
            FixedValidatorFinalityCommitOutcomeV0::AlreadyFinalized {
                height,
                ancestry_id,
                retained_envelope_id,
                state_id,
            } => Ok(FixedValidatorNodeFinalityOutcomeV0::Continues {
                scope: Box::new(FixedValidatorNodeSigningScopeV0 {
                    finality,
                    branch,
                    signing_session,
                }),
                selection: FixedValidatorNodeFinalitySelectionV0::AlreadyFinalized {
                    height,
                    ancestry_id,
                    retained_envelope_id,
                    state_id,
                },
            }),
            FixedValidatorFinalityCommitOutcomeV0::Halted(halt) => {
                let stopped = stop_after_finality_halt(finality, signing_session, halt)?;
                Ok(FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(
                    Box::new(stopped),
                ))
            }
        }
    }

    /// Finalizes one exact caller-selected retained candidate from an exact
    /// signed-precommit batch at an explicitly routed round.
    ///
    /// The route's evidence round is bounded metadata only. Unlike the
    /// specialized direct lower-round method, this compatibility sibling
    /// preserves the existing candidate-backed envelope path's acceptance of
    /// any round within both caller and persisted finality ceilings, including
    /// a round above the signer. The proposal and every vote must independently
    /// authenticate the derived round before the sealed transition reaches
    /// finality. Candidate and payload stores remain availability sources; no
    /// durable source entry or byte is mutated, while an integrity failure may
    /// poison only its owning live source handle under the reopen contract.
    pub fn commit_candidate_backed_finality_vote_batch(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_signed_precommits: &[&[u8]],
        route: FixedValidatorNodeFinalityRoundRouteV0,
    ) -> Result<
        FixedValidatorNodeCandidateBackedFinalityOutcomeV0<'node>,
        FixedValidatorNodeCandidateBackedFinalityErrorV0,
    > {
        let evidence_round = route.evidence_round();
        let inclusive_maximum_round = route.inclusive_maximum_round();
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        if inclusive_maximum_round > finality_maximum_round {
            return Ok(candidate_backed_finality_rejected(
                self,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::RoundWorkLimitExceedsFinality {
                    requested: inclusive_maximum_round,
                    finality: finality_maximum_round,
                },
            ));
        }
        if evidence_round > inclusive_maximum_round {
            return Ok(candidate_backed_finality_rejected(
                self,
                FixedValidatorNodeCandidateBackedFinalityRejectionV0::EvidenceRoundWorkLimitExceeded {
                    required: evidence_round,
                    maximum: inclusive_maximum_round,
                },
            ));
        }
        let round = derive_finality_round(&self.branch, evidence_round)
            .map_err(FixedValidatorNodeCandidateBackedFinalityErrorV0::Round)?;
        let canonical_artifact_bytes = match load_candidate_backed_proposal_payload(
            &round,
            candidates,
            payloads,
            expected_target,
            canonical_proposal_control_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(source) => {
                drop(round);
                return Ok(candidate_backed_finality_rejected(
                    self,
                    candidate_backed_finality_source_rejection(source),
                ));
            }
        };
        let proposal = match round.decode_and_verify_proposal_control(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                return Ok(candidate_backed_finality_rejected(
                    self,
                    FixedValidatorNodeCandidateBackedFinalityRejectionV0::Proposal(Box::new(
                        source,
                    )),
                ));
            }
        };
        let transition = match proposal.seal_with_precommit_vote_batch(canonical_signed_precommits)
        {
            Ok(transition) => transition.into_owned(),
            Err(source) => {
                drop(round);
                return Ok(candidate_backed_finality_rejected(
                    self,
                    FixedValidatorNodeCandidateBackedFinalityRejectionV0::PrecommitBatch(Box::new(
                        source,
                    )),
                ));
            }
        };
        drop(round);

        self.commit_verified_finality_with_origin(
            transition,
            FinalityTransitionOriginV0::CandidateBacked(expected_target),
        )
        .map(FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Finality)
        .map_err(|source| {
            FixedValidatorNodeCandidateBackedFinalityErrorV0::Finality(Box::new(source))
        })
    }

    /// Consumes one exact retained candidate and couples its finality to the signer.
    ///
    /// The caller explicitly chooses one unselected direct-child target and
    /// supplies the matching complete envelope plus caller-routed candidate and
    /// payload stores. Those stores provide only integrity-checked availability;
    /// the anchored finality journal performs the complete bounded verification
    /// and remains the sole source of signer-height authority. Success returns a
    /// replacement scope only after both anchored pairs and live signer memory
    /// reach the child. Every error consumes the scope.
    pub fn commit_candidate_backed_finality(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        canonical_envelope_bytes: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorNodeFinalityOutcomeV0<'node>, FixedValidatorNodeFinalityErrorV0> {
        let Self {
            finality,
            branch: _,
            signing_session,
        } = self;
        let commit = commit_candidate_backed_anchored_finality_v0(
            finality,
            candidates,
            payloads,
            expected_target,
            canonical_envelope_bytes,
            inclusive_maximum_round,
        )
        .map_err(|source| {
            FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(Box::new(source))
        })?;
        let selection = FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized {
            target: commit.target(),
            position: commit.position(),
            ancestry_id: commit.ancestry_id(),
            envelope_id: commit.envelope_id(),
            state_id: commit.state_id(),
        };
        continue_after_finalized(finality, signing_session, commit.position(), selection)
    }

    /// Consumes one exact retained candidate and stops on a finalized sibling.
    ///
    /// This deny-only path accepts only an already selected height and rejects the
    /// evidence-free selected value before source reads. It fully verifies a
    /// distinct candidate against the exact retained selected parent before the
    /// anchored finality journal may record its terminal conflict. Success returns
    /// only after the matching signer stop is independently anchored. Candidate
    /// and payload entries and durable bytes remain unchanged; an integrity/read
    /// failure may poison only the owning live source handle under its existing
    /// reopen contract. Every outcome consumes the scope.
    pub fn commit_candidate_backed_finality_conflict(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        canonical_envelope_bytes: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<FixedValidatorNodeFinalityStoppedV0, FixedValidatorNodeFinalityErrorV0> {
        let Self {
            finality,
            branch: _,
            signing_session,
        } = self;
        let conflict = commit_candidate_backed_anchored_finality_conflict_v0(
            finality,
            candidates,
            payloads,
            expected_target,
            canonical_envelope_bytes,
            inclusive_maximum_round,
        )
        .map_err(|source| {
            FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(Box::new(source))
        })?;
        debug_assert_eq!(conflict.target(), expected_target);
        stop_after_finality_halt(finality, signing_session, conflict.halt())
    }
}

#[derive(Clone, Copy)]
enum FinalityTransitionOriginV0 {
    Direct,
    CandidateBacked(ArtifactBlockId),
}

enum CurrentRoundPrecommitInputV0<'input> {
    CanonicalCertificate(&'input [u8]),
    ExactSignedVotes(&'input [&'input [u8]]),
}

enum CurrentRoundFinalityRoundErrorV0 {
    Rejected(FixedValidatorNodeCurrentRoundFinalityRejectionV0),
    Fatal(FixedValidatorNodeCurrentRoundFinalityErrorV0),
}

enum LowerRoundFinalityVerifyFailureV0 {
    Rejected(FixedValidatorNodeLowerRoundFinalityRejectionV0),
    Fatal(ProposerSelectionError),
}

fn commit_current_round_finality_with_precommits<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: Vec<u8>,
    precommits: CurrentRoundPrecommitInputV0<'_>,
    inclusive_maximum_round: ConsensusRound,
) -> Result<
    FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'node>,
    FixedValidatorNodeCurrentRoundFinalityErrorV0,
> {
    let finality_maximum_round = ConsensusRound::new(scope.finality.replay_limit().max_round());
    let signer_position = scope.signing_session.position();
    let round = match current_round_for_finality(
        &scope.branch,
        signer_position,
        inclusive_maximum_round,
        finality_maximum_round,
    ) {
        Ok(round) => round,
        Err(CurrentRoundFinalityRoundErrorV0::Rejected(rejection)) => {
            return Ok(current_round_finality_rejected(scope, rejection));
        }
        Err(CurrentRoundFinalityRoundErrorV0::Fatal(error)) => return Err(error),
    };
    let proposal = match round.decode_and_verify_proposal_control(
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    ) {
        Ok(proposal) => proposal,
        Err(source) => {
            drop(round);
            return Ok(current_round_finality_rejected(
                scope,
                FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(Box::new(source)),
            ));
        }
    };
    let transition = match precommits {
        CurrentRoundPrecommitInputV0::CanonicalCertificate(canonical_certificate) => {
            match proposal.seal_with_precommit_certificate(canonical_certificate) {
                Ok(transition) => transition.into_owned(),
                Err(source) => {
                    drop(round);
                    return Ok(current_round_finality_rejected(
                        scope,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(
                            Box::new(source),
                        ),
                    ));
                }
            }
        }
        CurrentRoundPrecommitInputV0::ExactSignedVotes(canonical_signed_precommits) => {
            match proposal.seal_with_precommit_vote_batch(canonical_signed_precommits) {
                Ok(transition) => transition.into_owned(),
                Err(source) => {
                    drop(round);
                    return Ok(current_round_finality_rejected(
                        scope,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitBatch(
                            Box::new(source),
                        ),
                    ));
                }
            }
        }
    };
    drop(round);

    scope
        .commit_verified_finality(transition)
        .map(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality)
        .map_err(|source| FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(Box::new(source)))
}

fn derive_finality_round(
    branch: &FixedConsensusBranchV0,
    required_round: ConsensusRound,
) -> Result<FixedConsensusRoundV0<'_>, ProposerSelectionError> {
    let mut round = branch.begin_round_zero()?;
    for _ in 0..required_round.value() {
        round = round.advance_round()?;
    }
    debug_assert_eq!(round.position().round(), required_round);
    Ok(round)
}

fn candidate_backed_finality_source_rejection(
    source: CandidateBackedProposalSourceErrorV0,
) -> FixedValidatorNodeCandidateBackedFinalityRejectionV0 {
    match source {
        CandidateBackedProposalSourceErrorV0::Proposal(source) => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::Proposal(source)
        }
        CandidateBackedProposalSourceErrorV0::CandidateChainMismatch { expected, actual } => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateChainMismatch {
                expected,
                actual,
            }
        }
        CandidateBackedProposalSourceErrorV0::CandidateStore(source) => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateStore(source)
        }
        CandidateBackedProposalSourceErrorV0::CandidateUnavailable { target } => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateUnavailable { target }
        }
        CandidateBackedProposalSourceErrorV0::ProposalTargetMismatch { expected, actual } => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::ProposalTargetMismatch {
                expected,
                actual,
            }
        }
        CandidateBackedProposalSourceErrorV0::CandidateBlockMismatch { target } => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateBlockMismatch { target }
        }
        CandidateBackedProposalSourceErrorV0::PayloadStore(source) => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::PayloadStore(source)
        }
        CandidateBackedProposalSourceErrorV0::PayloadUnavailable { target } => {
            FixedValidatorNodeCandidateBackedFinalityRejectionV0::PayloadUnavailable { target }
        }
    }
}

fn candidate_backed_finality_rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeCandidateBackedFinalityRejectionV0,
) -> FixedValidatorNodeCandidateBackedFinalityOutcomeV0<'node> {
    FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn current_round_for_finality<'branch>(
    branch: &'branch FixedConsensusBranchV0,
    signer_position: ConsensusPosition,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: ConsensusRound,
) -> Result<FixedConsensusRoundV0<'branch>, CurrentRoundFinalityRoundErrorV0> {
    let mut round = branch
        .begin_round_zero()
        .map_err(FixedValidatorNodeCurrentRoundFinalityErrorV0::Round)
        .map_err(CurrentRoundFinalityRoundErrorV0::Fatal)?;
    if round.position().height() != signer_position.height() {
        return Err(CurrentRoundFinalityRoundErrorV0::Fatal(
            FixedValidatorNodeCurrentRoundFinalityErrorV0::SignerBranchHeightMismatch {
                signer: signer_position,
                branch_next_height: round.position().height(),
            },
        ));
    }
    if signer_position.round() > finality_maximum_round {
        return Err(CurrentRoundFinalityRoundErrorV0::Fatal(
            FixedValidatorNodeCurrentRoundFinalityErrorV0::FinalityRoundLimitExceeded {
                required: signer_position.round(),
                maximum: finality_maximum_round,
            },
        ));
    }
    if signer_position.round() > inclusive_maximum_round {
        return Err(CurrentRoundFinalityRoundErrorV0::Rejected(
            FixedValidatorNodeCurrentRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                required: signer_position.round(),
                maximum: inclusive_maximum_round,
            },
        ));
    }
    for _ in 0..signer_position.round().value() {
        round = round
            .advance_round()
            .map_err(FixedValidatorNodeCurrentRoundFinalityErrorV0::Round)
            .map_err(CurrentRoundFinalityRoundErrorV0::Fatal)?;
    }
    debug_assert_eq!(round.position(), signer_position);
    Ok(round)
}

fn current_round_finality_rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeCurrentRoundFinalityRejectionV0,
) -> FixedValidatorNodeCurrentRoundFinalityOutcomeV0<'node> {
    FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn current_round_preselection_conflict_rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeCurrentRoundFinalityRejectionV0,
) -> FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0<'node> {
    FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn verify_lower_round_finality_inputs(
    branch: &FixedConsensusBranchV0,
    signer_round: ConsensusRound,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: Vec<u8>,
    canonical_precommit_certificate: &[u8],
    inclusive_maximum_round: ConsensusRound,
) -> Result<OwnedVerifiedFixedConsensusTransitionV0, LowerRoundFinalityVerifyFailureV0> {
    match branch.decode_and_verify_separate_finality_below_round(
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
        canonical_precommit_certificate,
        signer_round,
        inclusive_maximum_round,
    ) {
        Ok(transition) => Ok(transition),
        Err(FixedConsensusBoundedSeparateFinalityVerifyError::Proposer(source)) => {
            Err(LowerRoundFinalityVerifyFailureV0::Fatal(source))
        }
        Err(FixedConsensusBoundedSeparateFinalityVerifyError::RoundNotBelowUpperBound {
            round,
            exclusive_upper: _,
        }) => Err(LowerRoundFinalityVerifyFailureV0::Rejected(
            FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                evidence: round,
                signer: signer_round,
            },
        )),
        Err(FixedConsensusBoundedSeparateFinalityVerifyError::RoundLimitExceeded {
            round,
            maximum,
        }) => Err(LowerRoundFinalityVerifyFailureV0::Rejected(
            FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                required: round,
                maximum,
            },
        )),
        Err(source) => Err(LowerRoundFinalityVerifyFailureV0::Rejected(
            FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(Box::new(source)),
        )),
    }
}

fn lower_round_finality_preflight(
    branch: &FixedConsensusBranchV0,
    signer_position: ConsensusPosition,
    finality_maximum_round: ConsensusRound,
) -> Result<(), FixedValidatorNodeLowerRoundFinalityErrorV0> {
    let branch_next_height = branch
        .begin_round_zero()
        .map_err(FixedValidatorNodeLowerRoundFinalityErrorV0::Round)?
        .position()
        .height();
    if branch_next_height != signer_position.height() {
        return Err(
            FixedValidatorNodeLowerRoundFinalityErrorV0::SignerBranchHeightMismatch {
                signer: signer_position,
                branch_next_height,
            },
        );
    }
    if signer_position.round() > finality_maximum_round {
        return Err(
            FixedValidatorNodeLowerRoundFinalityErrorV0::FinalityRoundLimitExceeded {
                required: signer_position.round(),
                maximum: finality_maximum_round,
            },
        );
    }
    Ok(())
}

fn lower_round_finality_rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeLowerRoundFinalityRejectionV0,
) -> FixedValidatorNodeLowerRoundFinalityOutcomeV0<'node> {
    FixedValidatorNodeLowerRoundFinalityOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn lower_round_preselection_conflict_rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0,
) -> FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0<'node> {
    FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}

fn stop_after_finality_halt(
    finality: &FixedValidatorAnchoredFinalityJournalV0,
    mut signing_session: super::FixedValidatorNodeVotingSessionV0<'_>,
    halt: FixedValidatorFinalityHaltV0,
) -> Result<FixedValidatorNodeFinalityStoppedV0, FixedValidatorNodeFinalityErrorV0> {
    let durable = finality.acknowledge_signer_stop().map_err(|source| {
        FixedValidatorNodeFinalityErrorV0::SignerStopAuthority {
            halt: Box::new(halt),
            source: Box::new(source),
        }
    })?;
    let signer_stop = match signing_session
        .signing_session
        .stop_after_durable_finality_conflict(durable)
        .map_err(|source| FixedValidatorNodeFinalityErrorV0::SignerStop {
            halt: Box::new(halt),
            source: Box::new(source),
        })? {
        FixedValidatorFinalityConflictSignerStopOutcomeV0::Stopped(stop)
        | FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(stop) => stop,
    };
    Ok(FixedValidatorNodeFinalityStoppedV0 {
        finality_halt: halt,
        signer_stop,
    })
}

fn continue_after_finalized<'node>(
    finality: &'node mut FixedValidatorAnchoredFinalityJournalV0,
    mut signing_session: super::FixedValidatorNodeVotingSessionV0<'node>,
    position: ConsensusPosition,
    selection: FixedValidatorNodeFinalitySelectionV0,
) -> Result<FixedValidatorNodeFinalityOutcomeV0<'node>, FixedValidatorNodeFinalityErrorV0> {
    let durable = finality
        .acknowledge_signer_height_transition(position.height())
        .map_err(
            |source| FixedValidatorNodeFinalityErrorV0::SignerHeightAuthority {
                selection: Box::new(selection),
                source: Box::new(source),
            },
        )?;
    let prepared = signing_session
        .signing_session
        .prepare_height_with_durable_finality(durable)
        .map_err(
            |source| FixedValidatorNodeFinalityErrorV0::SignerHeightPrepare {
                selection: Box::new(selection),
                source: Box::new(source),
            },
        )?;
    let branch = signing_session
        .signing_session
        .acknowledge_prepared_height(prepared)
        .map_err(
            |source| FixedValidatorNodeFinalityErrorV0::SignerHeightAcknowledge {
                selection: Box::new(selection),
                source: Box::new(source),
            },
        )?;
    Ok(FixedValidatorNodeFinalityOutcomeV0::Continues {
        scope: Box::new(FixedValidatorNodeSigningScopeV0 {
            finality,
            branch,
            signing_session,
        }),
        selection,
    })
}
