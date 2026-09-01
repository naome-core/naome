use std::error::Error;
use std::fmt;

use naome_chain::ArtifactBlockId;
use naome_consensus::{
    ConsensusAncestryId, ConsensusEnvelopeId, ConsensusEnvelopeVerifyError, ConsensusHeight,
    ConsensusPosition, ConsensusProposalVerifyError, ConsensusRound,
    FixedConsensusBoundedSeparateFinalityVerifyError, FixedConsensusBranchV0,
    FixedConsensusRoundV0, OwnedVerifiedFixedConsensusTransitionV0, ProposerSelectionError,
};
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBackedFinalityErrorV0, CanonicalArtifactPayloadStore,
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityCommitOutcomeV0,
    FixedValidatorFinalityConflictSignerStopOutcomeV0, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityJournalStateIdV0,
    FixedValidatorVoteSafetyJournalErrorV0, commit_candidate_backed_anchored_finality_conflict_v0,
    commit_candidate_backed_anchored_finality_v0,
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

/// Result of admitting exact-current-round evidence into node-owned finality.
///
/// A rejection returns the unchanged signing scope because no finality or signer
/// effect occurred. Once the proposal and precommit certificate produce an
/// owned sealed transition, the existing consuming finality outcome is retained
/// without reinterpretation.
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
        }
    }
}

impl Error for FixedValidatorNodeCurrentRoundFinalityRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Proposal(source) => Some(source.as_ref()),
            Self::PrecommitCertificate(source) => Some(source.as_ref()),
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
        }
    }
}

impl Error for FixedValidatorNodeLowerRoundFinalityRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Evidence(source) => Some(source.as_ref()),
            Self::NotEarlierThanSigner { .. } | Self::RoundWorkLimitExceeded { .. } => None,
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
                return Ok(current_round_finality_rejected(self, rejection));
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
                    self,
                    FixedValidatorNodeCurrentRoundFinalityRejectionV0::Proposal(Box::new(source)),
                ));
            }
        };
        let transition =
            match proposal.seal_with_precommit_certificate(canonical_precommit_certificate) {
                Ok(transition) => transition.into_owned(),
                Err(source) => {
                    drop(round);
                    return Ok(current_round_finality_rejected(
                        self,
                        FixedValidatorNodeCurrentRoundFinalityRejectionV0::PrecommitCertificate(
                            Box::new(source),
                        ),
                    ));
                }
            };
        drop(round);

        self.commit_verified_finality(transition)
            .map(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality)
            .map_err(|source| {
                FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(Box::new(source))
            })
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

        let transition = match self.branch.decode_and_verify_separate_finality_below_round(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            canonical_precommit_certificate,
            signer_position.round(),
            inclusive_maximum_round,
        ) {
            Ok(transition) => transition,
            Err(FixedConsensusBoundedSeparateFinalityVerifyError::Proposer(source)) => {
                return Err(FixedValidatorNodeLowerRoundFinalityErrorV0::Round(source));
            }
            Err(FixedConsensusBoundedSeparateFinalityVerifyError::RoundNotBelowUpperBound {
                round,
                exclusive_upper: _,
            }) => {
                return Ok(lower_round_finality_rejected(
                    self,
                    FixedValidatorNodeLowerRoundFinalityRejectionV0::NotEarlierThanSigner {
                        evidence: round,
                        signer: signer_position.round(),
                    },
                ));
            }
            Err(FixedConsensusBoundedSeparateFinalityVerifyError::RoundLimitExceeded {
                round,
                maximum,
            }) => {
                return Ok(lower_round_finality_rejected(
                    self,
                    FixedValidatorNodeLowerRoundFinalityRejectionV0::RoundWorkLimitExceeded {
                        required: round,
                        maximum,
                    },
                ));
            }
            Err(source) => {
                return Ok(lower_round_finality_rejected(
                    self,
                    FixedValidatorNodeLowerRoundFinalityRejectionV0::Evidence(Box::new(source)),
                ));
            }
        };

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
                let selection = FixedValidatorNodeFinalitySelectionV0::Finalized {
                    position,
                    ancestry_id,
                    envelope_id,
                    state_id,
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

enum CurrentRoundFinalityRoundErrorV0 {
    Rejected(FixedValidatorNodeCurrentRoundFinalityRejectionV0),
    Fatal(FixedValidatorNodeCurrentRoundFinalityErrorV0),
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
