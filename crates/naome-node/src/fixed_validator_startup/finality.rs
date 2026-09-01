use std::error::Error;
use std::fmt;

use naome_chain::ArtifactBlockId;
use naome_consensus::{
    ConsensusAncestryId, ConsensusEnvelopeId, ConsensusHeight, ConsensusPosition, ConsensusRound,
    OwnedVerifiedFixedConsensusTransitionV0,
};
use naome_storage::{
    ArtifactBlockCandidateStore, CandidateBackedFinalityErrorV0, CanonicalArtifactPayloadStore,
    FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityCommitOutcomeV0,
    FixedValidatorFinalityConflictSignerStopOutcomeV0, FixedValidatorFinalityHaltV0,
    FixedValidatorFinalityJournalErrorV0, FixedValidatorFinalityJournalStateIdV0,
    FixedValidatorVoteSafetyJournalErrorV0, commit_candidate_backed_anchored_finality_v0,
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
            mut signing_session,
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
                    | FixedValidatorFinalityConflictSignerStopOutcomeV0::AlreadyStopped(stop) => {
                        stop
                    }
                };
                Ok(FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(
                    Box::new(FixedValidatorNodeFinalityStoppedV0 {
                        finality_halt: halt,
                        signer_stop,
                    }),
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
