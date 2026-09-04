use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;

use naome_chain::{ArtifactBlockId, ArtifactChainId};
use naome_consensus::{
    ConsensusHeight, ConsensusPosition, ConsensusRound, FixedConsensusBranchV0,
    FixedConsensusRoundV0, FixedValidatorLockPhaseV0, FixedValidatorProposalIntentErrorV0,
    FixedValidatorProposalSourceV0, ProposerSelectionError,
};
use naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreError, CanonicalArtifactPayloadStore,
    CanonicalArtifactPayloadStoreError, FixedValidatorProposalPrepareOutcomeV0,
    FixedValidatorProposalSafetyHaltV0, FixedValidatorSignedProposalV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::{
    FixedValidatorNodeCurrentRoundErrorV0, FixedValidatorNodeSigningScopeV0,
    FixedValidatorNodeVotingSessionV0, fixed_validator_node_current_round,
};

/// Complete result of one node-owned current-round proposal-authoring attempt.
///
/// An authored result returns continued node authority only after the exact
/// intent, independent anchor, producer signature, completion, and updated
/// anchor are all durable. A rejection returns the unchanged scope because no
/// journal write occurred. A same-slot conflicting intent returns no scope.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalAuthoringOutcomeV0<'node> {
    /// One exact current-round proposal completed durably and may be released.
    Authored {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        proposal: FixedValidatorSignedProposalV0,
    },
    /// A source or explicit input failed before any durable signer effect.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeProposalAuthoringRejectionV0>,
    },
    /// A non-identical intent at the same proposal slot durably stopped the signer.
    SignerStopped(FixedValidatorProposalSafetyHaltV0),
}

/// A pre-effect source or input failure that preserves the signing scope.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalAuthoringRejectionV0 {
    /// Reconstructing the signer's current round would exceed local work policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The caller-routed candidate store belongs to another artifact chain.
    CandidateChainMismatch {
        expected: ArtifactChainId,
        actual: ArtifactChainId,
    },
    /// The exact caller-routed candidate store could not serve the target.
    CandidateStore(Box<ArtifactBlockCandidateStoreError>),
    /// The exact caller-selected block candidate is not locally available.
    CandidateUnavailable { target: ArtifactBlockId },
    /// The exact caller-routed payload store could not serve the target.
    PayloadStore(Box<CanonicalArtifactPayloadStoreError>),
    /// The exact proposal target's canonical artifact payload is not locally available.
    PayloadUnavailable { target: ArtifactBlockId },
    /// The driver publication payload exceeds the protocol bound.
    PublicationPayloadTooLong { actual: usize, maximum: usize },
    /// The driver could not reserve payload custody before any durable effect.
    PublicationPayloadCopy(TryReserveError),
    /// The current phase, proposer, source, artifact, or retained value was invalid.
    Proposal(Box<FixedValidatorProposalIntentErrorV0>),
}

impl fmt::Display for FixedValidatorNodeProposalAuthoringRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds local proposal-authoring ceiling {maximum:?}"
            ),
            Self::CandidateChainMismatch { expected, actual } => write!(
                formatter,
                "candidate-store chain {actual:?} differs from proposal chain {expected:?}"
            ),
            Self::CandidateStore(source) => {
                write!(
                    formatter,
                    "candidate store could not serve proposal target: {source}"
                )
            }
            Self::CandidateUnavailable { target } => {
                write!(
                    formatter,
                    "proposal candidate {target:?} is not locally available"
                )
            }
            Self::PayloadStore(source) => {
                write!(
                    formatter,
                    "payload store could not serve proposal target: {source}"
                )
            }
            Self::PayloadUnavailable { target } => write!(
                formatter,
                "canonical payload for proposal target {target:?} is not locally available"
            ),
            Self::PublicationPayloadTooLong { actual, maximum } => write!(
                formatter,
                "proposal publication payload length {actual} exceeds {maximum}"
            ),
            Self::PublicationPayloadCopy(source) => write!(
                formatter,
                "proposal publication payload custody could not be reserved: {source}"
            ),
            Self::Proposal(source) => {
                write!(
                    formatter,
                    "current node proposal intent was rejected: {source}"
                )
            }
        }
    }
}

impl Error for FixedValidatorNodeProposalAuthoringRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CandidateStore(source) => Some(source.as_ref()),
            Self::PayloadStore(source) => Some(source.as_ref()),
            Self::Proposal(source) => Some(source.as_ref()),
            Self::PublicationPayloadCopy(source) => Some(source),
            Self::RoundWorkLimitExceeded { .. }
            | Self::CandidateChainMismatch { .. }
            | Self::CandidateUnavailable { .. }
            | Self::PayloadUnavailable { .. }
            | Self::PublicationPayloadTooLong { .. } => None,
        }
    }
}

/// A fatal node or signer error during current-round proposal authoring.
///
/// Every variant consumes the signing scope and grants no proposal bytes.
/// Strict restart is the only classifier after an ambiguous durable step.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalAuthoringErrorV0 {
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
    /// The signing session was not operational before proposal admission.
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The exact proposal intent could not be durably prepared.
    Prepare(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The anchored preparation could not issue exact key-use authority.
    Acknowledge(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Key use, self-verification, completion, or completion anchoring failed.
    Sign(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

impl fmt::Display for FixedValidatorNodeProposalAuthoringErrorV0 {
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
                "current node proposal round could not be reconstructed: {source}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Session(source) => {
                write!(
                    formatter,
                    "node proposal session is not operational: {source}"
                )
            }
            Self::Prepare(source) => {
                write!(formatter, "node proposal preparation failed: {source}")
            }
            Self::Acknowledge(source) => write!(
                formatter,
                "node proposal preparation acknowledgement failed: {source}"
            ),
            Self::Sign(source) => write!(formatter, "node proposal signing failed: {source}"),
        }
    }
}

impl Error for FixedValidatorNodeProposalAuthoringErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Session(source)
            | Self::Prepare(source)
            | Self::Acknowledge(source)
            | Self::Sign(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. } | Self::FinalityRoundLimitExceeded { .. } => {
                None
            }
        }
    }
}

enum CurrentRoundErrorV0 {
    Rejected(FixedValidatorNodeProposalAuthoringRejectionV0),
    Fatal(FixedValidatorNodeProposalAuthoringErrorV0),
}

pub(super) enum NodeProposalInputV0<'input> {
    Direct(FixedValidatorProposalSourceV0),
    CandidateFresh {
        candidates: &'input mut ArtifactBlockCandidateStore,
        payloads: &'input mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
    },
    PayloadRetained(&'input mut CanonicalArtifactPayloadStore),
}

impl NodeProposalInputV0<'_> {
    fn resolve(
        self,
        round: &FixedConsensusRoundV0<'_>,
        signing_session: &FixedValidatorNodeVotingSessionV0<'_>,
    ) -> Result<FixedValidatorProposalSourceV0, FixedValidatorNodeProposalAuthoringRejectionV0>
    {
        match self {
            Self::Direct(source) => Ok(source),
            Self::CandidateFresh {
                candidates,
                payloads,
                expected_target,
            } => {
                if signing_session.valid_value().is_some() {
                    return Err(FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(
                        Box::new(FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired),
                    ));
                }

                let expected_chain = round.context().chain_id();
                let actual_chain = candidates.chain_id();
                if actual_chain != expected_chain {
                    return Err(
                        FixedValidatorNodeProposalAuthoringRejectionV0::CandidateChainMismatch {
                            expected: expected_chain,
                            actual: actual_chain,
                        },
                    );
                }

                let artifact_block = candidates
                    .get(expected_target)
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringRejectionV0::CandidateStore(Box::new(
                            source,
                        ))
                    })?
                    .ok_or(
                        FixedValidatorNodeProposalAuthoringRejectionV0::CandidateUnavailable {
                            target: expected_target,
                        },
                    )?;
                let payload = payloads
                    .get(artifact_block.artifact_id())
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringRejectionV0::PayloadStore(Box::new(
                            source,
                        ))
                    })?
                    .ok_or(
                        FixedValidatorNodeProposalAuthoringRejectionV0::PayloadUnavailable {
                            target: expected_target,
                        },
                    )?;

                Ok(FixedValidatorProposalSourceV0::Fresh {
                    artifact_block,
                    canonical_artifact_bytes: payload.into_canonical_artifact_bytes().into_vec(),
                })
            }
            Self::PayloadRetained(payloads) => {
                let retained_value = signing_session.valid_value().ok_or_else(|| {
                    FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(Box::new(
                        FixedValidatorProposalIntentErrorV0::FreshValueRequired,
                    ))
                })?;
                let artifact_block = retained_value.value().artifact_block();
                let target = artifact_block.id();
                let payload = payloads
                    .get(artifact_block.artifact_id())
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringRejectionV0::PayloadStore(Box::new(
                            source,
                        ))
                    })?
                    .ok_or(
                        FixedValidatorNodeProposalAuthoringRejectionV0::PayloadUnavailable {
                            target,
                        },
                    )?;

                Ok(FixedValidatorProposalSourceV0::RetainedValid {
                    canonical_artifact_bytes: payload.into_canonical_artifact_bytes().into_vec(),
                })
            }
        }
    }
}

fn capture_publication_payload(
    source: &FixedValidatorProposalSourceV0,
    has_retained_value: bool,
    payload: &mut Vec<u8>,
) -> Result<(), FixedValidatorNodeProposalAuthoringRejectionV0> {
    let bytes = match (has_retained_value, source) {
        (
            false,
            FixedValidatorProposalSourceV0::Fresh {
                canonical_artifact_bytes,
                ..
            },
        )
        | (
            true,
            FixedValidatorProposalSourceV0::RetainedValid {
                canonical_artifact_bytes,
            },
        ) => canonical_artifact_bytes,
        (false, FixedValidatorProposalSourceV0::RetainedValid { .. }) => {
            return Err(FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(
                Box::new(FixedValidatorProposalIntentErrorV0::FreshValueRequired),
            ));
        }
        (true, FixedValidatorProposalSourceV0::Fresh { .. }) => {
            return Err(FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(
                Box::new(FixedValidatorProposalIntentErrorV0::RetainedValidValueRequired),
            ));
        }
    };
    if bytes.len() > ARTIFACT_PAYLOAD_MAX_BYTES {
        return Err(
            FixedValidatorNodeProposalAuthoringRejectionV0::PublicationPayloadTooLong {
                actual: bytes.len(),
                maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
            },
        );
    }
    payload
        .try_reserve_exact(bytes.len())
        .map_err(FixedValidatorNodeProposalAuthoringRejectionV0::PublicationPayloadCopy)?;
    payload.extend_from_slice(bytes);
    Ok(())
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Validates, durably prepares, signs, and completes one current-round proposal.
    ///
    /// The private signer state decides whether the caller must supply a fresh
    /// artifact candidate or the exact retained valid value. The node derives
    /// its scheduled proposer and current round, fully verifies the selected
    /// source, and releases proposal-control bytes only after durable completion.
    pub fn author_proposal(
        self,
        source: FixedValidatorProposalSourceV0,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeProposalAuthoringErrorV0,
    > {
        self.author_proposal_with_input(
            inclusive_maximum_round,
            NodeProposalInputV0::Direct(source),
            None,
        )
    }

    /// Authors one caller-selected fresh proposal from exact local availability stores.
    ///
    /// The caller chooses the target and routes both stores. Proposal phase,
    /// scheduled-proposer authority, and absence of a retained valid value are
    /// established before either store is read. Store membership grants only
    /// availability: the unchanged consensus path still completely validates
    /// the block and payload before any durable signer effect.
    pub fn author_candidate_backed_fresh_proposal(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: ArtifactBlockId,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeProposalAuthoringErrorV0,
    > {
        self.author_proposal_with_input(
            inclusive_maximum_round,
            NodeProposalInputV0::CandidateFresh {
                candidates,
                payloads,
                expected_target,
            },
            None,
        )
    }

    /// Re-authors the exact retained valid value from one local payload store.
    ///
    /// The private retained value supplies the sole artifact address. Proposal
    /// phase, scheduled-proposer authority, and retained-value presence are
    /// established before the payload store is read. Store presence grants only
    /// availability: the unchanged consensus path still re-verifies the retained
    /// certificate, value, and payload before any durable signer effect.
    pub fn author_payload_store_backed_retained_proposal(
        self,
        payloads: &mut CanonicalArtifactPayloadStore,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeProposalAuthoringErrorV0,
    > {
        self.author_proposal_with_input(
            inclusive_maximum_round,
            NodeProposalInputV0::PayloadRetained(payloads),
            None,
        )
    }

    /// Captures the exact resolved payload before signer effects for one driver command.
    pub(super) fn author_proposal_for_driver(
        self,
        input: NodeProposalInputV0<'_>,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        (FixedValidatorNodeProposalAuthoringOutcomeV0<'node>, Vec<u8>),
        FixedValidatorNodeProposalAuthoringErrorV0,
    > {
        let mut payload = Vec::new();
        let outcome =
            self.author_proposal_with_input(inclusive_maximum_round, input, Some(&mut payload))?;
        Ok((outcome, payload))
    }

    fn author_proposal_with_input(
        mut self,
        inclusive_maximum_round: ConsensusRound,
        input: NodeProposalInputV0<'_>,
        publication_payload: Option<&mut Vec<u8>>,
    ) -> Result<
        FixedValidatorNodeProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeProposalAuthoringErrorV0,
    > {
        let finality_maximum_round = self.finality.replay_limit().max_round();
        let round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };

        let phase = self.signing_session.phase();
        if phase != FixedValidatorLockPhaseV0::Proposal {
            drop(round);
            return Ok(rejected(
                self,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(Box::new(
                    FixedValidatorProposalIntentErrorV0::WrongPhase { actual: phase },
                )),
            ));
        }
        let signer = self.signing_session.signer();
        if round.proposer() != signer {
            let scheduled = round.proposer();
            drop(round);
            return Ok(rejected(
                self,
                FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(Box::new(
                    FixedValidatorProposalIntentErrorV0::NotScheduledProposer { scheduled, signer },
                )),
            ));
        }

        let source = match input.resolve(&round, &self.signing_session) {
            Ok(source) => source,
            Err(rejection) => {
                drop(round);
                return Ok(rejected(self, rejection));
            }
        };

        if let Some(payload) = publication_payload
            && let Err(rejection) = capture_publication_payload(
                &source,
                self.signing_session.valid_value().is_some(),
                payload,
            )
        {
            drop(round);
            return Ok(rejected(self, rejection));
        }

        let preparation = match self.signing_session.prepare_proposal(&round, source) {
            Ok(preparation) => preparation,
            Err(FixedValidatorVoteSafetyJournalErrorV0::ProposalPreparation(source)) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeProposalAuthoringRejectionV0::Proposal(Box::new(source)),
                ));
            }
            Err(source) => {
                return Err(FixedValidatorNodeProposalAuthoringErrorV0::Prepare(
                    Box::new(source),
                ));
            }
        };

        let proposal = match preparation {
            FixedValidatorProposalPrepareOutcomeV0::Prepared(prepared)
            | FixedValidatorProposalPrepareOutcomeV0::AlreadyPrepared(prepared) => {
                let acknowledgement = self
                    .signing_session
                    .acknowledge_prepared_proposal(prepared)
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringErrorV0::Acknowledge(Box::new(source))
                    })?;
                self.signing_session
                    .sign_prepared_proposal(acknowledgement)
                    .map_err(|source| {
                        FixedValidatorNodeProposalAuthoringErrorV0::Sign(Box::new(source))
                    })?
            }
            FixedValidatorProposalPrepareOutcomeV0::AlreadySigned(proposal) => proposal,
            FixedValidatorProposalPrepareOutcomeV0::Halted(halt) => {
                return Ok(FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(
                    halt,
                ));
            }
        };

        Ok(FixedValidatorNodeProposalAuthoringOutcomeV0::Authored {
            scope: Box::new(self),
            proposal,
        })
    }
}

fn current_round<'branch>(
    branch: &'branch FixedConsensusBranchV0,
    signing_session: &FixedValidatorNodeVotingSessionV0<'_>,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: u64,
) -> Result<FixedConsensusRoundV0<'branch>, CurrentRoundErrorV0> {
    fixed_validator_node_current_round(
        branch,
        signing_session,
        inclusive_maximum_round,
        finality_maximum_round,
    )
    .map_err(|error| match error {
        FixedValidatorNodeCurrentRoundErrorV0::SignerBranchHeightMismatch {
            signer,
            branch_next_height,
        } => CurrentRoundErrorV0::Fatal(
            FixedValidatorNodeProposalAuthoringErrorV0::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            },
        ),
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalAuthoringErrorV0::Round(source))
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Fatal(
                FixedValidatorNodeProposalAuthoringErrorV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Rejected(
                FixedValidatorNodeProposalAuthoringRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalAuthoringErrorV0::Session(source))
        }
    })
}

fn rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeProposalAuthoringRejectionV0,
) -> FixedValidatorNodeProposalAuthoringOutcomeV0<'node> {
    FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}
