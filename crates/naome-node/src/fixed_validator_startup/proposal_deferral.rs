use std::error::Error;
use std::fmt;

use naome_consensus::{
    ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError, ConsensusRound,
    ConsensusValueV0, FixedConsensusBranchCoordinateV0, FixedConsensusBranchV0,
    FixedConsensusRoundV0, ProposalSigningRoot, ProposerSelectionError,
    VerifiedFixedConsensusProposalV0,
};
use naome_storage::FixedValidatorVoteSafetyJournalErrorV0;

use super::{
    FixedValidatorNodeCurrentRoundErrorV0, FixedValidatorNodeSigningScopeV0,
    FixedValidatorNodeVotingSessionV0, fixed_validator_node_current_round,
};

/// Descriptive target and local work ceiling for one higher-round proposal.
///
/// Construction performs no verification and grants no proposal, progression,
/// voting, or finality authority. The consuming deferral operation derives the
/// exact target round from the node-owned branch and verifies the proposal there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct FixedValidatorNodeHigherRoundProposalRouteV0 {
    proposal_round: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
}

impl FixedValidatorNodeHigherRoundProposalRouteV0 {
    /// Binds the caller-routed proposal round and inclusive work ceiling.
    pub const fn new(
        proposal_round: ConsensusRound,
        inclusive_maximum_round: ConsensusRound,
    ) -> Self {
        Self {
            proposal_round,
            inclusive_maximum_round,
        }
    }

    /// Returns the caller-routed proposal round to derive and authenticate.
    pub const fn proposal_round(self) -> ConsensusRound {
        self.proposal_round
    }

    /// Returns the inclusive caller-local sequential work ceiling.
    pub const fn inclusive_maximum_round(self) -> ConsensusRound {
        self.inclusive_maximum_round
    }
}

/// One fully checked higher-round proposal retained only in caller-owned memory.
///
/// Private fields prevent raw construction. The token owns only descriptive
/// identities and the exact canonical inputs that passed complete proposal and
/// artifact admission. It contains no branch cursor, successor snapshot,
/// separately typed catch-up certificate, peer identity, signing capability, or
/// state-transition authority. It is deliberately not cloneable or serializable.
///
/// The type provides no implicit deep clone of the owned inputs:
///
/// ```compile_fail,E0599
/// use naome_node::FixedValidatorNodeDeferredProposalV0;
///
/// fn duplicate(proposal: FixedValidatorNodeDeferredProposalV0) {
///     let _ = proposal.clone();
/// }
/// ```
///
/// Nor can they convert the token directly into verified authority without
/// complete re-verification:
///
/// ```compile_fail
/// use naome_consensus::VerifiedFixedConsensusProposalV0;
/// use naome_node::FixedValidatorNodeDeferredProposalV0;
///
/// fn elevate(
///     proposal: FixedValidatorNodeDeferredProposalV0,
/// ) -> VerifiedFixedConsensusProposalV0<'static, 'static> {
///     proposal.into()
/// }
/// ```
#[must_use]
pub struct FixedValidatorNodeDeferredProposalV0 {
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
    value: ConsensusValueV0,
    canonical_proposal_control_bytes: Box<[u8]>,
    canonical_artifact_bytes: Box<[u8]>,
}

impl FixedValidatorNodeDeferredProposalV0 {
    /// Returns the exact branch parent against which the proposal was admitted.
    pub const fn parent_coordinate(&self) -> FixedConsensusBranchCoordinateV0 {
        self.parent_coordinate
    }

    /// Returns the exact height and round used for admission.
    pub const fn position(&self) -> ConsensusPosition {
        self.position
    }

    /// Returns the admitted proposal value as descriptive data only.
    pub const fn value(&self) -> ConsensusValueV0 {
        self.value
    }

    /// Returns the value-derived proposal signing root.
    pub fn proposal_signing_root(&self) -> ProposalSigningRoot {
        self.value.proposal_signing_root()
    }

    /// Returns the exact canonical proposal-control bytes retained by this token.
    pub fn canonical_proposal_control_bytes(&self) -> &[u8] {
        &self.canonical_proposal_control_bytes
    }

    /// Returns the exact complete canonical artifact payload retained by this token.
    pub fn canonical_artifact_bytes(&self) -> &[u8] {
        &self.canonical_artifact_bytes
    }

    /// Consumes the token and returns its raw canonical inputs.
    ///
    /// The returned bytes retain no verified status. Any later use must derive a
    /// live typed round and repeat complete proposal and payload verification.
    pub fn into_unverified_canonical_inputs(self) -> (Vec<u8>, Vec<u8>) {
        (
            self.canonical_proposal_control_bytes.into_vec(),
            self.canonical_artifact_bytes.into_vec(),
        )
    }
}

/// Result of one node-coordinated higher-round proposal deferral attempt.
///
/// Success returns the unchanged node scope and one caller-owned token. A
/// rejection likewise returns the unchanged scope because no volatile or
/// durable signer state changed.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalDeferralOutcomeV0<'node> {
    /// One exact proposal was verified and retained in caller-owned memory.
    Deferred {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    },
    /// Explicit routing, capacity, proposal, or payload input was rejected.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeProposalDeferralRejectionV0>,
    },
}

/// A pre-effect proposal-deferral rejection that preserves the signing scope.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalDeferralRejectionV0 {
    /// The first possible or routed higher round exceeds persisted finality policy.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The first possible or routed higher round exceeds caller-local policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The routed proposal round is not higher than the signer round.
    NotHigherThanSigner {
        signer: ConsensusRound,
        proposal: ConsensusRound,
    },
    /// Complete proposal-control and artifact admission failed at the routed round.
    Proposal(Box<ConsensusProposalVerifyError>),
}

impl fmt::Display for FixedValidatorNodeProposalDeferralRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "proposal deferral requires {required:?}, above node finality ceiling {maximum:?}"
            ),
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "proposal deferral requires {required:?}, above caller-local ceiling {maximum:?}"
            ),
            Self::NotHigherThanSigner { signer, proposal } => write!(
                formatter,
                "routed proposal round {proposal:?} is not higher than signer round {signer:?}"
            ),
            Self::Proposal(source) => {
                write!(formatter, "higher-round proposal was rejected: {source}")
            }
        }
    }
}

impl Error for FixedValidatorNodeProposalDeferralRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Proposal(source) => Some(source.as_ref()),
            Self::FinalityRoundLimitExceeded { .. }
            | Self::RoundWorkLimitExceeded { .. }
            | Self::NotHigherThanSigner { .. } => None,
        }
    }
}

/// A fatal node or signer error during proposal deferral.
///
/// These variants consume the signing scope because node coherence or session
/// health could not be established, even though deferral itself writes nothing.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeProposalDeferralErrorV0 {
    /// The node-owned signer and branch do not name the same next height.
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    /// The exact node-owned current or target round could not be derived.
    Round(ProposerSelectionError),
    /// The current round has no representable higher successor.
    RoundExhausted { current: ConsensusRound },
    /// The current signer round exceeds the persisted finality ceiling.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The signing session was not operational before input admission.
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
}

impl fmt::Display for FixedValidatorNodeProposalDeferralErrorV0 {
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
                "node proposal-deferral round could not be reconstructed: {source}"
            ),
            Self::RoundExhausted { current } => write!(
                formatter,
                "current node round {current:?} has no higher proposal successor"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "current signer round {required:?} exceeds node finality ceiling {maximum:?}"
            ),
            Self::Session(source) => write!(
                formatter,
                "node proposal-deferral session is not operational: {source}"
            ),
        }
    }
}

impl Error for FixedValidatorNodeProposalDeferralErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Session(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. }
            | Self::RoundExhausted { .. }
            | Self::FinalityRoundLimitExceeded { .. } => None,
        }
    }
}

pub(super) enum CurrentRoundErrorV0 {
    Rejected(FixedValidatorNodeProposalDeferralRejectionV0),
    Fatal(FixedValidatorNodeProposalDeferralErrorV0),
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Fully admits one exact strictly higher-round proposal without advancing state.
    ///
    /// The caller supplies one descriptive higher round, one inclusive local
    /// work ceiling, complete canonical proposal-control bytes, and the owned
    /// complete artifact payload. Success returns an inert caller-owned token
    /// and the unchanged scope. No separate catch-up certificate is accepted or
    /// inferred; an optional embedded valid-round proof remains proposal evidence.
    pub fn defer_higher_round_proposal(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        route: FixedValidatorNodeHigherRoundProposalRouteV0,
    ) -> Result<
        FixedValidatorNodeProposalDeferralOutcomeV0<'node>,
        FixedValidatorNodeProposalDeferralErrorV0,
    > {
        defer_higher_round_proposal(
            self,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            route,
        )
    }
}

fn defer_higher_round_proposal<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: Vec<u8>,
    route: FixedValidatorNodeHigherRoundProposalRouteV0,
) -> Result<
    FixedValidatorNodeProposalDeferralOutcomeV0<'node>,
    FixedValidatorNodeProposalDeferralErrorV0,
> {
    let proposal_round = match preflight_higher_round_proposal_route(&scope, route) {
        Ok(round) => round,
        Err(CurrentRoundErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
    };
    let proposal = match verify_deferred_proposal_at_round(
        &proposal_round,
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    ) {
        Ok(proposal) => proposal,
        Err(source) => {
            drop(proposal_round);
            return Ok(rejected(
                scope,
                FixedValidatorNodeProposalDeferralRejectionV0::Proposal(Box::new(source)),
            ));
        }
    };
    drop(proposal_round);

    Ok(FixedValidatorNodeProposalDeferralOutcomeV0::Deferred {
        scope: Box::new(scope),
        proposal,
    })
}

pub(super) fn preflight_deferred_proposal_control_framing(
    bytes: &[u8],
) -> Result<(), ConsensusProposalVerifyError> {
    if bytes.len() > VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH {
        return Err(ConsensusProposalVerifyError::InputTooLong {
            actual: bytes.len(),
            maximum: VerifiedFixedConsensusProposalV0::MAX_BYTE_LENGTH,
        });
    }
    if bytes.len() < VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH {
        return Err(ConsensusProposalVerifyError::InvalidLength {
            actual: bytes.len(),
            minimum: VerifiedFixedConsensusProposalV0::MIN_BYTE_LENGTH,
        });
    }

    let proof_tag = bytes[VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH - 1];
    match proof_tag {
        VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG
            if bytes.len() != VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH =>
        {
            Err(
                ConsensusProposalVerifyError::TrailingBytesWithoutValidRoundProof {
                    actual: bytes.len(),
                    expected: VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_BYTE_LENGTH,
                },
            )
        }
        VerifiedFixedConsensusProposalV0::NO_VALID_ROUND_PROOF_TAG
        | VerifiedFixedConsensusProposalV0::VALID_ROUND_PROOF_TAG => Ok(()),
        actual => Err(ConsensusProposalVerifyError::UnknownValidRoundProofTag { actual }),
    }
}

pub(super) fn verify_deferred_proposal_at_round(
    proposal_round: &FixedConsensusRoundV0<'_>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: Vec<u8>,
) -> Result<Box<FixedValidatorNodeDeferredProposalV0>, ConsensusProposalVerifyError> {
    let proposal = proposal_round.decode_and_verify_proposal_control(
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    )?;
    let parent_coordinate = proposal.parent_coordinate();
    let position = proposal.position();
    let value = proposal.value();
    let (canonical_proposal_control_bytes, canonical_artifact_bytes) =
        proposal.into_unverified_canonical_inputs();
    Ok(Box::new(FixedValidatorNodeDeferredProposalV0 {
        parent_coordinate,
        position,
        value,
        canonical_proposal_control_bytes: canonical_proposal_control_bytes.into_boxed_slice(),
        canonical_artifact_bytes: canonical_artifact_bytes.into_boxed_slice(),
    }))
}

pub(super) fn preflight_higher_round_proposal_route<'scope, 'node>(
    scope: &'scope FixedValidatorNodeSigningScopeV0<'node>,
    route: FixedValidatorNodeHigherRoundProposalRouteV0,
) -> Result<FixedConsensusRoundV0<'scope>, CurrentRoundErrorV0> {
    let finality_maximum_round = ConsensusRound::new(scope.finality.replay_limit().max_round());
    let current_round = current_round(
        &scope.branch,
        &scope.signing_session,
        route.inclusive_maximum_round(),
        finality_maximum_round.value(),
    )?;
    let current_position = current_round.position();
    let _ = successor_capacity(
        current_position.round(),
        route.inclusive_maximum_round(),
        finality_maximum_round,
    )?;
    if route.proposal_round() <= current_position.round() {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeProposalDeferralRejectionV0::NotHigherThanSigner {
                signer: current_position.round(),
                proposal: route.proposal_round(),
            },
        ));
    }
    if route.proposal_round() > finality_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeProposalDeferralRejectionV0::FinalityRoundLimitExceeded {
                required: route.proposal_round(),
                maximum: finality_maximum_round,
            },
        ));
    }
    if route.proposal_round() > route.inclusive_maximum_round() {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeProposalDeferralRejectionV0::RoundWorkLimitExceeded {
                required: route.proposal_round(),
                maximum: route.inclusive_maximum_round(),
            },
        ));
    }

    let mut proposal_round = current_round;
    for _ in current_position.round().value()..route.proposal_round().value() {
        proposal_round = proposal_round.advance_round().map_err(|source| {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalDeferralErrorV0::Round(source))
        })?;
    }
    debug_assert_eq!(proposal_round.position().round(), route.proposal_round());
    Ok(proposal_round)
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
            FixedValidatorNodeProposalDeferralErrorV0::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            },
        ),
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalDeferralErrorV0::Round(source))
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Fatal(
                FixedValidatorNodeProposalDeferralErrorV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Rejected(
                FixedValidatorNodeProposalDeferralRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            CurrentRoundErrorV0::Fatal(FixedValidatorNodeProposalDeferralErrorV0::Session(source))
        }
    })
}

fn successor_capacity(
    current: ConsensusRound,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: ConsensusRound,
) -> Result<ConsensusRound, CurrentRoundErrorV0> {
    let required = current
        .value()
        .checked_add(1)
        .map(ConsensusRound::new)
        .ok_or(CurrentRoundErrorV0::Fatal(
            FixedValidatorNodeProposalDeferralErrorV0::RoundExhausted { current },
        ))?;
    if required > finality_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeProposalDeferralRejectionV0::FinalityRoundLimitExceeded {
                required,
                maximum: finality_maximum_round,
            },
        ));
    }
    if required > inclusive_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeProposalDeferralRejectionV0::RoundWorkLimitExceeded {
                required,
                maximum: inclusive_maximum_round,
            },
        ));
    }
    Ok(required)
}

fn rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeProposalDeferralRejectionV0,
) -> FixedValidatorNodeProposalDeferralOutcomeV0<'node> {
    FixedValidatorNodeProposalDeferralOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}
