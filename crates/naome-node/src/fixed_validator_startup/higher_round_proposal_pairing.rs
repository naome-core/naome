use std::borrow::Cow;
use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;

use naome_consensus::{
    ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError, ConsensusRound,
    ConsensusVoteRole, ConsensusVoteTarget, FixedConsensusBranchCoordinateV0,
    FixedConsensusBranchV0, FixedConsensusRoundV0, FixedValidatorLockPhaseV0,
    FixedValidatorLockStateError, ProposalSigningRoot, ProposerSelectionError,
    QuorumCertificateBuildError,
};
use naome_storage::{
    FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0,
};

use super::higher_round_inbox::FixedValidatorNodeRetainedProposalPrevoteV0;
use super::voting::{FinishedVoteV0, FixedValidatorNodeVoteExecutionErrorV0, finish_vote};
use super::{
    FixedValidatorNodeCurrentRoundErrorV0, FixedValidatorNodeDeferredProposalV0,
    FixedValidatorNodeHigherRoundInboxAccessErrorV0, FixedValidatorNodeHigherRoundInboxV0,
    FixedValidatorNodeProposalBufferAccessErrorV0, FixedValidatorNodeProposalBufferV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorNodeVotingSessionV0,
    fixed_validator_node_current_round,
};

/// Result of exact buffered higher-round proposal and prevote-quorum pairing.
///
/// A signed result is released only after the higher-round checkpoint and the
/// matching precommit are independently anchored. It returns the exact removed
/// proposal token losslessly. Every rejection occurs before durable mutation
/// and returns unchanged signing authority; a signer stop or fatal error
/// returns no scope, while the leased proposal is restored to its buffer.
#[must_use]
#[non_exhaustive]
pub enum FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node> {
    /// The exact matching precommit completed and the paired token was removed.
    Signed {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        vote: FixedValidatorSignedVoteV0,
        proposal: Box<FixedValidatorNodeDeferredProposalV0>,
    },
    /// Exact buffer, capacity, proposal, or quorum input failed before mutation.
    Rejected {
        scope: Box<FixedValidatorNodeSigningScopeV0<'node>>,
        rejection: Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>,
    },
    /// A non-identical vote intent durably stopped the signer after catch-up.
    SignerStopped(FixedValidatorVoteSafetyHaltV0),
}

/// One no-effect rejection while pairing an exact buffered proposal.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeBufferedProposalPrecommitRejectionV0 {
    /// Saturation denied ordinary access to the proposal buffer.
    Buffer(FixedValidatorNodeProposalBufferAccessErrorV0),
    /// Saturation denied all ordinary access to a combined higher-round inbox.
    Inbox(FixedValidatorNodeHigherRoundInboxAccessErrorV0),
    /// No retained token matches both caller-supplied canonical byte strings.
    ProposalUnavailable,
    /// The caller-selected pairing height differs from the live signer height.
    PairingHeightMismatch {
        signer: ConsensusHeight,
        requested: ConsensusHeight,
    },
    /// No proposal-bearing root has strict greater-than-two-thirds prevote weight.
    NoActionableProposalQuorum { position: ConsensusPosition },
    /// More than one proposal-bearing root has an actionable prevote quorum.
    AmbiguousActionableProposalQuorums {
        position: ConsensusPosition,
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
    /// Temporary deterministic-selection storage could not be reserved.
    SelectionReservation(TryReserveError),
    /// Previously admitted retained prevotes failed exact quorum reconstruction.
    RetainedPrevoteInvariant(Box<QuorumCertificateBuildError>),
    /// The first possible or paired round exceeds persisted finality policy.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The first possible or paired round exceeds caller-local work policy.
    RoundWorkLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The retained proposal is not strictly above the live signer round.
    NotHigherThanSigner {
        signer: ConsensusRound,
        proposal: ConsensusRound,
    },
    /// The bounded temporary payload copy could not reserve memory.
    PayloadCopy(TryReserveError),
    /// Complete branch-relative proposal and artifact admission failed.
    Proposal(Box<ConsensusProposalVerifyError>),
    /// The complete exact signed-prevote batch did not form the proposal quorum.
    QuorumConstruction(Box<QuorumCertificateBuildError>),
    /// The exact higher-round prevote/proposal quorum did not match or verify.
    Quorum(Box<FixedValidatorLockStateError>),
}

impl fmt::Display for FixedValidatorNodeBufferedProposalPrecommitRejectionV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Buffer(source) => source.fmt(formatter),
            Self::Inbox(source) => source.fmt(formatter),
            Self::ProposalUnavailable => formatter
                .write_str("no buffered proposal matches both exact canonical input strings"),
            Self::PairingHeightMismatch { signer, requested } => write!(
                formatter,
                "caller-selected pairing height {requested:?} differs from signer height {signer:?}"
            ),
            Self::NoActionableProposalQuorum { position } => write!(
                formatter,
                "no uniquely pairable proposal prevote quorum is retained at {position:?}"
            ),
            Self::AmbiguousActionableProposalQuorums {
                position,
                first,
                second,
            } => write!(
                formatter,
                "multiple proposal prevote quorums are pairable at {position:?}: {first:?} and {second:?}"
            ),
            Self::SelectionReservation(source) => write!(
                formatter,
                "higher-round inbox selection reservation failed without mutation: {source}"
            ),
            Self::RetainedPrevoteInvariant(source) => write!(
                formatter,
                "retained proposal prevotes failed exact quorum reconstruction: {source}"
            ),
            Self::FinalityRoundLimitExceeded { required, maximum } => write!(
                formatter,
                "buffered proposal pairing requires {required:?}, above node finality ceiling {maximum:?}"
            ),
            Self::RoundWorkLimitExceeded { required, maximum } => write!(
                formatter,
                "buffered proposal pairing requires {required:?}, above caller-local ceiling {maximum:?}"
            ),
            Self::NotHigherThanSigner { signer, proposal } => write!(
                formatter,
                "buffered proposal round {proposal:?} is not higher than signer round {signer:?}"
            ),
            Self::PayloadCopy(source) => write!(
                formatter,
                "buffered proposal payload copy could not reserve memory: {source}"
            ),
            Self::Proposal(source) => {
                write!(formatter, "buffered proposal was rejected: {source}")
            }
            Self::QuorumConstruction(source) => write!(
                formatter,
                "buffered proposal prevote batch was rejected: {source}"
            ),
            Self::Quorum(source) => {
                write!(formatter, "buffered proposal quorum was rejected: {source}")
            }
        }
    }
}

impl Error for FixedValidatorNodeBufferedProposalPrecommitRejectionV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Buffer(source) => Some(source),
            Self::Inbox(source) => Some(source),
            Self::SelectionReservation(source) => Some(source),
            Self::RetainedPrevoteInvariant(source) => Some(source.as_ref()),
            Self::PayloadCopy(source) => Some(source),
            Self::Proposal(source) => Some(source.as_ref()),
            Self::QuorumConstruction(source) => Some(source.as_ref()),
            Self::Quorum(source) => Some(source.as_ref()),
            Self::ProposalUnavailable
            | Self::PairingHeightMismatch { .. }
            | Self::NoActionableProposalQuorum { .. }
            | Self::AmbiguousActionableProposalQuorums { .. }
            | Self::FinalityRoundLimitExceeded { .. }
            | Self::RoundWorkLimitExceeded { .. }
            | Self::NotHigherThanSigner { .. } => None,
        }
    }
}

/// A fatal node or signer failure during exact buffered-proposal pairing.
///
/// Every variant returns no signing scope. Once checkpoint preparation begins,
/// strict anchored restart is the sole signer-state classifier. The separately
/// borrowed proposal buffer nevertheless restores the exact leased token.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeBufferedProposalPrecommitErrorV0 {
    /// The node-owned signer and branch do not name the same next height.
    SignerBranchHeightMismatch {
        signer: ConsensusPosition,
        branch_next_height: ConsensusHeight,
    },
    /// An exact node-owned branch round could not be reconstructed.
    Round(ProposerSelectionError),
    /// The current round has no representable higher successor.
    RoundExhausted { current: ConsensusRound },
    /// The signer's current round exceeds persisted finality policy.
    FinalityRoundLimitExceeded {
        required: ConsensusRound,
        maximum: ConsensusRound,
    },
    /// The signing session was not operational before input admission.
    Session(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// An internal higher-round transition invariant failed before persistence.
    Transition(Box<FixedValidatorLockStateError>),
    /// The exact checkpoint could not complete durable preparation and anchoring.
    Prepare(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// The anchored checkpoint could not enter the same live signing session.
    Acknowledge(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Proposal admission unexpectedly changed after the durable checkpoint.
    PostCheckpointProposal(Box<ConsensusProposalVerifyError>),
    /// The matching precommit decision failed after the durable checkpoint.
    PostCheckpointDecision(Box<FixedValidatorLockStateError>),
    /// The signing session failed while deciding after the durable checkpoint.
    PostCheckpointSession(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    /// Durable preparation, key use, or completion of the precommit failed.
    Vote(Box<FixedValidatorNodeVoteExecutionErrorV0>),
}

impl fmt::Display for FixedValidatorNodeBufferedProposalPrecommitErrorV0 {
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
                "buffered-proposal pairing round could not be reconstructed: {source}"
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
                "buffered-proposal pairing session is not operational: {source}"
            ),
            Self::Transition(source) => write!(
                formatter,
                "buffered-proposal pairing invariant failed: {source}"
            ),
            Self::Prepare(source) => write!(
                formatter,
                "buffered-proposal higher-round checkpoint failed: {source}"
            ),
            Self::Acknowledge(source) => write!(
                formatter,
                "buffered-proposal checkpoint acknowledgement failed: {source}"
            ),
            Self::PostCheckpointProposal(source) => write!(
                formatter,
                "buffered proposal failed repeated admission after durable catch-up: {source}"
            ),
            Self::PostCheckpointDecision(source) => write!(
                formatter,
                "buffered proposal precommit decision failed after durable catch-up: {source}"
            ),
            Self::PostCheckpointSession(source) => write!(
                formatter,
                "buffered proposal signing session failed after durable catch-up: {source}"
            ),
            Self::Vote(source) => source.fmt(formatter),
        }
    }
}

impl Error for FixedValidatorNodeBufferedProposalPrecommitErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Round(source) => Some(source),
            Self::Session(source)
            | Self::Prepare(source)
            | Self::Acknowledge(source)
            | Self::PostCheckpointSession(source) => Some(source.as_ref()),
            Self::Transition(source) | Self::PostCheckpointDecision(source) => {
                Some(source.as_ref())
            }
            Self::PostCheckpointProposal(source) => Some(source.as_ref()),
            Self::Vote(source) => Some(source.as_ref()),
            Self::SignerBranchHeightMismatch { .. }
            | Self::RoundExhausted { .. }
            | Self::FinalityRoundLimitExceeded { .. } => None,
        }
    }
}

enum CurrentRoundErrorV0 {
    Rejected(FixedValidatorNodeBufferedProposalPrecommitRejectionV0),
    Fatal(FixedValidatorNodeBufferedProposalPrecommitErrorV0),
}

enum BufferedProposalPrevoteQuorumInputV0<'input> {
    CanonicalCertificate(&'input [u8]),
    ExactSignedVotes(&'input [&'input [u8]]),
}

impl<'node> FixedValidatorNodeSigningScopeV0<'node> {
    /// Pairs one exact buffered higher-round proposal with its prevote quorum.
    ///
    /// The buffer must be healthy and the caller must address one entry by both
    /// exact canonical byte strings. Complete proposal admission and an exact
    /// same-position `Prevote/Proposal(root)` quorum are checked before the
    /// signer durably catches up to `P/Prevote`. The proposal is then admitted
    /// again at that live position before the existing anchored precommit path
    /// runs. Only a completed signed precommit removes and losslessly returns
    /// the exact token; every other path restores it.
    ///
    /// This synchronous composition does not discover or select a proposal or
    /// certificate and grants no finality, rollback, timeout, event-routing,
    /// networking, peer-trust, daemon, or restart-buffer authority.
    pub fn sign_precommit_for_buffered_higher_round_proposal_quorum(
        self,
        proposals: &mut FixedValidatorNodeProposalBufferV0,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: &[u8],
        canonical_prevote_certificate: &[u8],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node>,
        FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    > {
        sign_precommit_for_buffered_higher_round_proposal_input(
            self,
            proposals,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            BufferedProposalPrevoteQuorumInputV0::CanonicalCertificate(
                canonical_prevote_certificate,
            ),
            inclusive_maximum_round,
        )
    }

    /// Pairs one exact buffered proposal with a complete signed-prevote batch.
    ///
    /// After the same node and buffer preflight plus complete proposal
    /// re-admission as the prebuilt-certificate sibling, every supplied vote is
    /// authenticated all-or-nothing against the proposal's derived exact round,
    /// `Prevote` role, and `Proposal(root)` target. Only the resulting canonical
    /// certificate enters the unchanged anchored catch-up and precommit path.
    /// Rejection restores the exact leased token; success returns one completed
    /// signed precommit without finalizing it. The batch is never observed,
    /// filtered, retained, grouped, or selected.
    pub fn sign_precommit_for_buffered_higher_round_proposal_vote_batch(
        self,
        proposals: &mut FixedValidatorNodeProposalBufferV0,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: &[u8],
        canonical_signed_prevotes: &[&[u8]],
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node>,
        FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    > {
        sign_precommit_for_buffered_higher_round_proposal_input(
            self,
            proposals,
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            BufferedProposalPrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes),
            inclusive_maximum_round,
        )
    }

    /// Explicitly pairs one uniquely actionable proposal/prevote inbox root.
    ///
    /// The caller selects the exact position and work ceiling. This operation
    /// inspects only the complete currently retained, unsaturated inbox subset
    /// admitted against this branch and position. It selects the
    /// lexicographically smallest complete canonical vote per signer and target,
    /// counts each active signer once for that target, and proceeds only when
    /// exactly one proposal-bearing target forms a strict supermajority. It then
    /// selects the lexicographically smallest `(proposal control, artifact)`
    /// variant for that root and reuses the existing fully verifying anchored
    /// precommit path.
    ///
    /// Zero or multiple actionable roots leave the scope and inbox unchanged.
    /// Success removes only the selected proposal token after the signed
    /// precommit completes; all retained votes and every sibling proposal remain.
    /// This explicit local choice is not automatic event routing, globally
    /// canonical evidence selection, finality, fork choice, or peer authority.
    pub fn try_pair_higher_round_inbox_at(
        self,
        inbox: &mut FixedValidatorNodeHigherRoundInboxV0,
        position: ConsensusPosition,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node>,
        FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    > {
        let finality_maximum_round = ConsensusRound::new(self.finality.replay_limit().max_round());
        let current_round = match current_round(
            &self.branch,
            &self.signing_session,
            inclusive_maximum_round,
            finality_maximum_round.value(),
        ) {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(rejected(self, rejection));
            }
            Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
        };
        let current_position = current_round.position();
        if let Err(error) = successor_capacity(
            current_position.round(),
            inclusive_maximum_round,
            finality_maximum_round,
        ) {
            drop(current_round);
            return match error {
                CurrentRoundErrorV0::Rejected(rejection) => Ok(rejected(self, rejection)),
                CurrentRoundErrorV0::Fatal(error) => Err(error),
            };
        }
        if position.height() != current_position.height() {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::PairingHeightMismatch {
                    signer: current_position.height(),
                    requested: position.height(),
                },
            ));
        }
        if position.round() <= current_position.round() {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::NotHigherThanSigner {
                    signer: current_position.round(),
                    proposal: position.round(),
                },
            ));
        }
        if position.round() > finality_maximum_round {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::FinalityRoundLimitExceeded {
                    required: position.round(),
                    maximum: finality_maximum_round,
                },
            ));
        }
        if position.round() > inclusive_maximum_round {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RoundWorkLimitExceeded {
                    required: position.round(),
                    maximum: inclusive_maximum_round,
                },
            ));
        }
        if let Err(source) = inbox.ensure_access() {
            drop(current_round);
            return Ok(rejected(
                self,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Inbox(source),
            ));
        }

        let parent_coordinate = self.branch.coordinate();
        let target_round = derive_round(&self.branch, position.round())
            .map_err(FixedValidatorNodeBufferedProposalPrecommitErrorV0::Round)?;
        let selection =
            match select_actionable_inbox_root(inbox, &target_round, parent_coordinate, position) {
                Ok(selection) => selection,
                Err(rejection) => {
                    drop(target_round);
                    drop(current_round);
                    return Ok(rejected(self, rejection));
                }
            };
        drop(target_round);
        drop(current_round);

        let (proposal_signing_root, canonical_prevote_certificate) = match selection {
            ActionableInboxSelectionV0::None => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeBufferedProposalPrecommitRejectionV0::NoActionableProposalQuorum {
                        position,
                    },
                ));
            }
            ActionableInboxSelectionV0::Ambiguous { first, second } => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeBufferedProposalPrecommitRejectionV0::AmbiguousActionableProposalQuorums {
                        position,
                        first,
                        second,
                    },
                ));
            }
            ActionableInboxSelectionV0::One {
                proposal_signing_root,
                canonical_prevote_certificate,
            } => (proposal_signing_root, canonical_prevote_certificate),
        };

        let (control, artifact, selected_proposal_bytes) = inbox
            .proposals
            .preferred_proposal_inputs(parent_coordinate, position, proposal_signing_root)
            .expect("one actionable inbox root retains a matching proposal");
        let canonical_proposal_control_bytes = match try_copy_bytes(control) {
            Ok(bytes) => bytes,
            Err(source) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation(
                        source,
                    ),
                ));
            }
        };
        let canonical_artifact_bytes = match try_copy_bytes(artifact) {
            Ok(bytes) => bytes,
            Err(source) => {
                return Ok(rejected(
                    self,
                    FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation(
                        source,
                    ),
                ));
            }
        };

        let outcome = self.sign_precommit_for_buffered_higher_round_proposal_quorum(
            &mut inbox.proposals,
            &canonical_proposal_control_bytes,
            &canonical_artifact_bytes,
            &canonical_prevote_certificate,
            inclusive_maximum_round,
        );
        if matches!(
            &outcome,
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Signed { .. })
        ) {
            inbox.note_selected_proposal_removed(selected_proposal_bytes);
        }
        outcome
    }
}

pub(super) enum ActionableInboxSelectionV0 {
    None,
    One {
        proposal_signing_root: ProposalSigningRoot,
        canonical_prevote_certificate: Vec<u8>,
    },
    Ambiguous {
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
}

pub(super) struct ActionableInboxSnapshotV0<'inbox> {
    votes: Vec<&'inbox FixedValidatorNodeRetainedProposalPrevoteV0>,
    proposal_identities: Vec<(ConsensusPosition, ProposalSigningRoot)>,
}

impl<'inbox> ActionableInboxSnapshotV0<'inbox> {
    pub(super) fn try_new(
        inbox: &'inbox FixedValidatorNodeHigherRoundInboxV0,
        parent_coordinate: FixedConsensusBranchCoordinateV0,
    ) -> Result<Self, FixedValidatorNodeBufferedProposalPrecommitRejectionV0> {
        let mut votes = Vec::new();
        votes.try_reserve_exact(inbox.prevote_len()).map_err(
            FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation,
        )?;
        votes.extend(
            inbox
                .prevotes
                .iter()
                .filter(|vote| vote.parent_coordinate() == parent_coordinate),
        );
        votes.sort_unstable_by(|left, right| {
            left.position()
                .cmp(&right.position())
                .then_with(|| {
                    left.proposal_signing_root()
                        .cmp(&right.proposal_signing_root())
                })
                .then_with(|| left.signer().cmp(&right.signer()))
                .then_with(|| left.canonical_bytes().cmp(right.canonical_bytes()))
        });

        let mut proposal_identities = Vec::new();
        proposal_identities
            .try_reserve_exact(inbox.proposal_len())
            .map_err(
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation,
            )?;
        proposal_identities.extend(inbox.proposals.retained_identities().filter_map(
            |(retained_parent, position, root)| {
                (retained_parent == parent_coordinate).then_some((position, root))
            },
        ));
        proposal_identities.sort_unstable();
        proposal_identities.dedup();

        Ok(Self {
            votes,
            proposal_identities,
        })
    }

    pub(super) fn select_position(
        &self,
        target_round: &FixedConsensusRoundV0<'_>,
        position: ConsensusPosition,
    ) -> Result<ActionableInboxSelectionV0, FixedValidatorNodeBufferedProposalPrecommitRejectionV0>
    {
        let start = self
            .votes
            .partition_point(|vote| vote.position() < position);
        let end = self
            .votes
            .partition_point(|vote| vote.position() <= position);
        select_actionable_sorted_inbox_root(&self.votes[start..end], target_round, |root| {
            self.proposal_identities
                .binary_search(&(position, root))
                .is_ok()
        })
    }
}

pub(super) fn select_actionable_inbox_root(
    inbox: &FixedValidatorNodeHigherRoundInboxV0,
    target_round: &FixedConsensusRoundV0<'_>,
    parent_coordinate: FixedConsensusBranchCoordinateV0,
    position: ConsensusPosition,
) -> Result<ActionableInboxSelectionV0, FixedValidatorNodeBufferedProposalPrecommitRejectionV0> {
    let mut candidates: Vec<&FixedValidatorNodeRetainedProposalPrevoteV0> = Vec::new();
    candidates
        .try_reserve_exact(inbox.prevotes.len())
        .map_err(FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation)?;
    candidates.extend(inbox.prevotes.iter().filter(|vote| {
        vote.parent_coordinate() == parent_coordinate && vote.position() == position
    }));
    candidates.sort_unstable_by(|left, right| {
        left.proposal_signing_root()
            .cmp(&right.proposal_signing_root())
            .then_with(|| left.signer().cmp(&right.signer()))
            .then_with(|| left.canonical_bytes().cmp(right.canonical_bytes()))
    });

    let mut proposal_roots = Vec::new();
    proposal_roots
        .try_reserve_exact(inbox.proposal_len())
        .map_err(FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation)?;
    proposal_roots.extend(inbox.proposals.retained_identities().filter_map(
        |(retained_parent, retained_position, root)| {
            (retained_parent == parent_coordinate && retained_position == position).then_some(root)
        },
    ));
    proposal_roots.sort_unstable();
    proposal_roots.dedup();

    select_actionable_sorted_inbox_root(&candidates, target_round, |root| {
        proposal_roots.binary_search(&root).is_ok()
    })
}

fn select_actionable_sorted_inbox_root(
    candidates: &[&FixedValidatorNodeRetainedProposalPrevoteV0],
    target_round: &FixedConsensusRoundV0<'_>,
    mut has_matching_proposal: impl FnMut(ProposalSigningRoot) -> bool,
) -> Result<ActionableInboxSelectionV0, FixedValidatorNodeBufferedProposalPrecommitRejectionV0> {
    let mut actionable: Option<(ProposalSigningRoot, Vec<u8>)> = None;
    let mut start = 0;
    while start < candidates.len() {
        let root = candidates[start].proposal_signing_root();
        let mut end = start + 1;
        while end < candidates.len() && candidates[end].proposal_signing_root() == root {
            end += 1;
        }
        if has_matching_proposal(root) {
            let mut preferred_votes: Vec<&[u8]> = Vec::new();
            preferred_votes.try_reserve_exact(end - start).map_err(
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::SelectionReservation,
            )?;
            let mut previous_signer = None;
            for vote in &candidates[start..end] {
                if previous_signer == Some(vote.signer()) {
                    continue;
                }
                previous_signer = Some(vote.signer());
                preferred_votes.push(vote.canonical_bytes());
            }
            match target_round.build_quorum_certificate_from_signed_votes(
                &preferred_votes,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(root),
            ) {
                Ok(certificate) => {
                    if let Some((first, _)) = actionable {
                        return Ok(ActionableInboxSelectionV0::Ambiguous {
                            first,
                            second: root,
                        });
                    }
                    actionable = Some((root, certificate.to_canonical_bytes()));
                }
                Err(QuorumCertificateBuildError::InsufficientAgreementWeight { .. }) => {}
                Err(source) => {
                    return Err(
                        FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RetainedPrevoteInvariant(
                            Box::new(source),
                        ),
                    );
                }
            }
        }
        start = end;
    }

    Ok(match actionable {
        Some((proposal_signing_root, canonical_prevote_certificate)) => {
            ActionableInboxSelectionV0::One {
                proposal_signing_root,
                canonical_prevote_certificate,
            }
        }
        None => ActionableInboxSelectionV0::None,
    })
}

fn sign_precommit_for_buffered_higher_round_proposal_input<'node>(
    mut scope: FixedValidatorNodeSigningScopeV0<'node>,
    proposals: &mut FixedValidatorNodeProposalBufferV0,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: &[u8],
    quorum: BufferedProposalPrevoteQuorumInputV0<'_>,
    inclusive_maximum_round: ConsensusRound,
) -> Result<
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node>,
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
> {
    let finality_maximum_round = ConsensusRound::new(scope.finality.replay_limit().max_round());
    let current_round = match current_round(
        &scope.branch,
        &scope.signing_session,
        inclusive_maximum_round,
        finality_maximum_round.value(),
    ) {
        Ok(round) => round,
        Err(CurrentRoundErrorV0::Rejected(rejection)) => {
            return Ok(rejected(scope, rejection));
        }
        Err(CurrentRoundErrorV0::Fatal(error)) => return Err(error),
    };
    let current_position = current_round.position();
    if let Err(error) = successor_capacity(
        current_position.round(),
        inclusive_maximum_round,
        finality_maximum_round,
    ) {
        drop(current_round);
        return match error {
            CurrentRoundErrorV0::Rejected(rejection) => Ok(rejected(scope, rejection)),
            CurrentRoundErrorV0::Fatal(error) => Err(error),
        };
    }

    let lease = match proposals
        .take_exact_lease(canonical_proposal_control_bytes, canonical_artifact_bytes)
    {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            drop(current_round);
            return Ok(rejected(
                scope,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::ProposalUnavailable,
            ));
        }
        Err(source) => {
            drop(current_round);
            return Ok(rejected(
                scope,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Buffer(source),
            ));
        }
    };
    let proposal_position = lease.proposal().position();
    let proposal_round = proposal_position.round();
    if proposal_round <= current_position.round() {
        drop(current_round);
        drop(lease);
        return Ok(rejected(
            scope,
            FixedValidatorNodeBufferedProposalPrecommitRejectionV0::NotHigherThanSigner {
                signer: current_position.round(),
                proposal: proposal_round,
            },
        ));
    }
    if proposal_round > finality_maximum_round {
        drop(current_round);
        drop(lease);
        return Ok(rejected(
            scope,
            FixedValidatorNodeBufferedProposalPrecommitRejectionV0::FinalityRoundLimitExceeded {
                required: proposal_round,
                maximum: finality_maximum_round,
            },
        ));
    }
    if proposal_round > inclusive_maximum_round {
        drop(current_round);
        drop(lease);
        return Ok(rejected(
            scope,
            FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RoundWorkLimitExceeded {
                required: proposal_round,
                maximum: inclusive_maximum_round,
            },
        ));
    }

    let copied_payload = match try_copy_bytes(lease.proposal().canonical_artifact_bytes()) {
        Ok(bytes) => bytes,
        Err(source) => {
            drop(current_round);
            drop(lease);
            return Ok(rejected(
                scope,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::PayloadCopy(source),
            ));
        }
    };
    let target_round = derive_round(&scope.branch, proposal_round)
        .map_err(FixedValidatorNodeBufferedProposalPrecommitErrorV0::Round)?;
    let admitted = match target_round.decode_and_verify_proposal_control(
        lease.proposal().canonical_proposal_control_bytes(),
        copied_payload,
    ) {
        Ok(proposal) => proposal,
        Err(source) => {
            drop(target_round);
            drop(current_round);
            drop(lease);
            return Ok(rejected(
                scope,
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Proposal(Box::new(source)),
            ));
        }
    };
    debug_assert_eq!(admitted.position(), proposal_position);
    debug_assert_eq!(
        admitted.proposal_signing_root(),
        lease.proposal().proposal_signing_root()
    );
    let proposal_root = admitted.proposal_signing_root();
    let (reverified_control, reverified_payload) = admitted.into_unverified_canonical_inputs();
    let canonical_prevote_certificate: Cow<'_, [u8]> = match quorum {
        BufferedProposalPrevoteQuorumInputV0::CanonicalCertificate(bytes) => Cow::Borrowed(bytes),
        BufferedProposalPrevoteQuorumInputV0::ExactSignedVotes(canonical_signed_prevotes) => {
            let certificate = match target_round.build_quorum_certificate_from_signed_votes(
                canonical_signed_prevotes,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Proposal(proposal_root),
            ) {
                Ok(certificate) => certificate,
                Err(source) => {
                    drop(target_round);
                    drop(current_round);
                    drop(lease);
                    return Ok(rejected(
                        scope,
                        FixedValidatorNodeBufferedProposalPrecommitRejectionV0::QuorumConstruction(
                            Box::new(source),
                        ),
                    ));
                }
            };
            Cow::Owned(certificate.to_canonical_bytes())
        }
    };

    let effective_maximum = ConsensusRound::new(
        inclusive_maximum_round
            .value()
            .min(finality_maximum_round.value()),
    );
    let prepared = match scope
        .signing_session
        .prepare_higher_round_proposal_prevote_advance(
            &current_round,
            canonical_prevote_certificate.as_ref(),
            proposal_position,
            proposal_root,
            effective_maximum,
        ) {
        Ok(prepared) => prepared,
        Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
            drop(target_round);
            drop(current_round);
            drop(lease);
            return match classify_quorum_rejection(
                source,
                inclusive_maximum_round,
                finality_maximum_round,
            ) {
                Ok(rejection) => Ok(rejected(scope, rejection)),
                Err(error) => Err(error),
            };
        }
        Err(source) => {
            return Err(FixedValidatorNodeBufferedProposalPrecommitErrorV0::Prepare(
                Box::new(source),
            ));
        }
    };
    let advanced = scope
        .signing_session
        .acknowledge_prepared_higher_round(prepared)
        .map_err(|source| {
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::Acknowledge(Box::new(source))
        })?;
    debug_assert_eq!(advanced.position(), proposal_position);
    debug_assert_eq!(
        scope.signing_session.phase(),
        FixedValidatorLockPhaseV0::Prevote
    );
    drop(advanced);

    let admitted = target_round
        .decode_and_verify_proposal_control(&reverified_control, reverified_payload)
        .map_err(|source| {
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::PostCheckpointProposal(Box::new(
                source,
            ))
        })?;
    let effect = match scope.signing_session.decide_precommit_for_proposal_quorum(
        &target_round,
        &admitted,
        canonical_prevote_certificate.as_ref(),
    ) {
        Ok(effect) => effect,
        Err(FixedValidatorVoteSafetyJournalErrorV0::LockState(source)) => {
            return Err(
                FixedValidatorNodeBufferedProposalPrecommitErrorV0::PostCheckpointDecision(
                    Box::new(source),
                ),
            );
        }
        Err(source) => {
            return Err(
                FixedValidatorNodeBufferedProposalPrecommitErrorV0::PostCheckpointSession(
                    Box::new(source),
                ),
            );
        }
    };
    let finished =
        finish_vote(&mut scope.signing_session, &target_round, effect).map_err(|source| {
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::Vote(Box::new(source))
        })?;
    drop(admitted);
    drop(target_round);
    drop(current_round);

    match finished {
        FinishedVoteV0::Signed(vote) => {
            let proposal = lease.release();
            Ok(
                FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Signed {
                    scope: Box::new(scope),
                    vote,
                    proposal,
                },
            )
        }
        FinishedVoteV0::SignerStopped(halt) => {
            drop(lease);
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::SignerStopped(halt))
        }
    }
}

fn try_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, TryReserveError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len())?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}

fn derive_round(
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
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::SignerBranchHeightMismatch {
                signer,
                branch_next_height,
            },
        ),
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => CurrentRoundErrorV0::Fatal(
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::Round(source),
        ),
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Fatal(
                FixedValidatorNodeBufferedProposalPrecommitErrorV0::FinalityRoundLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            CurrentRoundErrorV0::Rejected(
                FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RoundWorkLimitExceeded {
                    required,
                    maximum,
                },
            )
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => CurrentRoundErrorV0::Fatal(
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::Session(source),
        ),
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
            FixedValidatorNodeBufferedProposalPrecommitErrorV0::RoundExhausted { current },
        ))?;
    if required > finality_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeBufferedProposalPrecommitRejectionV0::FinalityRoundLimitExceeded {
                required,
                maximum: finality_maximum_round,
            },
        ));
    }
    if required > inclusive_maximum_round {
        return Err(CurrentRoundErrorV0::Rejected(
            FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RoundWorkLimitExceeded {
                required,
                maximum: inclusive_maximum_round,
            },
        ));
    }
    Ok(required)
}

fn classify_quorum_rejection(
    source: FixedValidatorLockStateError,
    inclusive_maximum_round: ConsensusRound,
    finality_maximum_round: ConsensusRound,
) -> Result<
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0,
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
> {
    match source {
        FixedValidatorLockStateError::HigherRoundLimitExceeded { round, .. } => {
            if round > finality_maximum_round {
                Ok(FixedValidatorNodeBufferedProposalPrecommitRejectionV0::FinalityRoundLimitExceeded {
                    required: round,
                    maximum: finality_maximum_round,
                })
            } else {
                Ok(FixedValidatorNodeBufferedProposalPrecommitRejectionV0::RoundWorkLimitExceeded {
                    required: round,
                    maximum: inclusive_maximum_round,
                })
            }
        }
        FixedValidatorLockStateError::HigherRoundCertificatePosition(_)
        | FixedValidatorLockStateError::HigherRoundHeightMismatch { .. }
        | FixedValidatorLockStateError::HigherRoundNotStrictlyGreater { .. }
        | FixedValidatorLockStateError::HigherRoundQuorumPositionMismatch { .. }
        | FixedValidatorLockStateError::HigherRoundQuorumRoleMismatch { .. }
        | FixedValidatorLockStateError::HigherRoundQuorumTargetMismatch { .. }
        | FixedValidatorLockStateError::QuorumVerification(_) => {
            Ok(FixedValidatorNodeBufferedProposalPrecommitRejectionV0::Quorum(Box::new(source)))
        }
        _ => Err(FixedValidatorNodeBufferedProposalPrecommitErrorV0::Transition(Box::new(source))),
    }
}

fn rejected<'node>(
    scope: FixedValidatorNodeSigningScopeV0<'node>,
    rejection: FixedValidatorNodeBufferedProposalPrecommitRejectionV0,
) -> FixedValidatorNodeBufferedProposalPrecommitOutcomeV0<'node> {
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Rejected {
        scope: Box::new(scope),
        rejection: Box::new(rejection),
    }
}
