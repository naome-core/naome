use crate::fixed_validator::round_context::derive_round;

use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use naome_consensus::{
    ConsensusContextV0, ConsensusHeight, ConsensusPosition, ConsensusProposalVerifyError,
    ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget, ConsensusVoteVerifyError,
    FixedConsensusNilPrecommitVerifyErrorV0, FixedConsensusNilPrevoteVerifyErrorV0,
    FixedConsensusProposalPrecommitVerifyErrorV0, FixedConsensusProposalPrevoteVerifyErrorV0,
    FixedConsensusRoundV0, FixedValidatorLockPhaseV0, FixedValidatorProposalSourceV0,
    ProposalSigningRoot, ProposerSelectionError, QuorumCertificateBuildError,
    VerifiedConsensusVoteV0,
};
use naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES;
use naome_storage::{
    ArtifactBlockCandidateStore, CanonicalArtifactPayloadStore, FixedValidatorProposalSafetyHaltV0,
    FixedValidatorSignedProposalV0, FixedValidatorSignedVoteV0, FixedValidatorVoteSafetyHaltV0,
    FixedValidatorVoteSafetyJournalErrorV0, SelectedArtifactHistory,
};

use super::current_round_finality_inbox::{
    CurrentRoundFinalityClassificationErrorV0, CurrentRoundFinalityClassificationV0,
    CurrentRoundFinalityInboxInsertOutcomeV0, CurrentRoundFinalityInboxV0,
    CurrentRoundFinalityPreclassificationV0, CurrentRoundFinalityPrecommitInsertErrorV0,
    CurrentRoundFinalityProposalInsertErrorV0,
};
use super::current_round_inbox::{
    CurrentRoundInboxInsertOutcomeV0, CurrentRoundInboxV0, CurrentRoundNilPrevoteInsertErrorV0,
    CurrentRoundPrevoteInsertErrorV0, CurrentRoundProposalInsertErrorV0,
    CurrentRoundProposalSelectionV0, CurrentRoundQuorumSelectionErrorV0,
    CurrentRoundQuorumSelectionV0,
};
use super::current_round_nil_precommit_inbox::{
    CurrentRoundNilPrecommitInboxInsertOutcomeV0, CurrentRoundNilPrecommitInboxV0,
    CurrentRoundNilPrecommitInsertErrorV0, CurrentRoundNilPrecommitPreclassificationV0,
    CurrentRoundNilPrecommitQuorumSelectionErrorV0, CurrentRoundNilPrecommitQuorumSelectionV0,
};
use super::higher_round_proposal_pairing::{ActionableInboxSelectionV0, ActionableInboxSnapshotV0};
use super::proposal_authoring::NodeProposalInputV0;
use super::proposal_deferral::{
    CurrentRoundErrorV0, preflight_deferred_proposal_control_framing,
    preflight_higher_round_proposal_route, verify_deferred_proposal_at_round,
};
use super::voting::{CurrentRoundErrorV0 as VotingCurrentRoundErrorV0, current_round};
use super::{
    FixedValidatorNodeBufferedProposalPrecommitErrorV0,
    FixedValidatorNodeBufferedProposalPrecommitOutcomeV0,
    FixedValidatorNodeBufferedProposalPrecommitRejectionV0,
    FixedValidatorNodeCandidateBackedFinalityErrorV0,
    FixedValidatorNodeCandidateBackedFinalityOutcomeV0,
    FixedValidatorNodeCandidateBackedFinalityRejectionV0, FixedValidatorNodeCurrentRoundErrorV0,
    FixedValidatorNodeCurrentRoundFinalityErrorV0,
    FixedValidatorNodeCurrentRoundFinalityInboxDrainV0,
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    FixedValidatorNodeCurrentRoundFinalityOutcomeV0,
    FixedValidatorNodeCurrentRoundFinalityRejectionV0, FixedValidatorNodeCurrentRoundInboxDrainV0,
    FixedValidatorNodeCurrentRoundInboxLimitsV0, FixedValidatorNodeCurrentRoundInboxSaturationV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxDrainV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxSaturationV0,
    FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeDeferredProposalV0, FixedValidatorNodeFinalityErrorV0,
    FixedValidatorNodeFinalityOutcomeV0, FixedValidatorNodeFinalityRoundRouteV0,
    FixedValidatorNodeFinalitySelectionV0, FixedValidatorNodeFinalityStoppedV0,
    FixedValidatorNodeHigherRoundInboxDrainV0, FixedValidatorNodeHigherRoundInboxLimitsV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertErrorV0,
    FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0,
    FixedValidatorNodeHigherRoundInboxSaturationV0, FixedValidatorNodeHigherRoundInboxV0,
    FixedValidatorNodeHigherRoundProposalRouteV0, FixedValidatorNodeHigherRoundVoteBatchRouteV0,
    FixedValidatorNodeLowerRoundFinalityErrorV0, FixedValidatorNodeLowerRoundFinalityOutcomeV0,
    FixedValidatorNodeLowerRoundFinalityRejectionV0,
    FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0,
    FixedValidatorNodeLowerRoundPreselectionConflictRejectionV0,
    FixedValidatorNodeProposalAuthoringErrorV0, FixedValidatorNodeProposalAuthoringOutcomeV0,
    FixedValidatorNodeProposalAuthoringRejectionV0, FixedValidatorNodeProposalDeferralErrorV0,
    FixedValidatorNodeProposalDeferralRejectionV0, FixedValidatorNodeRoundAdvanceErrorV0,
    FixedValidatorNodeRoundAdvanceOutcomeV0, FixedValidatorNodeRoundAdvanceRejectionV0,
    FixedValidatorNodeSigningScopeV0, FixedValidatorNodeVoteExecutionErrorV0,
    FixedValidatorNodeVoteExecutionOutcomeV0, FixedValidatorNodeVoteRejectionV0,
    fixed_validator_node_current_round,
};

mod admission;
mod classification;
mod execution;
mod explicit;
mod types;

use classification::*;
pub use types::*;

static NEXT_DRIVER_LINEAGE: AtomicU64 = AtomicU64::new(1);

enum DriverHigherRoundInputV0<'input> {
    Certificate(&'input [u8]),
    VoteBatch {
        canonical_signed_votes: &'input [&'input [u8]],
        evidence_round: ConsensusRound,
        expected_role: ConsensusVoteRole,
        expected_target: ConsensusVoteTarget,
    },
}

enum PendingCommandV0 {
    PublishProposal {
        proposal: FixedValidatorSignedProposalV0,
        canonical_artifact_bytes: Vec<u8>,
    },
    Arm(FixedValidatorNodePhaseTimeoutV0),
    Publish {
        vote: FixedValidatorSignedVoteV0,
        released_proposal: Option<Box<FixedValidatorNodeDeferredProposalV0>>,
        successor_generation: u64,
    },
}

/// One non-clone, closure-scoped fixed-validator event driver.
///
/// The driver privately owns the sole live signing scope. It exposes neither a
/// mutable nor consuming escape hatch back to that scope. Its ordinary actions
/// remain selected only by [`Self::step`]. Separate explicit methods submit
/// candidate-backed direct-child or historical-conflict evidence and complete
/// strictly lower-round conflict pairs after pending command custody transfers.
/// Explicit proposal authoring waits for ordinary step work, then queues the
/// completed proposal and exact payload without local admission or timer change.
/// Its only authority projection is the sealed
/// read-only selected artifact history required by caller-owned acquisition.
/// Evidence and due timers become authoritative only through the existing fully
/// checking consuming coordinators.
#[must_use]
pub struct FixedValidatorNodeDriverV0<'node> {
    scope: Option<FixedValidatorNodeSigningScopeV0<'node>>,
    inbox: FixedValidatorNodeHigherRoundInboxV0,
    current_inbox: CurrentRoundInboxV0,
    current_finality_inbox: CurrentRoundFinalityInboxV0,
    current_nil_precommit_inbox: CurrentRoundNilPrecommitInboxV0,
    inclusive_maximum_round: ConsensusRound,
    lineage: u64,
    generation: u64,
    active_timeout: Option<FixedValidatorNodePhaseTimeoutV0>,
    due: bool,
    ambiguity: Option<FixedValidatorNodeDriverBlockReasonV0>,
    current_ambiguity: Option<FixedValidatorNodeDriverBlockReasonV0>,
    pending_command: Option<PendingCommandV0>,
}

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Consumes the sole live scope and prepares this phase's first arm command.
    ///
    /// Every construction error also consumes the supplied scope without
    /// returning it. Recovery then requires the existing strict-reopen path.
    pub fn new(
        scope: FixedValidatorNodeSigningScopeV0<'node>,
        inbox_limits: FixedValidatorNodeHigherRoundInboxLimitsV0,
        current_inbox_limits: FixedValidatorNodeCurrentRoundInboxLimitsV0,
        current_finality_inbox_limits: FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
        current_nil_precommit_inbox_limits: FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
        inclusive_maximum_round: ConsensusRound,
    ) -> Result<Self, FixedValidatorNodeDriverCreateErrorV0> {
        let finality_maximum_round = scope.finality.replay_limit().max_round();
        let round = fixed_validator_node_current_round(
            &scope.branch,
            &scope.signing_session,
            inclusive_maximum_round,
            finality_maximum_round,
        )
        .map_err(map_create_error)?;
        let context = round.context();
        let position = round.position();
        let phase = scope.signing_session.phase();
        drop(round);
        let lineage = NEXT_DRIVER_LINEAGE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |lineage| {
                lineage.checked_add(1)
            })
            .map_err(|_| FixedValidatorNodeDriverCreateErrorV0::ProcessLineageExhausted)?;
        let active_timeout = FixedValidatorNodePhaseTimeoutV0 {
            lineage,
            context,
            position,
            phase,
            generation: 0,
        };
        Ok(Self {
            scope: Some(scope),
            inbox: FixedValidatorNodeHigherRoundInboxV0::new(inbox_limits),
            current_inbox: CurrentRoundInboxV0::new(current_inbox_limits),
            current_finality_inbox: CurrentRoundFinalityInboxV0::new(current_finality_inbox_limits),
            current_nil_precommit_inbox: CurrentRoundNilPrecommitInboxV0::new(
                current_nil_precommit_inbox_limits,
            ),
            inclusive_maximum_round,
            lineage,
            generation: 0,
            active_timeout: Some(active_timeout),
            due: false,
            ambiguity: None,
            current_ambiguity: None,
            pending_command: Some(PendingCommandV0::Arm(active_timeout)),
        })
    }

    /// Returns the exact live signer position as read-only diagnostics.
    pub fn position(&self) -> ConsensusPosition {
        self.scope().signing_session.position()
    }

    /// Returns the exact driver-owned context without exposing its signing scope.
    pub fn context(&self) -> ConsensusContextV0 {
        self.scope().branch.context()
    }

    /// Borrows the identity of the currently issued timer, if one is active.
    ///
    /// This diagnostic does not transfer a pending arm command, prove elapsed
    /// time, clear an existing due fence, or authorize a transition by itself.
    pub const fn active_timeout(&self) -> Option<FixedValidatorNodePhaseTimeoutV0> {
        self.active_timeout
    }

    /// Borrows only the sealed read-only selected artifact history.
    ///
    /// The borrow cannot expose the signing session or mutate selected finality.
    /// Its lifetime also prevents consuming driver work while a caller-owned
    /// acquisition workflow retains it. Target and peer choice, persistence,
    /// proposal admission, voting, and finality remain separate explicit steps.
    pub fn selected_artifact_history(&self) -> &dyn SelectedArtifactHistory {
        self.scope().finality()
    }

    /// Returns the exact live lock phase as read-only diagnostics.
    pub fn phase(&self) -> FixedValidatorLockPhaseV0 {
        self.scope().signing_session.phase()
    }

    /// Returns this driver's inclusive local round-work ceiling.
    pub const fn inclusive_maximum_round(&self) -> ConsensusRound {
        self.inclusive_maximum_round
    }

    /// Returns the higher-round retained proposal and proposal-prevote count.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    /// Returns the separate current proposal and proposal-or-nil prevote count.
    pub fn current_inbox_len(&self) -> usize {
        self.current_inbox.len()
    }

    /// Returns the current-round inbox's checked canonical-input byte count.
    pub const fn current_inbox_canonical_input_bytes(&self) -> u64 {
        self.current_inbox.total_canonical_input_bytes()
    }

    /// Returns the dedicated current finality proposal-and-precommit count.
    pub fn current_finality_inbox_len(&self) -> usize {
        self.current_finality_inbox.len()
    }

    /// Returns the finality inbox's checked logical canonical-input byte count.
    pub const fn current_finality_inbox_canonical_input_bytes(&self) -> u64 {
        self.current_finality_inbox.total_canonical_input_bytes()
    }

    /// Returns the dedicated exact-current nil-precommit count.
    pub fn current_nil_precommit_inbox_len(&self) -> usize {
        self.current_nil_precommit_inbox.len()
    }

    /// Returns the nil-precommit inbox's checked canonical-input byte count.
    pub const fn current_nil_precommit_inbox_canonical_input_bytes(&self) -> u64 {
        self.current_nil_precommit_inbox
            .total_canonical_input_bytes()
    }

    /// Returns whether the exact active phase timer has been reported due.
    pub const fn timeout_is_due(&self) -> bool {
        self.due
    }

    /// Returns whether one outward command must be emitted before another transition.
    pub const fn has_pending_command(&self) -> bool {
        self.pending_command.is_some()
    }

    /// Executes at most one transition or emits exactly one pending command.
    ///
    /// On `Err`, this consuming call returns neither the driver nor its signing
    /// scope, even when failure occurs before a coordinator starts. Recover only
    /// through strict reopen into a fresh driver.
    pub fn step(
        mut self,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        if let Some(pending) = self.pending_command.take() {
            let command = match pending {
                PendingCommandV0::Arm(timeout) => {
                    FixedValidatorNodeDriverCommandV0::ArmPhaseTimeout(timeout)
                }
                PendingCommandV0::PublishProposal {
                    proposal,
                    canonical_artifact_bytes,
                } => FixedValidatorNodeDriverCommandV0::PublishProposal {
                    proposal,
                    canonical_artifact_bytes,
                },
                PendingCommandV0::Publish {
                    vote,
                    released_proposal,
                    successor_generation,
                } => {
                    let timeout = self.install_next_timeout(successor_generation);
                    self.pending_command = Some(PendingCommandV0::Arm(timeout));
                    FixedValidatorNodeDriverCommandV0::PublishVote {
                        vote,
                        released_proposal,
                    }
                }
            };
            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Command {
                driver: Box::new(self),
                command,
            });
        }

        match self.classify_ordinary_work()? {
            DriverOrdinaryWorkV0::Finality(selection) => match selection {
                DriverCurrentFinalitySelectionV0::None
                | DriverCurrentFinalitySelectionV0::Saturated { .. } => {
                    unreachable!("classifier excludes empty finality work")
                }
                DriverCurrentFinalitySelectionV0::Ready {
                    action: _,
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                    canonical_precommit_certificate,
                } => {
                    let canonical_proposal_control_bytes =
                        match try_copy_bytes(canonical_proposal_control_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                            }
                        };
                    let canonical_artifact_bytes = match try_copy_bytes(canonical_artifact_bytes) {
                        Ok(bytes) => bytes,
                        Err(source) => {
                            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                        }
                    };
                    self.execute_current_finality(
                        canonical_proposal_control_bytes,
                        canonical_artifact_bytes,
                        canonical_precommit_certificate,
                    )
                }
                DriverCurrentFinalitySelectionV0::PreselectionConflict {
                    first_action: _,
                    first_canonical_proposal_control_bytes,
                    first_canonical_artifact_bytes,
                    first_canonical_precommit_certificate,
                    second_action: _,
                    second_canonical_proposal_control_bytes,
                    second_canonical_artifact_bytes,
                    second_canonical_precommit_certificate,
                } => {
                    let first_canonical_proposal_control_bytes =
                        match try_copy_bytes(first_canonical_proposal_control_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                            }
                        };
                    let first_canonical_artifact_bytes =
                        match try_copy_bytes(first_canonical_artifact_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                            }
                        };
                    let second_canonical_proposal_control_bytes =
                        match try_copy_bytes(second_canonical_proposal_control_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                            }
                        };
                    let second_canonical_artifact_bytes =
                        match try_copy_bytes(second_canonical_artifact_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                                driver: Box::new(self),
                                rejection: Box::new(
                                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(
                                        source,
                                    ),
                                ),
                            });
                            }
                        };
                    self.execute_current_preselection_conflict(
                        first_canonical_proposal_control_bytes,
                        first_canonical_artifact_bytes,
                        first_canonical_precommit_certificate,
                        second_canonical_proposal_control_bytes,
                        second_canonical_artifact_bytes,
                        second_canonical_precommit_certificate,
                    )
                }
                DriverCurrentFinalitySelectionV0::MissingProposal {
                    position,
                    proposal_signing_root,
                } => {
                    let reason =
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing {
                            position,
                            proposal_signing_root,
                        };
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                        driver: Box::new(self),
                        reason,
                    })
                }
                DriverCurrentFinalitySelectionV0::ConflictingRoots {
                    position,
                    first,
                    second,
                } => {
                    let reason =
                        FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityRootsConflicting {
                            position,
                            first,
                            second,
                        };
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                        driver: Box::new(self),
                        reason,
                    })
                }
                DriverCurrentFinalitySelectionV0::Rejected(source) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::CurrentFinalitySelection(
                                Box::new(source),
                            ),
                        ),
                    })
                }
                DriverCurrentFinalitySelectionV0::Reservation(source) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                        ),
                    })
                }
            },
            DriverOrdinaryWorkV0::Blocked(reason) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                    driver: Box::new(self),
                    reason,
                })
            }
            DriverOrdinaryWorkV0::Higher(selection) => match selection {
                DriverEvidenceSelectionV0::None => {
                    unreachable!("classifier excludes empty higher work")
                }
                DriverEvidenceSelectionV0::One(action) => self.execute_evidence(action),
                DriverEvidenceSelectionV0::Ambiguous { first, second } => {
                    let reason = FixedValidatorNodeDriverBlockReasonV0::Ambiguous { first, second };
                    self.ambiguity = Some(reason);
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                        driver: Box::new(self),
                        reason,
                    })
                }
                DriverEvidenceSelectionV0::Rejected(rejection) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::EvidenceSelection(rejection),
                        ),
                    })
                }
                DriverEvidenceSelectionV0::Reservation(source) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                        ),
                    })
                }
            },
            DriverOrdinaryWorkV0::NilPrecommit(selection) => match selection {
                DriverCurrentNilPrecommitSelectionV0::None => {
                    unreachable!("classifier excludes empty nil precommit work")
                }
                DriverCurrentNilPrecommitSelectionV0::One {
                    canonical_signed_precommits,
                } => self.execute_current_nil_precommit(canonical_signed_precommits),
                DriverCurrentNilPrecommitSelectionV0::Rejected(source) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::CurrentNilPrecommitSelection(
                                Box::new(source),
                            ),
                        ),
                    })
                }
                DriverCurrentNilPrecommitSelectionV0::Reservation(source) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                        ),
                    })
                }
            },
            DriverOrdinaryWorkV0::Current(selection) => match selection {
                DriverCurrentSelectionV0::None => {
                    unreachable!("classifier excludes empty current work")
                }
                DriverCurrentSelectionV0::Proposal {
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                } => self.execute_current_proposal(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                ),
                DriverCurrentSelectionV0::ProposalQuorum {
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                    canonical_prevote_certificate,
                } => self.execute_current_proposal_quorum(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                    canonical_prevote_certificate,
                ),
                DriverCurrentSelectionV0::NilQuorum {
                    canonical_prevote_certificate,
                } => self.execute_current_nil_quorum(canonical_prevote_certificate),
                DriverCurrentSelectionV0::AmbiguousQuorums {
                    position,
                    proposal_signing_root,
                } => {
                    let reason =
                        FixedValidatorNodeDriverBlockReasonV0::CurrentPrevoteQuorumAmbiguous {
                            position,
                            proposal_signing_root,
                        };
                    self.current_ambiguity = Some(reason);
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Blocked {
                        driver: Box::new(self),
                        reason,
                    })
                }
                DriverCurrentSelectionV0::Rejected(rejection) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(
                            rejection,
                        )),
                    })
                }
                DriverCurrentSelectionV0::Reservation(source) => {
                    Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection: Box::new(
                            FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                        ),
                    })
                }
            },
            DriverOrdinaryWorkV0::Due => self.execute_due(),
            DriverOrdinaryWorkV0::Idle => Ok(FixedValidatorNodeDriverStepOutcomeV0::Idle {
                driver: Box::new(self),
            }),
        }
    }

    fn next_generation(&self) -> Result<u64, FixedValidatorNodeDriverStepErrorV0> {
        self.generation.checked_add(1).ok_or(
            FixedValidatorNodeDriverStepErrorV0::TimeoutGenerationExhausted {
                generation: self.generation,
            },
        )
    }

    #[cfg(all(test, unix))]
    pub(super) fn set_timer_generation_for_test(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn install_next_timeout(&mut self, generation: u64) -> FixedValidatorNodePhaseTimeoutV0 {
        self.generation = generation;
        self.due = false;
        let timeout = FixedValidatorNodePhaseTimeoutV0 {
            lineage: self.lineage,
            context: self.scope().branch.context(),
            position: self.position(),
            phase: self.phase(),
            generation,
        };
        self.active_timeout = Some(timeout);
        timeout
    }

    fn invalidate_timeout(&mut self) {
        self.active_timeout = None;
        self.due = false;
    }

    fn scope(&self) -> &FixedValidatorNodeSigningScopeV0<'node> {
        self.scope
            .as_ref()
            .expect("live driver always owns its signing scope")
    }

    fn take_scope(&mut self) -> FixedValidatorNodeSigningScopeV0<'node> {
        self.scope
            .take()
            .expect("live driver always owns its signing scope")
    }
}

fn map_create_error(
    error: FixedValidatorNodeCurrentRoundErrorV0,
) -> FixedValidatorNodeDriverCreateErrorV0 {
    match error {
        FixedValidatorNodeCurrentRoundErrorV0::SignerBranchHeightMismatch {
            signer,
            branch_next_height,
        } => FixedValidatorNodeDriverCreateErrorV0::SignerBranchHeightMismatch {
            signer,
            branch_next_height,
        },
        FixedValidatorNodeCurrentRoundErrorV0::Round(source) => {
            FixedValidatorNodeDriverCreateErrorV0::Round(source)
        }
        FixedValidatorNodeCurrentRoundErrorV0::FinalityRoundLimitExceeded { required, maximum } => {
            FixedValidatorNodeDriverCreateErrorV0::FinalityRoundLimitExceeded { required, maximum }
        }
        FixedValidatorNodeCurrentRoundErrorV0::CallerRoundLimitExceeded { required, maximum } => {
            FixedValidatorNodeDriverCreateErrorV0::RoundWorkLimitExceeded { required, maximum }
        }
        FixedValidatorNodeCurrentRoundErrorV0::Session(source) => {
            FixedValidatorNodeDriverCreateErrorV0::Session(source)
        }
    }
}

fn try_copy_bytes(bytes: &[u8]) -> Result<Vec<u8>, TryReserveError> {
    let mut copied = Vec::new();
    copied.try_reserve_exact(bytes.len())?;
    copied.extend_from_slice(bytes);
    Ok(copied)
}
