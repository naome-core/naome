//! Read-only work classification and ordinary precedence.

use super::*;

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Classifies current proposal-finality evidence without changing driver work.
    ///
    /// This read-only result is descriptive only. It exposes no proposal,
    /// certificate, signing scope, or finality handle. [`Self::step`] uses the
    /// same private selection pipeline before independently copying and fully
    /// reverifying any uniquely ready evidence.
    #[allow(
        dead_code,
        reason = "the private diagnostic classifier is exercised by crate tests"
    )]
    pub(in crate::fixed_validator) fn classify_current_finality_evidence(
        &self,
    ) -> Result<
        FixedValidatorNodeDriverCurrentFinalityClassificationV0,
        FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0,
    > {
        match self
            .select_current_finality()
            .map_err(FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0::Round)?
        {
            DriverCurrentFinalitySelectionV0::Saturated {
                position,
                saturation,
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::Saturated {
                    position,
                    saturation,
                },
            ),
            DriverCurrentFinalitySelectionV0::None => {
                Ok(FixedValidatorNodeDriverCurrentFinalityClassificationV0::Incomplete)
            }
            DriverCurrentFinalitySelectionV0::MissingProposal {
                position,
                proposal_signing_root,
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::QuorumMissingProposal(
                    FixedValidatorNodeDriverFinalityActionV0 {
                        position,
                        proposal_signing_root,
                    },
                ),
            ),
            DriverCurrentFinalitySelectionV0::Ready {
                action,
                canonical_proposal_control_bytes: _,
                canonical_artifact_bytes: _,
                canonical_precommit_certificate: _,
            } => Ok(FixedValidatorNodeDriverCurrentFinalityClassificationV0::Ready(action)),
            DriverCurrentFinalitySelectionV0::PreselectionConflict {
                first_action,
                second_action,
                ..
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                    position: first_action.position,
                    first: first_action.proposal_signing_root,
                    second: second_action.proposal_signing_root,
                },
            ),
            DriverCurrentFinalitySelectionV0::ConflictingRoots {
                position,
                first,
                second,
            } => Ok(
                FixedValidatorNodeDriverCurrentFinalityClassificationV0::ConflictingRoots {
                    position,
                    first,
                    second,
                },
            ),
            DriverCurrentFinalitySelectionV0::Reservation(source) => Err(
                FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0::Reservation(source),
            ),
            DriverCurrentFinalitySelectionV0::Rejected(source) => Err(
                FixedValidatorNodeDriverCurrentFinalityClassificationErrorV0::QuorumInvariant(
                    source,
                ),
            ),
        }
    }

    // A single read-only classification defines ordinary work precedence for
    // execution and explicit authoring. Selectors do not advance consensus,
    // latch ambiguity, consume custody, or mark a timer due.
    pub(super) fn classify_ordinary_work(
        &self,
    ) -> Result<DriverOrdinaryWorkV0<'_>, FixedValidatorNodeDriverStepErrorV0> {
        let finality = self
            .select_current_finality()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
        if !matches!(
            finality,
            DriverCurrentFinalitySelectionV0::None
                | DriverCurrentFinalitySelectionV0::Saturated { .. }
        ) {
            return Ok(DriverOrdinaryWorkV0::Finality(finality));
        }
        if let Some(reason) = self.higher_block_reason() {
            return Ok(DriverOrdinaryWorkV0::Blocked(reason));
        }
        let higher = self.select_actionable_higher_round()?;
        if !matches!(higher, DriverEvidenceSelectionV0::None) {
            return Ok(DriverOrdinaryWorkV0::Higher(higher));
        }
        let nil_precommit = self.select_current_nil_precommit()?;
        if !matches!(nil_precommit, DriverCurrentNilPrecommitSelectionV0::None) {
            return Ok(DriverOrdinaryWorkV0::NilPrecommit(nil_precommit));
        }
        if let Some(reason) = self.current_block_reason() {
            return Ok(DriverOrdinaryWorkV0::Blocked(reason));
        }
        let current = self.select_actionable_current()?;
        if !matches!(current, DriverCurrentSelectionV0::None) {
            return Ok(DriverOrdinaryWorkV0::Current(current));
        }
        Ok(if self.due {
            DriverOrdinaryWorkV0::Due
        } else {
            DriverOrdinaryWorkV0::Idle
        })
    }

    pub(super) fn select_actionable_higher_round(
        &self,
    ) -> Result<DriverEvidenceSelectionV0, FixedValidatorNodeDriverStepErrorV0> {
        let current = self.position();
        let mut positions = Vec::new();
        if let Err(source) = positions.try_reserve_exact(self.inbox.len()) {
            return Ok(DriverEvidenceSelectionV0::Reservation(source));
        }
        positions.extend(self.inbox.retained_positions().filter(|position| {
            position.height() == current.height()
                && position.round() > current.round()
                && position.round() <= self.inclusive_maximum_round
        }));
        positions.sort_unstable();
        positions.dedup();

        if positions.is_empty() {
            return Ok(DriverEvidenceSelectionV0::None);
        }

        let parent_coordinate = self.scope().branch.coordinate();
        let snapshot = match ActionableInboxSnapshotV0::try_new(&self.inbox, parent_coordinate) {
            Ok(snapshot) => snapshot,
            Err(rejection) => {
                return Ok(DriverEvidenceSelectionV0::Rejected(Box::new(rejection)));
            }
        };
        let mut round = self
            .scope()
            .branch
            .begin_round_zero()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
        let mut selected: Option<FixedValidatorNodeDriverActionV0> = None;
        for position in positions {
            while round.position().round() < position.round() {
                round = round
                    .advance_round()
                    .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
            }
            debug_assert_eq!(round.position().round(), position.round());
            let selection = snapshot.select_position(&round, position);
            match selection {
                Ok(ActionableInboxSelectionV0::None) => {}
                Ok(ActionableInboxSelectionV0::One {
                    proposal_signing_root,
                    canonical_prevote_certificate: _,
                }) => {
                    let action = FixedValidatorNodeDriverActionV0 {
                        position,
                        proposal_signing_root,
                    };
                    if let Some(first) = selected {
                        return Ok(DriverEvidenceSelectionV0::Ambiguous {
                            first,
                            second: action,
                        });
                    }
                    selected = Some(action);
                }
                Ok(ActionableInboxSelectionV0::Ambiguous { first, second }) => {
                    return Ok(DriverEvidenceSelectionV0::Ambiguous {
                        first: FixedValidatorNodeDriverActionV0 {
                            position,
                            proposal_signing_root: first,
                        },
                        second: FixedValidatorNodeDriverActionV0 {
                            position,
                            proposal_signing_root: second,
                        },
                    });
                }
                Err(rejection) => {
                    return Ok(DriverEvidenceSelectionV0::Rejected(Box::new(rejection)));
                }
            }
        }
        Ok(match selected {
            Some(action) => DriverEvidenceSelectionV0::One(action),
            None => DriverEvidenceSelectionV0::None,
        })
    }

    pub(super) fn select_current_finality(
        &self,
    ) -> Result<DriverCurrentFinalitySelectionV0<'_>, ProposerSelectionError> {
        let position = self.position();
        let parent_coordinate = self.scope().branch.coordinate();
        match self
            .current_finality_inbox
            .preclassify(parent_coordinate, position)
        {
            CurrentRoundFinalityPreclassificationV0::Saturated {
                position,
                saturation,
            } => {
                return Ok(DriverCurrentFinalitySelectionV0::Saturated {
                    position,
                    saturation,
                });
            }
            CurrentRoundFinalityPreclassificationV0::NoMatchingPrecommit => {
                return Ok(DriverCurrentFinalitySelectionV0::None);
            }
            CurrentRoundFinalityPreclassificationV0::NeedsRound => {}
        }
        let round = derive_round(&self.scope().branch, position.round())?;
        let classification = self.current_finality_inbox.classify(&round);
        drop(round);
        match classification {
            Ok(CurrentRoundFinalityClassificationV0::Saturated {
                position,
                saturation,
            }) => Ok(DriverCurrentFinalitySelectionV0::Saturated {
                position,
                saturation,
            }),
            Ok(CurrentRoundFinalityClassificationV0::None) => {
                Ok(DriverCurrentFinalitySelectionV0::None)
            }
            Ok(CurrentRoundFinalityClassificationV0::OneQuorumMissingProposal {
                proposal_signing_root,
                canonical_precommit_certificate,
            }) => {
                drop(canonical_precommit_certificate);
                Ok(DriverCurrentFinalitySelectionV0::MissingProposal {
                    position,
                    proposal_signing_root,
                })
            }
            Ok(CurrentRoundFinalityClassificationV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            }) => Ok(DriverCurrentFinalitySelectionV0::Ready {
                action: FixedValidatorNodeDriverFinalityActionV0 {
                    position,
                    proposal_signing_root,
                },
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            }),
            Ok(CurrentRoundFinalityClassificationV0::Pair { first, second }) => {
                Ok(DriverCurrentFinalitySelectionV0::PreselectionConflict {
                    first_action: FixedValidatorNodeDriverFinalityActionV0 {
                        position,
                        proposal_signing_root: first.proposal_signing_root,
                    },
                    first_canonical_proposal_control_bytes: first.canonical_proposal_control_bytes,
                    first_canonical_artifact_bytes: first.canonical_artifact_bytes,
                    first_canonical_precommit_certificate: first.canonical_precommit_certificate,
                    second_action: FixedValidatorNodeDriverFinalityActionV0 {
                        position,
                        proposal_signing_root: second.proposal_signing_root,
                    },
                    second_canonical_proposal_control_bytes: second
                        .canonical_proposal_control_bytes,
                    second_canonical_artifact_bytes: second.canonical_artifact_bytes,
                    second_canonical_precommit_certificate: second.canonical_precommit_certificate,
                })
            }
            Ok(CurrentRoundFinalityClassificationV0::ConflictingRoots { first, second }) => {
                Ok(DriverCurrentFinalitySelectionV0::ConflictingRoots {
                    position,
                    first,
                    second,
                })
            }
            Err(CurrentRoundFinalityClassificationErrorV0::Reservation(source)) => {
                Ok(DriverCurrentFinalitySelectionV0::Reservation(source))
            }
            Err(CurrentRoundFinalityClassificationErrorV0::Invariant(source)) => {
                Ok(DriverCurrentFinalitySelectionV0::Rejected(source))
            }
        }
    }

    pub(super) fn select_current_nil_precommit(
        &self,
    ) -> Result<DriverCurrentNilPrecommitSelectionV0, FixedValidatorNodeDriverStepErrorV0> {
        let position = self.position();
        let parent_coordinate = self.scope().branch.coordinate();
        if matches!(
            self.current_nil_precommit_inbox
                .preclassify(parent_coordinate, position),
            CurrentRoundNilPrecommitPreclassificationV0::NoMatchingPrecommit
        ) {
            return Ok(DriverCurrentNilPrecommitSelectionV0::None);
        }
        let round = derive_round(&self.scope().branch, position.round())
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
        let selection = self.current_nil_precommit_inbox.select_nil_quorum(&round);
        drop(round);
        match selection {
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::None) => {
                Ok(DriverCurrentNilPrecommitSelectionV0::None)
            }
            Ok(CurrentRoundNilPrecommitQuorumSelectionV0::One {
                canonical_signed_precommits,
            }) => Ok(DriverCurrentNilPrecommitSelectionV0::One {
                canonical_signed_precommits,
            }),
            Err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Reservation(source)) => {
                Ok(DriverCurrentNilPrecommitSelectionV0::Reservation(source))
            }
            Err(CurrentRoundNilPrecommitQuorumSelectionErrorV0::Invariant(source)) => {
                Ok(DriverCurrentNilPrecommitSelectionV0::Rejected(source))
            }
        }
    }

    pub(super) fn select_actionable_current(
        &self,
    ) -> Result<DriverCurrentSelectionV0, FixedValidatorNodeDriverStepErrorV0> {
        let position = self.position();
        let parent_coordinate = self.scope().branch.coordinate();
        let proposal = match self
            .current_inbox
            .select_unique_proposal(parent_coordinate, position)
        {
            CurrentRoundProposalSelectionV0::None => None,
            CurrentRoundProposalSelectionV0::One {
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => Some((
                proposal_signing_root,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            )),
            CurrentRoundProposalSelectionV0::Ambiguous { .. } => {
                unreachable!("current proposal ambiguity is checked before selection")
            }
        };

        match self.phase() {
            FixedValidatorLockPhaseV0::Precommit => Ok(DriverCurrentSelectionV0::None),
            FixedValidatorLockPhaseV0::Proposal => {
                let Some((
                    _proposal_signing_root,
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                )) = proposal
                else {
                    return Ok(DriverCurrentSelectionV0::None);
                };
                let control = match try_copy_bytes(canonical_proposal_control_bytes) {
                    Ok(bytes) => bytes,
                    Err(source) => return Ok(DriverCurrentSelectionV0::Reservation(source)),
                };
                let artifact = match try_copy_bytes(canonical_artifact_bytes) {
                    Ok(bytes) => bytes,
                    Err(source) => return Ok(DriverCurrentSelectionV0::Reservation(source)),
                };
                Ok(DriverCurrentSelectionV0::Proposal {
                    canonical_proposal_control_bytes: control,
                    canonical_artifact_bytes: artifact,
                })
            }
            FixedValidatorLockPhaseV0::Prevote => {
                let round = derive_round(&self.scope().branch, position.round())
                    .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?;
                let proposal_quorum = if let Some((proposal_signing_root, _, _)) = proposal {
                    self.current_inbox
                        .select_proposal_quorum(&round, proposal_signing_root)
                } else {
                    Ok(CurrentRoundQuorumSelectionV0::None)
                };
                let nil_quorum = self.current_inbox.select_nil_quorum(&round);
                drop(round);
                let proposal_quorum = match proposal_quorum {
                    Ok(quorum) => quorum,
                    Err(CurrentRoundQuorumSelectionErrorV0::Reservation(source)) => {
                        return Ok(DriverCurrentSelectionV0::Reservation(source));
                    }
                    Err(CurrentRoundQuorumSelectionErrorV0::Invariant(source)) => {
                        return Ok(DriverCurrentSelectionV0::Rejected(Box::new(
                            FixedValidatorNodeVoteRejectionV0::QuorumConstruction(Box::new(source)),
                        )));
                    }
                };
                let nil_quorum = match nil_quorum {
                    Ok(quorum) => quorum,
                    Err(CurrentRoundQuorumSelectionErrorV0::Reservation(source)) => {
                        return Ok(DriverCurrentSelectionV0::Reservation(source));
                    }
                    Err(CurrentRoundQuorumSelectionErrorV0::Invariant(source)) => {
                        return Ok(DriverCurrentSelectionV0::Rejected(Box::new(
                            FixedValidatorNodeVoteRejectionV0::QuorumConstruction(Box::new(source)),
                        )));
                    }
                };
                match (proposal_quorum, nil_quorum) {
                    (
                        CurrentRoundQuorumSelectionV0::One { .. },
                        CurrentRoundQuorumSelectionV0::One { .. },
                    ) => {
                        let (proposal_signing_root, _, _) = proposal
                            .expect("an actionable proposal quorum requires its retained proposal");
                        Ok(DriverCurrentSelectionV0::AmbiguousQuorums {
                            position,
                            proposal_signing_root,
                        })
                    }
                    (
                        CurrentRoundQuorumSelectionV0::One {
                            canonical_certificate,
                        },
                        CurrentRoundQuorumSelectionV0::None,
                    ) => {
                        let (_, canonical_proposal_control_bytes, canonical_artifact_bytes) =
                            proposal.expect(
                                "an actionable proposal quorum requires its retained proposal",
                            );
                        let control = match try_copy_bytes(canonical_proposal_control_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(DriverCurrentSelectionV0::Reservation(source));
                            }
                        };
                        let artifact = match try_copy_bytes(canonical_artifact_bytes) {
                            Ok(bytes) => bytes,
                            Err(source) => {
                                return Ok(DriverCurrentSelectionV0::Reservation(source));
                            }
                        };
                        Ok(DriverCurrentSelectionV0::ProposalQuorum {
                            canonical_proposal_control_bytes: control,
                            canonical_artifact_bytes: artifact,
                            canonical_prevote_certificate: canonical_certificate,
                        })
                    }
                    (
                        CurrentRoundQuorumSelectionV0::None,
                        CurrentRoundQuorumSelectionV0::One {
                            canonical_certificate,
                        },
                    ) => Ok(DriverCurrentSelectionV0::NilQuorum {
                        canonical_prevote_certificate: canonical_certificate,
                    }),
                    (CurrentRoundQuorumSelectionV0::None, CurrentRoundQuorumSelectionV0::None) => {
                        Ok(DriverCurrentSelectionV0::None)
                    }
                }
            }
        }
    }

    pub(super) fn higher_block_reason(&self) -> Option<FixedValidatorNodeDriverBlockReasonV0> {
        self.ambiguity.or_else(|| {
            self.inbox
                .saturation()
                .map(FixedValidatorNodeDriverBlockReasonV0::Saturated)
        })
    }

    pub(super) fn current_block_reason(&self) -> Option<FixedValidatorNodeDriverBlockReasonV0> {
        if let Some(reason) = self.current_ambiguity {
            return Some(reason);
        }
        let position = self.position();
        if let Some((saturated_position, saturation)) = self.current_inbox.saturation() {
            return Some(FixedValidatorNodeDriverBlockReasonV0::CurrentSaturated {
                position: saturated_position,
                saturation,
            });
        }
        match self
            .current_inbox
            .select_unique_proposal(self.scope().branch.coordinate(), position)
        {
            CurrentRoundProposalSelectionV0::Ambiguous { first, second } => Some(
                FixedValidatorNodeDriverBlockReasonV0::CurrentProposalAmbiguous {
                    position,
                    first,
                    second,
                },
            ),
            CurrentRoundProposalSelectionV0::None | CurrentRoundProposalSelectionV0::One { .. } => {
                None
            }
        }
    }
}

pub(super) enum DriverOrdinaryWorkV0<'inbox> {
    Finality(DriverCurrentFinalitySelectionV0<'inbox>),
    Blocked(FixedValidatorNodeDriverBlockReasonV0),
    Higher(DriverEvidenceSelectionV0),
    NilPrecommit(DriverCurrentNilPrecommitSelectionV0),
    Current(DriverCurrentSelectionV0),
    Due,
    Idle,
}

pub(super) enum DriverEvidenceSelectionV0 {
    None,
    One(FixedValidatorNodeDriverActionV0),
    Ambiguous {
        first: FixedValidatorNodeDriverActionV0,
        second: FixedValidatorNodeDriverActionV0,
    },
    Rejected(Box<FixedValidatorNodeBufferedProposalPrecommitRejectionV0>),
    Reservation(TryReserveError),
}

pub(super) enum DriverCurrentFinalitySelectionV0<'inbox> {
    None,
    MissingProposal {
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    },
    Ready {
        action: FixedValidatorNodeDriverFinalityActionV0,
        canonical_proposal_control_bytes: &'inbox [u8],
        canonical_artifact_bytes: &'inbox [u8],
        canonical_precommit_certificate: Vec<u8>,
    },
    PreselectionConflict {
        first_action: FixedValidatorNodeDriverFinalityActionV0,
        first_canonical_proposal_control_bytes: &'inbox [u8],
        first_canonical_artifact_bytes: &'inbox [u8],
        first_canonical_precommit_certificate: Vec<u8>,
        second_action: FixedValidatorNodeDriverFinalityActionV0,
        second_canonical_proposal_control_bytes: &'inbox [u8],
        second_canonical_artifact_bytes: &'inbox [u8],
        second_canonical_precommit_certificate: Vec<u8>,
    },
    ConflictingRoots {
        position: ConsensusPosition,
        first: ProposalSigningRoot,
        second: ProposalSigningRoot,
    },
    Saturated {
        position: ConsensusPosition,
        saturation: FixedValidatorNodeCurrentRoundFinalityInboxSaturationV0,
    },
    Rejected(QuorumCertificateBuildError),
    Reservation(TryReserveError),
}

pub(super) enum DriverCurrentNilPrecommitSelectionV0 {
    None,
    One {
        canonical_signed_precommits: Vec<[u8; VerifiedConsensusVoteV0::BYTE_LENGTH]>,
    },
    Rejected(QuorumCertificateBuildError),
    Reservation(TryReserveError),
}

pub(super) enum DriverCurrentSelectionV0 {
    None,
    Proposal {
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
    },
    ProposalQuorum {
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
        canonical_prevote_certificate: Vec<u8>,
    },
    NilQuorum {
        canonical_prevote_certificate: Vec<u8>,
    },
    AmbiguousQuorums {
        position: ConsensusPosition,
        proposal_signing_root: ProposalSigningRoot,
    },
    Rejected(Box<FixedValidatorNodeVoteRejectionV0>),
    Reservation(TryReserveError),
}
