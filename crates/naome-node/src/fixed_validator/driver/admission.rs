//! Owned input admission and lossless evidence drains.

use super::*;

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Admits one owned event without choosing or executing a consensus action.
    ///
    /// On `Err`, this consuming call returns neither the driver nor its signing
    /// scope, even when failure occurs before a coordinator starts. Recover only
    /// through strict reopen into a fresh driver.
    pub fn admit_event(
        self,
        event: FixedValidatorNodeDriverEventV0,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(admission_rejected(
                self,
                event,
                FixedValidatorNodeDriverAdmissionRejectionV0::CommandPending,
            ));
        }
        let bypasses_higher_block = matches!(
            &event,
            FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal { .. }
                | FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit { .. }
                | FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit { .. }
        );
        if !bypasses_higher_block && let Some(reason) = self.higher_block_reason() {
            return Ok(admission_rejected(
                self,
                event,
                FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
            ));
        }
        match event {
            FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => self.admit_current_finality_proposal(
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            ),
            FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
                canonical_signed_precommit,
            } => self.admit_current_finality_precommit(canonical_signed_precommit),
            FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
                canonical_signed_precommit,
            } => self.admit_current_nil_precommit(canonical_signed_precommit),
            FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => {
                if let Some(reason) = self.current_block_reason() {
                    return Ok(admission_rejected(
                        self,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
                            canonical_proposal_control_bytes,
                            canonical_artifact_bytes,
                        },
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
                    ));
                }
                self.admit_current_proposal(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                )
            }
            FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                canonical_signed_prevote,
            } => {
                if let Some(reason) = self.current_block_reason() {
                    return Ok(admission_rejected(
                        self,
                        FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
                            canonical_signed_prevote,
                        },
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
                    ));
                }
                self.admit_current_prevote(canonical_signed_prevote)
            }
            FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                canonical_signed_prevote,
            } => {
                if let Some(reason) = self.current_block_reason() {
                    return Ok(admission_rejected(
                        self,
                        FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
                            canonical_signed_prevote,
                        },
                        FixedValidatorNodeDriverAdmissionRejectionV0::Blocked(reason),
                    ));
                }
                self.admit_current_nil_prevote(canonical_signed_prevote)
            }
            FixedValidatorNodeDriverEventV0::HigherRoundProposal {
                proposal_round,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            } => self.admit_proposal(
                proposal_round,
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
            ),
            FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
                canonical_signed_prevote,
            } => self.admit_prevote(canonical_signed_prevote),
            FixedValidatorNodeDriverEventV0::TimeoutDue(timeout) => Ok(self.admit_timeout(timeout)),
        }
    }

    /// Losslessly drains only higher-round evidence and clears its blocking.
    pub fn drain_inbox_and_reset(mut self) -> FixedValidatorNodeDriverDrainV0<'node> {
        let drained = self.inbox.drain_and_reset();
        self.ambiguity = None;
        FixedValidatorNodeDriverDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    /// Losslessly returns all separately budgeted current-round evidence.
    ///
    /// The active due observation and higher-round inbox remain unchanged.
    pub fn drain_current_inbox_and_reset(
        mut self,
    ) -> FixedValidatorNodeDriverCurrentRoundDrainV0<'node> {
        let drained = self.current_inbox.drain_and_reset();
        self.current_ambiguity = None;
        FixedValidatorNodeDriverCurrentRoundDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    /// Losslessly returns all separately budgeted current finality evidence.
    ///
    /// Ordinary current and higher inboxes, timer and due state, pending command,
    /// and signer and finality authority remain unchanged.
    pub fn drain_current_finality_inbox_and_reset(
        mut self,
    ) -> FixedValidatorNodeDriverCurrentFinalityDrainV0<'node> {
        let drained = self.current_finality_inbox.drain_and_reset();
        FixedValidatorNodeDriverCurrentFinalityDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    /// Losslessly returns all separately budgeted current nil precommits.
    ///
    /// Every other inbox, timer, due state, pending command, signing state, and
    /// durable authority file remains unchanged.
    pub fn drain_current_nil_precommit_inbox_and_reset(
        mut self,
    ) -> FixedValidatorNodeDriverCurrentNilPrecommitDrainV0<'node> {
        let drained = self.current_nil_precommit_inbox.drain_and_reset();
        FixedValidatorNodeDriverCurrentNilPrecommitDrainV0 {
            driver: Box::new(self),
            drained,
        }
    }

    pub(super) fn admit_current_finality_proposal(
        mut self,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_proposal_control_bytes = Some(canonical_proposal_control_bytes);
        let mut canonical_artifact_bytes = Some(canonical_artifact_bytes);
        if let Some((position, saturation)) = self.current_finality_inbox.saturation() {
            return Ok(admission_rejected(
                self,
                current_finality_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated: false,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_finality_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let proposal = match verify_current_proposal_at_round(
            &round,
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original current finality proposal control is retained"),
            canonical_artifact_bytes
                .as_ref()
                .expect("original current finality proposal payload is retained"),
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                let rejection =
                    source.into_admission_rejection(CurrentProposalDestinationV0::Finality);
                return Ok(admission_rejected(
                    self,
                    current_finality_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    rejection,
                ));
            }
        };
        drop(round);
        match self.current_finality_inbox.try_insert_proposal(proposal) {
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundFinalityProposalInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_finality_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundFinalityProposalInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_finality_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxReservation(
                        source,
                    ),
                ))
            }
        }
    }

    pub(super) fn admit_current_finality_precommit(
        mut self,
        canonical_signed_precommit: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_precommit = Some(canonical_signed_precommit);
        if let Some((position, saturation)) = self.current_finality_inbox.saturation() {
            return Ok(admission_rejected(
                self,
                current_finality_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated: false,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_finality_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_finality_inbox.try_insert_precommit(
            &round,
            canonical_signed_precommit
                .as_ref()
                .expect("original current proposal precommit is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundFinalityInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundFinalityPrecommitInsertErrorV0::Admission(source)) => {
                Ok(admission_rejected(
                    self,
                    current_finality_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityPrecommit(source),
                ))
            }
            Err(CurrentRoundFinalityPrecommitInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_finality_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundFinalityPrecommitInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_finality_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityInboxReservation(
                        source,
                    ),
                ))
            }
        }
    }

    pub(super) fn admit_current_nil_precommit(
        mut self,
        canonical_signed_precommit: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_precommit = Some(canonical_signed_precommit);
        if let Some((position, saturation)) = self.current_nil_precommit_inbox.saturation() {
            return Ok(admission_rejected(
                self,
                current_nil_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                    position,
                    saturation,
                    newly_saturated: false,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_nil_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_nil_precommit_inbox.try_insert_nil_precommit(
            &round,
            canonical_signed_precommit
                .as_ref()
                .expect("original current nil precommit is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundNilPrecommitInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundNilPrecommitInsertErrorV0::Admission(source)) => {
                Ok(admission_rejected(
                    self,
                    current_nil_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommit(source),
                ))
            }
            Err(CurrentRoundNilPrecommitInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_nil_precommit_event(&mut canonical_signed_precommit),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundNilPrecommitInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_nil_precommit_event(&mut canonical_signed_precommit),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrecommitInboxReservation(
                        source,
                    ),
                ))
            }
        }
    }

    pub(super) fn admit_current_proposal(
        mut self,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_proposal_control_bytes = Some(canonical_proposal_control_bytes);
        let mut canonical_artifact_bytes = Some(canonical_artifact_bytes);
        let phase = self.phase();
        if phase == FixedValidatorLockPhaseV0::Precommit {
            return Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                    actual: phase,
                },
            ));
        }
        if self.due {
            let position = self.position();
            return Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                    position,
                    phase,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let proposal = match verify_current_proposal_at_round(
            &round,
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original current proposal control is retained"),
            canonical_artifact_bytes
                .as_ref()
                .expect("original current proposal payload is retained"),
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(round);
                let rejection =
                    source.into_admission_rejection(CurrentProposalDestinationV0::Voting);
                return Ok(admission_rejected(
                    self,
                    current_proposal_event(
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    rejection,
                ));
            }
        };
        drop(round);
        match self.current_inbox.try_insert_proposal(proposal) {
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundProposalInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundProposalInsertErrorV0::Reservation(source)) => Ok(admission_rejected(
                self,
                current_proposal_event(
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxReservation(source),
            )),
        }
    }

    pub(super) fn admit_current_prevote(
        mut self,
        canonical_signed_prevote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_prevote = Some(canonical_signed_prevote);
        let phase = self.phase();
        if phase == FixedValidatorLockPhaseV0::Precommit {
            return Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                    actual: phase,
                },
            ));
        }
        if self.due {
            let position = self.position();
            return Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                    position,
                    phase,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_inbox.try_insert_prevote(
            &round,
            canonical_signed_prevote
                .as_ref()
                .expect("original current proposal prevote is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundPrevoteInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundPrevoteInsertErrorV0::Admission(source)) => Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentPrevote(source),
            )),
            Err(CurrentRoundPrevoteInsertErrorV0::Reservation(source)) => Ok(admission_rejected(
                self,
                current_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxReservation(source),
            )),
        }
    }

    pub(super) fn admit_current_nil_prevote(
        mut self,
        canonical_signed_prevote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_prevote = Some(canonical_signed_prevote);
        let phase = self.phase();
        if phase == FixedValidatorLockPhaseV0::Precommit {
            return Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceWrongPhase {
                    actual: phase,
                },
            ));
        }
        if self.due {
            let position = self.position();
            return Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentEvidenceAfterDue {
                    position,
                    phase,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = match current_round(
            &scope.branch,
            &scope.signing_session,
            self.inclusive_maximum_round,
            scope.finality.replay_limit().max_round(),
        ) {
            Ok(round) => round,
            Err(VotingCurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    current_nil_prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentRound(Box::new(rejection)),
                ));
            }
            Err(VotingCurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::CurrentRound(
                    Box::new(source),
                ));
            }
        };
        let insertion = self.current_inbox.try_insert_nil_prevote(
            &round,
            canonical_signed_prevote
                .as_ref()
                .expect("original current nil prevote is retained"),
        );
        drop(round);
        match insertion {
            Ok(CurrentRoundInboxInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(CurrentRoundInboxInsertOutcomeV0::AlreadyRetained) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(CurrentRoundNilPrevoteInsertErrorV0::Saturated {
                position,
                saturation,
                newly_saturated,
            }) => Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxSaturated {
                    position,
                    saturation,
                    newly_saturated,
                },
            )),
            Err(CurrentRoundNilPrevoteInsertErrorV0::Admission(source)) => Ok(admission_rejected(
                self,
                current_nil_prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::CurrentNilPrevote(source),
            )),
            Err(CurrentRoundNilPrevoteInsertErrorV0::Reservation(source)) => {
                Ok(admission_rejected(
                    self,
                    current_nil_prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentInboxReservation(source),
                ))
            }
        }
    }

    pub(super) fn admit_proposal(
        mut self,
        proposal_round: ConsensusRound,
        canonical_proposal_control_bytes: Box<[u8]>,
        canonical_artifact_bytes: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_proposal_control_bytes = Some(canonical_proposal_control_bytes);
        let mut canonical_artifact_bytes = Some(canonical_artifact_bytes);
        let route = FixedValidatorNodeHigherRoundProposalRouteV0::new(
            proposal_round,
            self.inclusive_maximum_round,
        );
        let proposal_round_token = match preflight_higher_round_proposal_route(self.scope(), route)
        {
            Ok(round) => round,
            Err(CurrentRoundErrorV0::Rejected(rejection)) => {
                return Ok(admission_rejected(
                    self,
                    proposal_event(
                        proposal_round,
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(Box::new(rejection)),
                ));
            }
            Err(CurrentRoundErrorV0::Fatal(source)) => {
                return Err(FixedValidatorNodeDriverAdmissionErrorV0::Proposal(
                    Box::new(source),
                ));
            }
        };
        let payload_len = canonical_artifact_bytes
            .as_ref()
            .expect("original proposal payload is retained")
            .len();
        if payload_len > ARTIFACT_PAYLOAD_MAX_BYTES {
            drop(proposal_round_token);
            return Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadTooLong {
                    actual: payload_len,
                    maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
                },
            ));
        }
        if let Err(source) = preflight_deferred_proposal_control_framing(
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original proposal control is retained"),
        ) {
            drop(proposal_round_token);
            return Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(Box::new(
                    FixedValidatorNodeProposalDeferralRejectionV0::Proposal(Box::new(source)),
                )),
            ));
        }
        let mut artifact_copy = Vec::new();
        if let Err(source) = artifact_copy.try_reserve_exact(
            canonical_artifact_bytes
                .as_ref()
                .expect("original proposal payload is retained")
                .len(),
        ) {
            drop(proposal_round_token);
            return Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadCopy(source),
            ));
        }
        artifact_copy.extend_from_slice(
            canonical_artifact_bytes
                .as_ref()
                .expect("original proposal payload is retained"),
        );
        let proposal = match verify_deferred_proposal_at_round(
            &proposal_round_token,
            canonical_proposal_control_bytes
                .as_ref()
                .expect("original proposal control is retained"),
            artifact_copy,
        ) {
            Ok(proposal) => proposal,
            Err(source) => {
                drop(proposal_round_token);
                return Ok(admission_rejected(
                    self,
                    proposal_event(
                        proposal_round,
                        &mut canonical_proposal_control_bytes,
                        &mut canonical_artifact_bytes,
                    ),
                    FixedValidatorNodeDriverAdmissionRejectionV0::Proposal(Box::new(
                        FixedValidatorNodeProposalDeferralRejectionV0::Proposal(Box::new(source)),
                    )),
                ));
            }
        };
        drop(proposal_round_token);

        match self.inbox.try_insert_proposal(proposal) {
            Ok(FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::Inserted) => {
                Ok(admitted(
                    self,
                    FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
                ))
            }
            Ok(FixedValidatorNodeHigherRoundInboxProposalInsertOutcomeV0::AlreadyRetained {
                proposal: _,
            }) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
            )),
            Err(source) => Ok(admission_rejected(
                self,
                proposal_event(
                    proposal_round,
                    &mut canonical_proposal_control_bytes,
                    &mut canonical_artifact_bytes,
                ),
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalInbox(Box::new(source)),
            )),
        }
    }

    pub(super) fn admit_prevote(
        mut self,
        canonical_signed_prevote: Box<[u8]>,
    ) -> Result<
        FixedValidatorNodeDriverAdmissionOutcomeV0<'node>,
        FixedValidatorNodeDriverAdmissionErrorV0,
    > {
        let mut canonical_signed_prevote = Some(canonical_signed_prevote);
        let context = self.scope().branch.context();
        let vote = match VerifiedConsensusVoteV0::decode_and_verify(
            canonical_signed_prevote
                .as_ref()
                .expect("original proposal prevote is retained"),
            context,
        ) {
            Ok(vote) => vote,
            Err(source) => {
                return Ok(admission_rejected(
                    self,
                    prevote_event(&mut canonical_signed_prevote),
                    FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRouting(source),
                ));
            }
        };
        let position = vote.position();
        let current = self.position();
        if position.height() != current.height() {
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteHeightMismatch {
                    current: current.height(),
                    event: position.height(),
                },
            ));
        }
        if position.round() <= current.round() {
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteNotHigher {
                    signer: current.round(),
                    event: position.round(),
                },
            ));
        }
        let finality_maximum =
            ConsensusRound::new(self.scope().finality.replay_limit().max_round());
        if position.round() > finality_maximum {
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteFinalityRoundLimitExceeded {
                    required: position.round(),
                    maximum: finality_maximum,
                },
            ));
        }
        if position.round() > self.inclusive_maximum_round {
            let maximum = self.inclusive_maximum_round;
            return Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteRoundWorkLimitExceeded {
                    required: position.round(),
                    maximum,
                },
            ));
        }
        let scope = self
            .scope
            .as_ref()
            .expect("live driver always owns its signing scope");
        let round = derive_round(&scope.branch, position.round())
            .map_err(FixedValidatorNodeDriverAdmissionErrorV0::Round)?;
        let insertion = self.inbox.try_insert_proposal_prevote(
            &round,
            canonical_signed_prevote
                .as_ref()
                .expect("original proposal prevote is retained"),
        );
        drop(round);
        match insertion {
            Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::Inserted) => Ok(admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::Inserted,
            )),
            Ok(FixedValidatorNodeHigherRoundInboxPrevoteInsertOutcomeV0::AlreadyRetained) => {
                Ok(admitted(
                    self,
                    FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyRetained,
                ))
            }
            Err(source) => Ok(admission_rejected(
                self,
                prevote_event(&mut canonical_signed_prevote),
                FixedValidatorNodeDriverAdmissionRejectionV0::PrevoteInbox(Box::new(source)),
            )),
        }
    }

    pub(super) fn admit_timeout(
        mut self,
        timeout: FixedValidatorNodePhaseTimeoutV0,
    ) -> FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
        if self.active_timeout != Some(timeout) {
            return admission_rejected(
                self,
                FixedValidatorNodeDriverEventV0::TimeoutDue(timeout),
                FixedValidatorNodeDriverAdmissionRejectionV0::TimeoutMismatch,
            );
        }
        if self.due {
            admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::AlreadyDue,
            )
        } else {
            self.due = true;
            admitted(
                self,
                FixedValidatorNodeDriverAdmissionDispositionV0::TimeoutMarkedDue,
            )
        }
    }
}

#[derive(Clone, Copy)]
enum CurrentProposalDestinationV0 {
    Voting,
    Finality,
}

enum CurrentProposalVerificationErrorV0 {
    PayloadTooLong { actual: usize, maximum: usize },
    Control(ConsensusProposalVerifyError),
    PayloadCopy(TryReserveError),
}

impl CurrentProposalVerificationErrorV0 {
    fn into_admission_rejection(
        self,
        destination: CurrentProposalDestinationV0,
    ) -> FixedValidatorNodeDriverAdmissionRejectionV0 {
        match self {
            Self::PayloadTooLong { actual, maximum } => {
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadTooLong {
                    actual,
                    maximum,
                }
            }
            Self::Control(source) => match destination {
                CurrentProposalDestinationV0::Voting => {
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentProposal(Box::new(source))
                }
                CurrentProposalDestinationV0::Finality => {
                    FixedValidatorNodeDriverAdmissionRejectionV0::CurrentFinalityProposal(Box::new(
                        source,
                    ))
                }
            },
            Self::PayloadCopy(source) => {
                FixedValidatorNodeDriverAdmissionRejectionV0::ProposalPayloadCopy(source)
            }
        }
    }
}

fn verify_current_proposal_at_round(
    round: &FixedConsensusRoundV0<'_>,
    canonical_proposal_control_bytes: &[u8],
    canonical_artifact_bytes: &[u8],
) -> Result<Box<FixedValidatorNodeDeferredProposalV0>, CurrentProposalVerificationErrorV0> {
    let payload_len = canonical_artifact_bytes.len();
    if payload_len > ARTIFACT_PAYLOAD_MAX_BYTES {
        return Err(CurrentProposalVerificationErrorV0::PayloadTooLong {
            actual: payload_len,
            maximum: ARTIFACT_PAYLOAD_MAX_BYTES,
        });
    }
    preflight_deferred_proposal_control_framing(canonical_proposal_control_bytes)
        .map_err(CurrentProposalVerificationErrorV0::Control)?;
    let artifact_copy = try_copy_bytes(canonical_artifact_bytes)
        .map_err(CurrentProposalVerificationErrorV0::PayloadCopy)?;
    verify_deferred_proposal_at_round(round, canonical_proposal_control_bytes, artifact_copy)
        .map_err(CurrentProposalVerificationErrorV0::Control)
}

fn admitted<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    disposition: FixedValidatorNodeDriverAdmissionDispositionV0,
) -> FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
    FixedValidatorNodeDriverAdmissionOutcomeV0::Admitted {
        driver: Box::new(driver),
        disposition,
    }
}

fn admission_rejected<'node>(
    driver: FixedValidatorNodeDriverV0<'node>,
    event: FixedValidatorNodeDriverEventV0,
    rejection: FixedValidatorNodeDriverAdmissionRejectionV0,
) -> FixedValidatorNodeDriverAdmissionOutcomeV0<'node> {
    FixedValidatorNodeDriverAdmissionOutcomeV0::Rejected {
        driver: Box::new(driver),
        event: Box::new(event),
        rejection: Box::new(rejection),
    }
}

fn proposal_event(
    proposal_round: ConsensusRound,
    canonical_proposal_control_bytes: &mut Option<Box<[u8]>>,
    canonical_artifact_bytes: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposal {
        proposal_round,
        canonical_proposal_control_bytes: canonical_proposal_control_bytes
            .take()
            .expect("rejected proposal retains its original control bytes"),
        canonical_artifact_bytes: canonical_artifact_bytes
            .take()
            .expect("rejected proposal retains its original payload bytes"),
    }
}

fn current_proposal_event(
    canonical_proposal_control_bytes: &mut Option<Box<[u8]>>,
    canonical_artifact_bytes: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposal {
        canonical_proposal_control_bytes: canonical_proposal_control_bytes
            .take()
            .expect("rejected current proposal retains its original control bytes"),
        canonical_artifact_bytes: canonical_artifact_bytes
            .take()
            .expect("rejected current proposal retains its original payload bytes"),
    }
}

fn current_finality_proposal_event(
    canonical_proposal_control_bytes: &mut Option<Box<[u8]>>,
    canonical_artifact_bytes: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundFinalityProposal {
        canonical_proposal_control_bytes: canonical_proposal_control_bytes
            .take()
            .expect("rejected current finality proposal retains its original control bytes"),
        canonical_artifact_bytes: canonical_artifact_bytes
            .take()
            .expect("rejected current finality proposal retains its original payload bytes"),
    }
}

fn current_finality_precommit_event(
    canonical_signed_precommit: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrecommit {
        canonical_signed_precommit: canonical_signed_precommit
            .take()
            .expect("rejected current proposal precommit retains its original bytes"),
    }
}

fn current_nil_precommit_event(
    canonical_signed_precommit: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundNilPrecommit {
        canonical_signed_precommit: canonical_signed_precommit
            .take()
            .expect("rejected current nil precommit retains its original bytes"),
    }
}

fn current_prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundProposalPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected current proposal prevote retains its original bytes"),
    }
}

fn current_nil_prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::CurrentRoundNilPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected current nil prevote retains its original bytes"),
    }
}

fn prevote_event(
    canonical_signed_prevote: &mut Option<Box<[u8]>>,
) -> FixedValidatorNodeDriverEventV0 {
    FixedValidatorNodeDriverEventV0::HigherRoundProposalPrevote {
        canonical_signed_prevote: canonical_signed_prevote
            .take()
            .expect("rejected proposal prevote retains its original bytes"),
    }
}
