//! Selected consensus transitions and durable completion.

use super::*;

impl<'node> FixedValidatorNodeDriverV0<'node> {
    pub(super) fn execute_current_finality(
        mut self,
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
        canonical_precommit_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let previous_position = self.position();
        let scope = self.take_scope();
        match scope.commit_current_round_finality(
            &canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            &canonical_precommit_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection },
            )) => {
                self.scope = Some(*scope);
                if self.position() != previous_position {
                    let timeout = self.install_next_timeout(next_generation);
                    self.pending_command = Some(PendingCommandV0::Arm(timeout));
                }
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Finality {
                    driver: Box::new(self),
                    selection,
                })
            }
            Ok(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(stop),
            )) => Ok(FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop)),
            Ok(FixedValidatorNodeCurrentRoundFinalityOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::CurrentFinality(
                        rejection,
                    )),
                })
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(
                Box::new(source),
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn execute_current_preselection_conflict(
        mut self,
        first_canonical_proposal_control_bytes: Vec<u8>,
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_precommit_certificate: Vec<u8>,
        second_canonical_proposal_control_bytes: Vec<u8>,
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_precommit_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let scope = self.take_scope();
        match scope.commit_current_round_preselection_conflict(
            &first_canonical_proposal_control_bytes,
            first_canonical_artifact_bytes,
            &first_canonical_precommit_certificate,
            &second_canonical_proposal_control_bytes,
            second_canonical_artifact_bytes,
            &second_canonical_precommit_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(
                stop,
            )) => Ok(FixedValidatorNodeDriverStepOutcomeV0::FinalityStopped(stop)),
            Ok(FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                scope,
                rejection,
            }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::CurrentFinality(
                        rejection,
                    )),
                })
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(
                Box::new(source),
            )),
        }
    }

    pub(super) fn execute_evidence(
        mut self,
        action: FixedValidatorNodeDriverActionV0,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.try_pair_higher_round_inbox_at(
            &mut self.inbox,
            action.position,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Signed {
                scope,
                vote,
                proposal,
            }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: Some(proposal),
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::Rejected {
                scope,
                rejection,
            }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(
                        FixedValidatorNodeDriverStepRejectionV0::EvidenceExecution(rejection),
                    ),
                })
            }
            Ok(FixedValidatorNodeBufferedProposalPrecommitOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Evidence(Box::new(
                source,
            ))),
        }
    }

    pub(super) fn execute_current_nil_precommit(
        mut self,
        canonical_signed_precommits: Vec<[u8; VerifiedConsensusVoteV0::BYTE_LENGTH]>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let mut vote_refs: Vec<&[u8]> = Vec::new();
        if let Err(source) = vote_refs.try_reserve_exact(canonical_signed_precommits.len()) {
            return Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                driver: Box::new(self),
                rejection: Box::new(
                    FixedValidatorNodeDriverStepRejectionV0::SelectionReservation(source),
                ),
            });
        }
        vote_refs.extend(
            canonical_signed_precommits
                .iter()
                .map(|canonical| canonical.as_slice()),
        );
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope
            .advance_round_for_nil_precommit_vote_batch(&vote_refs, self.inclusive_maximum_round)
        {
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. }) => {
                self.scope = Some(*scope);
                let timeout = self.install_next_timeout(next_generation);
                self.pending_command = Some(PendingCommandV0::Arm(timeout));
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(
                        rejection,
                    )),
                })
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(Box::new(
                source,
            ))),
        }
    }

    pub(super) fn execute_current_proposal(
        mut self,
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.sign_prevote_for_proposal(
            &canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: None,
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
        }
    }

    pub(super) fn execute_current_proposal_quorum(
        mut self,
        canonical_proposal_control_bytes: Vec<u8>,
        canonical_artifact_bytes: Vec<u8>,
        canonical_prevote_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.sign_precommit_for_proposal_quorum(
            &canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            &canonical_prevote_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: None,
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
        }
    }

    pub(super) fn execute_current_nil_quorum(
        mut self,
        canonical_prevote_certificate: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let scope = self.take_scope();
        match scope.sign_precommit_for_nil_quorum(
            &canonical_prevote_certificate,
            self.inclusive_maximum_round,
        ) {
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                self.scope = Some(*scope);
                self.invalidate_timeout();
                self.pending_command = Some(PendingCommandV0::Publish {
                    vote,
                    released_proposal: None,
                    successor_generation: next_generation,
                });
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                    driver: Box::new(self),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(rejection)),
                })
            }
            Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
        }
    }

    pub(super) fn execute_due(
        mut self,
    ) -> Result<FixedValidatorNodeDriverStepOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        let next_generation = self.next_generation()?;
        let active_timeout = self
            .active_timeout
            .expect("a due driver always retains its exact active timeout");
        let context = active_timeout.context;
        let position = active_timeout.position;
        let phase = active_timeout.phase;
        let scope = self.take_scope();
        match phase {
            FixedValidatorLockPhaseV0::Proposal | FixedValidatorLockPhaseV0::Prevote => {
                let result = if phase == FixedValidatorLockPhaseV0::Proposal {
                    scope.sign_prevote_after_proposal_close(
                        context,
                        position,
                        self.inclusive_maximum_round,
                    )
                } else {
                    scope.sign_precommit_after_prevote_close(
                        context,
                        position,
                        self.inclusive_maximum_round,
                    )
                };
                match result {
                    Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Signed { scope, vote }) => {
                        self.scope = Some(*scope);
                        self.invalidate_timeout();
                        self.pending_command = Some(PendingCommandV0::Publish {
                            vote,
                            released_proposal: None,
                            successor_generation: next_generation,
                        });
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                            driver: Box::new(self),
                        })
                    }
                    Ok(FixedValidatorNodeVoteExecutionOutcomeV0::Rejected { scope, rejection }) => {
                        self.scope = Some(*scope);
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                            driver: Box::new(self),
                            rejection: Box::new(FixedValidatorNodeDriverStepRejectionV0::Vote(
                                rejection,
                            )),
                        })
                    }
                    Ok(FixedValidatorNodeVoteExecutionOutcomeV0::SignerStopped(stop)) => {
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::SignerStopped(stop))
                    }
                    Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::Vote(Box::new(source))),
                }
            }
            FixedValidatorLockPhaseV0::Precommit => {
                match scope.advance_round_after_precommit_close(
                    context,
                    position,
                    self.inclusive_maximum_round,
                ) {
                    Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. }) => {
                        self.scope = Some(*scope);
                        let timeout = self.install_next_timeout(next_generation);
                        self.pending_command = Some(PendingCommandV0::Arm(timeout));
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Transitioned {
                            driver: Box::new(self),
                        })
                    }
                    Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection }) => {
                        self.scope = Some(*scope);
                        Ok(FixedValidatorNodeDriverStepOutcomeV0::Rejected {
                            driver: Box::new(self),
                            rejection: Box::new(
                                FixedValidatorNodeDriverStepRejectionV0::RoundAdvance(rejection),
                            ),
                        })
                    }
                    Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(
                        Box::new(source),
                    )),
                }
            }
        }
    }
}
