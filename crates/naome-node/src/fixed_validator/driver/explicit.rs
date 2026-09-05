//! Caller-selected catch-up, finality, and proposal authoring.

use super::*;

enum DriverLowerRoundFinalityInputV0<'input> {
    Certificate(&'input [u8]),
    VoteBatch {
        canonical_signed_precommits: &'input [&'input [u8]],
        evidence_round: ConsensusRound,
    },
}

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Checkpoints one explicitly supplied, fully verified higher-round quorum.
    ///
    /// Pending commands, non-fallthrough exact-current finality, and retained
    /// actionable or blocked higher-round proposal evidence take precedence.
    /// Those cases return the unchanged driver without inspecting the supplied
    /// certificate; use `step` or the appropriate lossless drain first.
    /// Otherwise the existing node coordinator enforces the construction-time
    /// round ceiling, preserves lock and complete valid evidence, and persists
    /// the checkpoint and independent anchor before returning continued authority.
    /// Success replaces the old timer with one pending arm, clears due state,
    /// and preserves all four inboxes. It neither signs nor changes finality.
    /// Every fatal error consumes the driver and requires strict anchored reopen.
    pub fn advance_to_higher_round_quorum(
        self,
        canonical_certificate: &[u8],
    ) -> Result<
        FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.advance_to_higher_round_input(DriverHigherRoundInputV0::Certificate(
            canonical_certificate,
        ))
    }

    /// Checkpoints one explicitly routed exact higher-round signed-vote batch.
    ///
    /// This has the same priority, timer, custody, and failure contract as
    /// [`Self::advance_to_higher_round_quorum`]. Routing metadata grants no
    /// authority: the existing coordinator authenticates every supplied vote
    /// all-or-nothing at the exact round, role, and target under the driver's
    /// construction-time ceiling. No input is retained or automatically chosen.
    pub fn advance_to_higher_round_vote_batch(
        self,
        canonical_signed_votes: &[&[u8]],
        evidence_round: ConsensusRound,
        expected_role: ConsensusVoteRole,
        expected_target: ConsensusVoteTarget,
    ) -> Result<
        FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.advance_to_higher_round_input(DriverHigherRoundInputV0::VoteBatch {
            canonical_signed_votes,
            evidence_round,
            expected_role,
            expected_target,
        })
    }

    pub(super) fn advance_to_higher_round_input(
        mut self,
        input: DriverHigherRoundInputV0<'_>,
    ) -> Result<
        FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }
        if self
            .current_finality_is_unresolved()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?
        {
            return Ok(
                FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::CurrentFinalityUnresolved {
                    driver: Box::new(self),
                },
            );
        }
        if self.higher_block_reason().is_some()
            || !matches!(
                self.select_actionable_higher_round()?,
                DriverEvidenceSelectionV0::None
            )
        {
            return Ok(
                FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::HigherEvidenceUnresolved {
                    driver: Box::new(self),
                },
            );
        }
        let next_generation = self.next_generation()?;
        let maximum_round = self.inclusive_maximum_round;
        let scope = self.take_scope();
        let result = match input {
            DriverHigherRoundInputV0::Certificate(bytes) => {
                scope.advance_to_higher_round_quorum(bytes, maximum_round)
            }
            DriverHigherRoundInputV0::VoteBatch {
                canonical_signed_votes,
                evidence_round,
                expected_role,
                expected_target,
            } => scope.advance_to_higher_round_vote_batch(
                canonical_signed_votes,
                FixedValidatorNodeHigherRoundVoteBatchRouteV0::new(
                    evidence_round,
                    expected_role,
                    expected_target,
                    maximum_round,
                ),
            ),
        };
        match result {
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Advanced { scope, .. }) => {
                self.scope = Some(*scope);
                let timeout = self.install_next_timeout(next_generation);
                self.pending_command = Some(PendingCommandV0::Arm(timeout));
                Ok(
                    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::Advanced {
                        driver: Box::new(self),
                    },
                )
            }
            Ok(FixedValidatorNodeRoundAdvanceOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(
                    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection,
                    },
                )
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::RoundAdvance(Box::new(
                source,
            ))),
        }
    }

    /// Routes one exact candidate-backed direct-child finality batch.
    ///
    /// Pending command custody and every non-fallthrough exact-current finality
    /// classification return the unchanged driver before candidate input or
    /// source work. Otherwise this preflights a successor timer generation and
    /// delegates the explicit caller target, proposal, exact precommit batch,
    /// evidence round, and source stores to the existing fully verifying
    /// candidate-backed coordinator under the driver's construction-time round
    /// ceiling. A pre-effect rejection restores the unchanged driver. Successful
    /// height advancement queues exactly one child round-zero Proposal arm;
    /// every fatal or post-effect failure consumes the driver and requires strict
    /// anchored reopen.
    pub fn commit_candidate_backed_finality_vote_batch(
        mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: naome_chain::ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0<'node>,
        FixedValidatorNodeDriverCandidateBackedFinalityErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }

        if self
            .current_finality_is_unresolved()
            .map_err(FixedValidatorNodeDriverCandidateBackedFinalityErrorV0::CurrentFinalityRound)?
        {
            return Ok(
                FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::CurrentFinalityUnresolved {
                    driver: Box::new(self),
                },
            );
        }

        let next_generation = self.generation.checked_add(1).ok_or(
            FixedValidatorNodeDriverCandidateBackedFinalityErrorV0::TimeoutGenerationExhausted {
                generation: self.generation,
            },
        )?;
        let previous_position = self.position();
        let inclusive_maximum_round = self.inclusive_maximum_round;
        let scope = self.take_scope();
        match scope.commit_candidate_backed_finality_vote_batch(
            candidates,
            payloads,
            expected_target,
            canonical_proposal_control_bytes,
            canonical_signed_precommits,
            FixedValidatorNodeFinalityRoundRouteV0::new(evidence_round, inclusive_maximum_round),
        ) {
            Ok(FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection },
            )) => {
                self.scope = Some(*scope);
                if self.position() != previous_position {
                    let timeout = self.install_next_timeout(next_generation);
                    self.pending_command = Some(PendingCommandV0::Arm(timeout));
                }
                Ok(
                    FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::Finality {
                        driver: Box::new(self),
                        selection,
                    },
                )
            }
            Ok(FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(stopped),
            )) => Ok(
                FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::FinalityStopped(stopped),
            ),
            Ok(FixedValidatorNodeCandidateBackedFinalityOutcomeV0::Rejected {
                scope,
                rejection,
            }) => {
                self.scope = Some(*scope);
                Ok(
                    FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection,
                    },
                )
            }
            Err(source) => Err(
                FixedValidatorNodeDriverCandidateBackedFinalityErrorV0::Finality(Box::new(source)),
            ),
        }
    }

    /// Finalizes one directly supplied strictly lower-round proposal and certificate.
    ///
    /// Pending commands and every non-fallthrough current-finality classification
    /// return the unchanged driver before supplied-input inspection. Otherwise a
    /// checked successor timer generation precedes the existing fully verifying
    /// lower-round coordinator, using this driver's construction-time ceiling.
    /// The certificate supplies only unauthenticated routing metadata until the
    /// complete proposal, payload, producer, fixed set, and proof are verified.
    ///
    /// Typed pre-effect rejection restores the unchanged driver. A child-height
    /// handoff preserves all four inboxes, replaces the old timer and due state,
    /// and queues one round-zero Proposal arm. Every fatal error consumes the
    /// driver and requires strict anchored reopen. The owned payload is consumed
    /// on every outcome; the driver retains none of the submitted input.
    pub fn commit_lower_round_finality(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_precommit_certificate: &[u8],
    ) -> Result<
        FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.commit_lower_round_finality_input(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            DriverLowerRoundFinalityInputV0::Certificate(canonical_precommit_certificate),
        )
    }

    /// Finalizes one directly supplied strictly lower-round exact precommit batch.
    ///
    /// This shares the priority, custody, timer, and failure contract of
    /// [`Self::commit_lower_round_finality`]. The explicit round is bounded route
    /// metadata only: the existing coordinator independently authenticates the
    /// proposal and every vote at that exact round, without filtering or grouping.
    pub fn commit_lower_round_finality_vote_batch(
        self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.commit_lower_round_finality_input(
            canonical_proposal_control_bytes,
            canonical_artifact_bytes,
            DriverLowerRoundFinalityInputV0::VoteBatch {
                canonical_signed_precommits,
                evidence_round,
            },
        )
    }

    fn commit_lower_round_finality_input(
        mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        input: DriverLowerRoundFinalityInputV0<'_>,
    ) -> Result<
        FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }
        if self
            .current_finality_is_unresolved()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?
        {
            return Ok(
                FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0::CurrentFinalityUnresolved {
                    driver: Box::new(self),
                },
            );
        }
        let next_generation = self.next_generation()?;
        let previous_position = self.position();
        let maximum_round = self.inclusive_maximum_round;
        let scope = self.take_scope();
        let result = match input {
            DriverLowerRoundFinalityInputV0::Certificate(certificate) => scope
                .commit_lower_round_finality(
                    canonical_proposal_control_bytes,
                    canonical_artifact_bytes,
                    certificate,
                    maximum_round,
                ),
            DriverLowerRoundFinalityInputV0::VoteBatch {
                canonical_signed_precommits,
                evidence_round,
            } => scope.commit_lower_round_finality_vote_batch(
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_signed_precommits,
                FixedValidatorNodeFinalityRoundRouteV0::new(evidence_round, maximum_round),
            ),
        };
        match result {
            Ok(FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection },
            )) => {
                self.scope = Some(*scope);
                if self.position() != previous_position {
                    let timeout = self.install_next_timeout(next_generation);
                    self.pending_command = Some(PendingCommandV0::Arm(timeout));
                }
                Ok(
                    FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0::Finality {
                        driver: Box::new(self),
                        selection,
                    },
                )
            }
            Ok(FixedValidatorNodeLowerRoundFinalityOutcomeV0::Finality(
                FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(stopped),
            )) => Ok(FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0::FinalityStopped(stopped)),
            Ok(FixedValidatorNodeLowerRoundFinalityOutcomeV0::Rejected { scope, rejection }) => {
                self.scope = Some(*scope);
                Ok(
                    FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection,
                    },
                )
            }
            Err(source) => Err(FixedValidatorNodeDriverStepErrorV0::LowerRoundFinality(
                Box::new(source),
            )),
        }
    }

    /// Routes one exact candidate-backed historical sibling conflict.
    ///
    /// An already pending outward command causes the unchanged driver to be
    /// returned before any input or store inspection. Otherwise this consumes
    /// the sole signing scope and delegates the caller-selected target, proposal,
    /// exact precommit batch, and evidence round to the existing fully verifying
    /// candidate-backed finality coordinator. The driver's construction-time
    /// round ceiling is reused as the local work ceiling. Every proof-processing
    /// success or error consumes the driver; success returns only terminal
    /// finality-and-signer evidence.
    pub fn commit_candidate_backed_finality_conflict_vote_batch(
        mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: naome_chain::ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0<'node>,
        FixedValidatorNodeFinalityErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }
        let inclusive_maximum_round = self.inclusive_maximum_round;
        let scope = self.take_scope();
        scope
            .commit_candidate_backed_finality_conflict_vote_batch(
                candidates,
                payloads,
                expected_target,
                canonical_proposal_control_bytes,
                canonical_signed_precommits,
                FixedValidatorNodeFinalityRoundRouteV0::new(
                    evidence_round,
                    inclusive_maximum_round,
                ),
            )
            .map(|stopped| {
                FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0::FinalityStopped(
                    Box::new(stopped),
                )
            })
    }

    /// Submits two complete exact-current proof batches for one neutral halt.
    ///
    /// Pending outward command custody is the sole driver gate. No retained
    /// evidence is classified or stepped first. The existing coordinator derives
    /// the current round, applies this driver's construction-time work ceiling,
    /// and independently verifies both proofs before any durable effect.
    /// Typed pre-effect rejection restores the unchanged driver. A verified
    /// distinct pair or any fatal error consumes it; strict anchored reopen is
    /// the sole later durable-state classifier. Owned payloads are consumed on
    /// every outcome, including pending-command and continuing rejection.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_current_round_preselection_conflict_vote_batches(
        mut self,
        first_canonical_proposal_control_bytes: &[u8],
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_signed_precommits: &[&[u8]],
        second_canonical_proposal_control_bytes: &[u8],
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_signed_precommits: &[&[u8]],
    ) -> Result<
        FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0<'node>,
        FixedValidatorNodeCurrentRoundFinalityErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }
        let scope = self.take_scope();
        match scope.commit_current_round_preselection_conflict_vote_batches(
            first_canonical_proposal_control_bytes,
            first_canonical_artifact_bytes,
            first_canonical_signed_precommits,
            second_canonical_proposal_control_bytes,
            second_canonical_artifact_bytes,
            second_canonical_signed_precommits,
            self.inclusive_maximum_round,
        )? {
            FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                scope,
                rejection,
            } => {
                self.scope = Some(*scope);
                Ok(
                    FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection,
                    },
                )
            }
            FixedValidatorNodeCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(
                stopped,
            ) => Ok(
                FixedValidatorNodeDriverCurrentRoundPreselectionConflictOutcomeV0::FinalityStopped(
                    stopped,
                ),
            ),
        }
    }

    /// Submits one explicitly routed strictly lower-round pair for a neutral halt.
    ///
    /// Pending outward command custody is the sole driver gate. After transfer,
    /// current-round inbox state, phase, due state, and timer generation do not
    /// delay complete independent verification by the existing lower-round
    /// paired coordinator. The explicit round is bounded by this driver's
    /// construction-time ceiling. Typed pre-effect rejection restores the
    /// unchanged driver; success and every fatal error return no driver and
    /// require strict anchored reopen for any later state classification.
    ///
    /// Owned payload arguments are consumed even on a driver-returning outcome.
    /// This method retains no caller evidence and performs no acquisition,
    /// automatic event selection, retry, or timer transition.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lower_round_preselection_conflict_vote_batches(
        mut self,
        first_canonical_proposal_control_bytes: &[u8],
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_signed_precommits: &[&[u8]],
        second_canonical_proposal_control_bytes: &[u8],
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<
        FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0<'node>,
        FixedValidatorNodeLowerRoundFinalityErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }
        let route = FixedValidatorNodeFinalityRoundRouteV0::new(
            evidence_round,
            self.inclusive_maximum_round,
        );
        let scope = self.take_scope();
        match scope.commit_lower_round_preselection_conflict_vote_batches(
            first_canonical_proposal_control_bytes,
            first_canonical_artifact_bytes,
            first_canonical_signed_precommits,
            second_canonical_proposal_control_bytes,
            second_canonical_artifact_bytes,
            second_canonical_signed_precommits,
            route,
        )? {
            FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::Rejected {
                scope,
                rejection,
            } => {
                self.scope = Some(*scope);
                Ok(
                    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection,
                    },
                )
            }
            FixedValidatorNodeLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(stopped) => {
                Ok(
                    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0::FinalityStopped(stopped),
                )
            }
        }
    }

    /// Authors one current-round proposal from explicit fresh or retained-value input.
    ///
    /// Existing commands and all work selected or blocked by `step` take priority.
    /// Success queues publication with the exact payload, preserves every inbox
    /// and the current timer, and does not admit the proposal for local voting.
    pub fn author_proposal(
        self,
        source: FixedValidatorProposalSourceV0,
    ) -> Result<
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.author_proposal_with_input(NodeProposalInputV0::Direct(source))
    }

    /// Authors the caller's exact fresh candidate through its two availability stores.
    ///
    /// Driver work, phase, proposer, and source-kind checks precede store access.
    /// The stores grant availability only; complete proposal validation is unchanged.
    pub fn author_candidate_backed_fresh_proposal(
        self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: naome_chain::ArtifactBlockId,
    ) -> Result<
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.author_proposal_with_input(NodeProposalInputV0::CandidateFresh {
            candidates,
            payloads,
            expected_target,
        })
    }

    /// Re-authors the private retained value using its exact payload-store address.
    ///
    /// The retained value and certificate remain authoritative; source membership
    /// supplies only availability and is resolved once before any signer effect.
    pub fn author_payload_store_backed_retained_proposal(
        self,
        payloads: &mut CanonicalArtifactPayloadStore,
    ) -> Result<
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        self.author_proposal_with_input(NodeProposalInputV0::PayloadRetained(payloads))
    }

    pub(super) fn author_proposal_with_input(
        mut self,
        input: NodeProposalInputV0<'_>,
    ) -> Result<
        FixedValidatorNodeDriverProposalAuthoringOutcomeV0<'node>,
        FixedValidatorNodeDriverStepErrorV0,
    > {
        if self.pending_command.is_some() {
            return Ok(
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::CommandPending {
                    driver: Box::new(self),
                },
            );
        }
        if !matches!(self.classify_ordinary_work()?, DriverOrdinaryWorkV0::Idle) {
            return Ok(
                FixedValidatorNodeDriverProposalAuthoringOutcomeV0::StepWorkPending {
                    driver: Box::new(self),
                },
            );
        }
        let scope = self.take_scope();
        let (outcome, canonical_artifact_bytes) = scope
            .author_proposal_for_driver(input, self.inclusive_maximum_round)
            .map_err(|source| {
                FixedValidatorNodeDriverStepErrorV0::ProposalAuthoring(Box::new(source))
            })?;
        match outcome {
            FixedValidatorNodeProposalAuthoringOutcomeV0::Authored { scope, proposal } => {
                self.scope = Some(*scope);
                self.pending_command = Some(PendingCommandV0::PublishProposal {
                    proposal,
                    canonical_artifact_bytes,
                });
                Ok(
                    FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Authored {
                        driver: Box::new(self),
                    },
                )
            }
            FixedValidatorNodeProposalAuthoringOutcomeV0::Rejected { scope, rejection } => {
                self.scope = Some(*scope);
                Ok(
                    FixedValidatorNodeDriverProposalAuthoringOutcomeV0::Rejected {
                        driver: Box::new(self),
                        rejection,
                    },
                )
            }
            FixedValidatorNodeProposalAuthoringOutcomeV0::SignerStopped(halt) => {
                Ok(FixedValidatorNodeDriverProposalAuthoringOutcomeV0::SignerStopped(halt))
            }
        }
    }
}
