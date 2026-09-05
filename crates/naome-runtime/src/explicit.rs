//! Caller-selected complete proofs through the existing driver coordinators.

use super::*;
use crate::FixedValidatorRuntimeProofRefusalV0 as ProofRefusal;
use naome_consensus::{ConsensusPosition, ConsensusRound, ConsensusVoteRole, ConsensusVoteTarget};
use naome_node::{
    FixedValidatorNodeDriverCandidateBackedFinalityConflictOutcomeV0 as CandidateConflict,
    FixedValidatorNodeDriverCandidateBackedFinalityErrorV0,
    FixedValidatorNodeDriverCandidateBackedFinalityOutcomeV0 as CandidateFinality,
    FixedValidatorNodeDriverHigherRoundAdvanceOutcomeV0 as HigherAdvance,
    FixedValidatorNodeDriverLowerRoundFinalityOutcomeV0 as LowerFinality,
    FixedValidatorNodeDriverLowerRoundPreselectionConflictOutcomeV0 as LowerConflict,
    FixedValidatorNodeDriverStepErrorV0,
};

impl<'node> FixedValidatorRuntimeV0<'node> {
    /// Explicitly checkpoints the caller's complete higher-round certificate.
    /// Publication and pending arm/command custody return `Busy` before any
    /// driver call. Buffered input, phase, and due state add no runtime gate;
    /// existing driver priorities and independent verification remain binding.
    pub fn advance_to_higher_round_quorum(
        &mut self,
        canonical_certificate: &[u8],
    ) -> Result<Event<'node>, ProofRefusal> {
        self.proof_gate()?;
        let driver = self.driver.take().unwrap();
        Ok(
            self.finish_higher_advance(
                driver.advance_to_higher_round_quorum(canonical_certificate),
            ),
        )
    }

    /// Explicitly checkpoints one exactly routed higher-round signed-vote batch.
    /// Shares the custody and priority contract of `advance_to_higher_round_quorum`.
    pub fn advance_to_higher_round_vote_batch(
        &mut self,
        canonical_signed_votes: &[&[u8]],
        evidence_round: ConsensusRound,
        expected_role: ConsensusVoteRole,
        expected_target: ConsensusVoteTarget,
    ) -> Result<Event<'node>, ProofRefusal> {
        self.proof_gate()?;
        let driver = self.driver.take().unwrap();
        Ok(
            self.finish_higher_advance(driver.advance_to_higher_round_vote_batch(
                canonical_signed_votes,
                evidence_round,
                expected_role,
                expected_target,
            )),
        )
    }

    /// Finalizes the caller's exact lower-round proposal and certificate through
    /// the existing driver. Runtime refusal returns the original payload before
    /// invocation; after invocation every outcome consumes it as in the driver.
    /// Buffered input stays raw and receives no new admission authority.
    pub fn commit_lower_round_finality(
        &mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_precommit_certificate: &[u8],
    ) -> Result<Event<'node>, (ProofRefusal, Vec<u8>)> {
        if let Err(reason) = self.proof_gate() {
            return Err((reason, canonical_artifact_bytes));
        }
        let driver = self.driver.take().unwrap();
        let previous_position = driver.position();
        Ok(self.finish_lower_finality(
            driver.commit_lower_round_finality(
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_precommit_certificate,
            ),
            previous_position,
        ))
    }

    /// Finalizes the caller's exact lower-round proposal and signed-precommit batch.
    /// Shares `commit_lower_round_finality` custody, refusal, and driver priorities.
    pub fn commit_lower_round_finality_vote_batch(
        &mut self,
        canonical_proposal_control_bytes: &[u8],
        canonical_artifact_bytes: Vec<u8>,
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<Event<'node>, (ProofRefusal, Vec<u8>)> {
        if let Err(reason) = self.proof_gate() {
            return Err((reason, canonical_artifact_bytes));
        }
        let driver = self.driver.take().unwrap();
        let previous_position = driver.position();
        Ok(self.finish_lower_finality(
            driver.commit_lower_round_finality_vote_batch(
                canonical_proposal_control_bytes,
                canonical_artifact_bytes,
                canonical_signed_precommits,
                evidence_round,
            ),
            previous_position,
        ))
    }

    /// Finalizes only the caller's exact candidate, proposal, and precommit batch.
    /// Runtime backpressure precedes source access; the existing driver grants
    /// selection only after complete independent verification and anchored effects.
    pub fn commit_candidate_backed_finality_vote_batch(
        &mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: naome_chain::ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<Event<'node>, ProofRefusal> {
        self.proof_gate()?;
        let driver = self.driver.take().unwrap();
        let previous_position = driver.position();
        Ok(self.finish_candidate_finality(
            driver.commit_candidate_backed_finality_vote_batch(
                candidates,
                payloads,
                expected_target,
                canonical_proposal_control_bytes,
                canonical_signed_precommits,
                evidence_round,
            ),
            previous_position,
        ))
    }

    /// Checks one explicitly routed historical sibling conflict as soon as
    /// pending driver commands have transferred. An owned publication, pending
    /// runtime arm, buffered input, or elapsed/due timer does not delay it.
    /// After delegation, both success and error consume the driver. Surviving
    /// runtime custody remains available through `into_parts`; queued transport
    /// work cannot be recalled, and no later `next_event` signs or starts sends.
    pub fn commit_candidate_backed_finality_conflict_vote_batch(
        &mut self,
        candidates: &mut ArtifactBlockCandidateStore,
        payloads: &mut CanonicalArtifactPayloadStore,
        expected_target: naome_chain::ArtifactBlockId,
        canonical_proposal_control_bytes: &[u8],
        canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<Event<'node>, ProofRefusal> {
        self.proof_command_gate()?;
        let driver = self.driver.take().unwrap();
        Ok(
            match driver.commit_candidate_backed_finality_conflict_vote_batch(
                candidates,
                payloads,
                expected_target,
                canonical_proposal_control_bytes,
                canonical_signed_precommits,
                evidence_round,
            ) {
                Ok(CandidateConflict::CommandPending { driver }) => {
                    self.driver = Some(*driver);
                    Event::ExplicitCommandPending
                }
                Ok(CandidateConflict::FinalityStopped(halt)) => {
                    Event::Fatal(Box::new(Failure::FinalityStopped(halt)))
                }
                Ok(other) => Event::UnsupportedCandidateBackedConflict(Box::new(other)),
                Err(error) => Event::Fatal(Box::new(Failure::CandidateBackedConflict(error))),
            },
        )
    }

    /// Checks two explicit lower-round proofs for a neutral halt. Pending driver
    /// commands are the sole runtime backpressure gate, as for the candidate
    /// conflict method. Runtime refusal returns both original payloads in order;
    /// after delegation all outcomes consume them under the driver contract.
    /// A typed pre-effect rejection restores the driver and all runtime markers;
    /// terminal and fatal outcomes preserve only independent runtime custody.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_lower_round_preselection_conflict_vote_batches(
        &mut self,
        first_canonical_proposal_control_bytes: &[u8],
        first_canonical_artifact_bytes: Vec<u8>,
        first_canonical_signed_precommits: &[&[u8]],
        second_canonical_proposal_control_bytes: &[u8],
        second_canonical_artifact_bytes: Vec<u8>,
        second_canonical_signed_precommits: &[&[u8]],
        evidence_round: ConsensusRound,
    ) -> Result<Event<'node>, (ProofRefusal, Vec<u8>, Vec<u8>)> {
        if let Err(reason) = self.proof_command_gate() {
            return Err((
                reason,
                first_canonical_artifact_bytes,
                second_canonical_artifact_bytes,
            ));
        }
        let driver = self.driver.take().unwrap();
        Ok(
            match driver.commit_lower_round_preselection_conflict_vote_batches(
                first_canonical_proposal_control_bytes,
                first_canonical_artifact_bytes,
                first_canonical_signed_precommits,
                second_canonical_proposal_control_bytes,
                second_canonical_artifact_bytes,
                second_canonical_signed_precommits,
                evidence_round,
            ) {
                Ok(LowerConflict::CommandPending { driver }) => {
                    self.driver = Some(*driver);
                    Event::ExplicitCommandPending
                }
                Ok(LowerConflict::Rejected { driver, rejection }) => {
                    self.driver = Some(*driver);
                    Event::LowerRoundPreselectionConflictRejected(rejection)
                }
                Ok(LowerConflict::FinalityStopped(halt)) => {
                    Event::Fatal(Box::new(Failure::FinalityStopped(halt)))
                }
                Ok(other) => Event::UnsupportedLowerRoundPreselectionConflict(Box::new(other)),
                Err(error) => {
                    Event::Fatal(Box::new(Failure::LowerRoundPreselectionConflict(error)))
                }
            },
        )
    }

    fn proof_command_gate(&self) -> Result<(), ProofRefusal> {
        let driver = self
            .driver
            .as_ref()
            .ok_or(ProofRefusal::DriverUnavailable)?;
        if driver.has_pending_command() {
            Err(ProofRefusal::Busy)
        } else {
            Ok(())
        }
    }

    fn proof_gate(&self) -> Result<(), ProofRefusal> {
        self.proof_command_gate()?;
        if self.publication.is_some() || self.pending_arm.is_some() {
            Err(ProofRefusal::Busy)
        } else {
            Ok(())
        }
    }

    fn finish_higher_advance(
        &mut self,
        result: Result<HigherAdvance<'node>, FixedValidatorNodeDriverStepErrorV0>,
    ) -> Event<'node> {
        let (driver, event, advanced) = match result {
            Ok(HigherAdvance::CommandPending { driver }) => {
                (driver, Event::ExplicitCommandPending, false)
            }
            Ok(HigherAdvance::CurrentFinalityUnresolved { driver }) => {
                (driver, Event::CurrentFinalityUnresolved, false)
            }
            Ok(HigherAdvance::HigherEvidenceUnresolved { driver }) => {
                (driver, Event::HigherEvidenceUnresolved, false)
            }
            Ok(HigherAdvance::Rejected { driver, rejection }) => {
                (driver, Event::HigherRoundAdvanceRejected(rejection), false)
            }
            Ok(HigherAdvance::Advanced { driver }) => {
                let event = Event::Transitioned {
                    position: driver.position(),
                    phase: driver.phase(),
                };
                (driver, event, true)
            }
            Ok(other) => return Event::UnsupportedHigherRoundAdvance(Box::new(other)),
            Err(error) => return Event::Fatal(Box::new(Failure::Step(error))),
        };
        self.restore_proof_driver(*driver, advanced);
        event
    }

    fn finish_lower_finality(
        &mut self,
        result: Result<LowerFinality<'node>, FixedValidatorNodeDriverStepErrorV0>,
        previous_position: ConsensusPosition,
    ) -> Event<'node> {
        let (driver, event, advanced) = match result {
            Ok(LowerFinality::CommandPending { driver }) => {
                (driver, Event::ExplicitCommandPending, false)
            }
            Ok(LowerFinality::CurrentFinalityUnresolved { driver }) => {
                (driver, Event::CurrentFinalityUnresolved, false)
            }
            Ok(LowerFinality::Rejected { driver, rejection }) => {
                (driver, Event::LowerRoundFinalityRejected(rejection), false)
            }
            Ok(LowerFinality::Finality { driver, selection }) => {
                let advanced = driver.position() != previous_position;
                (driver, Event::Finality(selection), advanced)
            }
            Ok(LowerFinality::FinalityStopped(halt)) => {
                return Event::Fatal(Box::new(Failure::FinalityStopped(halt)));
            }
            Ok(other) => return Event::UnsupportedLowerRoundFinality(Box::new(other)),
            Err(error) => return Event::Fatal(Box::new(Failure::Step(error))),
        };
        self.restore_proof_driver(*driver, advanced);
        event
    }

    fn finish_candidate_finality(
        &mut self,
        result: Result<
            CandidateFinality<'node>,
            FixedValidatorNodeDriverCandidateBackedFinalityErrorV0,
        >,
        previous_position: ConsensusPosition,
    ) -> Event<'node> {
        let (driver, event, advanced) = match result {
            Ok(CandidateFinality::CommandPending { driver }) => {
                (driver, Event::ExplicitCommandPending, false)
            }
            Ok(CandidateFinality::CurrentFinalityUnresolved { driver }) => {
                (driver, Event::CurrentFinalityUnresolved, false)
            }
            Ok(CandidateFinality::Rejected { driver, rejection }) => (
                driver,
                Event::CandidateBackedFinalityRejected(rejection),
                false,
            ),
            Ok(CandidateFinality::Finality { driver, selection }) => {
                let advanced = driver.position() != previous_position;
                (driver, Event::Finality(selection), advanced)
            }
            Ok(CandidateFinality::FinalityStopped(halt)) => {
                return Event::Fatal(Box::new(Failure::FinalityStopped(halt)));
            }
            Ok(other) => return Event::UnsupportedCandidateBackedFinality(Box::new(other)),
            Err(error) => return Event::Fatal(Box::new(Failure::CandidateBackedFinality(error))),
        };
        self.restore_proof_driver(*driver, advanced);
        event
    }

    fn restore_proof_driver(&mut self, driver: Driver<'node>, advanced: bool) {
        self.driver = Some(driver);
        if advanced {
            self.step_yielded = false;
            self.discard_superseded_deadline();
        }
    }
}
