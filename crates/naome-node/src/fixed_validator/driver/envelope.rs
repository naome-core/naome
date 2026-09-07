//! Complete direct-child proof ingress, independent of the live signer round.
use super::*;
use crate::fixed_validator::finality::{
    CurrentRoundFinalityRoundErrorV0, current_round_for_finality,
};
use naome_consensus::FixedConsensusBoundedEnvelopeVerifyError;

/// Unchanged-state rejection before any anchored finality effect.
#[derive(Debug)]
pub enum FixedValidatorNodeEnvelopeRejectionV0 {
    Preflight(Box<FixedValidatorNodeCurrentRoundFinalityRejectionV0>),
    Proof(Box<FixedConsensusBoundedEnvelopeVerifyError>),
}
impl fmt::Display for FixedValidatorNodeEnvelopeRejectionV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "complete finality proof rejected: {self:?}")
    }
}
impl Error for FixedValidatorNodeEnvelopeRejectionV0 {}

/// Custody after a single explicitly submitted complete direct-child proof.
#[must_use]
pub enum FixedValidatorNodeDriverEnvelopeOutcomeV0<'node> {
    CommandPending {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    CurrentFinalityUnresolved {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
    },
    Rejected {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        rejection: Box<FixedValidatorNodeEnvelopeRejectionV0>,
    },
    Finality {
        driver: Box<FixedValidatorNodeDriverV0<'node>>,
        selection: FixedValidatorNodeFinalitySelectionV0,
    },
    FinalityStopped(Box<FixedValidatorNodeFinalityStoppedV0>),
}

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Verifies only the complete envelope's direct child of the live branch.
    /// Pending commands and retained current-finality priority precede input
    /// inspection. Both local and persisted round ceilings remain binding.
    /// Rejection preserves the driver; durable-effect failure consumes it.
    /// No proposal/vote is signed, source is populated, or old-height conflict
    /// is routed. Successful anchored handoff queues one child Proposal arm.
    pub fn commit_finality_envelope(
        mut self,
        envelope: &[u8],
        payload: Vec<u8>,
    ) -> Result<FixedValidatorNodeDriverEnvelopeOutcomeV0<'node>, FixedValidatorNodeDriverStepErrorV0>
    {
        use FixedValidatorNodeDriverEnvelopeOutcomeV0 as Outcome;
        use FixedValidatorNodeEnvelopeRejectionV0 as Rejection;
        if self.pending_command.is_some() {
            return Ok(Outcome::CommandPending {
                driver: Box::new(self),
            });
        }
        if self
            .current_finality_is_unresolved()
            .map_err(FixedValidatorNodeDriverStepErrorV0::Round)?
        {
            return Ok(Outcome::CurrentFinalityUnresolved {
                driver: Box::new(self),
            });
        }
        let generation = self.next_generation()?;
        let maximum = self.inclusive_maximum_round;
        let scope = self.scope();
        let persisted = ConsensusRound::new(scope.finality.replay_limit().max_round());
        match current_round_for_finality(
            &scope.branch,
            scope.signing_session.position(),
            maximum,
            persisted,
        ) {
            Ok(round) => drop(round),
            Err(CurrentRoundFinalityRoundErrorV0::Rejected(reason)) => {
                return Ok(Outcome::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(Rejection::Preflight(Box::new(reason))),
                });
            }
            Err(CurrentRoundFinalityRoundErrorV0::Fatal(error)) => {
                return Err(FixedValidatorNodeDriverStepErrorV0::CurrentFinality(
                    Box::new(error),
                ));
            }
        }
        let transition = match self
            .scope()
            .branch
            .decode_and_verify_envelope_with_round_limit(envelope, payload, maximum.min(persisted))
        {
            Ok(transition) => transition,
            Err(error) => {
                return Ok(Outcome::Rejected {
                    driver: Box::new(self),
                    rejection: Box::new(Rejection::Proof(Box::new(error))),
                });
            }
        };
        match self
            .take_scope()
            .commit_verified_finality(transition)
            .map_err(|error| {
                FixedValidatorNodeDriverStepErrorV0::CurrentFinality(Box::new(
                    FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(Box::new(error)),
                ))
            })? {
            FixedValidatorNodeFinalityOutcomeV0::Continues { scope, selection } => {
                self.scope = Some(*scope);
                let timeout = self.install_next_timeout(generation);
                self.pending_command = Some(PendingCommandV0::Arm(timeout));
                Ok(Outcome::Finality {
                    driver: Box::new(self),
                    selection,
                })
            }
            FixedValidatorNodeFinalityOutcomeV0::FinalityStopped(halt) => {
                Ok(Outcome::FinalityStopped(halt))
            }
        }
    }
}
