//! Checked caller-local phase durations and exact driver-ticket deadlines.

use std::{error::Error, fmt, time::Duration};

use naome_consensus::{ConsensusRound, FixedValidatorLockPhaseV0};
use naome_node::FixedValidatorNodePhaseTimeoutV0;
use tokio::time::Instant;

/// Explicit positive local delivery interval, unrelated to consensus validity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorPublicationRetryIntervalV0(Duration);

impl FixedValidatorPublicationRetryIntervalV0 {
    pub fn new(duration: Duration) -> Result<Self, FixedValidatorRuntimeTimingErrorV0> {
        if duration.is_zero() {
            return Err(FixedValidatorRuntimeTimingErrorV0::ZeroRetryInterval);
        }
        let interval = Self(duration);
        interval.deadline()?;
        Ok(interval)
    }

    pub const fn duration(self) -> Duration {
        self.0
    }

    pub(crate) fn deadline(self) -> Result<Instant, FixedValidatorRuntimeTimingErrorV0> {
        Instant::now()
            .checked_add(self.0)
            .ok_or(FixedValidatorRuntimeTimingErrorV0::DeadlineOverflow)
    }
}

/// One positive phase base and positive per-round increment, with no defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorPhaseDurationV0 {
    base: Duration,
    round_increment: Duration,
}

impl FixedValidatorPhaseDurationV0 {
    pub fn new(
        base: Duration,
        round_increment: Duration,
    ) -> Result<Self, FixedValidatorRuntimeTimingErrorV0> {
        if base.is_zero() {
            return Err(FixedValidatorRuntimeTimingErrorV0::ZeroBase);
        }
        if round_increment.is_zero() {
            return Err(FixedValidatorRuntimeTimingErrorV0::ZeroRoundIncrement);
        }
        Ok(Self {
            base,
            round_increment,
        })
    }

    /// Computes `base + round * increment` without narrowing the `u64` round.
    pub fn duration(
        self,
        round: ConsensusRound,
    ) -> Result<Duration, FixedValidatorRuntimeTimingErrorV0> {
        let nanos = self
            .round_increment
            .as_nanos()
            .checked_mul(u128::from(round.value()))
            .and_then(|increment| self.base.as_nanos().checked_add(increment))
            .ok_or(FixedValidatorRuntimeTimingErrorV0::DurationOverflow { round })?;
        let seconds = u64::try_from(nanos / 1_000_000_000)
            .map_err(|_| FixedValidatorRuntimeTimingErrorV0::DurationOverflow { round })?;
        Ok(Duration::new(seconds, (nanos % 1_000_000_000) as u32))
    }
}

/// Explicit independent duration policies for all three fixed-validator phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorRuntimeTimeoutsV0 {
    proposal: FixedValidatorPhaseDurationV0,
    prevote: FixedValidatorPhaseDurationV0,
    precommit: FixedValidatorPhaseDurationV0,
}

impl FixedValidatorRuntimeTimeoutsV0 {
    pub const fn new(
        proposal: FixedValidatorPhaseDurationV0,
        prevote: FixedValidatorPhaseDurationV0,
        precommit: FixedValidatorPhaseDurationV0,
    ) -> Self {
        Self {
            proposal,
            prevote,
            precommit,
        }
    }

    pub fn duration(
        self,
        phase: FixedValidatorLockPhaseV0,
        round: ConsensusRound,
    ) -> Result<Duration, FixedValidatorRuntimeTimingErrorV0> {
        match phase {
            FixedValidatorLockPhaseV0::Proposal => self.proposal,
            FixedValidatorLockPhaseV0::Prevote => self.prevote,
            FixedValidatorLockPhaseV0::Precommit => self.precommit,
        }
        .duration(round)
    }
}

/// One exact driver-issued ticket and its process-local monotonic deadline.
///
/// This is not a consensus validity deadline or proof of elapsed time. The
/// deadline begins when this runtime observes the arm, including when it first
/// assumes custody of an already-armed driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedValidatorRuntimeTimerV0 {
    ticket: FixedValidatorNodePhaseTimeoutV0,
    deadline: Instant,
}

impl FixedValidatorRuntimeTimerV0 {
    pub(crate) fn new(
        ticket: FixedValidatorNodePhaseTimeoutV0,
        now: Instant,
        timeouts: FixedValidatorRuntimeTimeoutsV0,
    ) -> Result<Self, FixedValidatorRuntimeTimingErrorV0> {
        let duration = timeouts.duration(ticket.phase(), ticket.position().round())?;
        let deadline = now
            .checked_add(duration)
            .ok_or(FixedValidatorRuntimeTimingErrorV0::DeadlineOverflow)?;
        Ok(Self { ticket, deadline })
    }

    pub const fn ticket(self) -> FixedValidatorNodePhaseTimeoutV0 {
        self.ticket
    }

    pub const fn deadline(self) -> Instant {
        self.deadline
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedValidatorRuntimeTimingErrorV0 {
    ZeroRetryInterval,
    ZeroBase,
    ZeroRoundIncrement,
    DurationOverflow { round: ConsensusRound },
    DeadlineOverflow,
}

impl fmt::Display for FixedValidatorRuntimeTimingErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fixed-validator runtime timing rejected: {self:?}")
    }
}

impl Error for FixedValidatorRuntimeTimingErrorV0 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_retry_interval_rejects_zero_and_deadline_overflow_without_narrowing() {
        assert_eq!(
            FixedValidatorPublicationRetryIntervalV0::new(Duration::ZERO),
            Err(FixedValidatorRuntimeTimingErrorV0::ZeroRetryInterval)
        );
        assert_eq!(
            FixedValidatorPublicationRetryIntervalV0::new(Duration::MAX),
            Err(FixedValidatorRuntimeTimingErrorV0::DeadlineOverflow)
        );
        for millis in [1, u64::from(u32::MAX) + 1, u64::MAX] {
            let duration = Duration::from_millis(millis);
            match FixedValidatorPublicationRetryIntervalV0::new(duration) {
                Ok(interval) => assert_eq!(interval.duration(), duration),
                Err(error) => {
                    assert_eq!(error, FixedValidatorRuntimeTimingErrorV0::DeadlineOverflow);
                    assert!(Instant::now().checked_add(duration).is_none());
                }
            }
        }
    }

    #[test]
    fn phase_duration_is_positive_exact_and_does_not_narrow_rounds() {
        assert_eq!(
            FixedValidatorPhaseDurationV0::new(Duration::ZERO, Duration::from_nanos(1)),
            Err(FixedValidatorRuntimeTimingErrorV0::ZeroBase)
        );
        assert_eq!(
            FixedValidatorPhaseDurationV0::new(Duration::from_nanos(1), Duration::ZERO),
            Err(FixedValidatorRuntimeTimingErrorV0::ZeroRoundIncrement)
        );
        let policy =
            FixedValidatorPhaseDurationV0::new(Duration::from_nanos(3), Duration::from_nanos(7))
                .unwrap();
        for round in [0, 1, u64::from(u32::MAX) + 1, u64::MAX] {
            assert_eq!(
                policy
                    .duration(ConsensusRound::new(round))
                    .unwrap()
                    .as_nanos(),
                3 + u128::from(round) * 7
            );
        }
    }

    #[test]
    fn checked_duration_refuses_multiplication_and_addition_overflow() {
        let policy = FixedValidatorPhaseDurationV0::new(Duration::MAX, Duration::MAX).unwrap();
        assert_eq!(
            policy.duration(ConsensusRound::new(0)).unwrap(),
            Duration::MAX
        );
        for round in [1, u64::MAX] {
            assert_eq!(
                policy.duration(ConsensusRound::new(round)),
                Err(FixedValidatorRuntimeTimingErrorV0::DurationOverflow {
                    round: ConsensusRound::new(round)
                })
            );
        }
    }
}
