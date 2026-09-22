use super::*;
use naome_chain::StateRecordExecution;
use naome_ledger::time::TimeCertificate;
use std::time::{SystemTime, UNIX_EPOCH};

impl StateRuntime {
    pub(super) fn tick(&mut self) -> Result<()> {
        let wall = SystemTime::now();
        let monotonic = Instant::now();
        if let Some((previous_wall, previous_monotonic)) = self.last_clock {
            check_clock_progress(
                previous_wall,
                wall,
                monotonic.duration_since(previous_monotonic),
            )?;
        }
        self.last_clock = Some((wall, monotonic));
        let utc = wall
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StateRuntimeError::Clock("UTC precedes Unix epoch"))?
            .as_secs();
        if self.last_utc.is_some_and(|last| utc < last) {
            return Err(StateRuntimeError::Clock(
                "local UTC moved backwards; no new report signed",
            ));
        }
        self.last_utc = Some(utc);
        if !self.state()?.terminated() {
            if let Some(report) = self.node.sign_time_report(utc)? {
                self.own_time = Some(report.encode().into());
                self.time_reports.insert(report.validator(), report);
            }
            let record = self.prepare_record()?;
            let work_ready = record.is_some() || self.node.has_retained_value()?;
            if work_ready
                && !self.work_ready
                && self
                    .node
                    .position()?
                    .is_some_and(|p| p.2 == StatePhase::Proposal)
            {
                self.phase_started = Instant::now();
            }
            self.work_ready = work_ready;
            if self.node.is_proposer()? && !self.node.already_authored()? {
                if self.node.has_retained_value()? {
                    self.node.author(None)?;
                } else if let Some(record) = record {
                    self.node.author(Some(record))?;
                }
            }
            self.drive()?;
            if let Some((_, round, phase)) = self.node.position()? {
                let base = match phase {
                    StatePhase::Proposal => self.config.proposal_timeout,
                    StatePhase::Prevote => self.config.prevote_timeout,
                    StatePhase::Precommit => self.config.precommit_timeout,
                };
                let duration = round_timeout(base, round);
                if (self.work_ready || phase != StatePhase::Proposal)
                    && self.phase_started.elapsed() >= duration
                {
                    let _ = self.node.timeout()?;
                    self.drive()?;
                }
            }
        }
        self.enqueue_periodic()?;
        Ok(())
    }
    pub(super) fn prepare_record(&mut self) -> Result<Option<Vec<u8>>> {
        if self.time_reports.len() < 3 || self.node.signer_key().is_none() {
            return Ok(None);
        }
        let state = self.state()?;
        let certificate = TimeCertificate::new(
            self.time_reports.values().cloned().collect(),
            state.genesis(),
            state.head(),
            state
                .height()
                .checked_add(1)
                .ok_or(StateRuntimeError::Configuration("height overflow"))?,
            state.time(),
        )?;
        let mut operations = Vec::new();
        let mut rejected = Vec::new();
        let mut best = state.prepare_record(certificate.clone(), Vec::new()).ok();
        // Protected phase work consumes or establishes an attempt reservation.
        // Registration must never poison that automatic progress, nor a valid
        // pending vote, commitment, or reveal, through operation-ID ordering.
        let mut protected = best.as_ref().is_some_and(|transition| {
            transition.state().reserved_records() != state.reserved_records()
        });
        let mut pending = self
            .pending
            .values()
            .map(|operation| {
                let body = naome_ledger::operations::OperationBody::decode(
                    operation.payload(),
                    state.genesis(),
                )?;
                let priority = match body {
                    naome_ledger::operations::OperationBody::Register => 2,
                    naome_ledger::operations::OperationBody::Submit { .. } => 1,
                    _ => 0,
                };
                Ok((priority, operation))
            })
            .collect::<Result<Vec<_>>>()?;
        pending.sort_by_key(|(priority, _)| *priority);
        for (priority, operation) in pending {
            if operations.len() >= state.genesis().profile().limits().operations_per_record as usize
            {
                break;
            }
            if priority == 2 && protected {
                continue;
            }
            let mut candidate = operations.clone();
            candidate.push(operation.clone());
            match state.prepare_record(certificate.clone(), candidate.clone()) {
                Ok(transition) => {
                    protected |= transition.state().reserved_records() != state.reserved_records();
                    operations = candidate;
                    best = Some(transition);
                }
                Err(error) => {
                    // A group can exceed work/size bounds while this operation
                    // is individually valid. Defer that case to the next record.
                    let individual_error = if operations.is_empty() {
                        Some(error)
                    } else {
                        state
                            .prepare_record(certificate.clone(), vec![operation.clone()])
                            .err()
                    };
                    if let Some(error) = individual_error {
                        rejected.push((operation.id(), error.to_string()));
                    }
                }
            }
        }
        let result = best
            .map(|t| t.record().encode().map_err(StateRuntimeError::from))
            .transpose()?;
        for (id, reason) in rejected {
            self.reject_preview(id, reason)?;
        }
        Ok(result)
    }
}

// A later consensus round gives authenticated delivery and durable signing more
// time to complete. The replayed round determines the delay; duplicate traffic
// cannot reset it, and the finite round/journal budgets remain unchanged.
fn round_timeout(base: Duration, round: u64) -> Duration {
    base.saturating_mul(1u32 << round.min(4))
}

fn check_clock_progress(
    previous: SystemTime,
    current: SystemTime,
    elapsed: Duration,
) -> Result<()> {
    let wall_elapsed = current
        .duration_since(previous)
        .map_err(|_| StateRuntimeError::Clock("local UTC moved backwards; no new report signed"))?;
    if wall_elapsed.abs_diff(elapsed) > Duration::from_secs(2) {
        return Err(StateRuntimeError::Clock(
            "UTC drift exceeded two seconds relative to monotonic time; no new report signed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    #[test]
    fn consensus_round_timeout_grows_caps_and_saturates_without_overflow() {
        let base = Duration::from_millis(350);
        for (round, millis) in [
            (0, 350),
            (1, 700),
            (2, 1400),
            (3, 2800),
            (4, 5600),
            (8, 5600),
        ] {
            assert_eq!(round_timeout(base, round), Duration::from_millis(millis));
        }
        assert_eq!(round_timeout(base, u64::MAX), Duration::from_millis(5600));
        assert_eq!(
            round_timeout(Duration::from_secs(4), 4),
            Duration::from_secs(64)
        );
        assert_eq!(round_timeout(Duration::MAX, 0), Duration::MAX);
        assert_eq!(round_timeout(Duration::MAX, u64::MAX), Duration::MAX);
    }
    #[test]
    fn detectable_clock_jumps_halt_before_reporting() {
        let previous = UNIX_EPOCH + Duration::from_secs(100);
        assert!(
            check_clock_progress(
                previous,
                previous + Duration::from_secs(5),
                Duration::from_secs(5)
            )
            .is_ok()
        );
        assert!(
            check_clock_progress(
                previous,
                previous + Duration::from_secs(7),
                Duration::from_secs(5)
            )
            .is_ok()
        );
        assert!(
            check_clock_progress(
                previous,
                previous + Duration::from_millis(7001),
                Duration::from_secs(5)
            )
            .is_err()
        );
        assert!(
            check_clock_progress(
                previous,
                previous + Duration::from_secs(1),
                Duration::from_secs(5)
            )
            .is_err()
        );
        assert!(
            check_clock_progress(
                previous,
                previous - Duration::from_millis(1),
                Duration::ZERO
            )
            .is_err()
        );
    }
}
