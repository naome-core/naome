use super::*;
use naome_research::time::TimeCertificate;
use std::time::{SystemTime, UNIX_EPOCH};

impl ResearchRuntime {
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
            .map_err(|_| ResearchRuntimeError::Clock("UTC precedes Unix epoch"))?
            .as_secs();
        if self.last_utc.is_some_and(|last| utc < last) {
            return Err(ResearchRuntimeError::Clock(
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
                    .is_some_and(|p| p.2 == ResearchPhase::Proposal)
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
            if let Some((_, _, phase)) = self.node.position()? {
                let duration = match phase {
                    ResearchPhase::Proposal => self.config.proposal_timeout,
                    ResearchPhase::Prevote => self.config.prevote_timeout,
                    ResearchPhase::Precommit => self.config.precommit_timeout,
                };
                if (self.work_ready || phase != ResearchPhase::Proposal)
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
    fn prepare_record(&mut self) -> Result<Option<Vec<u8>>> {
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
                .ok_or(ResearchRuntimeError::Configuration("height overflow"))?,
            state.time(),
        )?;
        let mut operations = Vec::new();
        let mut rejected = Vec::new();
        let mut best = state.prepare_record(certificate.clone(), Vec::new()).ok();
        for operation in self
            .pending
            .values()
            .take(state.genesis().profile().limits().operations_per_record as usize)
        {
            let mut candidate = operations.clone();
            candidate.push(operation.clone());
            match state.prepare_record(certificate.clone(), candidate.clone()) {
                Ok(transition) => {
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
            .map(|t| t.record().encode().map_err(ResearchRuntimeError::from))
            .transpose()?;
        for (id, reason) in rejected {
            self.reject_preview(id, reason)?;
        }
        Ok(result)
    }
}

fn check_clock_progress(
    previous: SystemTime,
    current: SystemTime,
    elapsed: Duration,
) -> Result<()> {
    let wall_elapsed = current.duration_since(previous).map_err(|_| {
        ResearchRuntimeError::Clock("local UTC moved backwards; no new report signed")
    })?;
    if wall_elapsed.abs_diff(elapsed) > Duration::from_secs(2) {
        return Err(ResearchRuntimeError::Clock(
            "UTC drift exceeded two seconds relative to monotonic time; no new report signed",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod clock_tests {
    use super::*;
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
