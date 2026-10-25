//! One native attempt owns feedback ordering; telemetry grants no reservation.
use super::*;
use crate::resources::feedback::{self, Disposition, Phase, Role, Sample};

pub(super) struct Attempt {
    role: Role,
    started: Instant,
    paused: Duration,
    setup: Option<bool>,
    unit: Option<(u32, bool)>,
    finalized: Option<bool>,
    sample: Sample,
}
impl Attempt {
    pub(super) fn new(role: Role) -> Self {
        Self {
            role,
            started: Instant::now(),
            paused: Duration::ZERO,
            setup: None,
            unit: None,
            finalized: None,
            sample: Sample {
                cpu_nanos: Some(0),
                ..Sample::default()
            },
        }
    }
    pub(super) fn observe(
        &mut self,
        phase: Phase,
        sample: Sample,
        outstanding: Option<u32>,
        complete: bool,
    ) -> Result<(), String> {
        let elapsed_nanos = self
            .sample
            .elapsed_nanos
            .saturating_add(sample.elapsed_nanos);
        if !sample.validate(self.started.elapsed())
            || u128::from(elapsed_nanos) > self.started.elapsed().as_nanos()
        {
            return Err("provider feedback measurement differs from its owned attempt".into());
        }
        match phase {
            Phase::Setup
                if self.setup.is_none() && outstanding.is_none() && self.finalized.is_none() =>
            {
                self.setup = Some(sample.succeeded)
            }
            Phase::Unit { unit }
                if self.setup == Some(true)
                    && outstanding == Some(unit)
                    && self.unit.is_none()
                    && self.finalized.is_none() =>
            {
                self.unit = Some((unit, sample.succeeded))
            }
            Phase::Finalization
                if self.setup == Some(true)
                    && outstanding.is_none()
                    && self.unit.is_none()
                    && self.finalized.is_none()
                    && complete =>
            {
                self.finalized = Some(sample.succeeded)
            }
            _ => return Err("provider feedback phase or work-unit sequence differs".into()),
        }
        self.sample.elapsed_nanos = elapsed_nanos;
        self.sample.blocked_nanos = self
            .sample
            .blocked_nanos
            .saturating_add(sample.blocked_nanos);
        self.sample.cpu_nanos = self
            .sample
            .cpu_nanos
            .zip(sample.cpu_nanos)
            .map(|(before, after)| before.saturating_add(after));
        feedback::provider_sample(self.role, phase, sample);
        Ok(())
    }
    pub(super) fn ready(&self) -> bool {
        self.setup == Some(true) && self.finalized.is_none()
    }
    pub(super) fn unit_ready(&self, unit: u32) -> bool {
        self.unit == Some((unit, true))
    }
    pub(super) fn checkpoint(&mut self, unit: u32) -> Result<(), String> {
        if !self.unit_ready(unit) {
            return Err("provider progress lacks successful measured work".into());
        }
        self.unit = None;
        feedback::provider_checkpoint(self.role);
        Ok(())
    }
    pub(super) fn finished(&self) -> bool {
        self.finalized == Some(true)
    }
    pub(super) fn pause(&mut self, elapsed: Duration) {
        self.paused = self.paused.saturating_add(elapsed);
    }
    pub(super) fn finish(&self, state: State) {
        let disposition = match state {
            State::Complete => Disposition::Complete,
            State::Cancelled => Disposition::Cancelled,
            State::Expired => Disposition::Expired,
            State::InDoubt => Disposition::Uncertain,
            _ => Disposition::Failed,
        };
        feedback::provider_finished(
            self.role,
            disposition,
            self.started.elapsed().saturating_sub(self.paused),
            self.sample,
        );
    }
}

#[cfg(test)]
mod tests;
