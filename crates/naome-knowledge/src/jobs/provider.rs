//! Provider semantics are independent of process custody and durable budgets.
use super::*;
use crate::resources::feedback::{Meter, Phase, Sample};
use std::time::{Duration, Instant};

pub(super) const DEFAULT_PROVIDER: &str = "naome-deterministic-mocks-v1";
#[derive(Clone, Copy)]
pub(super) enum Probe {
    Descendant,
    CpuActive(u32),
    CpuDone(u32),
    ResultReady,
}
#[derive(Debug)]
pub(super) enum Failure {
    Failed(String),
    Uncertain(String),
}
impl From<String> for Failure {
    fn from(error: String) -> Self {
        Self::Failed(error)
    }
}
impl From<&str> for Failure {
    fn from(error: &str) -> Self {
        Self::Failed(error.to_owned())
    }
}
pub(super) trait Supervisor {
    fn program(
        &mut self,
        _unit: u32,
        _records: Vec<naome_proof::program::Command>,
    ) -> Result<(), String> {
        Err("provider does not support streamed candidates".into())
    }
    fn reserve(&mut self, next: u32) -> Result<(), String>;
    fn checkpoint(&mut self, checkpoint: u32) -> Result<(), String>;
    fn probe(&mut self, probe: Probe) -> Result<(), String>;
    fn blocked_nanos(&self) -> u64;
    fn observe(&mut self, phase: Phase, sample: Sample) -> Result<(), String>;
}
pub(super) trait Provider {
    fn start(&mut self, _supervisor: &mut dyn Supervisor) -> Result<(), Failure> {
        Ok(())
    }
    fn next(&self, checkpoint: u32) -> Result<Option<u32>, Failure>;
    fn execute(&mut self, unit: u32, supervisor: &mut dyn Supervisor) -> Result<(), Failure>;
    fn result(&mut self, supervisor: &mut dyn Supervisor) -> Result<Output, Failure>;
}
pub(super) fn drive(
    provider: &mut dyn Provider,
    supervisor: &mut dyn Supervisor,
    mut checkpoint: u32,
) -> Result<Output, Failure> {
    measured(supervisor, Phase::Setup, |owner| provider.start(owner))?;
    while let Some(next) = provider.next(checkpoint)? {
        if checkpoint.checked_add(1) != Some(next) {
            return Err(Failure::Uncertain(
                "provider work-unit sequence differs".into(),
            ));
        }
        supervisor.reserve(next)?;
        measured(supervisor, Phase::Unit { unit: next }, |owner| {
            provider.execute(next, owner)
        })?;
        supervisor.checkpoint(next)?;
        checkpoint = next;
    }
    measured(supervisor, Phase::Finalization, |owner| {
        provider.result(owner)
    })
}
fn measured<T>(
    supervisor: &mut dyn Supervisor,
    phase: Phase,
    operation: impl FnOnce(&mut dyn Supervisor) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let blocked = supervisor.blocked_nanos();
    let meter = Meter::start();
    let result = operation(supervisor);
    let sample = meter.finish(
        supervisor.blocked_nanos().saturating_sub(blocked),
        result.is_ok(),
    );
    supervisor.observe(phase, sample)?;
    result
}
#[derive(Clone, Copy)]
pub(super) struct Contract {
    pub units: u32,
    pub resumable: bool,
}
pub(super) fn contract(record: &Record) -> Option<Contract> {
    match record.provider.as_str() {
        DEFAULT_PROVIDER => Some(Contract {
            units: if streams(&record.input, record.settings.mock) {
                record.settings.mock.program_units
            } else {
                record.settings.mock.steps
            },
            resumable: true,
        }),
        _ => None,
    }
}
pub(super) fn complete(record: &Record, checkpoint: u32) -> bool {
    contract(record).is_some_and(|c| c.units > 0 && c.units == checkpoint)
}
pub(super) fn valid_checkpoint(record: &Record) -> bool {
    contract(record).is_some_and(|c| {
        record.checkpoint <= c.units
            && (record.state != State::Complete || complete(record, record.checkpoint))
    })
}
pub(super) fn resumable(record: &Record) -> bool {
    contract(record).is_some_and(|c| c.resumable)
        && (cfg!(feature = "developer-tools") || record.settings.mock == MockWork::default())
}
pub(super) fn select(record: &Record) -> Result<Box<dyn Provider>, String> {
    match record.provider.as_str() {
        DEFAULT_PROVIDER => Ok(Box::new(Mock {
            input: record.input.clone(),
            work: record.settings.mock,
        })),
        _ => Err("unknown research provider".into()),
    }
}
struct Mock {
    input: Input,
    work: MockWork,
}
fn streams(input: &Input, work: MockWork) -> bool {
    work.program_units > 0
        && matches!(input,Input::Solve{question} if naome_checker::question::ResearchQuestion::from_hex(question).ok()==naome_checker::question::ResearchQuestion::from_hex(&crate::mocks::create_question(0)).ok())
}
impl Mock {
    fn streams(&self) -> bool {
        streams(&self.input, self.work)
    }
}
impl Provider for Mock {
    fn start(&mut self, supervisor: &mut dyn Supervisor) -> Result<(), Failure> {
        if self.work.descendant {
            supervisor.probe(Probe::Descendant)?;
        }
        Ok(())
    }
    fn next(&self, checkpoint: u32) -> Result<Option<u32>, Failure> {
        let units = if self.streams() {
            self.work.program_units
        } else {
            self.work.steps
        };
        if units != 0 && checkpoint >= units {
            return Ok(None);
        }
        checkpoint
            .checked_add(1)
            .map(Some)
            .ok_or_else(|| Failure::Failed("provider checkpoint overflow".into()))
    }
    fn execute(&mut self, next: u32, supervisor: &mut dyn Supervisor) -> Result<(), Failure> {
        if self.streams() {
            supervisor.program(
                next,
                super::program::mock_group(next, self.work.program_units, self.work.outcome)?,
            )?;
        }

        if self.work.step_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.work.step_ms));
        }
        if self.work.cpu_ms > 0 {
            supervisor.probe(Probe::CpuActive(next))?;
            let until = Instant::now() + Duration::from_millis(self.work.cpu_ms);
            let mut value = 0u64;
            while Instant::now() < until {
                value = std::hint::black_box(value.wrapping_mul(1664525).wrapping_add(1013904223));
            }
            std::hint::black_box(value);
            supervisor.probe(Probe::CpuDone(next))?;
        }
        if self.work.steps == 0 {
            loop {
                std::thread::park();
            }
        }
        Ok(())
    }
    fn result(&mut self, supervisor: &mut dyn Supervisor) -> Result<Output, Failure> {
        if self.work.outcome == MockOutcome::Failed {
            return Err(Failure::Failed("deterministic provider failed".into()));
        }
        if self.work.result_delay_ms > 0 {
            supervisor.probe(Probe::ResultReady)?;
            std::thread::sleep(Duration::from_millis(self.work.result_delay_ms));
        }
        if self.streams() {
            return Ok(Output::Program {
                units: self.work.program_units,
            });
        }
        let output = match &self.input {
            Input::Find { question, .. } => {
                Output::Question(if self.work.outcome == MockOutcome::Malformed {
                    "invalid question".into()
                } else {
                    question.clone()
                })
            }
            Input::Solve { question } => {
                if naome_checker::question::ResearchQuestion::source_requires_definitions(question)
                    .map_err(|e| e.to_string())?
                {
                    return Ok(Output::NoCandidate);
                }
                let compiled = naome_checker::question::ResearchQuestion::from_hex(question)
                    .map_err(|e| e.to_string())?;
                let proof = if self.work.outcome == MockOutcome::Malformed {
                    Some("00ff".into())
                } else {
                    let target = if self.work.outcome == MockOutcome::WrongTarget {
                        (0..3)
                            .map(crate::mocks::create_question)
                            .filter_map(|bytes| {
                                naome_checker::question::ResearchQuestion::from_hex(&bytes).ok()
                            })
                            .find(|other| other.resolution_id() != compiled.resolution_id())
                            .ok_or("mock alternate target absent")?
                    } else {
                        compiled
                    };
                    crate::mocks::create_padded_proof(&target, self.work.proof_padding_bytes)
                };
                proof
                    .map(|proof| Output::Proof {
                        proof,
                        helpers: Vec::new(),
                    })
                    .unwrap_or(Output::NoCandidate)
            }
            Input::Select { question, .. } => {
                naome_checker::question::ResearchQuestion::source_requires_definitions(question)
                    .map_err(|e| e.to_string())?;
                // Formal validation (including definition resolution) belongs to the receiver.
                Output::Selected(self.work.outcome != MockOutcome::Malformed)
            }
        };
        Ok(output)
    }
}

#[cfg(test)]
mod tests;
