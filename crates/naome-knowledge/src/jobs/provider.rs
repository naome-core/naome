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
    Failed,
    Coded(crate::outcome::JobFailureCode),
    Uncertain,
}
impl From<crate::Error> for Failure {
    fn from(error: crate::Error) -> Self {
        Self::Coded(crate::outcome::JobFailureCode::from_owner(&error))
    }
}
impl From<crate::outcome::WorkerFailure> for Failure {
    fn from(error: crate::outcome::WorkerFailure) -> Self {
        Self::Coded(error.into())
    }
}
impl From<String> for Failure {
    fn from(_: String) -> Self {
        Self::Failed
    }
}
impl From<&str> for Failure {
    fn from(_: &str) -> Self {
        Self::Failed
    }
}
pub(super) trait Supervisor {
    fn external_history_cpu(&self) -> bool {
        false
    }

    fn history(
        &mut self,
        _request: &crate::learning::history::Request,
    ) -> Result<crate::learning::history::Receipt, crate::Error> {
        Err(crate::WorkerFailure::HistoryUnsupported.into())
    }
    fn program(
        &mut self,
        _unit: u32,
        _records: Vec<naome_proof::program::Command>,
    ) -> Result<(), crate::outcome::WorkerFailure> {
        Err(crate::outcome::WorkerFailure::ProgramUnsupported)
    }
    fn read_model(
        &mut self,
        _blob: crate::learning::Blob,
        _range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>, crate::Error> {
        Err(crate::WorkerFailure::ModelReadUnsupported.into())
    }
    fn write_model(
        &mut self,
        _blob: crate::learning::Blob,
        _range: std::ops::Range<usize>,
        _bytes: Vec<u8>,
    ) -> Result<(), crate::Error> {
        Err(crate::WorkerFailure::ModelWriteUnsupported.into())
    }
    fn learning(
        &mut self,
        _unit: u32,
        _progress: crate::learning::Progress,
    ) -> Result<(), crate::outcome::WorkerFailure> {
        Err(crate::outcome::WorkerFailure::LearningUnsupported)
    }
    fn reserve(&mut self, next: u32) -> Result<(), crate::outcome::WorkerFailure>;
    fn checkpoint(&mut self, checkpoint: u32) -> Result<(), crate::outcome::WorkerFailure>;
    fn probe(&mut self, probe: Probe) -> Result<(), crate::outcome::WorkerFailure>;
    fn blocked_nanos(&self) -> u64;
    fn observe(
        &mut self,
        phase: Phase,
        sample: Sample,
    ) -> Result<(), crate::outcome::WorkerFailure>;
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
            return Err(Failure::Uncertain);
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
        crate::frontier::PROVIDER if matches!(record.input, Input::Find { .. }) => Some(Contract {
            units: 1,
            resumable: true,
        }),
        crate::learning::PROVIDER => record.native.as_ref().map(|job| Contract {
            units: job.units(),
            resumable: true,
        }),
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
pub(super) fn select(record: &Record) -> Result<Box<dyn Provider>, crate::Error> {
    match record.provider.as_str() {
        crate::frontier::PROVIDER => match &record.input {
            Input::Find { question, .. } => Ok(Box::new(Finding {
                question: question.clone(),
            })),
            _ => Err(crate::ResearchFailure::ProviderRoleMismatch.into()),
        },
        crate::learning::PROVIDER => Ok(Box::new(Native {
            record: record.clone(),
            engine: crate::learning::Engine::default(),
        })),
        DEFAULT_PROVIDER => Ok(Box::new(Mock {
            input: record.input.clone(),
            work: record.settings.mock,
        })),
        _ => Err(crate::ResearchFailure::ProviderUnknown.into()),
    }
}
/// Generation and its learned state belong to Frontier. This worker finalizes
/// the immutable selected source under the ordinary job reservation/custody.
struct Finding {
    question: String,
}
impl Provider for Finding {
    fn next(&self, checkpoint: u32) -> Result<Option<u32>, Failure> {
        Ok((checkpoint == 0).then_some(1))
    }
    fn execute(&mut self, _unit: u32, _owner: &mut dyn Supervisor) -> Result<(), Failure> {
        naome_checker::question::ResearchQuestion::source_requires_definitions(&self.question)
            .map_err(crate::Error::from)?;
        Ok(())
    }
    fn result(&mut self, _owner: &mut dyn Supervisor) -> Result<Output, Failure> {
        Ok(Output::Question(self.question.clone()))
    }
}
struct Native {
    record: Record,
    engine: crate::learning::Engine,
}
impl Provider for Native {
    fn next(&self, checkpoint: u32) -> Result<Option<u32>, Failure> {
        let units = contract(&self.record)
            .ok_or("native provider contract")?
            .units;
        Ok((checkpoint < units).then_some(checkpoint + 1))
    }
    fn execute(&mut self, unit: u32, owner: &mut dyn Supervisor) -> Result<(), Failure> {
        let question = match &self.record.input {
            Input::Solve { question } | Input::Peer { question, .. } => Some(question.as_str()),
            Input::Train { .. } => None,
            _ => return Ok(()),
        };
        let job = self
            .record
            .native
            .as_mut()
            .ok_or("native model snapshot missing")?;
        job.execute(
            unit,
            if matches!(self.record.input, Input::Peer { .. }) {
                None
            } else {
                question
            },
            self.record.id,
            &mut self.engine,
            owner,
        )?;
        if let Input::Peer {
            evidence,
            question,
            artifact,
            ..
        } = &self.record.input
        {
            let p = job
                .progress
                .as_mut()
                .ok_or("peer extraction progress missing")?;
            match crate::learning::peer::extract_source(question, artifact, evidence) {
                Ok(solution) => {
                    p.cost = Some((*solution.cost).clone());
                    p.terminal =
                        crate::learning::experience::TerminalEvidence::certified(&solution);
                    p.result = Some(solution);
                }
                Err(_) => {
                    p.result = None;
                    p.terminal = crate::learning::experience::TerminalEvidence::Unsupported(
                        crate::learning::experience::Capacity::PeerConversion,
                    );
                }
            }
        }
        owner.learning(unit, job.progress.clone().ok_or("native progress missing")?)?;
        Ok(())
    }
    fn result(&mut self, _owner: &mut dyn Supervisor) -> Result<Output, Failure> {
        let job = self
            .record
            .native
            .as_ref()
            .ok_or("native model snapshot missing")?;
        Ok(match &self.record.input {
            Input::Solve { .. } | Input::Peer { .. } | Input::Train { .. } => {
                let p = job.progress.as_ref().ok_or("native final state missing")?;
                Output::Native {
                    solution: p.result.clone(),
                    frontier: p.frontier.clone(),
                    terminal: p.terminal.clone().into(),
                }
            }
            _ => return Err("native provider role differs".into()),
        })
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
        checkpoint.checked_add(1).map(Some).ok_or(Failure::Failed)
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
            return Err(Failure::Failed);
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
                    .map_err(crate::Error::from)?
                {
                    return Ok(Output::NoCandidate);
                }
                let compiled = naome_checker::question::ResearchQuestion::from_hex(question)
                    .map_err(crate::Error::from)?;
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
            Input::Peer { .. } | Input::Train { .. } => {
                return Err("native learning jobs require the native provider".into());
            }
            Input::Select { question, .. } => {
                naome_checker::question::ResearchQuestion::source_requires_definitions(question)
                    .map_err(crate::Error::from)?;
                // Formal validation (including definition resolution) belongs to the receiver.
                Output::Selected(self.work.outcome != MockOutcome::Malformed)
            }
        };
        Ok(output)
    }
}

#[cfg(test)]
mod tests;

impl crate::learning::ArtifactIo for dyn Supervisor + '_ {
    fn external_history_cpu(&self) -> bool {
        Supervisor::external_history_cpu(self)
    }

    fn history(
        &mut self,
        request: &crate::learning::history::Request,
    ) -> Result<crate::learning::history::Receipt, crate::Error> {
        Supervisor::history(self, request)
    }
    fn read(
        &mut self,
        blob: &crate::learning::Blob,
        range: std::ops::Range<usize>,
    ) -> Result<Vec<u8>, crate::Error> {
        self.read_model(blob.clone(), range)
    }
    fn write(
        &mut self,
        blob: &crate::learning::Blob,
        range: std::ops::Range<usize>,
        bytes: Vec<u8>,
    ) -> Result<(), crate::Error> {
        self.write_model(blob.clone(), range, bytes)
    }
}
