//! Provider semantics are independent of process custody and durable budgets.
use super::*;
use std::time::{Duration, Instant};

pub(super) const DEFAULT_PROVIDER: &str = "naome-deterministic-mocks-v1";
pub(super) const DECISION_PROVIDER: &str = "naome-decision-interest-v1";
pub(super) fn for_input(input: &Input, settings: Settings) -> &'static str {
    if matches!(input, Input::Interest { .. })
        && settings.interest_provider == InterestProvider::Decision
    {
        DECISION_PROVIDER
    } else {
        DEFAULT_PROVIDER
    }
}
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
    provider.start(supervisor)?;
    while let Some(next) = provider.next(checkpoint)? {
        if checkpoint.checked_add(1) != Some(next) {
            return Err(Failure::Uncertain(
                "provider work-unit sequence differs".into(),
            ));
        }
        supervisor.reserve(next)?;
        provider.execute(next, supervisor)?;
        supervisor.checkpoint(next)?;
        checkpoint = next;
    }
    provider.result(supervisor)
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
        DECISION_PROVIDER if matches!(record.input, Input::Interest { .. }) => Some(Contract {
            units: 1,
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
            && (record.provider != DECISION_PROVIDER
                || record.checkpoint == 0
                || record.state == State::Complete)
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
        && matches!(input,Input::Solve{question} if naome_authoring::CompiledQuestion::compile(question).ok()==naome_authoring::CompiledQuestion::compile(&crate::mocks::create_question(0)).ok())
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
            Input::Find { cursor } => {
                Output::Question(if self.work.outcome == MockOutcome::Malformed {
                    "invalid question".into()
                } else {
                    crate::mocks::create_question(*cursor)
                })
            }
            Input::Solve { question } => {
                let compiled = naome_authoring::CompiledQuestion::compile(question)
                    .map_err(|e| e.to_string())?;
                let source = if self.work.outcome == MockOutcome::Malformed {
                    Some("invalid proof".into())
                } else if self.work.outcome == MockOutcome::WrongTarget {
                    let other = (0..3)
                        .find_map(|cursor| {
                            let other = naome_authoring::CompiledQuestion::compile(
                                &crate::mocks::create_question(cursor),
                            )
                            .ok()?;
                            (other.resolution_id() != compiled.resolution_id()).then_some(other)
                        })
                        .ok_or("mock alternate target absent")?;
                    crate::mocks::create_proof(&other)
                } else {
                    crate::mocks::create_proof(&compiled)
                };
                source
                    .map(|mut source| {
                        source.push_str(
                            &" ".repeat(
                                self.work.proof_padding_bytes.min(
                                    crate::resources::limits()
                                        .proof_bytes
                                        .saturating_sub(source.len()),
                                ),
                            ),
                        );
                        Output::Proof {
                            source,
                            helpers: Vec::new(),
                        }
                    })
                    .unwrap_or(Output::NoCandidate)
            }
            Input::Interest { .. } => {
                #[cfg(not(any(test, feature = "developer-tools")))]
                return Err("deterministic interest selection requires developer-tools".into());
                #[cfg(any(test, feature = "developer-tools"))]
                {
                    let Input::Interest { question, .. } = &self.input else {
                        unreachable!()
                    };
                    let compiled = naome_authoring::CompiledQuestion::compile(question)
                        .map_err(|e| e.to_string())?;
                    let yes = libp2p::futures::executor::block_on(crate::mocks::assess_interest(
                        compiled,
                    ))?;
                    Output::Interest(yes && self.work.outcome != MockOutcome::Malformed)
                }
            }
        };
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct OtherProvider {
        uncertain: bool,
    }
    impl Provider for OtherProvider {
        fn next(&self, checkpoint: u32) -> Result<Option<u32>, Failure> {
            Ok((checkpoint < 2).then_some(checkpoint + 1))
        }
        fn execute(&mut self, _: u32, _: &mut dyn Supervisor) -> Result<(), Failure> {
            if self.uncertain {
                Err(Failure::Uncertain("effect requires reconciliation".into()))
            } else {
                Ok(())
            }
        }
        fn result(&mut self, _: &mut dyn Supervisor) -> Result<Output, Failure> {
            Ok(Output::NoCandidate)
        }
    }
    #[derive(Default)]
    struct Grants(Vec<(bool, u32)>);
    impl Supervisor for Grants {
        fn reserve(&mut self, unit: u32) -> Result<(), String> {
            self.0.push((false, unit));
            Ok(())
        }
        fn checkpoint(&mut self, unit: u32) -> Result<(), String> {
            self.0.push((true, unit));
            Ok(())
        }
        fn probe(&mut self, _: Probe) -> Result<(), String> {
            Ok(())
        }
    }
    #[test]
    fn another_provider_resumes_through_the_same_reservations_and_preserves_uncertainty() {
        let mut grants = Grants::default();
        assert!(matches!(
            drive(&mut OtherProvider { uncertain: false }, &mut grants, 1),
            Ok(Output::NoCandidate)
        ));
        assert_eq!(grants.0, [(false, 2), (true, 2)]);
        grants.0.clear();
        assert!(matches!(
            drive(&mut OtherProvider { uncertain: true }, &mut grants, 0),
            Err(Failure::Uncertain(_))
        ));
        assert_eq!(grants.0, [(false, 1)]);
    }
}
