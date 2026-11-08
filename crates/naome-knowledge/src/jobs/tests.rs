use super::*;
use std::collections::{BTreeMap, VecDeque};

/// Unit-level role coordination control; native process tests exercise Service.
pub(crate) struct Manual {
    pub client: Client,
    receiver: mpsc::Receiver<Command>,
    next: u64,
    waiting: BTreeMap<u64, (Input, Binding, oneshot::Sender<Completion>)>,
    acknowledged: Vec<u64>,
    recovery_pages: VecDeque<RecoveryPage>,
    recovery_requests: Vec<(u64, u64)>,
    discarded: Vec<Input>,
    receipts: Vec<Receipt>,
}

impl Manual {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::channel(crate::resources::limits().job_commands);
        Self {
            client: Client {
                sender,
                feedback: Default::default(),
            },
            receiver,
            next: 1,
            waiting: BTreeMap::new(),
            acknowledged: Vec::new(),
            recovery_pages: VecDeque::new(),
            recovery_requests: Vec::new(),
            discarded: Vec::new(),
            receipts: Vec::new(),
        }
    }
    pub(crate) fn requests(&mut self) -> Vec<(u64, Input)> {
        let mut requests = Vec::new();
        while let Ok(command) = self.receiver.try_recv() {
            match command {
                Command::Accepted { id, root } => {
                    self.receipts.push(Receipt::Accepted { id, root })
                }
                Command::PeerVerified(_)
                | Command::PeerCursor(_)
                | Command::DefinitionVerified { .. }
                | Command::TheoremVerified { .. } => {}
                Command::Program { reply, .. } => {
                    let _ = reply.send(Err("manual provider has no retained program".into()));
                }
                Command::Submit(input, binding, _required, _prerequisites, reply) => {
                    let id = self.next;
                    self.next += 1;
                    requests.push((id, input.clone()));
                    self.waiting.insert(id, (input, binding, reply));
                }
                Command::Discard(input, binding) => {
                    self.receipts
                        .push(Receipt::Discard(input.clone(), binding.clone()));
                    self.waiting
                        .retain(|_, (i, b, _)| i != &input || b != &binding);
                    self.discarded.push(input);
                }
                Command::Acknowledge(id) => {
                    self.receipts.push(Receipt::Acknowledge(id));
                    self.acknowledged.push(id);
                }
                Command::Recover {
                    after,
                    before,
                    reply,
                } => {
                    self.recovery_requests.push((after, before));
                    let _ = reply.send(Ok(self.recovery_pages.pop_front().unwrap_or(
                        super::RecoveryPage {
                            records: vec![],
                            next: None,
                        },
                    )));
                }
            }
        }
        requests
    }
    pub(crate) fn complete(&mut self, id: u64, result: Result<Output, String>) {
        let (_, binding, reply) = self.waiting.remove(&id).expect("selected test request");
        let state = if result.is_ok() {
            State::Complete
        } else {
            State::Failed
        };
        let _ = reply.send(Completion {
            experience: None,
            model_checkpoint: None,
            id,
            binding,
            spent_ms: 0,
            reserved_units: 1,
            state,
            result: result.map_err(|_| CompletionFailure::NoResult(State::Failed)),
        });
    }
    pub(crate) fn recovery(&self) -> Recovery {
        Recovery {
            archive_end: 0,
            next_cursor: 0,
            peer_cursor: 0,
            records: Vec::new(),
        }
    }
    pub(crate) fn acknowledgements(&mut self) -> Vec<u64> {
        self.requests();
        std::mem::take(&mut self.acknowledged)
    }
    pub(crate) fn queue_recovery(&mut self, records: Vec<Record>, next: Option<u64>) {
        self.recovery_pages
            .push_back(RecoveryPage { records, next });
    }
    pub(crate) fn receipts(&mut self) -> Vec<Receipt> {
        self.requests();
        std::mem::take(&mut self.receipts)
    }
    pub(crate) fn recovery_requests(&self) -> &[(u64, u64)] {
        &self.recovery_requests
    }
    pub(crate) fn discarded(&self) -> &[Input] {
        &self.discarded
    }
}

#[test]
fn role_horizons_have_no_lifetime_ceiling_and_reject_zero_or_overflow() {
    let mut settings = Settings::default();
    for horizon in [
        60 * 60 * 1_000,
        24 * 60 * 60 * 1_000,
        30 * 24 * 60 * 60 * 1_000,
        365 * 24 * 60 * 60 * 1_000,
    ] {
        settings.solving.limits.horizon_ms = horizon;
        assert!(settings.validate().is_ok());
    }
    for horizon in [0, u64::MAX] {
        settings.solving.limits.horizon_ms = horizon;
        assert!(settings.validate().is_err());
    }
    let mut settings = Settings::default();
    settings.selection.limits.work_units = 0;
    assert!(settings.validate().is_err());
}

#[test]
fn source_binding_preserves_original_question_orientation_and_strict_schema() {
    let source = "02040101000000000100000000";
    let input = Input::Solve {
        question: source.into(),
    };
    input.validate().unwrap();
    let bytes = serde_json::to_vec(&input).unwrap();
    let decoded: Input = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, input);
    assert_eq!(decoded.account_key(), input.account_key());
    let mut value = serde_json::to_value(&input).unwrap();
    value["new_budget"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Input>(value).is_err());
}

#[cfg(not(feature = "developer-tools"))]
#[test]
fn ordinary_product_rejects_developer_workloads_before_spawning() {
    let mut settings = Settings::default();
    settings.solving.mock.steps = 2;
    assert!(matches!(
        settings.validate().unwrap_err(),
        crate::Error::Research(crate::ResearchFailure::DeveloperWorkloadUnavailable)
    ));
    assert!(Settings::default().validate().is_ok());
}

#[test]
fn selected_finding_question_binds_the_returned_question() {
    let supplied = "040001000000000100000000".to_owned();
    let input = Input::Find {
        cursor: 1,
        question: supplied.clone(),
    };
    assert!(Output::Question(supplied).validate(&input).is_ok());
    assert!(
        Output::Question("040101000000000100000000".into())
            .validate(&input)
            .is_err()
    );
}

#[test]
fn job_states_use_registered_codes_and_reject_unknown_values() {
    for (state, code) in [
        (State::Queued, 0x001d_0001u32),
        (State::Running, 0x001d_0002),
        (State::Suspended, 0x001d_0003),
        (State::Complete, 0x001d_0004),
        (State::Failed, 0x001d_0005),
        (State::Cancelled, 0x001d_0006),
        (State::Expired, 0x001d_0007),
        (State::InDoubt, 0x001d_0008),
    ] {
        assert_eq!(serde_json::to_value(state).unwrap(), code);
        assert_eq!(serde_json::from_value::<State>(code.into()).unwrap(), state);
    }
    assert!(serde_json::from_value::<State>(0x001d_0009u32.into()).is_err());
}

#[test]
fn selection_purposes_use_registered_codes_and_reject_unknown_values() {
    for (purpose, code) in [
        (Purpose::Assessment, 0x0039_0001u32),
        (Purpose::Admission, 0x0039_0002),
        (Purpose::Initial, 0x0039_0003),
        (Purpose::Final, 0x0039_0004),
        (Purpose::Publication, 0x0039_0005),
    ] {
        assert_eq!(serde_json::to_value(purpose).unwrap(), code);
        assert_eq!(
            serde_json::from_value::<Purpose>(code.into()).unwrap(),
            purpose
        );
    }
    assert!(serde_json::from_value::<Purpose>(0x0039_0006u32.into()).is_err());
    let input = Input::Select {
        question: crate::mocks::create_question(0),
        purpose: Purpose::Admission,
        root: None,
    };
    let mut encoded = serde_json::to_value(&input).unwrap();
    assert_eq!(encoded["purpose"], 0x0039_0002u32);
    assert_eq!(
        serde_json::from_value::<Input>(encoded.clone()).unwrap(),
        input
    );
    encoded["purpose"] = 0x0039_0006u32.into();
    assert!(serde_json::from_value::<Input>(encoded).is_err());
}

#[test]
fn cooperative_job_binding_is_limited_to_solving() {
    let binding = Binding::new([1; 32], [2; 32]).for_cooperation();
    assert!(
        binding
            .validate_role(&Input::Solve {
                question: crate::mocks::create_question(0)
            })
            .is_ok()
    );
    assert!(binding.validate_role(&Input::find(0)).is_err());
}

#[test]
fn invalid_role_settings_report_machine_readable_reason() {
    let mut settings = Settings::default();
    settings.solving.limits.work_units = 0;
    let error = settings.validate().unwrap_err();
    assert!(matches!(
        error,
        crate::Error::Research(crate::ResearchFailure::InvalidRoleLimits)
    ));
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(
        value["code"],
        u32::from(crate::ResearchFailure::InvalidRoleLimits)
    );
}

#[test]
fn research_command_capacity_and_service_stop_have_distinct_codes() {
    let owner = Manual::new();
    for ordinal in 0..crate::resources::limits().job_commands {
        owner.client.peer_cursor(ordinal as u64).unwrap();
    }
    let full = owner.client.peer_cursor(99).unwrap_err();
    assert_eq!(
        serde_json::to_value(full).unwrap()["code"],
        u32::from(crate::ResearchFailure::CommandQueueFull)
    );
    let client = owner.client.clone();
    drop(owner);
    let stopped = client.peer_cursor(100).unwrap_err();
    assert_eq!(
        serde_json::to_value(stopped).unwrap()["code"],
        u32::from(crate::ResearchFailure::ServiceStopped)
    );
}

#[test]
fn research_submission_preserves_validation_and_capacity_codes() {
    let owner = Manual::new();
    let binding = Binding::new([0; 32], [0; 32]);
    let error = owner
        .client
        .submit(Input::Train { epoch: 0 }, binding.clone())
        .err()
        .unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        u32::from(crate::InputFault::EmptyTrainingEpoch)
    );
    let mut invalid = binding.clone();
    invalid.compatibility = "00".repeat(32);
    let error = owner.client.submit(Input::find(0), invalid).err().unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        u32::from(crate::InputFault::ResearchCompatibility)
    );
    for ordinal in 0..crate::resources::limits().job_commands {
        owner.client.peer_cursor(ordinal as u64).unwrap();
    }
    let error = owner.client.submit(Input::find(0), binding).err().unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        u32::from(crate::ResearchFailure::CommandQueueFull)
    );
}

#[test]
fn oversized_peer_certificate_keeps_its_capacity_code() {
    let owner = Manual::new();
    let input = Input::Peer {
        evidence: crate::learning::peer::Source::Certificate(vec![
            0;
            crate::learning::knowledge::BYTES
                + 1
        ]),
        question: String::new(),
        artifact: String::new(),
        peer: String::new(),
    };
    let error = owner
        .client
        .submit(input, Binding::new([0; 32], [0; 32]))
        .err()
        .unwrap();
    assert_eq!(
        serde_json::to_value(error).unwrap()["code"],
        u32::from(crate::InputLimit::PeerCertificateCapacity)
    );
}
