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
            client: Client { sender },
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
                Command::Submit(input, binding, reply) => {
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
            id,
            binding,
            spent_ms: 0,
            reserved_units: 1,
            state,
            result,
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
    let source = "goal = not(all(x,mem(x,x)))";
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
    assert_eq!(
        settings.validate().unwrap_err(),
        "controlled mock workloads require developer-tools"
    );
    assert!(Settings::default().validate().is_ok());
}

#[test]
fn selected_finding_question_binds_the_returned_question() {
    let supplied = "goal=all(x,eq(x,x))".to_owned();
    let input = Input::Find {
        cursor: 1,
        question: supplied.clone(),
    };
    assert!(Output::Question(supplied).validate(&input).is_ok());
    assert!(
        Output::Question("goal=all(x,eq(x,x)) ".into())
            .validate(&input)
            .is_err()
    );
}
