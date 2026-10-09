use super::*;
use std::collections::BTreeMap;

/// Unit-level role coordination control; native process tests exercise Service.
pub(crate) struct Manual {
    pub client: Client,
    receiver: mpsc::Receiver<Command>,
    next: u64,
    waiting: BTreeMap<u64, (Input, Binding, oneshot::Sender<Completion>)>,
    acknowledged: Vec<u64>,
    discarded: Vec<(Input, Binding)>,
    generation: BTreeMap<u64, crate::generation::Request>,
}

impl Manual {
    pub(crate) fn new() -> Self {
        let (sender, receiver) = mpsc::channel(COMMAND_CAPACITY);
        Self {
            client: Client { sender },
            receiver,
            next: 1,
            waiting: BTreeMap::new(),
            acknowledged: Vec::new(),
            discarded: Vec::new(),
            generation: BTreeMap::new(),
        }
    }
    pub(crate) fn requests(&mut self) -> Vec<(u64, Input)> {
        let mut requests = Vec::new();
        while let Ok(command) = self.receiver.try_recv() {
            match command {
                Command::Submit(input, binding, generation, reply) => {
                    validate_generation(&input, &binding, generation.as_deref()).unwrap();
                    let id = self.next;
                    self.next += 1;
                    requests.push((id, input.clone()));
                    if let Some(request) = generation {
                        self.generation.insert(id, *request);
                    }
                    self.waiting.insert(id, (input, binding, reply));
                }
                Command::Discard(input, binding) => {
                    self.waiting
                        .retain(|_, (i, b, _)| i != &input || b != &binding);
                    self.discarded.push((input, binding));
                }
                Command::Acknowledge(id) => self.acknowledged.push(id),
            }
        }
        requests
    }
    pub(crate) fn generation(&self, id: u64) -> &crate::generation::Request {
        self.generation
            .get(&id)
            .expect("completed test generation request")
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
            next_cursor: 0,
            records: Vec::new(),
        }
    }
    pub(crate) fn discards(&mut self) -> Vec<(Input, Binding)> {
        self.requests();
        std::mem::take(&mut self.discarded)
    }
    pub(crate) fn acknowledgements(&mut self) -> Vec<u64> {
        self.requests();
        std::mem::take(&mut self.acknowledged)
    }
}

#[test]
fn finite_role_horizons_accept_days_and_reject_unbounded_values() {
    let mut settings = Settings::default();
    for horizon in [60 * 60 * 1_000, 24 * 60 * 60 * 1_000, MAX_HORIZON_MS] {
        settings.solving.limits.horizon_ms = horizon;
        assert!(settings.validate().is_ok());
    }
    for horizon in [0, MAX_HORIZON_MS + 1, u64::MAX] {
        settings.solving.limits.horizon_ms = horizon;
        assert!(settings.validate().is_err());
    }
    let mut settings = Settings::default();
    settings.interest.limits.work_units = 0;
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

#[test]
fn generation_submissions_require_an_exact_completed_role_request() {
    let owner = Manual::new();
    let graph = crate::Graph::default();
    let policy = naome_checker::question::PrefilterPolicy::default();
    let binding = Binding::new([0; 32], policy.identity());
    let input = Input::Find { cursor: 7 };
    assert!(
        owner
            .client
            .submit(input.clone(), binding.clone())
            .err()
            .unwrap()
            .contains("completed request")
    );
    let request = crate::generation::Request::build(
        &input,
        &binding,
        &graph,
        crate::generation::OwnerContext::Unavailable {
            reason: "unit fixture has no owner control".into(),
        },
    )
    .unwrap();
    assert!(
        owner
            .client
            .submit_generation(Input::Find { cursor: 8 }, binding.clone(), request.clone(),)
            .is_err()
    );
    let interest = Input::Interest {
        question: crate::mocks::create_question(0),
        purpose: Purpose::Assessment,
        root: None,
    };
    assert!(
        owner
            .client
            .submit_generation(interest, binding.clone(), request.clone())
            .is_err()
    );
    assert!(
        owner
            .client
            .submit_generation(input, binding, request)
            .is_ok()
    );
}
