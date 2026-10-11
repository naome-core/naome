use super::*;
use std::collections::BTreeMap;

/// Unit-level role coordination control; native process tests exercise Service.
pub(crate) struct Manual {
    pub client: Client,
    receiver: mpsc::Receiver<Command>,
    next: u64,
    waiting: BTreeMap<u64, (Input, Binding, oneshot::Sender<Completion>)>,
    acknowledged: Vec<u64>,
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
        }
    }
    pub(crate) fn requests(&mut self) -> Vec<(u64, Input)> {
        let mut requests = Vec::new();
        while let Ok(command) = self.receiver.try_recv() {
            match command {
                Command::Submit(input, binding, reply) => {
                    let id = self.next;
                    self.next += 1;
                    requests.push((id, input.clone()));
                    self.waiting.insert(id, (input, binding, reply));
                }
                Command::Discard(input, binding) => self
                    .waiting
                    .retain(|_, (i, b, _)| i != &input || b != &binding),
                Command::Acknowledge(id) => self.acknowledged.push(id),
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
            next_cursor: 0,
            records: Vec::new(),
        }
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

#[tokio::test]
async fn python_clock_matches_rust_original_deadline_domain() {
    let mut interpreters = vec![std::path::PathBuf::from("python3")];
    if let Some(path) = std::env::var_os("NAOME_INTEREST_CLOCK_PYTHON") {
        let path = std::path::PathBuf::from(path);
        assert!(
            path.is_absolute(),
            "selected backend interpreter is absolute"
        );
        interpreters.push(path);
    }
    for python in interpreters {
        let before = monotonic_ns().unwrap();
        let command = "import json,time,sys;print(json.dumps({'clock':'clock_gettime(CLOCK_MONOTONIC)','now_ns':time.clock_gettime_ns(time.CLOCK_MONOTONIC),'expired':time.clock_gettime_ns(time.CLOCK_MONOTONIC)>=int(sys.argv[1]),'python':sys.version.split()[0]}))";
        let mut child = tokio::process::Command::new(&python);
        child
            .args(["-I", "-S", "-B", "-c", command])
            .arg(before.to_string())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let child = {
            let _spawn = process::SPAWN.lock().unwrap();
            child.spawn().expect("native Python clock probe spawn")
        };
        let output =
            tokio::time::timeout(std::time::Duration::from_secs(2), child.wait_with_output())
                .await
                .expect("finite clock probe deadline")
                .expect("native Python clock probe");
        let after = monotonic_ns().unwrap();
        assert!(output.status.success(), "clock probe exited successfully");
        assert!(output.stdout.len() <= 1024 && output.stderr.len() <= 1024);
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let python_ns = value["now_ns"].as_u64().unwrap();
        assert!(before <= python_ns && python_ns <= after);
        assert_eq!(value["expired"], true);
        assert_eq!(value["clock"], "clock_gettime(CLOCK_MONOTONIC)");
        println!(
            "\n{}",
            serde_json::json!({"clock_probe":value,"interpreter":python,
                "rust_before_ns":before,"rust_after_ns":after,
                "scope":"native clock domain only; no model loading or inference"})
        );
    }
}
