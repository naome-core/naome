use super::*;
use crate::scenario::{equality_answer, equality_question, refutation_answer, refutation_question};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
fn config() -> (PathBuf, RunConfig) {
    let root = std::env::temp_dir().join(format!(
        "naome-research-run-tests-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let home = root.with_extension("home");
    fs::create_dir(&home).unwrap();
    let path = prepare(&root, &home, "fixture-model", true).unwrap();
    let mut config = read_config(&path).unwrap();
    config.tick_mode = TickMode::SignedFixture;
    (root, config)
}

fn fixture_reply(prompt: &str) -> Value {
    if prompt.contains("TASK discovery") {
        let q = if prompt.contains("Formal refutations") {
            refutation_question()
        } else {
            equality_question(0)
        };
        json!({"title":q.title,"context":q.context,"formula_json":serde_json::to_string(&q.formula).unwrap(),"definitions":q.definitions})
    } else if prompt.contains("TASK vote") {
        let questions = prompt
            .split("Questions: ")
            .nth(1)
            .unwrap()
            .split(". Cast one")
            .next()
            .unwrap();
        let questions: Vec<Value> = serde_json::from_str(questions).unwrap();
        json!({"votes":questions.iter().map(|q|json!({"question_id":q["question_id"],"yes":true})).collect::<Vec<_>>()})
    } else {
        let id = prompt
            .split("question_id ")
            .nth(1)
            .unwrap()
            .split('.')
            .next()
            .unwrap();
        let (file, outcome) = if id == hex(&refutation_question().id().unwrap()) {
            (refutation_answer(), Outcome::Refutation)
        } else {
            (equality_answer(0), Outcome::Proof)
        };
        json!({"question_id":id,"outcome":outcome,"source":file.source,"dependencies":file.dependencies})
    }
}

#[test]
fn autonomous_interest_discovery_votes_proof_refutation_and_restart_consume_six_calls() {
    let (root, config) = config();
    let mut prompts = Vec::new();
    let result = execute(&config, |_, prompt, schema| {
        assert_eq!(schema["additionalProperties"], false);
        prompts.push(prompt.to_owned());
        Ok((
            ProviderReply {
                value: fixture_reply(prompt),
                usage: json!({"fixture":true}),
            },
            json!({"fixture":true}),
        ))
    })
    .unwrap();
    assert_eq!(result["run"]["provider_calls_consumed"], 6);
    assert_eq!(result["run"]["result_blocks"], 2);
    assert_eq!(prompts.len(), 6);
    assert!(prompts[0].contains("Equality and elementary"));
    assert!(prompts[1].contains("Formal refutations"));
    assert!(prompts[2].contains("Equality and elementary"));
    assert!(prompts[3].contains("Formal refutations"));
    let restarted = execute(&config, |_, _, _| {
        panic!("restart must not reset the saved provider budget")
    })
    .unwrap();
    assert_eq!(restarted["run"]["provider_calls_consumed"], 6);
    let (_, state) = Journal::open(&config.directory.join("history")).unwrap();
    assert_eq!(state.results().len(), 2);
    assert!(
        state
            .results()
            .iter()
            .any(|r| r.outcome == Outcome::Refutation)
    );
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(root.with_extension("home")).unwrap();
}

#[test]
fn quota_stops_and_restart_does_not_spend_again() {
    let (root, config) = config();
    let result = execute(&config, |_, _, _| {
        Err(ProviderError {
            kind: ProviderErrorKind::Quota,
            message: "fixture quota".into(),
        })
    })
    .unwrap();
    assert_eq!(result["status"], "stopped");
    assert_eq!(result["provider_calls_consumed"], 1);
    assert_eq!(result["result_blocks"], 0);
    let result = execute(&config, |_, _, _| panic!("quota stop must persist")).unwrap();
    assert_eq!(result["provider_calls_consumed"], 1);
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(root.with_extension("home")).unwrap();
}

#[test]
fn transient_failure_backs_off_once_then_stops_with_consumed_budget() {
    let (root, config) = config();
    let mut calls = 0;
    let result = execute(&config, |_, _, _| {
        calls += 1;
        Err(ProviderError {
            kind: ProviderErrorKind::Transient,
            message: "fixture transient".into(),
        })
    })
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(result["status"], "stopped");
    assert_eq!(result["provider_calls_consumed"], 2);
    let first: Receipt = read_bounded(
        &config.directory.join("provider_calls/receipt-0000.json"),
        MAX_CONFIG_BYTES,
    )
    .unwrap();
    let second: Receipt = read_bounded(
        &config.directory.join("provider_calls/receipt-0001.json"),
        MAX_CONFIG_BYTES,
    )
    .unwrap();
    assert_eq!(first.status, "backoff");
    assert_eq!(second.status, "stopped");
    assert_eq!(first.reservation.task, second.reservation.task);
    assert_eq!(second.reservation.attempt, 1);
    execute(&config, |_, _, _| {
        panic!("persisted stop must prevent another retry")
    })
    .unwrap();
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(root.with_extension("home")).unwrap();
}

#[test]
fn schema_valid_substitution_and_invalid_proof_never_confirm() {
    let (root, config) = config();
    let result = execute(&config, |_, prompt, _| {
        let mut reply = fixture_reply(prompt);
        if prompt.contains("TASK solve") {
            reply["question_id"] = Value::String(hex(&[0; 32]));
        }
        Ok((
            ProviderReply {
                value: reply,
                usage: Value::Null,
            },
            Value::Null,
        ))
    })
    .unwrap();
    assert_eq!(result["run"]["result_blocks"], 0);
    assert_eq!(result["rejected_replies"].as_array().unwrap().len(), 2);
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(root.with_extension("home")).unwrap();
}

#[test]
fn unfinished_provider_reservation_and_changed_budget_fail_closed() {
    let (root, mut config) = config();
    execute(&config, |_, _, _| {
        Err(ProviderError {
            kind: ProviderErrorKind::Auth,
            message: "fixture auth".into(),
        })
    })
    .unwrap();
    fs::remove_file(config.directory.join("provider_calls/receipt-0000.json")).unwrap();
    let error = execute(&config, |_, _, _| {
        panic!("unfinished reservation cannot be respent")
    })
    .unwrap_err();
    assert!(error.contains("unfinished provider reservation"));
    config.max_calls = 7;
    let error = execute(&config, |_, _, _| panic!("changed budget cannot be spent")).unwrap_err();
    assert!(error.contains("budget configuration is pinned"));
    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(root.with_extension("home")).unwrap();
}

#[test]
fn projections_and_typed_replies_are_strictly_bounded() {
    assert!(
        Interests {
            topics: vec!["x".repeat(257)],
            context: String::new()
        }
        .validate()
        .is_err()
    );
    assert!(parse_id(&"A".repeat(64)).is_err());
    assert!(serde_json::from_value::<SolveReply>(json!({"question_id":"x","outcome":"proof","source":"x","dependencies":[],"confidence":1})).is_err());
    assert!(
        serde_json::from_value::<FormulaInput>(
            json!({"op":"equal","left":0,"right":0,"axiom":true})
        )
        .is_err()
    );
}
