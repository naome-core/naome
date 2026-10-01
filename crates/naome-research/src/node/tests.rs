use super::{
    budget::{Allowance, Budgets, Period, Phase, Usage},
    engine::Operation,
    *,
};
use crate::{
    formal::{AnswerFile, FormulaInput, Outcome},
    journal::write_new,
    provider::{ProviderConfig, ProviderReply},
    run::Interests,
    state::{Id, PoolConfig, Question, hex},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: PathBuf,
    config: Config,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "naome-node-v2-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let identity_file = root.join("identity.json");
        write_new(&identity_file, &[37u8; 32]).unwrap();
        let config = Config {
            version: 2,
            directory: root.join("node"),
            identity_file,
            run_label: "offline-v2-fixture".into(),
            interests: Interests {
                topics: vec!["Formal logic".into()],
                context: "Offline checked fixture".into(),
            },
            provider: ProviderConfig {
                codex_binary: root.join("never-started"),
                codex_home: root.join("unused-home"),
                model: "offline-fixture".into(),
                timeout_seconds: 5,
                max_output_bytes: 4096,
                disabled_registries: Default::default(),
                pure_js: None,
            },
            budgets: Budgets {
                timezone: "Europe/Berlin".into(),
                research: Allowance {
                    amount: 20,
                    period: Period::Day,
                },
                discoveries: Allowance {
                    amount: 2,
                    period: Period::Hour,
                },
                evaluations: Allowance {
                    amount: 2,
                    period: Period::Hour,
                },
            },
            credit: 3,
            pool: PoolConfig {
                minimum: 1,
                initial: 2,
                maximum: 4,
                drought_ticks: 3,
                quick_result_ticks: 3,
                cooldown_ticks: 3,
            },
        };
        Self { root, config }
    }
    fn init(&self) -> Node {
        Node::initialize(self.config.clone(), 1_790_841_600).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn theorem(number: u8) -> (Question, String) {
    let equality = FormulaInput::Forall {
        variable: 0,
        body: Box::new(FormulaInput::Equal { left: 0, right: 0 }),
    };
    let mut b = equality.clone();
    for bit in 0..7 {
        let left = if number & (1 << bit) == 0 {
            equality.clone()
        } else {
            FormulaInput::Not {
                body: Box::new(equality.clone()),
            }
        };
        b = FormulaInput::Implies {
            left: Box::new(left),
            right: Box::new(b),
        };
    }
    let formula = FormulaInput::Implies {
        left: Box::new(equality.clone()),
        right: Box::new(FormulaInput::Implies {
            left: Box::new(b.clone()),
            right: Box::new(equality.clone()),
        }),
    };
    let source = format!(
        "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n p0 = simplification({}, {})\n return p0\n",
        formula.to_nao().unwrap(),
        equality.to_nao().unwrap(),
        b.to_nao().unwrap()
    );
    (
        Question {
            title: format!("Simplification {number}"),
            context: "Exact closed theorem fixture".into(),
            formula,
            definitions: vec![],
        },
        source,
    )
}
fn publish(node: &mut Node, q: Question) -> Id {
    let id = q.id().unwrap();
    let signed = node.sign(Action::Publish { question: q }).unwrap();
    node.submit(signed).unwrap();
    id
}
fn evaluate(node: &mut Node, id: Id, yes: bool) {
    let signed = node.sign(Action::Evaluate { question: id, yes }).unwrap();
    node.submit(signed).unwrap();
}
fn admit(node: &mut Node, id: Id) {
    evaluate(node, id, true);
    while node.pending(id).unwrap().is_none() {
        node.tick(node.state.clock).unwrap();
    }
}
fn answer(node: &mut Node, id: Id, source: String, outcome: Outcome) -> SignedAction {
    node.sign(Action::Answer {
        question: id,
        outcome,
        file: AnswerFile {
            source,
            dependencies: vec![],
        },
    })
    .unwrap()
}
fn usage(input: u64, output: u64) -> Value {
    let total = json!({"inputTokens":input,"outputTokens":output,"totalTokens":input+output,"cachedInputTokens":0,"reasoningOutputTokens":0});
    let mut response = total.clone();
    response["responseId"] = json!("offline-response");
    json!({"complete":true,"total":total,"responseUsage":[response]})
}
fn response(value: Value, spent: Value) -> ProviderOutcome {
    ProviderOutcome {
        reply: Some(ProviderReply {
            raw_response: value.to_string(),
            value,
            usage: spent.clone(),
            computation: vec![],
        }),
        error: None,
        known_usage: spent,
        provenance: json!({"offline":true}),
        retained_raw_response: None,
    }
}

#[test]
fn pending_identity_late_finalization_exact_retry_and_replay() {
    let f = Fixture::new();
    let mut node = f.init();
    let (q1, s1) = theorem(1);
    let (q2, s2) = theorem(2);
    let id1 = publish(&mut node, q1);
    let id2 = publish(&mut node, q2);
    admit(&mut node, id1);
    admit(&mut node, id2);
    let first = node.pending(id1).unwrap().unwrap();
    // Retiring the lease affects scheduling, never possession eligibility.
    evaluate(&mut node, id1, false);
    node.tick(node.state.clock).unwrap();
    let wrong = answer(&mut node, id1, s2.clone(), Outcome::Proof);
    assert!(node.submit(wrong).is_err());
    assert_eq!(node.credit(node.profile.coordinator).unwrap(), 0);
    let second = answer(&mut node, id2, s2, Outcome::Proof);
    node.submit(second).unwrap();
    let late = answer(&mut node, id1, s1, Outcome::Proof);
    let receipt = node.submit(late.clone()).unwrap();
    assert_eq!(first.id(), receipt.finalization.as_ref().unwrap().block);
    let selected = node.checkpoint().clone();
    assert_eq!(node.submit(late.clone()).unwrap(), receipt);
    assert_eq!(node.checkpoint(), &selected);
    assert_eq!(node.credit(node.profile.coordinator).unwrap(), 6);
    drop(node);
    let mut reopened = Node::open(f.config.clone()).unwrap();
    assert_eq!(reopened.submit(late).unwrap(), receipt);
    drop(reopened);
    let report = Node::replay(
        f.config.clone(),
        &f.root.join("replayed"),
        Some((selected.head, selected.count)),
    )
    .unwrap();
    assert_eq!(report["records_verified"], selected.count);
    assert_eq!(report["independent_checkpoint_verified"], true);
    assert!(
        Node::replay(
            f.config.clone(),
            &f.root.join("wrong-checkpoint"),
            Some(([0; 32], selected.count))
        )
        .is_err()
    );
}

#[test]
fn zero_credit_config_and_never_admitted_answers() {
    let mut f = Fixture::new();
    f.config.credit = 0;
    let mut node = f.init();
    let (q, source) = theorem(3);
    let id = publish(&mut node, q);
    let signed = answer(&mut node, id, source.clone(), Outcome::Proof);
    assert!(node.submit(signed).is_err());
    admit(&mut node, id);
    let signed = answer(&mut node, id, source, Outcome::Proof);
    let receipt = node.submit(signed).unwrap();
    assert_eq!(receipt.finalization.unwrap().credit, 0);
    assert_eq!(node.credit(node.profile.coordinator).unwrap(), 0);
    drop(node);
    let mut changed = f.config.clone();
    changed.credit = 1;
    assert!(Node::open(changed).is_err());
}

#[test]
fn copied_proof_and_early_citation_survive_more_than_64_results() {
    let f = Fixture::new();
    let mut node = f.init();
    let mut early = None;
    for n in 0..70u8 {
        let (q, source) = theorem(n);
        let id = publish(&mut node, q);
        admit(&mut node, id);
        let signed = answer(&mut node, id, source, Outcome::Proof);
        let result = node.submit(signed).unwrap().finalization.unwrap();
        if n == 0 {
            early = Some((id, result.artifact_ids.last().unwrap().clone()));
        }
    }
    assert_eq!(node.state.questions, 70);
    assert_eq!(node.state.finalized, 70);
    let (_, proof) = early.unwrap();
    let mut all = std::collections::BTreeSet::new();
    for cursor in (0..70).step_by(16) {
        for (id, _, pending, finalized) in node.questions(cursor, 16).unwrap() {
            assert!(all.insert(id));
            assert!(pending.is_some());
            assert!(finalized.is_some());
        }
    }
    assert_eq!(all.len(), 70);
    assert!(node.questions(70, 16).unwrap().is_empty());
    assert!(node.questions(71, 16).is_err());
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    assert!(
        node.artifact_source(crate::run::parse_id(&proof).unwrap())
            .unwrap()
            .is_some()
    );
    // The old proof is selected by exact ID even outside the recent projection.
    let (mut q, _) = theorem(0);
    q.formula = FormulaInput::Not {
        body: Box::new(q.formula),
    };
    let id = publish(&mut node, q);
    admit(&mut node, id);
    let statement = node
        .question(id)
        .unwrap()
        .unwrap()
        .formula
        .to_nao()
        .unwrap();
    // Possession of the positive theorem refutes its single negation only if
    // the exact checker conclusion matches Not(target); double negation is not normalized.
    let bad = answer(
        &mut node,
        id,
        format!(
            "foundation = \"naome:zfc\"\nstatement = {statement}\nproof:\n p0 = cite(\"{proof}\")\n return p0\n"
        ),
        Outcome::Proof,
    );
    assert!(node.submit(bad).is_err());
    // Use that early proof as a necessary premise for a new exact conclusion.
    let (base, _) = theorem(0);
    let target = FormulaInput::Forall {
        variable: 9,
        body: Box::new(base.formula.clone()),
    };
    let id = publish(
        &mut node,
        Question {
            title: "Early citation after archive growth".into(),
            context: String::new(),
            formula: target.clone(),
            definitions: vec![],
        },
    );
    admit(&mut node, id);
    let source = format!(
        "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n p0 = cite(\"{proof}\")\n p1 = generalization(p0, x9)\n return p1\n",
        target.to_nao().unwrap()
    );
    let signed = answer(&mut node, id, source, Outcome::Proof);
    node.submit(signed).unwrap();
    assert_eq!(node.state.finalized, 71);
}

#[test]
fn independent_attempts_and_research_overrun_settle_the_admission_window() {
    let f = Fixture::new();
    let mut node = f.init();
    let (q, source) = theorem(5);
    let id = publish(&mut node, q);
    admit(&mut node, id);
    let old = node.state.research.window;
    let reservation = node
        .reserve(
            Phase::Solve,
            Some(id),
            old.end - 1,
            "offline solve".into(),
            json!({}),
        )
        .unwrap();
    assert_eq!(reservation.window, old);
    node.observe(old.end + 1).unwrap();
    let reply = json!({"question_id":hex(&id),"outcome":"proof","source":source,"dependencies":[]});
    node.record_response(&reservation, response(reply, usage(18, 9)))
        .unwrap();
    node.recover_provider().unwrap();
    assert_eq!(
        node.window_ledger(Phase::Solve, old.start)
            .unwrap()
            .unwrap()
            .spent,
        27
    );
    assert_eq!(node.state.research.used, 0);
    assert_eq!(node.state.discovery.used, 0);
    let now = node.state.clock;
    let r = node
        .reserve(
            Phase::Discover,
            None,
            now,
            "offline discovery".into(),
            json!({}),
        )
        .unwrap();
    assert_eq!(node.state.discovery.used, 1);
    let mut failed = ProviderOutcome {
        reply: None,
        error: Some("invalid JSON".into()),
        known_usage: usage(5, 2),
        provenance: json!({}),
        retained_raw_response: Some("not JSON".into()),
    };
    failed.provenance = json!({"offline":true});
    node.record_response(&r, failed).unwrap();
    node.recover_provider().unwrap();
    assert_eq!(node.state.research.used, 0);
    assert_eq!(node.state.discovery.used, 1);
    assert_eq!(
        node.window_ledger(Phase::Discover, r.window.start)
            .unwrap()
            .unwrap()
            .input,
        5
    );
    assert!(
        node.reserve(
            Phase::Discover,
            None,
            now,
            "blocked backoff".into(),
            json!({})
        )
        .is_err()
    );
}

#[test]
fn restart_before_response_blocks_every_phase_across_renewal_and_moving_store() {
    let f = Fixture::new();
    let mut node = f.init();
    let clock = node.state.clock;
    node.reserve(Phase::Discover, None, clock, "offline".into(), json!({}))
        .unwrap();
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    assert!(matches!(
        node.step(clock + 86400).unwrap(),
        Step::Wait {
            reason: WaitReason::AccountingUnknown,
            ..
        }
    ));
    assert!(
        node.reserve(
            Phase::Discover,
            None,
            clock + 86400,
            "retry".into(),
            json!({})
        )
        .is_err()
    );
    drop(node);
    let moved = f.root.join("moved");
    fs::rename(&f.config.directory, &moved).unwrap();
    let mut config = f.config.clone();
    config.directory = moved;
    let mut node = Node::open(config).unwrap();
    assert!(!node.recover_provider().unwrap());
    assert_eq!(node.state.attempts, 1);
}

#[test]
fn missing_usage_is_retained_and_clock_rollback_never_reissues_allowance() {
    let f = Fixture::new();
    let mut node = f.init();
    let now = node.state.clock;
    let r = node
        .reserve(Phase::Discover, None, now, "offline".into(), json!({}))
        .unwrap();
    node.record_response(
        &r,
        response(
            json!({"invalid":true}),
            json!({"total":{"inputTokens":4,"outputTokens":2,"totalTokens":6}}),
        ),
    )
    .unwrap();
    assert!(!node.recover_provider().unwrap());
    node.observe(now + 86400).unwrap();
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    assert!(node.state.usage_unknown.is_some());
    assert_eq!(node.state.attempts, 1);
    assert!(
        node.reserve(
            Phase::Discover,
            None,
            now + 86400,
            "retry".into(),
            json!({})
        )
        .is_err()
    );
    drop(node);
    let clean = Fixture::new();
    let mut node = clean.init();
    node.observe(now + 4000).unwrap();
    assert!(!node.observe(now).unwrap());
    assert!(matches!(
        node.step(now).unwrap(),
        Step::Wait {
            reason: WaitReason::ClockRollback,
            ..
        }
    ));
}

#[test]
fn response_settlement_action_and_commit_marker_recover_once() {
    for boundary in 0..4 {
        let f = Fixture::new();
        let mut node = f.init();
        let (q, source) = theorem(8);
        let id = publish(&mut node, q);
        admit(&mut node, id);
        let r = node
            .reserve(
                Phase::Solve,
                Some(id),
                node.state.clock,
                "offline".into(),
                json!({}),
            )
            .unwrap();
        node.record_response(
            &r,
            response(
                json!({"question_id":hex(&id),"outcome":"proof","source":source,"dependencies":[]}),
                usage(3, 2),
            ),
        )
        .unwrap();
        if boundary >= 1 {
            let operation = Operation::Settle {
                settlement: Some(super::model::Settlement {
                    reservation: r.id(),
                    window: r.window,
                    phase: r.phase,
                    usage: Usage::from_complete_provider(&usage(3, 2)).unwrap(),
                }),
                error: None,
            };
            let (next, changes) = node.derive(&operation).unwrap();
            node.commit(operation, next, changes).unwrap();
        }
        if boundary >= 2 {
            let Operation::Response {
                action: Some(signed),
                ..
            } = node.operation(node.state.received.unwrap()).unwrap()
            else {
                panic!("saved action")
            };
            let before = fs::read(f.config.directory.join("checkpoint.json")).unwrap();
            node.submit(signed).unwrap();
            if boundary == 3 {
                fs::write(f.config.directory.join("checkpoint.json"), before).unwrap();
            }
        }
        drop(node);
        let mut reopened = Node::open(f.config.clone()).unwrap();
        assert!(reopened.recover_provider().unwrap());
        assert_eq!(reopened.state.finalized, 1);
        assert_eq!(reopened.state.research.used, 5);
        assert_eq!(reopened.credit(reopened.profile.coordinator).unwrap(), 3);
        let checkpoint = reopened.checkpoint().clone();
        assert!(reopened.recover_provider().unwrap());
        assert_eq!(reopened.checkpoint(), &checkpoint);
    }
}

#[test]
fn second_writer_fails_before_any_provider_admission() {
    let f = Fixture::new();
    let node = f.init();
    assert!(Node::open(f.config.clone()).is_err());
    assert_eq!(node.state.attempts, 0);
    drop(node);
    assert!(Node::open(f.config.clone()).is_ok());
}

#[test]
fn depleted_discovery_continues_evaluation_and_solving_without_repeated_no_votes() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 0;
    let mut node = f.init();
    let (q, source) = theorem(10);
    let id = publish(&mut node, q);
    let Step::Admitted(r) = node.step(node.state.clock).unwrap() else {
        panic!("evaluation admitted")
    };
    assert_eq!(r.phase, Phase::Evaluate);
    node.record_response(
        &r,
        response(json!({"question_id":hex(&id),"yes":true}), usage(100, 1)),
    )
    .unwrap();
    node.recover_provider().unwrap();
    assert_eq!(node.state.research.used, 0);
    assert!(matches!(
        node.step(node.state.clock).unwrap(),
        Step::Progress
    ));
    let Step::Admitted(r) = node.step(node.state.clock).unwrap() else {
        panic!("solve admitted")
    };
    assert_eq!(r.phase, Phase::Solve);
    node.record_response(
        &r,
        response(
            json!({"question_id":hex(&id),"outcome":"proof","source":source,"dependencies":[]}),
            usage(19, 5),
        ),
    )
    .unwrap();
    node.recover_provider().unwrap();
    assert_eq!(node.state.research.used, 24);
    assert!(matches!(
        node.step(node.state.clock).unwrap(),
        Step::Wait {
            reason: WaitReason::Dormant,
            until: None
        }
    ));
    let (q, _) = theorem(11);
    let id = publish(&mut node, q);
    evaluate(&mut node, id, false);
    assert!(matches!(
        node.step(node.state.clock).unwrap(),
        Step::Wait {
            reason: WaitReason::Dormant,
            ..
        }
    ));
}

#[test]
fn all_zero_allocations_wait_dormant_and_stop_wakes_without_provider() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 0;
    f.config.budgets.evaluations.amount = 0;
    f.config.budgets.research.amount = 0;
    let mut node = f.init();
    let control = Control::default();
    let other = control.clone();
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(40));
        other.stop();
    });
    let now = node.state.clock;
    let checkpoint = node.checkpoint().clone();
    node.run_with(
        &control,
        || Ok(now),
        |_, _| panic!("no provider for a zero allocation"),
    )
    .unwrap();
    stopper.join().unwrap();
    assert_eq!(node.checkpoint(), &checkpoint);
    assert_eq!(node.state.attempts, 0);
}

#[test]
fn segmented_history_crosses_4096_records_and_32_mib_with_streamed_replay() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 1000;
    let mut node = f.init();
    for n in 0..850 {
        let now = node.state.clock + 60;
        let reservation = node
            .reserve(
                Phase::Discover,
                None,
                now,
                "offline prompt ".repeat(1000),
                json!({}),
            )
            .unwrap();
        let outcome = ProviderOutcome {
            reply: None,
            error: Some("offline invalid output".into()),
            known_usage: usage(1, 1),
            provenance: json!({"offline_padding":"a".repeat(40*1024)}),
            retained_raw_response: Some("invalid fixture".into()),
        };
        node.record_response(&reservation, outcome).unwrap();
        assert!(node.recover_provider().unwrap());
        assert_eq!(node.state.attempts, n + 1);
    }
    let selected = node.checkpoint().clone();
    assert!(selected.count > 4096);
    let mut bytes = 0;
    for ordinal in 0..selected.count {
        let record = node.store.record(ordinal).unwrap();
        bytes += serde_json::to_vec(&record).unwrap().len();
    }
    assert!(bytes > 32 * 1024 * 1024);
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    assert_eq!(node.checkpoint(), &selected);
    let (q, _) = theorem(45);
    let id = publish(&mut node, q);
    assert!(node.question(id).unwrap().is_some());
    let selected = node.checkpoint().clone();
    drop(node);
    let report = Node::replay(
        f.config.clone(),
        &f.root.join("streamed-replay"),
        Some((selected.head, selected.count)),
    )
    .unwrap();
    assert_eq!(report["records_verified"], selected.count);
    assert_eq!(report["provider_turns"], 0);
}

#[test]
fn dormant_local_mailbox_wakes_the_single_writer_and_returns_a_receipt() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 0;
    f.config.budgets.evaluations.amount = 0;
    f.config.budgets.research.amount = 0;
    let mut node = f.init();
    let control = Control::default();
    let other = control.clone();
    let (q, _) = theorem(21);
    let signed = node.sign(Action::Publish { question: q }).unwrap();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        let receipt = other
            .submit(signed)
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap()
            .unwrap();
        other.stop();
        receipt
    });
    let now = node.state.clock;
    node.run_with(
        &control,
        || Ok(now),
        |_, _| panic!("no allocated provider work"),
    )
    .unwrap();
    let receipt = writer.join().unwrap();
    assert_eq!(node.state.questions, 1);
    assert_eq!(node.state.attempts, 0);
    assert_eq!(receipt.record, 0);
}

#[test]
fn productive_depleted_phase_sleeps_then_renews_without_carryover() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 1;
    f.config.budgets.evaluations.amount = 0;
    f.config.budgets.research.amount = 0;
    let mut node = f.init();
    let boundary = node.state.discovery.window.end;
    let r = node
        .reserve(
            Phase::Discover,
            None,
            boundary - 1,
            "offline".into(),
            json!({}),
        )
        .unwrap();
    let (q, _) = theorem(22);
    node.record_response(&r,response(json!({"title":q.title,"context":q.context,"formula_json":serde_json::to_string(&q.formula).unwrap(),"definitions":[]}),usage(2,1))).unwrap();
    node.recover_provider().unwrap();
    assert!(
        matches!(node.step(boundary-1).unwrap(),Step::Wait {until:Some(t),reason:WaitReason::BudgetRenewal} if t==boundary)
    );
    let clock = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(boundary - 1));
    let advancing = clock.clone();
    let control = Control::default();
    let wake = control.clone();
    let timer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(30));
        advancing.store(boundary + 1, Ordering::SeqCst);
        wake.notify();
    });
    let mut calls = 0;
    node.run_with(
        &control,
        || Ok(clock.load(Ordering::SeqCst)),
        |_, control| {
            calls += 1;
            control.stop();
            ProviderOutcome {
                reply: None,
                error: Some("offline failure".into()),
                known_usage: usage(1, 1),
                provenance: json!({}),
                retained_raw_response: None,
            }
        },
    )
    .unwrap();
    timer.join().unwrap();
    assert_eq!(calls, 1);
    assert_eq!(node.state.discovery.used, 1);
    assert_eq!(node.state.attempts, 2);
    assert_eq!(
        node.window_ledger(Phase::Discover, r.window.start)
            .unwrap()
            .unwrap()
            .spent,
        1
    );
}

#[test]
fn the_same_known_proof_can_finalize_separate_exact_proof_and_refutation_blocks() {
    let f = Fixture::new();
    let mut node = f.init();
    let q = crate::scenario::refutation_question();
    let id = publish(&mut node, q.clone());
    admit(&mut node, id);
    let file = crate::scenario::refutation_answer();
    let bad = node
        .sign(Action::Answer {
            question: id,
            outcome: Outcome::Proof,
            file: file.clone(),
        })
        .unwrap();
    assert!(node.submit(bad).is_err());
    let signed = node
        .sign(Action::Answer {
            question: id,
            outcome: Outcome::Refutation,
            file: file.clone(),
        })
        .unwrap();
    let first = node.submit(signed).unwrap().finalization.unwrap();
    let proof_question = Question {
        title: "Exact positive Infinity statement".into(),
        context: String::new(),
        formula: FormulaInput::Not {
            body: Box::new(q.formula),
        },
        definitions: vec![],
    };
    let proof_id = publish(&mut node, proof_question);
    admit(&mut node, proof_id);
    let copied = node
        .sign(Action::Answer {
            question: proof_id,
            outcome: Outcome::Proof,
            file,
        })
        .unwrap();
    let second = node.submit(copied).unwrap().finalization.unwrap();
    assert_eq!(first.canonical_proof, second.canonical_proof);
    assert_ne!(first.block, second.block);
    assert_ne!(first.award, second.award);
    assert_eq!(node.credit(node.profile.coordinator).unwrap(), 6);
}

#[test]
fn oversized_model_action_keeps_usage_and_rejection_through_restart_and_retry() {
    for restart in [false, true] {
        let mut f = Fixture::new();
        f.config.provider.max_output_bytes = 256 * 1024;
        let mut node = f.init();
        let (q, _) = theorem(40);
        let id = publish(&mut node, q);
        admit(&mut node, id);
        let value = json!({"question_id":hex(&id),"outcome":"proof","source":"a".repeat(100*1024),"dependencies":[]});
        let outcome = response(value.clone(), usage(8, 7));
        assert!(serde_json::to_vec(&value).unwrap().len() < f.config.provider.max_output_bytes);
        let reservation = node
            .reserve(
                Phase::Solve,
                Some(id),
                node.state.clock,
                "offline large action".into(),
                json!({}),
            )
            .unwrap();
        let nonce = node.next_nonce().unwrap();
        node.record_response(&reservation, outcome).unwrap();
        let response_index = node.state.received.unwrap();
        let Operation::Response {
            action,
            semantic_error,
            outcome,
            ..
        } = node.operation(response_index).unwrap()
        else {
            panic!("stored response")
        };
        assert!(action.is_none());
        assert!(semantic_error.unwrap().contains("per-action size"));
        assert_eq!(outcome.reply.unwrap().raw_response, value.to_string());
        if restart {
            drop(node);
            node = Node::open(f.config.clone()).unwrap();
        }
        assert!(node.recover_provider().unwrap());
        assert!(node.state.usage_unknown.is_none());
        assert_eq!(node.state.research.used, 15);
        assert_eq!(node.state.finalized, 0);
        assert_eq!(node.credit(node.profile.coordinator).unwrap(), 0);
        assert_eq!(node.next_nonce().unwrap(), nonce);
        assert_eq!(node.state.backoff_until[2], node.state.clock + 30);
        assert!(node.state.leases.iter().all(|lease| lease.question != id));
        assert_eq!(
            node.window_ledger(Phase::Solve, reservation.window.start)
                .unwrap()
                .unwrap()
                .spent,
            15
        );
        let after = node.checkpoint().clone();
        assert!(node.recover_provider().unwrap());
        assert_eq!(node.checkpoint(), &after);
        assert!(
            node.reserve(
                Phase::Discover,
                None,
                node.state.clock,
                "unaffected discovery".into(),
                json!({})
            )
            .is_ok()
        );
    }
}

fn record_path(directory: &std::path::Path, ordinal: u64) -> PathBuf {
    directory
        .join("records")
        .join(format!("{:014x}", ordinal >> 8))
        .join(format!("{:02x}.json", ordinal & 255))
}

#[test]
fn actual_atomic_write_faults_recover_finalization_credit_and_nonce_once() {
    use super::index::{WriteFailure, fail_next_write};
    for checkpoint_write in [false, true] {
        for failure in [
            WriteFailure::PartialWrite,
            WriteFailure::FileSync,
            WriteFailure::DirectorySync,
        ] {
            let f = Fixture::new();
            let mut node = f.init();
            let (q, source) = theorem(46);
            let id = publish(&mut node, q);
            admit(&mut node, id);
            let signed = answer(&mut node, id, source, Outcome::Proof);
            let before = node.checkpoint().clone();
            let target = if checkpoint_write {
                f.config.directory.join("checkpoint.json")
            } else {
                record_path(&f.config.directory, before.count)
            };
            fail_next_write(target, failure);
            assert!(
                node.submit(signed.clone())
                    .unwrap_err()
                    .contains("injected")
            );
            assert!(node.store.failed());
            assert!(node.submit(signed.clone()).unwrap_err().contains("reopen"));
            drop(node);
            let mut node = Node::open(f.config.clone()).unwrap();
            let selected = checkpoint_write || failure == WriteFailure::DirectorySync;
            assert_eq!(node.state.finalized, u64::from(selected));
            assert_eq!(
                node.credit(node.profile.coordinator).unwrap(),
                if selected { 3 } else { 0 }
            );
            let receipt = node.submit(signed.clone()).unwrap();
            assert_eq!(receipt.record, before.count);
            let after = node.checkpoint().clone();
            assert_eq!(after.count, before.count + 1);
            assert_eq!(node.submit(signed.clone()).unwrap(), receipt);
            assert_eq!(node.checkpoint(), &after);
            assert_eq!(node.next_nonce().unwrap(), signed.nonce + 1);
            assert_eq!(node.credit(node.profile.coordinator).unwrap(), 3);
            drop(node);
            let replay = Node::replay(
                f.config.clone(),
                &f.root.join("fault-replay"),
                Some((after.head, after.count)),
            )
            .unwrap();
            assert_eq!(replay["records_verified"], after.count);
        }
    }
}

#[test]
fn streamed_replay_detects_tamper_truncate_gap_reorder_and_removed_suffix() {
    for corruption in 0..5 {
        let f = Fixture::new();
        let mut node = f.init();
        let (q, _) = theorem(47);
        publish(&mut node, q);
        let prefix = fs::read(f.config.directory.join("checkpoint.json")).unwrap();
        let (q, _) = theorem(48);
        publish(&mut node, q);
        node.observe(node.state.clock + 1).unwrap();
        let selected = node.checkpoint().clone();
        drop(node);
        let zero = record_path(&f.config.directory, 0);
        let one = record_path(&f.config.directory, 1);
        match corruption {
            0 => {
                let mut value: Value = serde_json::from_slice(&fs::read(&zero).unwrap()).unwrap();
                value["body"]["operation"]["signed"]["action"]["question"]["title"] =
                    json!("tampered source");
                fs::write(&zero, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            1 => {
                let bytes = fs::read(&zero).unwrap();
                fs::write(&zero, &bytes[..bytes.len() / 2]).unwrap();
            }
            2 => {
                fs::remove_file(&one).unwrap();
            }
            3 => {
                let a = fs::read(&zero).unwrap();
                let b = fs::read(&one).unwrap();
                fs::write(&zero, b).unwrap();
                fs::write(&one, a).unwrap();
            }
            4 => {
                fs::write(f.config.directory.join("checkpoint.json"), prefix).unwrap();
                fs::remove_file(&one).unwrap();
                fs::remove_file(record_path(&f.config.directory, 2)).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            Node::replay(
                f.config.clone(),
                &f.root.join("corrupt-replay"),
                Some((selected.head, selected.count))
            )
            .is_err(),
            "corruption {corruption}"
        );
    }
}

#[test]
fn bounded_evaluation_cursor_survives_restart_and_visits_every_unreviewed_question() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 0;
    f.config.budgets.research.amount = 0;
    f.config.budgets.evaluations.amount = 100;
    let mut node = f.init();
    let mut ids = vec![];
    for n in 0..41 {
        let (q, _) = theorem(n);
        ids.push(publish(&mut node, q));
    }
    for id in &ids[..36] {
        evaluate(&mut node, *id, false);
    }
    let now = node.state.clock;
    assert!(matches!(node.step(now).unwrap(), Step::Progress));
    assert_eq!(node.state.evaluated_cursor, 16);
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    assert_eq!(node.state.evaluated_cursor, 16);
    assert!(matches!(node.step(now).unwrap(), Step::Progress));
    assert_eq!(node.state.evaluated_cursor, 32);
    for id in &ids[36..] {
        let Step::Admitted(reservation) = node.step(now).unwrap() else {
            panic!("unreviewed evaluation");
        };
        assert_eq!(reservation.phase, Phase::Evaluate);
        assert_eq!(reservation.target, Some(*id));
        node.record_response(
            &reservation,
            response(json!({"question_id":hex(id),"yes":false}), usage(1, 1)),
        )
        .unwrap();
        node.recover_provider().unwrap();
        drop(node);
        node = Node::open(f.config.clone()).unwrap();
    }
    assert_eq!(node.state.attempts, 5);
    assert_eq!(node.state.unreviewed, 0);
    assert!(matches!(
        node.step(now).unwrap(),
        Step::Wait {
            until: None,
            reason: WaitReason::Dormant
        }
    ));
}

#[test]
fn transitive_proof_helpers_recheck_after_restart_and_failed_order_is_atomic() {
    const H: &str = "foundation = \"naome:zfc\"\nstatement = forall(x, equal(x, x))\nproof:\n p0 = equality_reflexivity(x)\n p1 = generalization(p0, x)\n return p1\n";
    let h_id = hex(naome_authoring::compile(H).unwrap().proof_id().as_bytes());
    let helper = format!(
        "foundation = \"naome:zfc\"\nformulas:\n h = forall(x, equal(x, x))\nstatement = implies(h, h)\nproof:\n p0 = cite(\"{h_id}\")\n p1 = simplification(h, h)\n p2 = modus_ponens(p0, p1)\n return p2\n"
    );
    let (_, prepared) = super::context::prepare(&[H, &helper], |_| Ok(None)).unwrap();
    let b_id = hex(&prepared[1].id);
    let source = format!(
        "foundation = \"naome:zfc\"\nformulas:\n h = forall(x, equal(x, x))\n b = implies(h, h)\nstatement = implies(h, b)\nproof:\n p0 = cite(\"{b_id}\")\n p1 = simplification(b, h)\n p2 = modus_ponens(p0, p1)\n return p2\n"
    );
    let h = FormulaInput::Forall {
        variable: 0,
        body: Box::new(FormulaInput::Equal { left: 0, right: 0 }),
    };
    let target = FormulaInput::Implies {
        left: Box::new(h.clone()),
        right: Box::new(FormulaInput::Implies {
            left: Box::new(h.clone()),
            right: Box::new(h),
        }),
    };
    let f = Fixture::new();
    let mut node = f.init();
    let id = publish(
        &mut node,
        Question {
            title: "Transitive helper closure".into(),
            context: String::new(),
            formula: target.clone(),
            definitions: vec![],
        },
    );
    admit(&mut node, id);
    let mut file = AnswerFile {
        source,
        dependencies: vec![H.into(), helper],
    };
    let before = node.checkpoint().clone();
    file.dependencies.swap(0, 1);
    let bad = node
        .sign(Action::Answer {
            question: id,
            outcome: Outcome::Proof,
            file: file.clone(),
        })
        .unwrap();
    assert!(node.submit(bad).is_err());
    assert_eq!(node.checkpoint(), &before);
    file.dependencies.swap(0, 1);
    let signed = node
        .sign(Action::Answer {
            question: id,
            outcome: Outcome::Proof,
            file,
        })
        .unwrap();
    let finalized = node.submit(signed).unwrap().finalization.unwrap();
    assert_eq!(finalized.artifact_ids.len(), 3);
    let final_id = finalized.artifact_ids.last().unwrap();
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    let next_target = FormulaInput::Forall {
        variable: 9,
        body: Box::new(target),
    };
    let id = publish(
        &mut node,
        Question {
            title: "Restart selected transitive proof".into(),
            context: String::new(),
            formula: next_target.clone(),
            definitions: vec![],
        },
    );
    admit(&mut node, id);
    let source = format!(
        "foundation = \"naome:zfc\"\nstatement = {}\nproof:\n p0 = cite(\"{final_id}\")\n p1 = generalization(p0, x9)\n return p1\n",
        next_target.to_nao().unwrap()
    );
    let signed = answer(&mut node, id, source, Outcome::Proof);
    node.submit(signed).unwrap();
    assert_eq!(node.state.finalized, 2);
    assert_eq!(node.credit(node.profile.coordinator).unwrap(), 6);
    let selected = node.checkpoint().clone();
    drop(node);
    assert!(
        Node::replay(
            f.config.clone(),
            &f.root.join("helper-replay"),
            Some((selected.head, selected.count))
        )
        .is_ok()
    );
}

#[test]
fn function_definition_resolver_loads_exact_obligation_from_signed_disk_after_restart() {
    use super::{
        context::{self, Reference, StoredArtifact},
        store::{Store, change, index_key},
    };
    let obligation = include_str!("../../../../examples/identity-function-obligation.nao");
    let definition = include_str!("../../../../examples/identity-function.nao");
    let source = include_str!("../../../../examples/identity-function-term-proof.nao");
    let (_, artifacts) = context::prepare(&[obligation, definition], |_| Ok(None)).unwrap();
    assert_eq!(artifacts[1].dependencies, vec![artifacts[0].id]);
    let f = Fixture::new();
    let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
    let directory = f.root.join("resolver-library");
    let profile = [19; 32];
    let mut store = Store::create(&directory, profile, &key, &json!({})).unwrap();
    for (ordinal, artifact) in artifacts.iter().enumerate() {
        let mut changes = vec![change("artifact", &artifact.id, &ordinal).unwrap()];
        if let Some(statement) = artifact.statement {
            changes.push(change("statement", &statement, &ordinal).unwrap());
        }
        store.append(artifact, &json!({}), changes, &key).unwrap();
    }
    drop(store);
    let store = Store::open(&directory, profile, key.verifying_key().to_bytes()).unwrap();
    let lookup = |reference: Reference, omit: bool| -> Result<Option<StoredArtifact>, String> {
        let (namespace, id) = match reference {
            Reference::Artifact(id) => ("artifact", id),
            Reference::Statement(id) => ("statement", id),
            Reference::Derivation(_) => return Ok(None),
        };
        let Some(ordinal) = store.get::<u64>(index_key(namespace, &id))? else {
            return Ok(None);
        };
        if omit && ordinal == 0 {
            return Ok(None);
        }
        serde_json::from_value(store.record(ordinal)?.body.operation)
            .map(Some)
            .map_err(|e| e.to_string())
    };
    let (base, final_artifact) =
        context::prepare(&[source], |reference| lookup(reference, false)).unwrap();
    let naome_proof::ArtifactPayload::Proof(proof) =
        naome_proof::ArtifactPayload::from_canonical_bytes(&final_artifact[0].bytes).unwrap()
    else {
        panic!("function proof")
    };
    let normal = proof
        .into_unchecked_normal_form()
        .with_matching_canonical_bytes(final_artifact[0].bytes[1..].into())
        .unwrap();
    let checked = naome_checker::check_normal_form_with_state(normal, &base).unwrap();
    assert!(
        crate::formal::check_answer(
            &AnswerFile {
                source: source.into(),
                dependencies: vec![]
            },
            checked.conclusion(),
            Outcome::Proof,
            &base
        )
        .is_ok()
    );
    assert!(context::prepare(&[source], |reference| lookup(reference, true)).is_err());
}

#[test]
fn bad_signature_stays_fatal_and_never_spends_nonce_or_credit() {
    let f = Fixture::new();
    let mut node = f.init();
    let (q, source) = theorem(49);
    let id = publish(&mut node, q);
    admit(&mut node, id);
    let mut signed = answer(&mut node, id, source, Outcome::Proof);
    signed.signature[0] ^= 1;
    let before = node.checkpoint().clone();
    assert!(node.submit(signed).is_err());
    assert_eq!(node.checkpoint(), &before);
    assert_eq!(node.state.finalized, 0);
    assert_eq!(node.credit(node.profile.coordinator).unwrap(), 0);
}

#[test]
fn malformed_complete_usage_in_each_phase_survives_restart_and_blocks_all_phases() {
    for phase in [Phase::Discover, Phase::Evaluate, Phase::Solve] {
        let f = Fixture::new();
        let mut node = f.init();
        let (q, _) = theorem(50);
        let id = publish(&mut node, q);
        admit(&mut node, id);
        let now = node.state.clock;
        let reservation = node
            .reserve(
                phase,
                if phase == Phase::Discover {
                    None
                } else {
                    Some(id)
                },
                now,
                "offline malformed usage".into(),
                json!({}),
            )
            .unwrap();
        let mut malformed = usage(3, 2);
        malformed["responseUsage"][0]["cachedInputTokens"] = json!(4);
        node.record_response(
            &reservation,
            response(json!({"invalid":true}), malformed.clone()),
        )
        .unwrap();
        assert!(!node.recover_provider().unwrap());
        drop(node);
        let mut node = Node::open(f.config.clone()).unwrap();
        assert!(node.state.usage_unknown.is_some());
        let Operation::Response { outcome, .. } =
            node.operation(node.state.received.unwrap()).unwrap()
        else {
            panic!("retained response")
        };
        assert_eq!(outcome.known_usage, malformed);
        node.observe(now + 86400).unwrap();
        for next_phase in [Phase::Discover, Phase::Evaluate, Phase::Solve] {
            assert!(
                node.reserve(
                    next_phase,
                    if next_phase == Phase::Discover {
                        None
                    } else {
                        Some(id)
                    },
                    now + 86400,
                    "globally blocked".into(),
                    json!({})
                )
                .is_err()
            );
        }
        assert_eq!(node.state.attempts, 1);
        assert_eq!(node.state.finalized, 0);
    }
}

#[test]
fn frozen_v1_journal_replays_byte_for_byte_alongside_a_distinct_v2_store() {
    use sha2::{Digest, Sha256};
    let files: [(&str, &[u8]); 3] = [
        (
            "genesis.json",
            include_bytes!("../../tests/fixtures/research-v1/genesis.json"),
        ),
        (
            "event-000000.json",
            include_bytes!("../../tests/fixtures/research-v1/event-000000.json"),
        ),
        (
            "event-000001.json",
            include_bytes!("../../tests/fixtures/research-v1/event-000001.json"),
        ),
    ];
    let manifest: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/research-v1/manifest.json"
    ))
    .unwrap();
    let expected = crate::run::parse_id(manifest["head"].as_str().unwrap()).unwrap();
    let f = Fixture::new();
    let directory = f.root.join("preserved-v1");
    fs::create_dir(&directory).unwrap();
    for (name, bytes) in &files {
        assert_eq!(
            hex(&Sha256::digest(bytes)),
            manifest["sha256"][*name].as_str().unwrap()
        );
        fs::write(directory.join(name), bytes).unwrap();
    }
    let (_, legacy) = crate::journal::Journal::open_at(&directory, expected, 2).unwrap();
    assert_eq!(legacy.genesis().genesis.version, 1);
    assert_eq!(legacy.genesis().genesis.limits.questions, 64);
    assert_eq!(legacy.questions().len(), 2);
    let mut wrong = f.config.clone();
    wrong.directory = directory.clone();
    assert!(Node::open(wrong).is_err());
    let mut node = f.init();
    let (q, source) = theorem(51);
    let id = publish(&mut node, q);
    admit(&mut node, id);
    let signed = answer(&mut node, id, source, Outcome::Proof);
    node.submit(signed).unwrap();
    let selected = node.checkpoint().clone();
    drop(node);
    Node::replay(
        f.config.clone(),
        &f.root.join("v2-next-to-v1"),
        Some((selected.head, selected.count)),
    )
    .unwrap();
    assert!(crate::journal::Journal::open(&f.config.directory).is_err());
    assert!(crate::journal::Journal::open_at(&directory, expected, 2).is_ok());
    for (name, bytes) in files {
        assert_eq!(fs::read(directory.join(name)).unwrap(), bytes);
    }
}

#[test]
fn v2_output_storage_limit_is_enforced_before_initialization_or_contact() {
    let mut f = Fixture::new();
    let maximum = super::model::NODE_MAX_OUTPUT_BYTES;
    f.config.provider.max_output_bytes = maximum;
    assert!(f.config.validate().is_ok());
    for excessive in [maximum + 1, crate::provider::MAX_OUTPUT_BYTES] {
        f.config.provider.max_output_bytes = excessive;
        assert!(
            f.config
                .validate()
                .unwrap_err()
                .contains("response storage")
        );
        assert!(Node::initialize(f.config.clone(), 1_790_841_600).is_err());
        assert!(!f.config.directory.exists());
        assert!(!f.config.provider.codex_home.exists());
    }
}

#[test]
fn production_outcome_constructor_retains_maximum_escaped_answers_and_known_usage_once() {
    let maximum = super::model::NODE_MAX_OUTPUT_BYTES;
    for unit in ["a", "\"\\\n\0", "é🙂"] {
        let mut f = Fixture::new();
        f.config.provider.max_output_bytes = maximum;
        let mut node = f.init();
        let (q, _) = theorem(52);
        let id = publish(&mut node, q);
        admit(&mut node, id);
        // Compute the largest final event within the actual serialized stdio
        // ceiling, with room for the usage/completion/RPC frames in that stream.
        let mut lo = 0;
        let mut hi = maximum;
        while lo + 1 < hi {
            let n = (lo + hi) / 2;
            let value = json!({"question_id":hex(&id),"outcome":"proof","source":unit.repeat(n),"dependencies":[]});
            let event = json!({"method":"item/completed","params":{"threadId":"fixture-thread","turnId":"fixture-turn","item":{"id":"answer","type":"agentMessage","phase":"final_answer","text":value.to_string()}}});
            if serde_json::to_vec(&event).unwrap().len() + 8192 <= maximum {
                lo = n;
            } else {
                hi = n;
            }
        }
        let value = json!({"question_id":hex(&id),"outcome":"proof","source":unit.repeat(lo),"dependencies":[]});
        let raw = value.to_string();
        let reply = ProviderReply {
            value,
            raw_response: raw.clone(),
            usage: usage(8, 7),
            computation: vec![],
        };
        let outcome = ProviderOutcome::from_provider_result(
            Ok(reply),
            usage(8, 7),
            json!({"transport":"stdio","source":"offline-production-constructor"}),
            Some(raw.clone()),
        );
        assert!(outcome.retained_raw_response.is_none());
        assert_eq!(
            outcome.provenance["raw_reply"]["location"],
            "reply.raw_response"
        );
        assert_eq!(
            outcome.provenance["raw_reply"]["observation"]["matches_reply"],
            true
        );
        let reservation = node
            .reserve(
                Phase::Solve,
                Some(id),
                node.state.clock,
                "large production outcome".into(),
                json!({}),
            )
            .unwrap();
        node.record_response(&reservation, outcome).unwrap();
        let ordinal = node.state.received.unwrap();
        let record = node.store.record(ordinal).unwrap();
        assert!(
            serde_json::to_vec(&record).unwrap().len() as u64 <= super::store::MAX_RECORD_BYTES
        );
        let Operation::Response { outcome, .. } = node.operation(ordinal).unwrap() else {
            panic!("response")
        };
        assert_eq!(outcome.reply.unwrap().raw_response, raw);
        drop(node);
        let mut node = Node::open(f.config.clone()).unwrap();
        assert!(node.recover_provider().unwrap());
        assert_eq!(node.state.research.used, 15);
        assert!(node.state.usage_unknown.is_none());
        assert_eq!(node.state.finalized, 0);
        assert_eq!(node.credit(node.profile.coordinator).unwrap(), 0);
        let selected = node.checkpoint().clone();
        assert!(node.recover_provider().unwrap());
        assert_eq!(node.checkpoint(), &selected);
        drop(node);
        let replay = Node::replay(
            f.config.clone(),
            &f.root.join("large-outcome-replay"),
            Some((selected.head, selected.count)),
        )
        .unwrap();
        assert_eq!(replay["records_verified"], selected.count);
    }
}

#[test]
fn run_with_large_model_action_returns_stopped_after_settling_known_usage() {
    let mut f = Fixture::new();
    f.config.provider.max_output_bytes = 256 * 1024;
    f.config.budgets.discoveries.amount = 0;
    f.config.budgets.evaluations.amount = 0;
    let mut node = f.init();
    let (q, _) = theorem(41);
    let id = publish(&mut node, q);
    admit(&mut node, id);
    let now = node.state.clock;
    let control = Control::default();
    let mut calls = 0;
    let status=node.run_with(&control,||Ok(now),|reservation,control|{
        assert_eq!(reservation.phase,Phase::Solve);calls+=1;control.stop();
        response(json!({"question_id":hex(&id),"outcome":"proof","source":"a".repeat(100*1024),"dependencies":[]}),usage(3,4))
    }).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(status["lifecycle"], "stopped");
    assert_eq!(node.state.research.used, 7);
    assert!(node.state.usage_unknown.is_none());
}

#[test]
fn bounded_prompts_preserve_definition_identity_and_handle_json_escape_expansion() {
    let mut f = Fixture::new();
    f.config.interests = Interests {
        topics: vec!["\0".repeat(256); 16],
        context: "\0".repeat(2048),
    };
    let mut node = f.init();
    let (mut q, _) = theorem(42);
    q.context = "\0".repeat(4096);
    q.definitions = vec![format!(
        "foundation = \"naome:zfc\"\ndefinition self_equal = relation(x):\n equal(x, x)\n{}",
        " ".repeat(40 * 1024)
    )];
    let id = publish(&mut node, q.clone());
    admit(&mut node, id);
    let Step::Admitted(discovery) = node.step(node.state.clock).unwrap() else {
        panic!("bounded discovery")
    };
    assert!(discovery.prompt_text.len() <= crate::provider::MAX_INPUT_BYTES);
    let failed = ProviderOutcome {
        reply: None,
        error: Some("offline failure".into()),
        known_usage: usage(1, 1),
        provenance: json!({}),
        retained_raw_response: None,
    };
    node.record_response(&discovery, failed).unwrap();
    node.recover_provider().unwrap();
    let Step::Admitted(solve) = node.step(node.state.clock).unwrap() else {
        panic!("bounded solve despite large definition")
    };
    assert_eq!(solve.phase, Phase::Solve);
    assert!(solve.prompt_text.len() <= crate::provider::MAX_INPUT_BYTES);
    assert!(solve.prompt_text.contains("definition_id"));
    assert!(solve.prompt_text.contains(&q.formula.to_nao().unwrap()));
    assert!(!solve.prompt_text.contains(&" ".repeat(40 * 1024)));
    assert_eq!(
        node.question(id).unwrap().unwrap().definitions,
        q.definitions
    );
}

#[test]
fn idle_observed_clock_high_water_blocks_same_window_rollback_across_restart() {
    let mut f = Fixture::new();
    f.config.budgets.discoveries.amount = 1;
    let mut node = f.init();
    let t0 = node.state.clock;
    let reservation = node
        .reserve(Phase::Discover, None, t0, "offline".into(), json!({}))
        .unwrap();
    node.record_response(
        &reservation,
        ProviderOutcome {
            reply: None,
            error: Some("offline failure".into()),
            known_usage: usage(1, 1),
            provenance: json!({}),
            retained_raw_response: None,
        },
    )
    .unwrap();
    node.recover_provider().unwrap();
    assert!(matches!(
        node.step(t0 + 300).unwrap(),
        Step::Wait {
            reason: WaitReason::BudgetRenewal,
            ..
        }
    ));
    assert_eq!(node.state.clock, t0 + 300);
    let (q, _) = theorem(43);
    let id = publish(&mut node, q);
    drop(node);
    let mut node = Node::open(f.config.clone()).unwrap();
    assert_eq!(node.state.clock, t0 + 300);
    assert!(
        matches!(node.step(t0+60).unwrap(),Step::Wait {reason:WaitReason::ClockRollback,until:Some(time)} if time==t0+300)
    );
    assert!(
        node.reserve(
            Phase::Evaluate,
            Some(id),
            t0 + 60,
            "rollback".into(),
            json!({})
        )
        .is_err()
    );
    assert_eq!(node.state.attempts, 1);
    let Step::Admitted(next) = node.step(t0 + 300).unwrap() else {
        panic!("catch-up resumes the affordable evaluation")
    };
    assert_eq!(next.phase, Phase::Evaluate);
}
