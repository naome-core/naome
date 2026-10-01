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
