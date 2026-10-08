use super::*;
use crate::{Graph, network};
use libp2p::identity;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::sync::Notify;

const PROOF: &str = "foundation = \"naome:zfc\" statement = forall(x,equal(x,x)) proof: p0 = equality_reflexivity(x) p1 = generalization(p0,x) return p1";
const QUESTION: &str = "foundation = \"naome:zfc\" statement = forall(x,member(x,x))";
const SOLVED: &str = "foundation = \"naome:zfc\" statement = forall(x,equal(x,x))";

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-local-question-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let key = identity::Keypair::generate_ed25519();
        std::fs::write(
            path.join("identity.key"),
            key.to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        Self(path)
    }
    fn config(&self, sources: Vec<String>) -> network::Config {
        let discovery = network::DiscoveryConfig {
            mdns: false,
            dht: false,
            ..network::DiscoveryConfig::default()
        };
        network::Config {
            directory: self.0.clone(),
            listen: "/ip4/127.0.0.1/tcp/0".into(),
            peers: Vec::new(),
            discovery: Some(discovery),
            producer_sources: sources,
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn question(source: &str) -> CompiledQuestion {
    CompiledQuestion::compile(source).unwrap()
}
async fn context(handle: &QuestionHandle) -> LocalQuestionContext {
    tokio::time::timeout(Duration::from_secs(5), handle.context())
        .await
        .unwrap()
        .unwrap()
}
async fn stop(handle: QuestionAdminHandle, task: tokio::task::JoinHandle<Result<(), String>>) {
    handle.stop().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn running_node_rejects_checked_answers_and_registry_aliases_before_interest() {
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let envelope = graph.author(PROOF).unwrap();
    graph.ingest(envelope, Instant::now()).unwrap();
    let root = graph.content_root();
    drop(graph);
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(true) }
        },
    ));
    assert_eq!(context(&handle).await.checked_proofs, 1);
    let proved = handle.admit_question(question(SOLVED)).await.unwrap();
    assert_eq!(
        proved.assessment.prefilter.reason,
        Some(RejectionReason::KnownProof)
    );
    assert_eq!(proved.assessment.interest, InterestAssessment::NotRun);
    let refuted = handle
        .admit_question(question(
            "foundation = \"naome:zfc\" statement = not_(forall(a,equal(a,a)))",
        ))
        .await
        .unwrap();
    assert_eq!(
        refuted.assessment.prefilter.reason,
        Some(RejectionReason::KnownRefutation)
    );
    assert!(refuted.assessment.submitted_negation_parity);
    let double_negative = handle
        .admit_question(question(
            "foundation = \"naome:zfc\" statement = not_(not_(forall(a,equal(a,a))))",
        ))
        .await
        .unwrap();
    assert_eq!(
        double_negative.assessment.prefilter.reason,
        Some(RejectionReason::KnownProof)
    );
    assert_eq!(proved.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(refuted.outcome, AdmissionOutcome::NotInserted);
    assert!(proved.assessment.novelty().is_none());
    assert!(refuted.assessment.novelty().is_none());
    assert!(double_negative.assessment.novelty().is_none());
    assert_eq!(double_negative.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(context(&handle).await.registered_questions, 0);
    admin
        .import_baseline(question(SOLVED))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        context(&handle).await.registered_questions,
        1,
        "the separate owner capability deliberately imports known baseline knowledge"
    );
    admin
        .import_baseline(question(QUESTION))
        .await
        .unwrap()
        .unwrap();
    let before = context(&handle).await;
    let alias = handle.admit_question(question("# cosmetic source and binder change\nfoundation = \"naome:zfc\"\nstatement = forall(renamed, member(renamed, renamed)) success = \"resolve\"")).await.unwrap();
    assert_eq!(
        alias.assessment.prefilter.reason,
        Some(RejectionReason::ExactDuplicate)
    );
    assert_eq!(alias.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(
        context(&handle).await,
        before,
        "rejected admission cannot modify registry or graph"
    );
    assert_eq!(alias.outcome, AdmissionOutcome::NotInserted);
    assert!(alias.assessment.novelty().is_none());
    let mut limited = PrefilterPolicy::default();
    limited.limits.operations = 1;
    admin.set_policy(limited).await.unwrap();
    let frozen = context(&handle).await;
    let exhausted = handle
        .admit_question(question(
            "foundation = \"naome:zfc\" statement = forall(x,implies(member(x,x),member(x,x)))",
        ))
        .await
        .unwrap();
    assert_eq!(
        exhausted.assessment.prefilter.reason,
        Some(RejectionReason::ExecutionLimit)
    );
    assert_eq!(exhausted.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(exhausted.outcome, AdmissionOutcome::NotInserted);
    assert!(exhausted.assessment.novelty().is_none());
    assert_eq!(context(&handle).await, frozen);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(admin, task).await;
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(root, reopened.content_root());
}

#[tokio::test]
async fn running_node_prefilter_reaches_separate_interest_without_storing_question() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            let ordinal = observed.fetch_add(1, Ordering::SeqCst);
            async move {
                if ordinal == 2 {
                    Err("bounded provider fixture failure".into())
                } else {
                    Ok(false)
                }
            }
        },
    ));
    let before = context(&handle).await;
    for expected in [
        InterestAssessment::Assessed(false),
        InterestAssessment::Assessed(false),
        InterestAssessment::ProviderFailed,
    ] {
        let result = handle.assess(question(QUESTION)).await.unwrap();
        assert!(
            result.prefilter.passed(),
            "interest is not a proof-validity or prefilter oracle"
        );
        assert_eq!(result.interest, expected);
        assert!(result.novelty().is_some());
        assert_eq!(context(&handle).await, before);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    stop(admin, task).await;
}

#[tokio::test]
async fn running_node_checked_proof_ingest_invalidates_pending_interest() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let observed = calls.clone();
    let notify = started.clone();
    let permit = release.clone();
    let (producer, commands) = mpsc::channel(8);
    // Exercise the real shared Node loop and its existing producer intake,
    // after the initial prefilter is captured. No timer or scheduler race may
    // put the proof into the initial snapshot before the callback starts.
    let task = tokio::spawn(network::run_inner(
        directory.config(Vec::new()),
        false,
        inbox,
        Some(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            let notify = notify.clone();
            let permit = permit.clone();
            async move {
                notify.notify_one();
                permit.notified().await;
                Ok(true)
            }
        }),
        commands,
        None,
    ));
    assert_eq!(context(&handle).await.checked_proofs, 0);
    let readonly_client = handle.clone();
    let readonly =
        tokio::spawn(async move { readonly_client.assess(question(SOLVED)).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    release.notify_one();
    let prior_pass = readonly.await.unwrap();
    assert!(prior_pass.prefilter.passed());
    assert_eq!(prior_pass.interest, InterestAssessment::Assessed(true));
    let old_context = context(&handle).await;
    assert_eq!(
        old_context.registered_questions, 0,
        "an earlier read-only Pass has no effect"
    );
    let client = handle.clone();
    let assessment =
        tokio::spawn(async move { client.admit_question(question(SOLVED)).await.unwrap() });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    producer
        .send(Ok(serde_json::json!({"command":"produce", "source":PROOF})))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while context(&handle).await.checked_proofs != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let changed_context = context(&handle).await;
    assert_ne!(changed_context.snapshot, old_context.snapshot);
    release.notify_one();
    let stale = tokio::time::timeout(Duration::from_secs(5), assessment)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stale.assessment.prefilter.reason,
        Some(RejectionReason::StaleContext)
    );
    assert_eq!(stale.assessment.interest, InterestAssessment::Stale);
    assert!(stale.assessment.novelty().is_none());
    assert!(
        prior_pass.novelty().is_some(),
        "the old result remains historical"
    );
    assert_ne!(
        prior_pass.novelty().unwrap().snapshot_id(),
        changed_context.snapshot
    );
    let fresh = handle.admit_question(question(SOLVED)).await.unwrap();
    assert_eq!(
        fresh.assessment.prefilter.reason,
        Some(RejectionReason::KnownProof)
    );
    assert_eq!(fresh.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(stale.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(fresh.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(context(&handle).await, changed_context);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    stop(admin, task).await;
    assert_eq!(
        Graph::open(&directory.0).unwrap().ids().len(),
        1,
        "actual producer path checked and durably ingested the proof"
    );
}

#[tokio::test]
async fn running_node_registry_and_policy_updates_invalidate_pending_interest() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let notify = started.clone();
    let permit = release.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            let notify = notify.clone();
            let permit = permit.clone();
            async move {
                notify.notify_one();
                permit.notified().await;
                Ok(true)
            }
        },
    ));
    for policy_change in [false, true] {
        let client = handle.clone();
        let assessment =
            tokio::spawn(async move { client.admit_question(question(QUESTION)).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        if policy_change {
            let mut policy = PrefilterPolicy::default();
            policy.revision += 1;
            admin.set_policy(policy).await.unwrap();
        } else {
            admin
                .import_baseline(question(SOLVED))
                .await
                .unwrap()
                .unwrap();
        }
        let changed = context(&handle).await;
        release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), assessment)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.assessment.prefilter.reason,
            Some(RejectionReason::StaleContext)
        );
        assert_eq!(result.assessment.interest, InterestAssessment::Stale);
        assert!(result.assessment.novelty().is_none());
        assert_eq!(result.outcome, AdmissionOutcome::NotInserted);
        assert_eq!(context(&handle).await, changed);
    }
    let unsupported = PrefilterPolicy {
        rule_set: 9,
        ..PrefilterPolicy::default()
    };
    admin.set_policy(unsupported).await.unwrap();
    let result = handle.admit_question(question(QUESTION)).await.unwrap();
    assert_eq!(
        result.assessment.prefilter.reason,
        Some(RejectionReason::UnsupportedPolicy)
    );
    assert_eq!(result.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(result.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(context(&handle).await.registered_questions, 1);
    stop(admin, task).await;
}

struct OwnedInterest(Arc<AtomicUsize>);
impl Drop for OwnedInterest {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn running_node_bounds_pending_interest_and_drops_it_on_cancel_and_stop() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let started = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicUsize::new(0));
    let notify = started.clone();
    let observed = dropped.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            let owned = OwnedInterest(observed.clone());
            let notify = notify.clone();
            async move {
                let _owned = owned;
                notify.notify_one();
                std::future::pending::<()>().await;
                Ok(true)
            }
        },
    ));
    let client = handle.clone();
    let first = tokio::spawn(async move { client.admit_question(question(QUESTION)).await });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    let crowded = handle.admit_question(question(SOLVED)).await.unwrap();
    assert_eq!(
        crowded.assessment.prefilter.reason,
        Some(RejectionReason::ReceivingLimit)
    );
    assert_eq!(crowded.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(crowded.outcome, AdmissionOutcome::NotInserted);
    assert!(crowded.assessment.novelty().is_none());
    first.abort();
    let _ = first.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while dropped.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(context(&handle).await.registered_questions, 0);
    let client = handle.clone();
    let second = tokio::spawn(async move { client.admit_question(question(QUESTION)).await });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    assert_eq!(context(&handle).await.registered_questions, 0);
    stop(admin, task).await;
    assert_eq!(second.await.unwrap().unwrap_err(), IntakeError::Stopped);
    assert!(Graph::open(&directory.0).unwrap().ids().is_empty());
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        2,
        "no independently spawned interest task survives node lifetime"
    );
}

#[test]
fn one_entry_prefilter_cache_reuses_both_outcomes_and_invalidates_all_context() {
    let mut graph = Graph::default();
    let mut local = LocalQuestions::new(Some(|_| async { Ok(true) }));
    let input = question(QUESTION);
    let first = local.assess(&graph, &input);
    assert!(first.passed());
    assert_eq!(local.assess(&graph, &input), first);
    assert_eq!(
        local.computations, 1,
        "same full inputs reuse the computed PASS"
    );
    let registered = question(QUESTION);
    local
        .registry
        .insert(RegisteredQuestion::new(*registered.source_hash(), registered.core()).unwrap())
        .unwrap();
    let rejected = local.assess(&graph, &input);
    assert_eq!(rejected.reason, Some(RejectionReason::ExactDuplicate));
    assert_eq!(local.assess(&graph, &input), rejected);
    assert_eq!(
        local.computations, 2,
        "same full inputs reuse the computed REJECT"
    );
    local.policy.revision += 1;
    let next = local.assess(&graph, &input);
    assert!(!next.same_context(&rejected));
    assert_eq!(local.computations, 3);
    let proof = graph.author(PROOF).unwrap();
    graph.ingest(proof, Instant::now()).unwrap();
    let next = local.assess(&graph, &input);
    assert_eq!(
        local.computations, 4,
        "checked graph changes invalidate cache"
    );
    let renamed = question("foundation = \"naome:zfc\" statement = forall(z,member(z,z))");
    let alias = local.assess(&graph, &renamed);
    assert_eq!(next.question, alias.question);
    assert_ne!(next.input, alias.input);
    assert_eq!(
        local.computations, 5,
        "full source changes invalidate even the same canonical question"
    );
}

fn registry_pattern(index: u32) -> naome_foundation::Formula {
    use naome_foundation::{Formula, FreeVariable};
    let x = FreeVariable::new(0);
    let mut body = Formula::equal(x, x);
    for bit in 0..11 {
        let atom = if index & (1 << bit) == 0 {
            Formula::equal(x, x)
        } else {
            Formula::member(x, x)
        };
        body = Formula::implies(atom, body);
    }
    for _ in 0..4 {
        body = Formula::implies(body.clone(), body);
    }
    Formula::for_all(x, body)
}

#[tokio::test]
async fn running_node_uses_entire_large_graph_and_registry_before_interest() {
    use naome_foundation::Formula;
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let target = question(QUESTION);
    let late = graph.author(PROOF).unwrap();
    let late_id = late.proof_id.clone();
    let mut index = 0;
    while graph.ids().len() < 1025 {
        assert!(index < 2048, "finite unique checked source family");
        let formula = registry_pattern(index);
        index += 1;
        let conclusion = Formula::implies(
            formula.clone(),
            Formula::implies(target.core().clone(), formula.clone()),
        );
        let source = format!(
            "foundation = \"naome:zfc\" statement = {} proof: p0 = simplification({}, {}) return p0",
            conclusion.to_source(),
            formula.to_source(),
            target.core().to_source()
        );
        let envelope = graph.author(&source).unwrap();
        if envelope.proof_id < late_id {
            graph.ingest(envelope, Instant::now()).unwrap();
        }
    }
    graph.ingest(late, Instant::now()).unwrap();
    assert_eq!(graph.ids().len(), 1026);
    let root = graph.content_root();
    let conclusions = graph
        .checked_context()
        .proof_conclusions()
        .map(|(_, _, _, length)| length)
        .sum::<usize>();
    assert!(conclusions > 1024 * 1024);
    drop(graph);
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(true) }
        },
    ));
    let initial = tokio::time::timeout(Duration::from_secs(30), handle.context())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        initial.checked_proofs, 1026,
        "real startup recovered and rechecked the entire durable graph"
    );
    let solved = handle.assess(question(SOLVED)).await.unwrap();
    assert_eq!(solved.prefilter.reason, Some(RejectionReason::KnownProof));
    assert_eq!(solved.interest, InterestAssessment::NotRun);
    for index in 0..257 {
        let source = format!(
            "foundation = \"naome:zfc\" statement = {}",
            registry_pattern(index).to_source()
        );
        admin
            .import_baseline(question(&source))
            .await
            .unwrap()
            .unwrap();
    }
    let full = context(&handle).await;
    assert_eq!(full.registered_questions, 257);
    assert_ne!(full.snapshot, initial.snapshot);
    let last = format!(
        "foundation = \"naome:zfc\" statement = {}",
        registry_pattern(256).to_source()
    );
    let duplicate = handle.assess(question(&last)).await.unwrap();
    assert_eq!(
        duplicate.prefilter.reason,
        Some(RejectionReason::ExactDuplicate)
    );
    assert_eq!(duplicate.interest, InterestAssessment::NotRun);
    let mut policy = PrefilterPolicy::default();
    policy.limits.operations = 1;
    admin.set_policy(policy).await.unwrap();
    let exhausted = handle.assess(target.clone()).await.unwrap();
    assert_eq!(
        exhausted.prefilter.reason,
        Some(RejectionReason::ExecutionLimit)
    );
    assert_eq!(exhausted.interest, InterestAssessment::NotRun);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    admin.set_policy(PrefilterPolicy::default()).await.unwrap();
    let approved = handle.assess(target).await.unwrap();
    assert!(
        approved.prefilter.passed(),
        "irrelevant data beyond former caps must not reject the full scope"
    );
    assert_eq!(approved.interest, InterestAssessment::Assessed(true));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        context(&handle).await,
        full,
        "assessments leave full graph and registry unchanged"
    );
    stop(admin, task).await;
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(reopened.content_root(), root);
    assert_eq!(reopened.ids().len(), 1026);
}

#[tokio::test]
async fn running_node_admission_commits_receipt_and_serializes_duplicate_requests() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(true) }
        },
    ));
    let before = context(&handle).await;
    let input = question(QUESTION);
    let readonly = handle.assess(input.clone()).await.unwrap();
    assert!(readonly.prefilter.passed());
    assert_eq!(readonly.interest, InterestAssessment::Assessed(true));
    assert_eq!(context(&handle).await, before);
    let (first, second) = tokio::join!(
        handle.admit_question(input.clone()),
        handle.admit_question(input.clone())
    );
    let results = [first.unwrap(), second.unwrap()];
    let admitted: Vec<_> = results
        .iter()
        .filter_map(|result| {
            if let AdmissionOutcome::Admitted(receipt) = &result.outcome {
                Some(receipt)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        admitted.len(),
        1,
        "one serialized admission wins concurrent duplicates"
    );
    let rejected = results
        .iter()
        .find(|result| result.outcome == AdmissionOutcome::NotInserted)
        .unwrap();
    assert!(matches!(
        rejected.assessment.prefilter.reason,
        Some(RejectionReason::ExactDuplicate | RejectionReason::ReceivingLimit)
    ));
    assert_eq!(rejected.assessment.interest, InterestAssessment::NotRun);
    let after = context(&handle).await;
    assert_eq!(after.registered_questions, 1);
    assert_eq!(after.checked_proofs, 0);
    let receipt = admitted[0];
    assert_eq!(receipt.record(), *input.source_hash());
    assert_eq!(receipt.input(), readonly.prefilter.input);
    assert_eq!(receipt.policy(), before.policy);
    assert_eq!(receipt.snapshot_before(), before.snapshot);
    assert_eq!(receipt.novelty(), readonly.novelty().unwrap());
    assert_eq!(receipt.novelty().input_id(), receipt.input());
    assert_eq!(receipt.novelty().policy_id(), receipt.policy());
    assert_eq!(receipt.novelty().snapshot_id(), receipt.snapshot_before());
    assert_ne!(receipt.novelty().snapshot_id(), receipt.snapshot_after());
    assert_eq!(receipt.snapshot_after(), after.snapshot);
    assert_ne!(receipt.registry_before(), receipt.registry_after());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "assessment and winning admission each run separate interest"
    );
    let alias = handle
        .admit_question(question(
            "# another source\nfoundation = \"naome:zfc\" statement = forall(a,member(a,a))",
        ))
        .await
        .unwrap();
    assert_eq!(
        alias.assessment.prefilter.reason,
        Some(RejectionReason::ExactDuplicate)
    );
    assert_eq!(alias.outcome, AdmissionOutcome::NotInserted);
    assert!(alias.assessment.novelty().is_none());
    assert_eq!(context(&handle).await, after);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    stop(admin, task).await;
}

#[tokio::test]
async fn running_node_admission_without_interest_reports_pass_without_insertion() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let task = tokio::spawn(network::run_with_questions_without_interest(
        directory.config(Vec::new()),
        false,
        inbox,
    ));
    let before = context(&handle).await;
    let result = handle.admit_question(question(QUESTION)).await.unwrap();
    assert!(result.assessment.prefilter.passed());
    assert!(result.assessment.novelty().is_some());
    assert_eq!(result.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(result.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(context(&handle).await, before);
    stop(admin, task).await;
}

#[tokio::test]
async fn running_node_admission_false_error_and_timeout_have_no_effect() {
    let directory = Directory::new();
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let observed_calls = calls.clone();
    let observed_drops = dropped.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            let ordinal = observed_calls.fetch_add(1, Ordering::SeqCst);
            let owned = OwnedInterest(observed_drops.clone());
            async move {
                let _owned = owned;
                match ordinal {
                    0 => Ok(false),
                    1 => Err("fixture interest failure".into()),
                    _ => std::future::pending().await,
                }
            }
        },
    ));
    let before = context(&handle).await;
    for expected in [
        InterestAssessment::Assessed(false),
        InterestAssessment::ProviderFailed,
        InterestAssessment::TimedOut,
    ] {
        let result = tokio::time::timeout(
            INTEREST_TIMEOUT + Duration::from_secs(5),
            handle.admit_question(question(QUESTION)),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            result.assessment.prefilter.passed(),
            "interest cannot change the formal Pass claim"
        );
        assert_eq!(result.assessment.interest, expected);
        assert!(result.assessment.novelty().is_some());
        assert_eq!(result.outcome, AdmissionOutcome::NotInserted);
        assert_eq!(context(&handle).await, before);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        3,
        "the timed-out future is dropped inside the node lifetime"
    );
    stop(admin, task).await;
}

#[tokio::test]
async fn running_node_multistep_admission_rechecks_original_proofs_and_certificate_budget() {
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::{ProofCertificate, ProofId, ProofStep};
    let directory = Directory::new();
    let mut graph = Graph::open(&directory.0).unwrap();
    let seed = graph.author(PROOF).unwrap();
    let seed_id = seed.proof_id.clone();
    graph.ingest(seed, Instant::now()).unwrap();
    let p = question(SOLVED).core().clone();
    let q = Formula::for_all(FreeVariable::new(1), p.clone());
    let r = Formula::for_all(FreeVariable::new(2), q.clone());
    let mut ids = vec![seed_id];
    for (antecedent, consequent) in [(&p, &q), (&q, &r)] {
        let source = format!(
            "foundation = \"naome:zfc\" statement = {} proof: p0 = vacuous_universal({}) return p0",
            Formula::implies(antecedent.clone(), consequent.clone()).to_source(),
            antecedent.to_source()
        );
        let envelope = graph.author(&source).unwrap();
        ids.push(envelope.proof_id.clone());
        graph.ingest(envelope, Instant::now()).unwrap();
    }
    let root = graph.content_root();
    drop(graph);
    let (handle, admin, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let task = tokio::spawn(network::run_with_questions(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            async { Ok(true) }
        },
    ));
    let before = context(&handle).await;
    assert_eq!(before.checked_proofs, 3);
    let source = format!("foundation = \"naome:zfc\" statement = {}", r.to_source());
    let result = handle.admit_question(question(&source)).await.unwrap();
    assert_eq!(
        result.assessment.prefilter.reason,
        Some(RejectionReason::KnownProof)
    );
    assert_eq!(result.assessment.prefilter.rule, "Q04_CHECKED_MP_CLOSURE");
    assert_eq!(result.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(result.outcome, AdmissionOutcome::NotInserted);
    assert_eq!(context(&handle).await, before);
    let witness = result.assessment.prefilter.deduction.as_ref().unwrap();
    let certificate =
        ProofCertificate::from_canonical_bytes(witness.canonical_certificate()).unwrap();
    assert_eq!(certificate.steps().len(), 5);
    assert_eq!(
        certificate
            .steps()
            .iter()
            .filter(|step| matches!(step, ProofStep::ModusPonens { .. }))
            .count(),
        2
    );
    let mut expected: Vec<_> = ids
        .iter()
        .map(|id| ProofId::from_bytes(crate::object::unhex(id).unwrap().try_into().unwrap()))
        .collect();
    expected.sort();
    assert_eq!(witness.original_proofs(), expected);
    let mut limited = PrefilterPolicy::default();
    limited.limits.certificate_steps = 4;
    admin.set_policy(limited).await.unwrap();
    let limited_context = context(&handle).await;
    let exhausted = handle.admit_question(question(&source)).await.unwrap();
    assert_eq!(
        exhausted.assessment.prefilter.reason,
        Some(RejectionReason::ExecutionLimit)
    );
    assert_eq!(exhausted.assessment.interest, InterestAssessment::NotRun);
    assert_eq!(exhausted.outcome, AdmissionOutcome::NotInserted);
    assert!(exhausted.assessment.novelty().is_none());
    assert!(exhausted.assessment.prefilter.deduction.is_none());
    assert_eq!(context(&handle).await, limited_context);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(admin, task).await;
    let reopened = Graph::open(&directory.0).unwrap();
    let checked =
        naome_checker::normalize_and_check_with_state(certificate, reopened.checked_context())
            .unwrap();
    assert_eq!(checked.conclusion(), &r);
    assert_eq!(checked.proof_id(), witness.proof_id());
    assert_eq!(reopened.content_root(), root);
}
