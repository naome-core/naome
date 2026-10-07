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
async fn stop(handle: QuestionHandle, task: tokio::task::JoinHandle<Result<(), String>>) {
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
    let (handle, inbox) = channel();
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
    let proved = handle.assess(question(SOLVED)).await.unwrap();
    assert_eq!(proved.approval.reason, Some(RejectionReason::KnownProof));
    assert_eq!(proved.interest, InterestAssessment::NotRun);
    let refuted = handle
        .assess(question(
            "foundation = \"naome:zfc\" statement = not_(forall(a,equal(a,a)))",
        ))
        .await
        .unwrap();
    assert_eq!(
        refuted.approval.reason,
        Some(RejectionReason::KnownRefutation)
    );
    assert!(refuted.submitted_negation_parity);
    let double_negative = handle
        .assess(question(
            "foundation = \"naome:zfc\" statement = not_(not_(forall(a,equal(a,a))))",
        ))
        .await
        .unwrap();
    assert_eq!(
        double_negative.approval.reason,
        Some(RejectionReason::KnownProof)
    );
    handle.register(question(QUESTION)).await.unwrap().unwrap();
    let before = context(&handle).await;
    let alias = handle.assess(question("# cosmetic source and binder change\nfoundation = \"naome:zfc\"\nstatement = forall(renamed, member(renamed, renamed)) success = \"resolve\"")).await.unwrap();
    assert_eq!(alias.approval.reason, Some(RejectionReason::ExactDuplicate));
    assert_eq!(alias.interest, InterestAssessment::NotRun);
    assert_eq!(
        context(&handle).await,
        before,
        "read-only assessment cannot register or modify state"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(handle, task).await;
    let reopened = Graph::open(&directory.0).unwrap();
    assert_eq!(root, reopened.content_root());
}

#[tokio::test]
async fn running_node_approval_reaches_separate_interest_without_storing_question() {
    let directory = Directory::new();
    let (handle, inbox) = channel();
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
            result.approval.approved(),
            "interest is not a proof-validity or approval oracle"
        );
        assert_eq!(result.interest, expected);
        assert_eq!(context(&handle).await, before);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    stop(handle, task).await;
}

#[tokio::test]
async fn running_node_checked_proof_ingest_invalidates_pending_interest() {
    let directory = Directory::new();
    let (handle, inbox) = channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let observed = calls.clone();
    let notify = started.clone();
    let permit = release.clone();
    let (producer, commands) = mpsc::channel(8);
    // Exercise the real shared Node loop and its existing producer intake,
    // after the initial approval is captured. No timer or scheduler race may
    // put the proof into the initial snapshot before the callback starts.
    let task = tokio::spawn(network::run_inner(
        directory.config(Vec::new()),
        false,
        inbox,
        move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            let notify = notify.clone();
            let permit = permit.clone();
            async move {
                notify.notify_one();
                permit.notified().await;
                Ok(true)
            }
        },
        commands,
    ));
    assert_eq!(context(&handle).await.checked_proofs, 0);
    let client = handle.clone();
    let assessment = tokio::spawn(async move { client.assess(question(SOLVED)).await.unwrap() });
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
    release.notify_one();
    let stale = tokio::time::timeout(Duration::from_secs(5), assessment)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stale.approval.reason, Some(RejectionReason::StaleContext));
    assert_eq!(stale.interest, InterestAssessment::Stale);
    let fresh = handle.assess(question(SOLVED)).await.unwrap();
    assert_eq!(fresh.approval.reason, Some(RejectionReason::KnownProof));
    assert_eq!(fresh.interest, InterestAssessment::NotRun);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop(handle, task).await;
    assert_eq!(
        Graph::open(&directory.0).unwrap().ids().len(),
        1,
        "actual producer path checked and durably ingested the proof"
    );
}

#[tokio::test]
async fn running_node_registry_and_policy_updates_invalidate_pending_interest() {
    let directory = Directory::new();
    let (handle, inbox) = channel();
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
            tokio::spawn(async move { client.assess(question(QUESTION)).await.unwrap() });
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .unwrap();
        if policy_change {
            let mut policy = ApprovalPolicy::default();
            policy.revision += 1;
            handle.set_policy(policy).await.unwrap();
        } else {
            handle.register(question(SOLVED)).await.unwrap().unwrap();
        }
        release.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), assessment)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.approval.reason, Some(RejectionReason::StaleContext));
        assert_eq!(result.interest, InterestAssessment::Stale);
    }
    let unsupported = ApprovalPolicy {
        rule_set: 9,
        ..ApprovalPolicy::default()
    };
    handle.set_policy(unsupported).await.unwrap();
    let result = handle.assess(question(QUESTION)).await.unwrap();
    assert_eq!(
        result.approval.reason,
        Some(RejectionReason::UnsupportedPolicy)
    );
    assert_eq!(result.interest, InterestAssessment::NotRun);
    stop(handle, task).await;
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
    let (handle, inbox) = channel();
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
    let first = tokio::spawn(async move { client.assess(question(QUESTION)).await });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    let crowded = handle.assess(question(SOLVED)).await.unwrap();
    assert_eq!(
        crowded.approval.reason,
        Some(RejectionReason::ReceivingLimit)
    );
    assert_eq!(crowded.interest, InterestAssessment::NotRun);
    first.abort();
    let _ = first.await;
    tokio::time::timeout(Duration::from_secs(2), async {
        while dropped.load(Ordering::SeqCst) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let client = handle.clone();
    let second = tokio::spawn(async move { client.assess(question(QUESTION)).await });
    tokio::time::timeout(Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    stop(handle, task).await;
    assert_eq!(second.await.unwrap().unwrap_err(), IntakeError::Stopped);
    assert_eq!(
        dropped.load(Ordering::SeqCst),
        2,
        "no independently spawned interest task survives node lifetime"
    );
}

#[test]
fn one_entry_prefilter_cache_reuses_both_outcomes_and_invalidates_all_context() {
    let mut graph = Graph::default();
    let mut local = LocalQuestions::new(|_| async { Ok(true) });
    let input = question(QUESTION);
    let first = local.assess(&graph, &input);
    assert!(first.approved());
    assert_eq!(local.assess(&graph, &input), first);
    assert_eq!(
        local.computations, 1,
        "same full inputs reuse the computed APPROVE"
    );
    let registered = question(QUESTION);
    local.registry.insert(*registered.source_hash(), registered);
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
