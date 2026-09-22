#![cfg(unix)]
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_consensus::{
    ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget,
    state::{StateBranch, StateLockEvent, StateLockState, StatePublication, StateQuorum},
};
use naome_ledger::{
    AccountId,
    operations::OperationBody,
    profile::{Genesis, Limits, Profile, STATE_CHECKER_PROFILE, TimingKind, ValidatorRegistration},
    question::CompiledQuestion,
    time::SignedTimeReport,
};
use naome_network::Keypair;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "naome-state-runtime-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("temporary runtime directory: {e}"),
            }
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn account(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 1; 32])
}
fn consensus(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 101; 32])
}
fn transport(i: u8) -> Keypair {
    Keypair::ed25519_from_bytes([i + 201; 32]).unwrap()
}
fn genesis() -> Genesis {
    let limits = Limits {
        run_records: 65,
        record_bytes: 128 * 1024,
        package_bytes: 64 * 1024,
        transport_frame_bytes: 192 * 1024,
        consensus_rounds: 8,
        ..Limits::default()
    };
    Genesis::new(
        Profile::with_limits(TimingKind::ShortTest, limits).unwrap(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [9; 32],
        (0..6)
            .map(|i| account(i).verifying_key().to_bytes())
            .collect(),
        (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(account(i).verifying_key().as_bytes()),
                consensus_key: consensus(i).verifying_key().to_bytes(),
                transport_key: SigningKey::from_bytes(&[201 + i; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 46000 + u16::from(i)),
            })
            .collect(),
    )
    .unwrap()
}
fn operation(g: &Genesis, nonce: u64) -> SignedOperation {
    OperationBody::Submit {
        purpose: "Clock interval regression".into(),
        question: CompiledQuestion::compile(
            "foundation = \"naome:zfc\"\nstatement = forall(x,equal(x,x))",
            g.profile(),
        )
        .unwrap(),
    }
    .sign(g, nonce, &account(4))
    .unwrap()
}
fn runtime() -> (Directory, Directory, StateRuntime) {
    runtime_with_genesis(genesis())
}
fn runtime_with_genesis(g: Genesis) -> (Directory, Directory, StateRuntime) {
    let branch = StateBranch::from_genesis(LedgerState::new(g.clone())).unwrap();
    let index = (0..4)
        .find(|i| {
            let signer = ConsensusKey::from_bytes(consensus(*i).verifying_key().to_bytes());
            (0..=1).all(|round| branch.proposer(round, 8).unwrap() != signer)
        })
        .unwrap();
    let directory = Directory::new();
    let anchors = Directory::new();
    let history = StateHistory::create(&directory.0, &anchors.0, g.clone(), 8).unwrap();
    let signer =
        StateSigner::create(&directory.0, &anchors.0, g.clone(), consensus(index), 8).unwrap();
    let network = StateNetwork::new_state(transport(index), &g).unwrap();
    let peers = (0..4)
        .filter(|i| *i != index)
        .map(|i| transport(i).public().to_peer_id())
        .collect();
    let runtime = StateRuntime::new(
        history,
        Some(signer),
        network,
        peers,
        StateRuntimeConfig::default(),
    )
    .unwrap();
    (directory, anchors, runtime)
}
fn ready_work(runtime: &mut StateRuntime) {
    let g = runtime.state().unwrap().genesis().clone();
    let state = runtime.state().unwrap();
    let utc = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let reports: Vec<_> = (0..4)
        .map(|i| SignedTimeReport::sign(&g, state.head(), 1, utc, &consensus(i)).unwrap())
        .collect();
    for report in reports {
        runtime.time_reports.insert(report.validator(), report);
    }
    runtime.submit_operation(operation(&g, 1)).unwrap();
    runtime.tick().unwrap();
}

fn enter_round_one(runtime: &mut StateRuntime) -> Vec<StateLockState> {
    let g = runtime.state().unwrap().genesis().clone();
    let branch = StateBranch::from_genesis(runtime.state().unwrap().clone()).unwrap();
    let mut kernels: Vec<_> = (0..4)
        .map(|i| {
            StateLockState::new(
                &branch,
                ConsensusKey::from_bytes(consensus(i).verifying_key().to_bytes()),
            )
            .unwrap()
        })
        .collect();
    let prevotes = kernels
        .iter_mut()
        .enumerate()
        .map(|(i, kernel)| {
            let intent = kernel
                .apply(&branch, &StateLockEvent::ProposalTimeout, 8)
                .unwrap();
            let signature = consensus(i as u8)
                .sign(&intent.signing_bytes().unwrap())
                .to_bytes();
            match intent.complete(signature, &branch, 8).unwrap() {
                StatePublication::Vote(vote) => vote,
                _ => unreachable!(),
            }
        })
        .collect();
    let quorum = StateQuorum::from_votes(prevotes, &g).unwrap();
    let mut precommits = Vec::new();
    for (i, kernel) in kernels.iter_mut().enumerate() {
        let intent = kernel
            .apply(
                &branch,
                &StateLockEvent::Precommit {
                    proposal: None,
                    quorum: quorum.encode(),
                },
                8,
            )
            .unwrap();
        let signature = consensus(i as u8)
            .sign(&intent.signing_bytes().unwrap())
            .to_bytes();
        let StatePublication::Vote(vote) = intent.complete(signature, &branch, 8).unwrap() else {
            unreachable!()
        };
        runtime.node.accept_vote(&vote.encode()).unwrap();
        precommits.push(vote);
    }
    let quorum = StateQuorum::from_votes(precommits, &g).unwrap();
    for kernel in &mut kernels {
        kernel
            .apply(
                &branch,
                &StateLockEvent::NilPrecommit {
                    quorum: quorum.encode(),
                },
                8,
            )
            .unwrap();
    }
    runtime.drive().unwrap();
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 1, StatePhase::Proposal)
    );
    kernels
}

#[tokio::test(start_paused = true)]
async fn later_consensus_round_after_restart_waits_longer_without_duplicate_resets() {
    let (directory, anchors, mut runtime) = runtime();
    enter_round_one(&mut runtime);
    let g = runtime.state().unwrap().genesis().clone();
    let index = (0..4)
        .find(|i| {
            Some(ConsensusKey::from_bytes(
                consensus(*i).verifying_key().to_bytes(),
            )) == runtime.node.signer_key()
        })
        .unwrap();
    drop(runtime);
    let history = StateHistory::open(&directory.0, &anchors.0, g.clone(), 8).unwrap();
    let signer =
        StateSigner::open(&directory.0, &anchors.0, g.clone(), consensus(index), 8).unwrap();
    let network = StateNetwork::new_state(transport(index), &g).unwrap();
    let peers = (0..4)
        .filter(|i| *i != index)
        .map(|i| transport(i).public().to_peer_id())
        .collect();
    let mut runtime = StateRuntime::new(
        history,
        Some(signer),
        network,
        peers,
        StateRuntimeConfig::default(),
    )
    .unwrap();
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 1, StatePhase::Proposal)
    );
    ready_work(&mut runtime);
    let base = runtime.config.proposal_timeout;
    for elapsed in [base, base - Duration::from_nanos(1)] {
        tokio::time::advance(elapsed).await;
        runtime.last_clock = None;
        runtime.tick().unwrap();
        assert_eq!(
            runtime.position().unwrap().unwrap(),
            (1, 1, StatePhase::Proposal)
        );
        let before = runtime.phase_started;
        let g = runtime.state().unwrap().genesis();
        runtime.submit_operation(operation(g, 1)).unwrap();
        runtime.drive().unwrap();
        assert_eq!(runtime.phase_started, before);
    }
    tokio::time::advance(Duration::from_nanos(1)).await;
    runtime.last_clock = None;
    runtime.tick().unwrap();
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 1, StatePhase::Prevote)
    );
}

fn authored_proposal(
    runtime: &StateRuntime,
    kernel: &mut StateLockState,
    index: u8,
) -> StatePublication {
    let branch = StateBranch::from_genesis(runtime.state().unwrap().clone()).unwrap();
    let state = runtime.state().unwrap();
    let certificate = naome_ledger::time::TimeCertificate::new(
        runtime.time_reports.values().cloned().collect(),
        state.genesis(),
        state.head(),
        1,
        state.time(),
    )
    .unwrap();
    let record = state
        .prepare_record(certificate, vec![operation(state.genesis(), 1)])
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let intent = kernel
        .apply(
            &branch,
            &StateLockEvent::Author {
                record: Some(record),
            },
            8,
        )
        .unwrap();
    let signature = consensus(index)
        .sign(&intent.signing_bytes().unwrap())
        .to_bytes();
    intent.complete(signature, &branch, 8).unwrap()
}

#[tokio::test(start_paused = true)]
async fn valid_proposal_after_old_interval_is_accepted_within_grown_round() {
    let (_directory, _anchors, mut runtime) = runtime();
    let mut kernels = enter_round_one(&mut runtime);
    ready_work(&mut runtime);
    let branch = StateBranch::from_genesis(runtime.state().unwrap().clone()).unwrap();
    let index = (0..4)
        .find(|i| {
            ConsensusKey::from_bytes(consensus(*i).verifying_key().to_bytes())
                == branch.proposer(1, 8).unwrap()
        })
        .unwrap();
    let proposal = authored_proposal(&runtime, &mut kernels[index as usize], index);
    tokio::time::advance(runtime.config.proposal_timeout + Duration::from_millis(1)).await;
    runtime.last_clock = None;
    runtime.tick().unwrap();
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 1, StatePhase::Proposal)
    );
    runtime
        .node
        .accept_proposal(&proposal.encode().unwrap())
        .unwrap();
    runtime.tick().unwrap();
    assert!(runtime.node.publications().unwrap().iter().any(|p| matches!(p,
        StatePublication::Vote(vote) if vote.round() == 1 && vote.role() == ConsensusVoteRole::Prevote && matches!(vote.target(), ConsensusVoteTarget::Proposal(_))
    )));
}

#[tokio::test(start_paused = true)]
async fn retained_proposal_is_driven_before_an_elapsed_timeout_can_emit_nil() {
    let (_directory, _anchors, mut runtime) = runtime();
    ready_work(&mut runtime);
    let branch = StateBranch::from_genesis(runtime.state().unwrap().clone()).unwrap();
    let scheduled = branch.proposer(0, 8).unwrap();
    let index = (0..4)
        .find(|i| ConsensusKey::from_bytes(consensus(*i).verifying_key().to_bytes()) == scheduled)
        .unwrap();
    let mut kernel = StateLockState::new(&branch, scheduled).unwrap();
    let proposal = authored_proposal(&runtime, &mut kernel, index);
    tokio::time::advance(runtime.config.proposal_timeout).await;
    runtime
        .node
        .accept_proposal(&proposal.encode().unwrap())
        .unwrap();
    runtime.last_clock = None;
    runtime.tick().unwrap();
    let votes: Vec<_> = runtime
        .node
        .publications()
        .unwrap()
        .into_iter()
        .filter_map(|p| match p {
            StatePublication::Vote(vote) if vote.role() == ConsensusVoteRole::Prevote => Some(vote),
            _ => None,
        })
        .collect();
    assert_eq!(votes.len(), 1);
    assert!(matches!(
        votes[0].target(),
        ConsensusVoteTarget::Proposal(_)
    ));
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 0, StatePhase::Prevote)
    );
}
#[tokio::test(start_paused = true)]
async fn productive_work_after_long_idle_gets_a_complete_proposal_interval() {
    let (_directory, _anchors, mut runtime) = runtime();
    tokio::time::advance(Duration::from_secs(120)).await;
    let g = runtime.state().unwrap().genesis().clone();
    let state = runtime.state().unwrap();
    let utc = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let reports: Vec<_> = (0..4)
        .map(|i| SignedTimeReport::sign(&g, state.head(), 1, utc, &consensus(i)).unwrap())
        .collect();
    for report in reports {
        runtime.time_reports.insert(report.validator(), report);
    }
    runtime.submit_operation(operation(&g, 1)).unwrap();
    runtime.tick().unwrap();
    assert!(runtime.work_ready);
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 0, StatePhase::Proposal)
    );
    assert_eq!(runtime.phase_started.elapsed(), Duration::ZERO);
    tokio::time::advance(runtime.config.proposal_timeout).await;
    // Tokio's paused clock advances without wall UTC. Reset the paired clock
    // baseline because this test isolates proposal timing; clock-jump rejection
    // has its own dedicated regression using mismatched clock observations.
    runtime.last_clock = None;
    runtime.tick().unwrap();
    assert_eq!(
        runtime.position().unwrap().unwrap(),
        (1, 0, StatePhase::Prevote)
    );
}
#[tokio::test]
async fn queue_receipt_is_not_finality_and_duplicate_identity_is_idempotent() {
    let (_directory, _anchors, mut runtime) = runtime();
    let g = runtime.state().unwrap().genesis().clone();
    let before = runtime.state().unwrap().commitment();
    let op = operation(&g, 1);
    let id = op.id();
    assert_eq!(runtime.submit_operation(op.clone()).unwrap(), id);
    assert_eq!(runtime.submit_operation(op).unwrap(), id);
    assert_eq!(runtime.pending_operations(), 1);
    assert!(runtime.state().unwrap().receipt(id).is_none());
    assert_eq!(runtime.state().unwrap().commitment(), before);
    assert!(runtime.submit_operation(operation(&g, 2)).is_err());
    assert_eq!(runtime.pending_operations(), 1);
    assert!(runtime.set_peer_enabled(runtime.peers[0], false).is_err());
}

#[tokio::test]
async fn action_for_unopened_phase_does_not_occupy_the_next_nonce() {
    let (_directory, _anchors, mut runtime) = runtime();
    let g = runtime.state().unwrap().genesis().clone();
    let author = AccountId::for_key(account(0).verifying_key().as_bytes());
    let premature = OperationBody::Vote {
        question: naome_ledger::QuestionId::from_bytes([7; 32]),
        attempt: 1,
        yes: true,
    }
    .sign(&g, 1, &account(0))
    .unwrap();
    assert!(runtime.submit_operation(premature).is_err());
    assert_eq!(runtime.pending_operations(), 0);
    assert_eq!(runtime.state().unwrap().next_nonce(author), Some(1));
    let corrected = OperationBody::Submit {
        purpose: "Corrected same unconsumed nonce".into(),
        question: CompiledQuestion::compile(
            "foundation = \"naome:zfc\"\nstatement = forall(x,equal(x,x))",
            g.profile(),
        )
        .unwrap(),
    }
    .sign(&g, 1, &account(0))
    .unwrap();
    assert!(runtime.submit_operation(corrected).is_ok());
    assert_eq!(runtime.pending_operations(), 1);
    assert_eq!(runtime.state().unwrap().next_nonce(author), Some(1));
}

mod intake_priority;
mod proof_fetch;
mod registration;

#[tokio::test]
async fn refreshing_time_reports_preserves_delivery_order_under_backpressure() {
    let (_directory, _anchors, mut runtime) = runtime();
    let g = runtime.state().unwrap().genesis().clone();
    let parent = runtime.state().unwrap().head();
    let peer = runtime.peers[0];
    let first = SignedTimeReport::sign(&g, parent, 1, 101, &consensus(0)).unwrap();
    runtime.own_time = Some(first.encode().into());
    runtime.enqueue_periodic().unwrap();
    let initial_len = runtime.outbox.len();
    for utc in 102..202 {
        let report = SignedTimeReport::sign(&g, parent, 1, utc, &consensus(0)).unwrap();
        let bytes: Arc<[u8]> = report.encode().into();
        runtime.own_time = Some(bytes.clone());
        runtime.enqueue_periodic().unwrap();
        let queued: Vec<_> = runtime.outbox.iter().filter(|d| d.peer == peer).collect();
        assert!(
            matches!(&queued[0].body, StateRequestBody::TimeReport(actual) if actual == &bytes)
        );
        assert!(matches!(&queued[1].body, StateRequestBody::History { .. }));
        assert_eq!(queued.len(), 2);
        assert_eq!(runtime.outbox.len(), initial_len);
    }
}
