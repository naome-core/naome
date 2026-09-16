#![cfg(unix)]
use super::*;
use ed25519_dalek::SigningKey;
use naome_consensus::{ConsensusKey, research::ResearchBranch};
use naome_network::Keypair;
use naome_research::{
    AccountId,
    operations::OperationBody,
    profile::{
        Genesis, Limits, Profile, RESEARCH_CHECKER_PROFILE, TimingKind, ValidatorRegistration,
    },
    question::CompiledQuestion,
    time::SignedTimeReport,
};
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
                "naome-research-runtime-{}-{}",
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
        RESEARCH_CHECKER_PROFILE.into(),
        1,
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
fn runtime() -> (Directory, Directory, ResearchRuntime) {
    let g = genesis();
    let proposer = ResearchBranch::from_genesis(ResearchState::new(g.clone()))
        .unwrap()
        .proposer(0, 8)
        .unwrap();
    let index = (0..4)
        .find(|i| ConsensusKey::from_bytes(consensus(*i).verifying_key().to_bytes()) != proposer)
        .unwrap();
    let directory = Directory::new();
    let anchors = Directory::new();
    let history = ResearchHistory::create(&directory.0, &anchors.0, g.clone(), 8).unwrap();
    let signer =
        ResearchSigner::create(&directory.0, &anchors.0, g.clone(), consensus(index), 8).unwrap();
    let network = StaticArtifactNetwork::new_research(transport(index), &g).unwrap();
    let peers = (0..4)
        .filter(|i| *i != index)
        .map(|i| transport(i).public().to_peer_id())
        .collect();
    let runtime = ResearchRuntime::new(
        history,
        Some(signer),
        network,
        peers,
        ResearchRuntimeConfig::default(),
    )
    .unwrap();
    (directory, anchors, runtime)
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
        (1, 0, ResearchPhase::Proposal)
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
        (1, 0, ResearchPhase::Prevote)
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
        question: naome_research::QuestionId::from_bytes([7; 32]),
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

mod proof_fetch;
