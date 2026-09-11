#![cfg(unix)]

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_consensus::verified_membership::*;
use naome_foundation::ZfcAxiom;
use naome_network::{Keypair, StaticPeer, verified_membership::MembershipNetwork};
use naome_node::verified_membership::{MembershipCandidate, MembershipNode};
use naome_proof::{ArtifactPayload, ProofCertificate, ProofStep};
use naome_runtime::verified_membership::{MembershipRuntime, MembershipRuntimeTiming};
use naome_storage::verified_membership::{MembershipJournal, MembershipJournalLimits};
use std::{
    net::TcpListener,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
#[path = "verified_membership/epochs.rs"]
mod epochs;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "naome-member-network-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        for id in 1..=5 {
            std::fs::create_dir(path.join(format!("j{id}"))).unwrap();
            std::fs::create_dir(path.join(format!("a{id}"))).unwrap();
        }
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn seed(id: u8, role: u8) -> [u8; 32] {
    let mut bytes = [id; 32];
    bytes[0] = role;
    bytes
}
fn keys(id: u8) -> [SigningKey; 3] {
    std::array::from_fn(|role| SigningKey::from_bytes(&seed(id, role as u8)))
}
fn network_key(id: u8) -> Keypair {
    Keypair::ed25519_from_bytes(seed(id, 2)).unwrap()
}
fn member(id: u8) -> Member {
    let keys = keys(id);
    Member {
        organization: [id; 32],
        consensus_key: keys[0].verifying_key().to_bytes(),
        approval_key: keys[1].verifying_key().to_bytes(),
        network_key: keys[2].verifying_key().to_bytes(),
    }
}
fn definition() -> ArtifactChainDefinition {
    ArtifactChainDefinition::new([74; 32])
}
fn genesis() -> MembershipBranch {
    MembershipBranch::genesis(
        ArtifactChainState::new(definition()).branch_snapshot(),
        (1..=4).map(member).collect(),
    )
    .unwrap()
}
fn limits() -> MembershipJournalLimits {
    MembershipJournalLimits {
        maximum_round: 64,
        maximum_records: 200_000,
        maximum_bytes: 2_000_000_000,
    }
}
fn payload(axiom: ZfcAxiom) -> Vec<u8> {
    ArtifactPayload::Proof(
        ProofCertificate::new(vec![ProofStep::ZfcAxiom(axiom)])
            .unwrap()
            .into_unchecked_normal_form()
            .certificate()
            .clone(),
    )
    .to_canonical_bytes()
}

async fn step(runtimes: &mut [MembershipRuntime; 5], partition_fourth: bool) {
    let [a, b, c, d, e] = runtimes;
    tokio::select! {
        result = a.next_event() => { result.unwrap(); }, result = b.next_event() => { result.unwrap(); },
        result = c.next_event() => { result.unwrap(); }, result = d.next_event(), if !partition_fourth => { result.unwrap(); },
        result = e.next_event() => { result.unwrap(); },
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("membership network stopped emitting events"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn network_application_operator_approvals_finality_partition_and_observer_replay() {
    let directory = Directory::new();
    let reservations: Vec<_> = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<naome_network::Multiaddr> = reservations
        .iter()
        .map(|listener| {
            format!(
                "/ip4/127.0.0.1/tcp/{}",
                listener.local_addr().unwrap().port()
            )
            .parse()
            .unwrap()
        })
        .collect();
    drop(reservations);
    let peers: Vec<_> = (1..=5)
        .map(|id| network_key(id).public().to_peer_id())
        .collect();
    let mut runtimes: [MembershipRuntime; 5] = std::array::from_fn(|index| {
        let id = index as u8 + 1;
        let journal = MembershipJournal::create(
            &directory.0.join(format!("j{id}")),
            &directory.0.join(format!("a{id}")),
            genesis(),
            Some(keys(id)[0].clone()),
            limits(),
        )
        .unwrap();
        let node = MembershipNode::new(journal).unwrap();
        let bootstraps = (0..4)
            .filter(|peer| *peer != index)
            .map(|peer| StaticPeer::new(peers[peer], addresses[peer].clone()))
            .collect();
        let mut network =
            MembershipNetwork::new(network_key(id), bootstraps, node.snapshot().unwrap()).unwrap();
        network.listen_on(addresses[index].clone()).unwrap();
        MembershipRuntime::new(
            node,
            network,
            MembershipRuntimeTiming {
                phase_base: Duration::from_secs(2),
                round_increment: Duration::from_millis(100),
                tick: Duration::from_millis(10),
            },
        )
        .unwrap()
    });
    let applicant = keys(5);
    let request = MembershipRequest::join(
        runtimes[4].node().snapshot().unwrap(),
        member(5),
        [&applicant[0], &applicant[1], &applicant[2]],
    )
    .unwrap();
    let request_id = request.id();
    runtimes[4].node_mut().ingest_request(request).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "membership approval gossip deadline"
        );
        step(&mut runtimes, false).await;
        for (index, runtime) in runtimes.iter_mut().take(3).enumerate() {
            if runtime.node().requests().contains_key(&request_id) {
                runtime
                    .node_mut()
                    .approve(request_id, [index as u8 + 1; 32], &keys(index as u8 + 1)[1])
                    .unwrap();
            }
        }
        if runtimes
            .iter()
            .all(|runtime| runtime.node().approval_count(&request_id) == 3)
        {
            break;
        }
    }
    assert!(
        runtimes
            .iter()
            .all(|runtime| runtime.node().machine().unwrap().branch().height() == 0)
    );
    assert!(!runtimes[4].node().machine().unwrap().is_active());
    let mut artifact_state = ArtifactChainState::new(definition());
    for (offset, axiom) in [ZfcAxiom::Pairing, ZfcAxiom::Extensionality]
        .into_iter()
        .enumerate()
    {
        let bytes = payload(axiom);
        let artifact_id = ArtifactDag::new()
            .apply_canonical_artifact_bytes(bytes.clone())
            .unwrap()
            .artifact_id();
        let artifact = artifact_state.prepare_block(artifact_id).unwrap();
        runtimes[0]
            .node_mut()
            .ingest_candidate(MembershipCandidate {
                context: genesis().context(),
                artifact,
                payload: bytes.clone(),
            })
            .unwrap();
        let height = offset as u64 + 1;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "membership finality deadline at {height}: {:?}",
                runtimes
                    .iter()
                    .map(|runtime| {
                        let machine = runtime.node().machine().unwrap();
                        (
                            machine.branch().height(),
                            machine.round(),
                            machine.phase(),
                            runtime.network().connected_peers().len(),
                        )
                    })
                    .collect::<Vec<_>>()
            );
            step(&mut runtimes, offset == 1).await;
            if runtimes.iter().enumerate().all(|(index, runtime)| {
                (offset == 1 && index == 3)
                    || runtime.node().machine().unwrap().branch().height() >= height
            }) {
                break;
            }
        }
        artifact_state.apply_block(&artifact, bytes).unwrap();
    }
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "minority finality catch-up deadline"
        );
        step(&mut runtimes, false).await;
        if runtimes
            .iter()
            .all(|runtime| runtime.node().machine().unwrap().branch().height() == 2)
        {
            break;
        }
    }
    let ancestry = runtimes[0].node().machine().unwrap().branch().ancestry();
    for runtime in &mut runtimes {
        assert_eq!(
            runtime.node().machine().unwrap().branch().ancestry(),
            ancestry
        );
        assert_eq!(
            runtime
                .node()
                .machine()
                .unwrap()
                .branch()
                .membership()
                .pending_activation(),
            Some(16385)
        );
        let mut replay = genesis();
        for height in 1..=2 {
            let proof = runtime.node_mut().finalized_proof(height).unwrap().unwrap();
            replay = replay
                .verify_finality(proof.proposal, proof.payload, proof.certificate, 64)
                .unwrap()
                .into_branch();
        }
        assert_eq!(replay.ancestry(), ancestry);
    }
    drop(runtimes);
    let journal = MembershipJournal::open(
        &directory.0.join("j5"),
        &directory.0.join("a5"),
        genesis(),
        Some(keys(5)[0].clone()),
        limits(),
    )
    .unwrap();
    assert_eq!(journal.machine().unwrap().branch().ancestry(), ancestry);
    assert!(!journal.machine().unwrap().is_active());
    assert!(
        !journal
            .publications()
            .unwrap()
            .iter()
            .any(|publication| matches!(
                publication,
                MembershipPublication::Vote(_) | MembershipPublication::Proposal { .. }
            ))
    );
}
