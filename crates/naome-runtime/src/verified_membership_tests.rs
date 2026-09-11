use super::*;
use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_network::{Keypair, StaticPeer};
use naome_storage::verified_membership::{MembershipJournal, MembershipJournalLimits};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    root: PathBuf,
    branch: MembershipBranch,
    peers: Vec<StaticPeer>,
}
fn seed(id: u8, role: u8) -> [u8; 32] {
    let mut value = [id; 32];
    value[0] = role;
    value
}
fn keys(id: u8) -> [SigningKey; 3] {
    std::array::from_fn(|role| SigningKey::from_bytes(&seed(id, role as u8)))
}
fn member(id: u8) -> Member {
    let k = keys(id);
    Member {
        organization: [id; 32],
        consensus_key: k[0].verifying_key().to_bytes(),
        approval_key: k[1].verifying_key().to_bytes(),
        network_key: k[2].verifying_key().to_bytes(),
    }
}
impl Fixture {
    fn new(count: u8) -> Self {
        let root = std::env::temp_dir().join(format!(
            "membership-scheduler-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        for name in ["journal", "anchor"] {
            std::fs::create_dir(root.join(name)).unwrap();
        }
        let branch = MembershipBranch::genesis(
            ArtifactChainState::new(ArtifactChainDefinition::new([89; 32])).branch_snapshot(),
            (1..=4).map(member).collect(),
        )
        .unwrap();
        let peers = (5..5 + count)
            .map(|id| {
                StaticPeer::new(
                    Keypair::ed25519_from_bytes(seed(id, 2))
                        .unwrap()
                        .public()
                        .to_peer_id(),
                    "/ip4/127.0.0.1/tcp/9".parse().unwrap(),
                )
            })
            .collect();
        Self {
            root,
            branch,
            peers,
        }
    }
    fn network(&self) -> MembershipNetwork {
        MembershipNetwork::new(
            Keypair::ed25519_from_bytes(seed(1, 2)).unwrap(),
            self.peers.clone(),
            self.branch.next_snapshot().unwrap(),
        )
        .unwrap()
    }
    fn runtime(&self) -> MembershipRuntime {
        let journal = MembershipJournal::create(
            &self.root.join("journal"),
            &self.root.join("anchor"),
            self.branch.clone(),
            Some(keys(1)[0].clone()),
            MembershipJournalLimits {
                maximum_round: 64,
                maximum_records: 1000,
                maximum_bytes: 100_000_000,
            },
        )
        .unwrap();
        MembershipRuntime::new(
            MembershipNode::new(journal).unwrap(),
            self.network(),
            MembershipRuntimeTiming {
                phase_base: Duration::from_secs(10),
                round_increment: Duration::from_secs(1),
                tick: Duration::from_secs(2),
            },
        )
        .unwrap()
    }
    // Complete the simulated transport turn without changing scheduler state.
    fn complete_turn(&self, runtime: &mut MembershipRuntime) {
        runtime.network = self.network();
        runtime.pending.clear();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[tokio::test]
async fn verified_membership_scheduler_gives_all_peers_a_turn_above_exchange_cap() {
    let fixture = Fixture::new(64);
    let mut runtime = fixture.runtime();
    let mut contacted = std::collections::HashSet::new();
    let occupied = runtime.network.peers()[0];
    for _ in 0..64 {
        // Model an ongoing proof occupying one transport slot at every tick.
        runtime
            .network
            .send(
                occupied,
                MembershipRequestMessage::Status {
                    context: fixture.branch.context().0,
                },
            )
            .unwrap();
        runtime.schedule().unwrap();
        for pending in runtime.pending.values() {
            if let Pending::Status { peer } = pending {
                contacted.insert(*peer);
            }
        }
        fixture.complete_turn(&mut runtime);
        runtime.status_attempt.clear();
    }
    assert_eq!(contacted.len(), 63);
    assert!(!contacted.contains(&occupied));
}
#[tokio::test]
async fn verified_membership_status_retry_cannot_starve_application_delivery() {
    let fixture = Fixture::new(1);
    let mut runtime = fixture.runtime();
    let k = keys(8);
    let request = MembershipRequest::join(
        runtime.node.snapshot().unwrap(),
        member(8),
        [&k[0], &k[1], &k[2]],
    )
    .unwrap();
    runtime.node.ingest_request(request).unwrap();
    runtime.schedule().unwrap();
    assert!(
        runtime
            .pending
            .values()
            .any(|pending| matches!(pending, Pending::Status { .. }))
    );
    fixture.complete_turn(&mut runtime);
    // A status retry is due again at a slow configured tick.
    for last in runtime.status_attempt.values_mut() {
        *last = Instant::now() - RETRY_AFTER;
    }
    runtime.schedule().unwrap();
    assert!(
        runtime
            .pending
            .values()
            .any(|pending| matches!(pending, Pending::Publication { .. }))
    );
}
#[tokio::test]
async fn verified_membership_expired_bad_source_backoff_still_rotates_proof_source() {
    let fixture = Fixture::new(2);
    let mut runtime = fixture.runtime();
    for peer in runtime.network.peers() {
        runtime.remote.insert(peer, (1, Instant::now()));
    }
    runtime.schedule().unwrap();
    let first = runtime
        .pending
        .values()
        .find_map(|pending| {
            if let Pending::Proof { peer, .. } = pending {
                Some(*peer)
            } else {
                None
            }
        })
        .unwrap();
    fixture.complete_turn(&mut runtime);
    runtime
        .proof_backoff
        .insert(first, Instant::now() - RETRY_AFTER);
    runtime.schedule().unwrap();
    let second = runtime
        .pending
        .values()
        .find_map(|pending| {
            if let Pending::Proof { peer, .. } = pending {
                Some(*peer)
            } else {
                None
            }
        })
        .unwrap();
    assert_ne!(first, second);
}

#[tokio::test]
async fn verified_membership_operator_request_survives_network_inbox_saturation() {
    let fixture = Fixture::new(1);
    let mut runtime = fixture.runtime();
    let request = |id| {
        let k = keys(id);
        MembershipRequest::join(
            fixture.branch.next_snapshot().unwrap(),
            member(id),
            [&k[0], &k[1], &k[2]],
        )
        .unwrap()
    };
    for id in 10..26 {
        runtime.node.ingest_request(request(id)).unwrap();
    }
    let desired = request(30);
    let desired_id = desired.id();
    assert!(runtime.node.ingest_request(desired.clone()).is_err());
    runtime.node.reject_request(desired_id).unwrap();
    assert!(runtime.node.ingest_operator_request(desired).unwrap());
    assert_eq!(runtime.node.requests().len(), 16);
    assert!(runtime.node.requests().contains_key(&desired_id));
    assert!(!runtime.node.rejected_requests().contains(&desired_id));
    assert!(runtime.node.approval_messages().is_empty());
}
