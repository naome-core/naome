#![cfg(unix)]
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_ledger::{
    AccountId,
    authentication::SignedOperation,
    operations::OperationBody,
    profile::{Genesis, Limits, Profile, STATE_CHECKER_PROFILE, TimingKind, ValidatorRegistration},
    question::CompiledQuestion,
    time::{SignedTimeReport, TimeCertificate},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_ROUND: u64 = 8;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "naome-state-node-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("temporary node directory: {e}"),
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
fn key(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 101; 32])
}
fn genesis() -> Genesis {
    genesis_with_rounds(MAX_ROUND)
}
fn genesis_with_rounds(rounds: u64) -> Genesis {
    let limits = Limits {
        run_records: 65,
        record_bytes: 128 * 1024,
        package_bytes: 64 * 1024,
        transport_frame_bytes: 192 * 1024,
        consensus_rounds: rounds,
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
                consensus_key: key(i).verifying_key().to_bytes(),
                transport_key: SigningKey::from_bytes(&[201 + i; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 45000 + u16::from(i)),
            })
            .collect(),
    )
    .unwrap()
}
fn node(i: u8, g: &Genesis) -> (Directory, Directory, StateNode) {
    let dir = Directory::new();
    let anchors = Directory::new();
    let maximum = g.profile().limits().consensus_rounds;
    let history = StateHistory::create(&dir.0, &anchors.0, g.clone(), maximum).unwrap();
    let signer = StateSigner::create(&dir.0, &anchors.0, g.clone(), key(i), maximum).unwrap();
    let node = StateNode::new(history, Some(signer)).unwrap();
    (dir, anchors, node)
}
fn operation(g: &Genesis) -> SignedOperation {
    OperationBody::Submit {
        purpose: "A real research proposal".into(),
        question: CompiledQuestion::compile(
            "foundation = \"naome:zfc\"\nstatement = forall(x,equal(x,x))",
            g.profile(),
        )
        .unwrap(),
    }
    .sign(g, 1, &account(4))
    .unwrap()
}
fn record(state: &LedgerState) -> Vec<u8> {
    let reports = (0..3)
        .map(|i| {
            SignedTimeReport::sign(
                state.genesis(),
                state.head(),
                state.height() + 1,
                state.time(),
                &key(i),
            )
            .unwrap()
        })
        .collect();
    let certificate = TimeCertificate::new(
        reports,
        state.genesis(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap();
    state
        .prepare_record(certificate, vec![operation(state.genesis())])
        .unwrap()
        .record()
        .encode()
        .unwrap()
}
fn relay(nodes: &mut [StateNode], only_role: Option<ConsensusVoteRole>) {
    let messages: Vec<_> = nodes
        .iter()
        .flat_map(|node| node.publications().unwrap())
        .filter(|p| match (p, only_role) {
            (StatePublication::Vote(v), Some(role)) => v.role() == role,
            (StatePublication::Proposal(_), _) => true,
            (_, None) => true,
        })
        .collect();
    for node in nodes {
        for message in &messages {
            match message {
                StatePublication::Proposal(p) => {
                    if p.value().height() == node.state().unwrap().height() + 1 {
                        node.accept_proposal(&p.encode().unwrap()).unwrap();
                    }
                }
                StatePublication::Vote(v) => {
                    if v.height() == node.state().unwrap().height() + 1 {
                        node.accept_vote(&v.encode()).unwrap();
                    }
                }
            }
        }
        node.drive().unwrap();
    }
}

#[test]
fn absent_proposer_advances_by_nil_quorums_then_three_nodes_finalize_and_fourth_catches_up() {
    let g = genesis();
    let all: Vec<_> = (0..4).map(|i| node(i, &g)).collect();
    let initial = all[0].2.branch().unwrap().proposer(0, MAX_ROUND).unwrap();
    let missing = all
        .iter()
        .position(|(_, _, n)| n.signer_key() == Some(initial))
        .unwrap();
    let mut directories = Vec::new();
    let mut live = Vec::new();
    let mut offline = None;
    for (index, (dir, anchor, n)) in all.into_iter().enumerate() {
        directories.push((dir, anchor));
        if index == missing {
            offline = Some(n)
        } else {
            live.push(n)
        }
    }
    // Only three independent sole-key nodes participate. Timeout emits a local
    // NIL prevote; no centrally manufactured quorum or reduced denominator.
    for node in &mut live {
        assert!(node.timeout().unwrap());
    }
    relay(&mut live, None);
    relay(&mut live, None);
    assert!(live.iter().all(|n| n.position().unwrap().unwrap().1 == 1));
    let bytes = record(live[0].state().unwrap());
    let proposer = live.iter().position(|n| n.is_proposer().unwrap()).unwrap();
    live[proposer].author(Some(bytes)).unwrap();
    for _ in 0..4 {
        relay(&mut live, None);
    }
    assert!(live.iter().all(|n| n.state().unwrap().height() == 1));
    assert!(
        live.iter()
            .all(|n| n.state().unwrap().commitment() == live[0].state().unwrap().commitment())
    );
    let mut offline = offline.unwrap();
    let proof = live[0].finality_bytes(1).unwrap();
    assert_eq!(
        offline.accept_finality(&proof).unwrap(),
        StateAppendOutcome::Finalized
    );
    assert_eq!(
        offline.state().unwrap().commitment(),
        live[0].state().unwrap().commitment()
    );
    assert_eq!(
        offline.position().unwrap().unwrap(),
        (2, 0, StatePhase::Proposal)
    );
    assert_eq!(offline.state().unwrap().library().proofs().count(), 0);
    assert!(
        offline
            .state()
            .unwrap()
            .receipt(operation(&g).id())
            .is_some()
    );
    drop((live, offline, directories));
}

#[test]
fn clean_two_two_partition_does_not_consume_round_budget_and_heals() {
    let g = genesis();
    let mut directories = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..4 {
        let (dir, anchors, n) = node(i, &g);
        directories.push((dir, anchors));
        nodes.push(n);
    }
    for n in &mut nodes {
        assert!(n.timeout().unwrap());
    }
    let (left, right) = nodes.split_at_mut(2);
    for _ in 0..32 {
        for half in [&mut *left, &mut *right] {
            relay(half, None);
            for n in half {
                assert!(!n.timeout().unwrap());
                assert_eq!(n.position().unwrap().unwrap(), (1, 0, StatePhase::Prevote));
                assert_eq!(n.state().unwrap().height(), 0);
            }
        }
    }
    relay(&mut nodes, None);
    relay(&mut nodes, None);
    assert!(nodes.iter().all(|n| n.position().unwrap().unwrap().1 == 1));
    let bytes = record(nodes[0].state().unwrap());
    let proposer = nodes.iter().position(|n| n.is_proposer().unwrap()).unwrap();
    nodes[proposer].author(Some(bytes)).unwrap();
    for _ in 0..4 {
        relay(&mut nodes, None);
    }
    assert!(nodes.iter().all(|n| n.state().unwrap().height() == 1));
    assert!(
        nodes
            .iter()
            .all(|n| { n.state().unwrap().commitment() == nodes[0].state().unwrap().commitment() })
    );
}

#[test]
fn asymmetric_nil_quorum_delivery_recovers_after_full_cold_restart() {
    for restart in [false, true] {
        let g = genesis();
        let mut directories = Vec::new();
        let mut live = Vec::new();
        let mut identities = Vec::new();
        for i in 0..4 {
            let (dir, anchors, n) = node(i, &g);
            if n.is_proposer().unwrap() {
                // Round zero's proposer stays offline for the entire test.
                continue;
            }
            directories.push((dir, anchors));
            identities.push(i);
            live.push(n);
        }
        assert_eq!(live.len(), 3);
        for n in &mut live {
            assert!(n.timeout().unwrap());
        }
        relay(&mut live, Some(ConsensusVoteRole::Prevote));
        assert!(
            live.iter()
                .all(|n| { n.position().unwrap().unwrap() == (1, 0, StatePhase::Precommit) })
        );
        let precommits: Vec<_> = live
            .iter()
            .flat_map(|n| n.publications().unwrap())
            .filter_map(|p| match p {
                StatePublication::Vote(v) if v.role() == ConsensusVoteRole::Precommit => {
                    assert_eq!(v.target(), ConsensusVoteTarget::Nil);
                    Some(v.encode())
                }
                _ => None,
            })
            .collect();
        // Only node zero receives the complete nil quorum. The other two
        // cannot advance from its single future-round identity.
        for bytes in &precommits {
            live[0].accept_vote(bytes).unwrap();
        }
        live[0].drive().unwrap();
        assert_eq!(live[0].position().unwrap().unwrap().1, 1);
        assert!(
            live[1..]
                .iter()
                .all(|n| n.position().unwrap().unwrap().1 == 0)
        );
        if restart {
            drop(live);
            live = directories
                .iter()
                .zip(&identities)
                .map(|((dir, anchors), i)| {
                    let history =
                        StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
                    let signer =
                        StateSigner::open(&dir.0, &anchors.0, g.clone(), key(*i), MAX_ROUND)
                            .unwrap();
                    StateNode::new(history, Some(signer)).unwrap()
                })
                .collect();
        }
        assert!(live[0].publications().unwrap().iter().any(|p| {
            matches!(p, StatePublication::Vote(v)
                if v.encode() == precommits[0])
        }));
        // Periodic publication alone must heal the asymmetric delivery. No
        // artificial quorum, reduced threshold, or saved peer messages help.
        relay(&mut live, None);
        assert!(live.iter().all(|n| n.position().unwrap().unwrap().1 == 1));
        let bytes = record(live[0].state().unwrap());
        let proposer = live.iter().position(|n| n.is_proposer().unwrap()).unwrap();
        live[proposer].author(Some(bytes)).unwrap();
        for _ in 0..4 {
            relay(&mut live, None);
        }
        assert!(live.iter().all(|n| n.state().unwrap().height() == 1));
        assert!(
            live.iter().all(|n| {
                n.state().unwrap().commitment() == live[0].state().unwrap().commitment()
            })
        );
    }
}

#[test]
fn cold_restart_resends_identical_completed_precommit_and_retains_record() {
    let g = genesis();
    let mut directories = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..4 {
        let (dir, anchors, node) = node(i, &g);
        directories.push((dir, anchors));
        nodes.push(node);
    }
    let bytes = record(nodes[0].state().unwrap());
    let proposer = nodes.iter().position(|n| n.is_proposer().unwrap()).unwrap();
    nodes[proposer].author(Some(bytes.clone())).unwrap();
    relay(&mut nodes, Some(ConsensusVoteRole::Prevote));
    relay(&mut nodes, Some(ConsensusVoteRole::Prevote));
    let last = nodes[0]
        .signer
        .as_ref()
        .unwrap()
        .last_publication()
        .unwrap()
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        nodes[0].position().unwrap().unwrap().2,
        StatePhase::Precommit
    );
    assert_eq!(nodes[0].state().unwrap().height(), 0);
    let old = nodes.remove(0);
    drop(old);
    let history = StateHistory::open(
        &directories[0].0.0,
        &directories[0].1.0,
        g.clone(),
        MAX_ROUND,
    )
    .unwrap();
    let signer = StateSigner::open(
        &directories[0].0.0,
        &directories[0].1.0,
        g.clone(),
        key(0),
        MAX_ROUND,
    )
    .unwrap();
    let restarted = StateNode::new(history, Some(signer)).unwrap();
    assert!(
        restarted
            .publications()
            .unwrap()
            .iter()
            .any(|p| p.encode().unwrap() == last)
    );
    assert!(restarted.has_retained_value().unwrap());
    nodes.insert(0, restarted);
    relay(&mut nodes, None);
    relay(&mut nodes, None);
    assert!(nodes.iter().all(|n| n.state().unwrap().height() == 1));
    drop((nodes, directories));
}

#[test]
fn all_validators_restart_after_prevoting_and_recover_the_durable_proposal() {
    let g = genesis();
    let mut directories = Vec::new();
    let mut nodes = Vec::new();
    for i in 0..4 {
        let (dir, anchors, node) = node(i, &g);
        directories.push((dir, anchors));
        nodes.push(node);
    }
    let bytes = record(nodes[0].state().unwrap());
    let proposer = nodes.iter().position(|n| n.is_proposer().unwrap()).unwrap();
    nodes[proposer].author(Some(bytes)).unwrap();
    let exact_proposal = nodes[proposer]
        .publications()
        .unwrap()
        .into_iter()
        .find_map(|p| match p {
            StatePublication::Proposal(p) => Some(p.encode().unwrap()),
            _ => None,
        })
        .unwrap();
    relay(&mut nodes, Some(ConsensusVoteRole::Prevote));
    assert!(
        nodes
            .iter()
            .all(|n| n.position().unwrap().unwrap().2 == StatePhase::Prevote)
    );
    nodes.clear();
    for (i, directory) in directories.iter().enumerate() {
        let history =
            StateHistory::open(&directory.0.0, &directory.1.0, g.clone(), MAX_ROUND).unwrap();
        let signer = StateSigner::open(
            &directory.0.0,
            &directory.1.0,
            g.clone(),
            key(i as u8),
            MAX_ROUND,
        )
        .unwrap();
        nodes.push(StateNode::new(history, Some(signer)).unwrap());
    }
    assert!(
        nodes[proposer]
            .publications()
            .unwrap()
            .iter()
            .any(|p| matches!(p, StatePublication::Proposal(_))
                && p.encode().unwrap() == exact_proposal)
    );
    relay(&mut nodes, None);
    relay(&mut nodes, None);
    assert!(nodes.iter().all(|n| n.state().unwrap().height() == 1));
    assert!(
        nodes
            .iter()
            .all(|n| n.state().unwrap().commitment() == nodes[0].state().unwrap().commitment())
    );
    drop((nodes, directories));
}

#[test]
fn one_faulty_future_vote_and_proposal_flood_cannot_starve_three_honest_signers() {
    let g = genesis_with_rounds(64);
    let initial = StateBranch::from_genesis(LedgerState::new(g.clone()))
        .unwrap()
        .proposer(0, 64)
        .unwrap();
    let faulty = (0..4)
        .find(|i| ConsensusKey::from_bytes(key(*i).verifying_key().to_bytes()) != initial)
        .unwrap();
    let mut directories = Vec::new();
    let mut honest = Vec::new();
    let mut faulty_node = None;
    for i in 0..4 {
        let (dir, anchor, n) = node(i, &g);
        directories.push((dir, anchor));
        if i == faulty {
            faulty_node = Some(n)
        } else {
            honest.push(n)
        }
    }
    let proposer = honest
        .iter()
        .position(|n| n.is_proposer().unwrap())
        .unwrap();
    let record = record(honest[0].state().unwrap());
    honest[proposer].author(Some(record)).unwrap();
    let proposal = honest[proposer]
        .publications()
        .unwrap()
        .into_iter()
        .find_map(|p| match p {
            StatePublication::Proposal(p) => Some(p.encode().unwrap()),
            _ => None,
        })
        .unwrap();
    let mut faulty_node = faulty_node.unwrap();
    faulty_node.timeout().unwrap();
    let vote = faulty_node
        .publications()
        .unwrap()
        .into_iter()
        .find_map(|p| match p {
            StatePublication::Vote(v) => Some(v.encode()),
            _ => None,
        })
        .unwrap();
    let faulty_key = ConsensusKey::from_bytes(key(faulty).verifying_key().to_bytes());
    for round in 1u64..=64 {
        for role_ in [1u8, 2] {
            // A Byzantine key bypasses its local journal and signs arbitrary
            // future positions. Authentication succeeds; retention must isolate it.
            let mut encoded = vote.clone();
            let round_offset = 5 + 32 + 32 + 8;
            encoded[round_offset..round_offset + 8].copy_from_slice(&round.to_be_bytes());
            encoded[round_offset + 8] = role_;
            let signature_offset = encoded.len() - 64;
            let mut transcript = if role_ == 1 {
                b"naome:state:prevote:v1\0".to_vec()
            } else {
                b"naome:state:precommit:v1\0".to_vec()
            };
            transcript.extend_from_slice(&encoded[..signature_offset]);
            encoded[signature_offset..].copy_from_slice(&key(faulty).sign(&transcript).to_bytes());
            for node in &mut honest {
                let _ = node.accept_vote(&encoded);
                node.drive().unwrap();
            }
        }
        if honest[0].branch().unwrap().proposer(round, 64).unwrap() == faulty_key {
            let mut encoded = proposal.clone();
            let offset = 5 + naome_consensus::state::StateValue::BYTE_LENGTH;
            encoded[offset..offset + 8].copy_from_slice(&round.to_be_bytes());
            encoded[offset + 8..offset + 40].copy_from_slice(faulty_key.as_bytes());
            let mut transcript = b"naome:state:proposal:v1\0".to_vec();
            transcript.extend_from_slice(&encoded[5..offset + 40]);
            encoded[offset + 40..offset + 104]
                .copy_from_slice(&key(faulty).sign(&transcript).to_bytes());
            for node in &mut honest {
                node.accept_proposal(&encoded).unwrap();
                node.drive().unwrap();
            }
        }
    }
    for node in &honest {
        assert_eq!(node.position().unwrap().unwrap().1, 0);
        assert!(
            node.votes
                .values()
                .filter(|v| v.signer() == faulty_key)
                .count()
                <= VOTES_PER_SIGNER
        );
        assert!(
            node.proposals
                .values()
                .filter(|p| p.proposer() == faulty_key)
                .count()
                <= PROPOSALS_PER_SIGNER
        );
    }
    for _ in 0..4 {
        relay(&mut honest, None);
    }
    assert!(honest.iter().all(|n| n.state().unwrap().height() == 1));
    assert!(
        honest
            .iter()
            .all(|n| n.state().unwrap().commitment() == honest[0].state().unwrap().commitment())
    );
    drop((honest, faulty_node, directories));
}
