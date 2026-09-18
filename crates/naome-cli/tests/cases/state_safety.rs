use super::*;
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_consensus::{
    ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget,
    state::{ResearchBranch, ResearchLockEvent, ResearchPhase, ResearchPublication},
};
use naome_ledger::{
    ResearchState,
    operations::OperationBody,
    profile::Genesis,
    question::CompiledQuestion,
    time::{SignedTimeReport, TimeCertificate},
};
use naome_storage::state::ResearchSigner;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

fn key(lab: &Lab, relative: &str, role: u8) -> SigningKey {
    let bytes = Zeroizing::new(fs::read(lab.root.join(relative)).unwrap());
    assert_eq!(bytes.len(), 41);
    assert_eq!(&bytes[..8], b"NSKEY001");
    assert_eq!(bytes[8], role);
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&bytes[9..]).unwrap());
    SigningKey::from_bytes(&seed)
}
fn genesis(lab: &Lab) -> Genesis {
    Genesis::decode(&fs::read(lab.root.join("genesis.bin")).unwrap()).unwrap()
}
fn signer(lab: &Lab, node: usize) -> ResearchSigner {
    let g = genesis(lab);
    let maximum = g.profile().limits().consensus_rounds;
    ResearchSigner::open(
        lab.root.join(format!("node-{node}/signer")),
        lab.root.join(format!("anchor-signer-{node}")),
        g,
        key(lab, &format!("node-{node}/consensus.key"), 2),
        maximum,
    )
    .unwrap()
}
fn journal(lab: &Lab, node: usize) -> PathBuf {
    fs::read_dir(lab.root.join(format!("node-{node}/signer")))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "journal"))
        .unwrap()
}
fn kill(lab: &mut Lab, node: usize) {
    let mut child = lab.nodes[node].take().unwrap();
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
}
fn image(lab: &Lab, node: usize) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut result = BTreeMap::new();
    let genesis = lab.root.join("genesis.bin");
    result.insert(genesis.clone(), fs::read(genesis).unwrap());
    for directory in [
        format!("node-{node}/history"),
        format!("node-{node}/signer"),
        format!("anchor-history-{node}"),
        format!("anchor-signer-{node}"),
    ] {
        for entry in fs::read_dir(lab.root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            result.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    result
}
fn alternate_proposal(lab: &Lab) -> Vec<u8> {
    let branch = ResearchBranch::from_genesis(ResearchState::new(genesis(lab))).unwrap();
    make_proposal(lab, &branch, "conflicting vote target", 4, "question-a.nao")
}
fn make_proposal(
    lab: &Lab,
    branch: &ResearchBranch,
    purpose: &str,
    author: usize,
    source: &str,
) -> Vec<u8> {
    let state = branch.state();
    let g = state.genesis();
    let maximum = g.profile().limits().consensus_rounds;
    let height = state.height() + 1;
    let reports = (0..4)
        .map(|i| {
            SignedTimeReport::sign(
                g,
                state.head(),
                height,
                state.time(),
                &key(lab, &format!("node-{i}/consensus.key"), 2),
            )
            .unwrap()
        })
        .collect();
    let time = TimeCertificate::new(reports, g, state.head(), height, state.time()).unwrap();
    let question =
        CompiledQuestion::compile(&fs::read_to_string(example(source)).unwrap(), g.profile())
            .unwrap();
    let author = key(lab, &format!("accounts/account-{author}.key"), 1);
    let account = naome_ledger::AccountId::for_key(author.verifying_key().as_bytes());
    let operation = OperationBody::Submit {
        purpose: purpose.into(),
        question,
    }
    .sign(g, state.next_nonce(account).unwrap(), &author)
    .unwrap();
    let record = state
        .prepare_record(time, vec![operation])
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let proposer = branch.proposer(0, maximum).unwrap();
    let signing = (0..4)
        .map(|i| key(lab, &format!("node-{i}/consensus.key"), 2))
        .find(|key| key.verifying_key().as_bytes() == proposer.as_bytes())
        .unwrap();
    let mut kernel = naome_consensus::state::ResearchLockState::new(branch, proposer).unwrap();
    let intent = kernel
        .apply(
            branch,
            &ResearchLockEvent::Author {
                record: Some(record),
            },
            maximum,
        )
        .unwrap();
    let signature = signing.sign(&intent.signing_bytes().unwrap()).to_bytes();
    intent
        .complete(signature, branch, maximum)
        .unwrap()
        .encode()
        .unwrap()
}
fn exported(lab: &Lab, node: usize, label: &str) -> PathBuf {
    let root = lab.root.join(label);
    command(&["export".into(), lab.config(node), path(&root)]);
    root
}

#[test]
fn canonical_sigkill_resends_exact_vote_then_catches_up_and_supplies_required_quorum_vote() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    lab.start(3);
    lab.wait(3, |_| true);
    let proposal = alternate_proposal(&lab);
    // The authenticated fixture peer supplies a valid proposal but deliberately
    // withholds the receipt for the actual process's durably completed vote.
    let observed_vote = capture_vote_without_receipt(&lab, Some(proposal.clone()), 1);
    kill(&mut lab, 3);
    let before = image(&lab, 3);
    let journal_path = journal(&lab, 3);
    let prefix = fs::read(&journal_path).unwrap();
    let mut recovered = signer(&lab, 3);
    assert_eq!(recovered.phase().unwrap(), ResearchPhase::Prevote);
    let publications = recovered.retry_publications().unwrap();
    assert_eq!(publications.len(), 1);
    let ResearchPublication::Vote(vote) = &publications[0] else {
        panic!("expected durable vote")
    };
    assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
    assert!(matches!(vote.target(), ConsensusVoteTarget::Proposal(_)));
    assert_eq!(vote.encode(), observed_vote);
    assert_eq!(
        recovered
            .apply_and_sign(&ResearchLockEvent::Prevote {
                proposal: Some(proposal.clone())
            })
            .unwrap(),
        Some(publications[0].clone())
    );
    assert!(
        recovered
            .apply_and_sign(&ResearchLockEvent::ProposalTimeout)
            .is_err()
    );
    drop(recovered);
    assert_eq!(image(&lab, 3), before);
    lab.start(3);
    lab.wait(3, |status| {
        status["consensus_position"]["phase"] == "Prevote"
    });
    // A receive-only peer observes retransmission without supplying a new proposal.
    assert_eq!(capture_vote_without_receipt(&lab, None, 1), observed_vote);
    kill(&mut lab, 3);
    assert_eq!(signer(&lab, 3).retry_publications().unwrap(), publications);
    assert_eq!(image(&lab, 3), before);

    // Three other independent processes settle while this signer remains offline.
    for node in 0..3 {
        lab.start(node);
    }
    for node in 0..3 {
        lab.wait(node, |_| true);
    }
    lab.submit(0, 4, example("question-a.nao"), "crash-a");
    let prior = lab.wait(0, |status| {
        status["height"].as_u64().unwrap() >= 3
            && status["active"].is_null()
            && status["queued"] == 0
    });
    lab.assert_same(&[0, 1, 2], &prior);
    let provider = exported(&lab, 0, "provider-prefix");
    lab.stop(1);
    lab.start(3);
    lab.assert_same(&[0, 2, 3], &prior);
    let caught = exported(&lab, 3, "caught-prefix");
    for height in 1..=prior["height"].as_u64().unwrap() {
        let name = format!("{height:08}.finality");
        assert_eq!(
            fs::read(provider.join(&name)).unwrap(),
            fs::read(caught.join(name)).unwrap()
        );
    }
    // Only 0, 2 and the recovered signer 3 are online: its vote is necessary.
    let target = prior["height"].as_u64().unwrap() + 1;
    lab.submit(0, 5, example("question-b.nao"), "crash-b");
    let next = lab.wait(0, |status| {
        status["height"].as_u64().unwrap() >= target && status["active"]["phase"] == "Voting"
    });
    lab.assert_same(&[0, 2, 3], &next);
    let final_archive = exported(&lab, 0, "after-catch-up");
    let g = genesis(&lab);
    let maximum = g.profile().limits().consensus_rounds;
    let mut branch = ResearchBranch::from_genesis(ResearchState::new(g)).unwrap();
    let recovered_key = ConsensusKey::from_bytes(
        key(&lab, "node-3/consensus.key", 2)
            .verifying_key()
            .to_bytes(),
    );
    for height in 1..=next["height"].as_u64().unwrap() {
        let bytes = fs::read(final_archive.join(format!("{height:08}.finality"))).unwrap();
        let finality = branch.decode_finality(&bytes, maximum).unwrap();
        if height >= target {
            assert!(
                finality
                    .quorum()
                    .vote_set()
                    .votes()
                    .iter()
                    .any(|vote| vote.signer() == recovered_key)
            );
        }
        branch = finality.into_branch();
    }
    for node in [0, 2, 3] {
        lab.stop(node);
    }
    assert!(fs::read(journal_path).unwrap().starts_with(&prefix));
    startup_corruption_matrix(&lab, &before);
    lab.start(3);
    lab.assert_same(&[3], &next);
    lab.stop(3);
}

fn restore(snapshot: &BTreeMap<PathBuf, Vec<u8>>) {
    use std::os::unix::fs::PermissionsExt;
    for (path, bytes) in snapshot {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn refused_start_preserves(lab: &Lab, node: usize) {
    let before = image(lab, node);
    let mut child = Command::new(process_binary("naome-validator"))
        .args(["start", &lab.config(node)])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("invalid authority startup did not fail closed");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\"event\":\"started\""));
    assert_eq!(
        image(lab, node),
        before,
        "failed startup repaired authority files"
    );
}
fn startup_corruption_matrix(lab: &Lab, old: &BTreeMap<PathBuf, Vec<u8>>) {
    let current = image(lab, 3);
    let history = current
        .iter()
        .find(|(_, bytes)| bytes.starts_with(b"NAOSHIS1"))
        .unwrap()
        .0
        .clone();
    let anchor = current
        .iter()
        .find(|(path, bytes)| {
            path.starts_with(lab.root.join("anchor-history-3")) && bytes.starts_with(b"NAOSANC1")
        })
        .unwrap()
        .0
        .clone();
    let signer_anchor = current
        .iter()
        .find(|(path, bytes)| {
            path.starts_with(lab.root.join("anchor-signer-3")) && bytes.starts_with(b"NAOSANC1")
        })
        .unwrap()
        .0
        .clone();
    let signer_journal = journal(lab, 3);
    assert_ne!(current[&history], old[&history]);
    assert_ne!(current[&anchor], old[&anchor]);
    for (path, bytes) in [(&history, &old[&history]), (&anchor, &old[&anchor])] {
        fs::write(path, bytes).unwrap();
        refused_start_preserves(lab, 3);
        restore(&current);
    }
    let sibling = image(lab, 0)
        .into_iter()
        .find(|(path, bytes)| {
            path.starts_with(lab.root.join("anchor-signer-0")) && bytes.starts_with(b"NAOSANC1")
        })
        .unwrap()
        .1;
    fs::write(&signer_anchor, sibling).unwrap();
    refused_start_preserves(lab, 3);
    restore(&current);
    fs::remove_file(&signer_journal).unwrap();
    refused_start_preserves(lab, 3);
    restore(&current);
    for path in [&history, &signer_journal] {
        let mut bytes = current[path].clone();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        refused_start_preserves(lab, 3);
        restore(&current);
    }
    fs::remove_file(&anchor).unwrap();
    refused_start_preserves(lab, 3);
    restore(&current);
    let foreign = Lab::new();
    let genesis_path = lab.root.join("genesis.bin");
    let original = fs::read(&genesis_path).unwrap();
    fs::write(
        &genesis_path,
        fs::read(foreign.root.join("genesis.bin")).unwrap(),
    )
    .unwrap();
    refused_start_preserves(lab, 3);
    fs::write(&genesis_path, original).unwrap();
    assert_eq!(image(lab, 3), current);
}

fn capture_vote_without_receipt(
    lab: &Lab,
    proposal: Option<Vec<u8>>,
    expected_height: u64,
) -> Vec<u8> {
    use naome_network::{
        Keypair, NetworkEvent, PeerSessionEvent, ResearchRequestBody as Request,
        ResearchResponseBody as Response, StaticArtifactNetwork, research_peer_id,
    };
    let g = genesis(lab);
    let mut seed = Zeroizing::new(key(lab, "node-0/transport.key", 3).to_bytes());
    let identity = Keypair::ed25519_from_bytes(&mut *seed).unwrap();
    let peer = research_peer_id(
        key(lab, "node-3/transport.key", 3)
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut network = StaticArtifactNetwork::new_research(identity, &g).unwrap();
            network
                .listen_on(network.research_listen_address().unwrap().clone())
                .unwrap();
            tokio::time::timeout(Duration::from_secs(20), async {
                let mut ticket = None;
                loop {
                    match network.next_event().await {
                        NetworkEvent::PeerSession(PeerSessionEvent::Established { peer_id })
                            if peer_id == peer && ticket.is_none() && proposal.is_some() =>
                        {
                            ticket = Some(
                                network
                                    .request_research(
                                        peer,
                                        Request::Proposal(
                                            proposal.as_ref().unwrap().clone().into(),
                                        ),
                                    )
                                    .unwrap(),
                            );
                        }
                        NetworkEvent::InboundResearch(inbound) => {
                            assert_eq!(inbound.peer_id(), peer);
                            if let Request::Vote(bytes) = inbound.request().body() {
                                let vote = naome_consensus::state::ResearchVote::decode(bytes, &g)
                                    .unwrap();
                                assert_eq!(
                                    vote.signer(),
                                    ConsensusKey::from_bytes(
                                        key(lab, "node-3/consensus.key", 2)
                                            .verifying_key()
                                            .to_bytes()
                                    )
                                );
                                assert_eq!(vote.height(), expected_height);
                                assert_eq!(vote.round(), 0);
                                // Dropping the retained inbound request sends no receipt.
                                return bytes.to_vec();
                            }
                            let response = match inbound.request().body() {
                                Request::Handshake => Response::Ready,
                                Request::History { .. } => Response::History(Vec::new()),
                                Request::Proof { .. } => Response::Unavailable,
                                _ => Response::Accepted,
                            };
                            network.respond_research(inbound, response).unwrap();
                        }
                        NetworkEvent::OutboundResearch(event) => {
                            if let Some(active) = ticket.take() {
                                let received = active.complete(event).unwrap().unwrap();
                                assert_eq!(received.response().body(), &Response::Accepted);
                            }
                        }
                        _ => {}
                    }
                }
            })
            .await
            .expect("proposal delivery and unacknowledged actual vote")
        })
}

// Fixture certificates intentionally model a quorum that equivocates. They are
// not evidence that a public network tolerates a compromised supermajority.
fn certify(
    lab: &Lab,
    branch: &ResearchBranch,
    bytes: &[u8],
) -> naome_consensus::state::ResearchFinality {
    use naome_consensus::state::{ResearchLockState, ResearchQuorum};
    let maximum = branch.state().genesis().profile().limits().consensus_rounds;
    let proposal = branch.verify_proposal(bytes, maximum).unwrap();
    let keys = (0..3)
        .map(|i| key(lab, &format!("node-{i}/consensus.key"), 2))
        .collect::<Vec<_>>();
    let mut kernels = keys
        .iter()
        .map(|key| {
            ResearchLockState::new(
                branch,
                ConsensusKey::from_bytes(key.verifying_key().to_bytes()),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let mut votes = Vec::new();
    for (kernel, key) in kernels.iter_mut().zip(&keys) {
        let intent = kernel
            .apply(
                branch,
                &ResearchLockEvent::Prevote {
                    proposal: Some(bytes.to_vec()),
                },
                maximum,
            )
            .unwrap();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        let ResearchPublication::Vote(vote) = intent.complete(signature, branch, maximum).unwrap()
        else {
            panic!("vote")
        };
        votes.push(vote);
    }
    let prevotes = ResearchQuorum::from_votes(votes, branch.state().genesis()).unwrap();
    let mut votes = Vec::new();
    for (kernel, key) in kernels.iter_mut().zip(&keys) {
        let intent = kernel
            .apply(
                branch,
                &ResearchLockEvent::Precommit {
                    proposal: Some(bytes.to_vec()),
                    quorum: prevotes.encode(),
                },
                maximum,
            )
            .unwrap();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        let ResearchPublication::Vote(vote) = intent.complete(signature, branch, maximum).unwrap()
        else {
            panic!("vote")
        };
        votes.push(vote);
    }
    let quorum = ResearchQuorum::from_votes(votes, branch.state().genesis()).unwrap();
    branch.verify_finality(&proposal, &quorum, maximum).unwrap()
}

#[test]
fn canonical_authenticated_historical_conflict_stops_pending_publication_and_persists_halt() {
    use naome_storage::state::{ResearchHistory, ResearchObserver};
    let _guard = process_guard();
    let mut lab = Lab::new();
    lab.start(3);
    lab.wait(3, |_| true);
    lab.stop(3);
    let g = genesis(&lab);
    let maximum = g.profile().limits().consensus_rounds;
    let initial = ResearchBranch::from_genesis(ResearchState::new(g.clone())).unwrap();
    let selected = certify(
        &lab,
        &initial,
        &make_proposal(&lab, &initial, "selected", 4, "question-a.nao"),
    );
    let conflicting = certify(
        &lab,
        &initial,
        &make_proposal(&lab, &initial, "conflicting", 4, "question-a.nao"),
    );
    assert_ne!(
        selected.branch().commitment(),
        conflicting.branch().commitment()
    );
    let mut history = ResearchHistory::open(
        lab.root.join("node-3/history"),
        lab.root.join("anchor-history-3"),
        g.clone(),
        maximum,
    )
    .unwrap();
    history
        .append_finality(&selected.encode().unwrap())
        .unwrap();
    drop(history);
    let pending = make_proposal(
        &lab,
        selected.branch(),
        "pending next record",
        5,
        "question-b.nao",
    );
    lab.start(3);
    lab.wait(3, |status| status["height"] == 1);
    let vote = capture_vote_without_receipt(&lab, Some(pending), 2);
    let journal_path = journal(&lab, 3);
    let prefix = fs::read(&journal_path).unwrap();
    let before = image(&lab, 3);
    deliver_conflict_until_process_stops(&mut lab, conflicting.encode().unwrap(), &vote);
    let observer = ResearchObserver::open(
        lab.root.join("node-3/history"),
        lab.root.join("anchor-history-3"),
        g,
        maximum,
    )
    .unwrap();
    assert!(observer.halted());
    assert_eq!(
        observer.branch().commitment(),
        selected.branch().commitment()
    );
    let mut stopped = signer(&lab, 3);
    assert!(stopped.stopped().unwrap());
    assert!(stopped.retry_publications().is_err());
    assert!(
        stopped
            .apply_and_sign(&ResearchLockEvent::ProposalTimeout)
            .is_err()
    );
    drop(stopped);
    let after = fs::read(&journal_path).unwrap();
    assert!(after.starts_with(&prefix));
    // Exactly one STOP frame follows the pending publication; no signing PREPARE
    // or COMPLETE frame can be hidden in the suffix.
    let suffix = &after[prefix.len()..];
    assert_eq!(
        suffix.len() as u64,
        naome_ledger::profile::SIGNER_STOP_FRAME_BYTES
    );
    assert_eq!(&suffix[..4], &41u32.to_be_bytes());
    assert_eq!(suffix[4], 4);
    for (path, bytes) in before
        .iter()
        .filter(|(_, bytes)| bytes.starts_with(b"NAOSHIS1"))
    {
        assert!(fs::read(path).unwrap().starts_with(bytes));
    }
    let halted = image(&lab, 3);
    refused_start_preserves(&lab, 3);
    assert_eq!(image(&lab, 3), halted);
}

fn deliver_conflict_until_process_stops(lab: &mut Lab, conflict: Vec<u8>, pending_vote: &[u8]) {
    use naome_network::{
        Keypair, NetworkEvent, PeerSessionEvent, ResearchRequestBody as Request,
        ResearchResponseBody as Response, StaticArtifactNetwork, research_peer_id,
    };
    let g = genesis(lab);
    let mut seed = Zeroizing::new(key(lab, "node-0/transport.key", 3).to_bytes());
    let identity = Keypair::ed25519_from_bytes(&mut *seed).unwrap();
    let peer = research_peer_id(
        key(lab, "node-3/transport.key", 3)
            .verifying_key()
            .to_bytes(),
    )
    .unwrap();
    let child = lab.nodes[3].as_mut().unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut network=StaticArtifactNetwork::new_research(identity,&g).unwrap();
        network.listen_on(network.research_listen_address().unwrap().clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(20),async {
            let mut ticket=None;let mut sent=false;
            loop {tokio::select! {
                _=tokio::time::sleep(Duration::from_millis(10))=>if let Some(status)=child.try_wait().unwrap() {assert!(sent);assert!(!status.success());break;},
                event=network.next_event()=>match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established{peer_id}) if peer_id==peer&&!sent=> {
                        ticket=Some(network.request_research(peer,Request::Finalized(conflict.clone().into())).unwrap());sent=true;
                    }
                    NetworkEvent::InboundResearch(inbound)=> {
                        assert_eq!(inbound.peer_id(),peer);
                        if let Request::Vote(bytes)=inbound.request().body() {assert_eq!(bytes.as_ref(),pending_vote);continue;}
                        let response=match inbound.request().body() {Request::Handshake=>Response::Ready,Request::History{..}=>Response::History(Vec::new()),Request::Proof{..}=>Response::Unavailable,_=>Response::Accepted};
                        network.respond_research(inbound,response).unwrap();
                    }
                    NetworkEvent::OutboundResearch(event)=>if let Some(active)=ticket.take() {let _ = active.complete(event).unwrap();},
                    _=>{}
                }
            }}
        }).await.expect("authenticated conflict must stop the live process");
    });
    let mut child = lab.nodes[3].take().unwrap();
    assert!(!child.wait().unwrap().success());
}
