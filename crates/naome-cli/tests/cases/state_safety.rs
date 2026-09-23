use super::*;
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_consensus::{
    ConsensusKey, ConsensusVoteRole, ConsensusVoteTarget,
    state::{
        SealRole, SealSignature, StateAgreement, StateBranch, StateLockEvent, StatePhase,
        StatePublication, StateSeal,
    },
};
use naome_ledger::{
    AccountId, LedgerState,
    authority::{HandoffPlan, NextPeriodKeys},
    operations::OperationBody,
    profile::Genesis,
    question::CompiledQuestion,
    time::{SignedTimeReport, TimeCertificate},
};
use naome_storage::state::{StatePeriodCustody, StateSigner};
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
fn fixture_next_custody(lab: &Lab, state: &LedgerState, index: usize) -> StatePeriodCustody {
    let owner = key(lab, &format!("accounts/account-{index}.key"), 1);
    let unit = state
        .authority()
        .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
        .unwrap();
    let endpoint =
        if unit.keys().unwrap().endpoint() == format!("127.0.0.1:{}", lab.base + index as u16) {
            format!("127.0.0.1:{}", lab.base + 4 + index as u16)
        } else {
            format!("127.0.0.1:{}", lab.base + index as u16)
        };
    StatePeriodCustody::stage_offer(
        lab.root.join(format!("node-{index}/custody")),
        lab.root.join(format!("anchor-custody-{index}")),
        state,
        unit.id(),
        &owner,
        endpoint,
    )
    .unwrap()
}
fn fixture_period_key(lab: &Lab, state: &LedgerState, index: usize) -> SigningKey {
    let height = state.authority().effective_height();
    if height == 1 {
        key(lab, &format!("node-{index}/consensus.key"), 2)
    } else {
        assert_eq!(height, 2, "fixture only constructs one successor period");
        fixture_next_custody(lab, &LedgerState::new(genesis(lab)), index)
            .consensus_key()
            .clone()
    }
}
fn fixture_period_transport_key(lab: &Lab, state: &LedgerState, index: usize) -> SigningKey {
    if state.authority().effective_height() == 1 {
        key(lab, &format!("node-{index}/transport.key"), 3)
    } else {
        assert_eq!(state.authority().effective_height(), 2);
        fixture_next_custody(lab, &LedgerState::new(genesis(lab)), index)
            .transport_key()
            .clone()
    }
}
fn fixture_public_key(lab: &Lab, state: &LedgerState, index: usize, transport: bool) -> [u8; 32] {
    let owner = key(lab, &format!("accounts/account-{index}.key"), 1);
    let keys = state
        .authority()
        .owner(AccountId::for_key(owner.verifying_key().as_bytes()))
        .unwrap()
        .keys()
        .unwrap();
    if transport {
        *keys.transport()
    } else {
        *keys.consensus()
    }
}
fn fixture_plan(lab: &Lab, state: &LedgerState) -> HandoffPlan {
    let mut offers: Vec<_> = (0..4)
        .map(|index| {
            fixture_next_custody(lab, state, index)
                .offer()
                .unwrap()
                .clone()
        })
        .collect();
    offers.sort_by_key(NextPeriodKeys::unit);
    HandoffPlan::new(offers, None).unwrap()
}
fn fixture_seal(lab: &Lab, branch: &StateBranch, agreement: &StateAgreement) -> StateSeal {
    let signatures = |role: SealRole, incoming: bool| {
        let authority = if incoming {
            agreement.incoming()
        } else {
            agreement.outgoing()
        };
        authority
            .units()
            .iter()
            .filter_map(|unit| unit.keys().map(|keys| (unit, keys)))
            .take(3)
            .map(|(unit, keys)| {
                let index = (0..4)
                    .find(|i| {
                        AccountId::for_key(
                            key(lab, &format!("accounts/account-{i}.key"), 1)
                                .verifying_key()
                                .as_bytes(),
                        ) == unit.owner()
                    })
                    .unwrap();
                let signer = if incoming {
                    fixture_next_custody(lab, branch.state(), index)
                        .consensus_key()
                        .clone()
                } else {
                    fixture_period_key(lab, branch.state(), index)
                };
                let consensus = ConsensusKey::from_bytes(*keys.consensus());
                let signature = signer
                    .sign(&SealSignature::signing_bytes(
                        role,
                        agreement.seal_context(),
                        consensus,
                    ))
                    .to_bytes();
                SealSignature::complete(
                    role,
                    agreement.seal_context(),
                    consensus,
                    signature,
                    agreement.outgoing(),
                    agreement.incoming(),
                )
                .unwrap()
            })
            .collect()
    };
    StateSeal::new(
        signatures(SealRole::Ready, true),
        signatures(SealRole::Terminal, false),
        agreement.seal_context(),
        agreement.outgoing(),
        agreement.incoming(),
    )
    .unwrap()
}
fn signer(lab: &Lab, node: usize) -> StateSigner {
    let g = genesis(lab);
    let maximum = g.profile().limits().consensus_rounds;
    StateSigner::open(
        lab.root.join(format!("node-{node}/signer")),
        lab.root.join(format!("anchor-signer-{node}")),
        g,
        key(lab, &format!("node-{node}/consensus.key"), 2),
        maximum,
    )
    .unwrap()
}
fn journal(lab: &Lab, branch: &StateBranch, node: usize) -> PathBuf {
    let key = fixture_public_key(lab, branch.state(), node, false);
    let name: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    lab.root
        .join(format!("node-{node}/signer/state-signer-{name}.journal"))
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
        format!("node-{node}/custody"),
        format!("node-{node}/handoff"),
        format!("anchor-history-{node}"),
        format!("anchor-signer-{node}"),
        format!("anchor-custody-{node}"),
        format!("anchor-handoff-{node}"),
    ] {
        for entry in fs::read_dir(lab.root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            result.insert(path.clone(), fs::read(path).unwrap());
        }
    }
    result
}
fn alternate_proposal(lab: &Lab) -> Vec<u8> {
    let branch = StateBranch::from_genesis(LedgerState::new(genesis(lab))).unwrap();
    make_proposal(lab, &branch, "conflicting vote target", 4, "question-a.nao")
}
fn make_proposal(
    lab: &Lab,
    branch: &StateBranch,
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
                state.authority(),
                state.head(),
                height,
                state.time(),
                &fixture_period_key(lab, state, i),
            )
            .unwrap()
        })
        .collect();
    let time = TimeCertificate::new(
        reports,
        g,
        state.authority(),
        state.head(),
        height,
        state.time(),
    )
    .unwrap();
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
        .prepare_record(time, vec![operation], fixture_plan(lab, state))
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let proposer = branch.proposer(0, maximum).unwrap().unwrap();
    let signing = (0..4)
        .map(|i| fixture_period_key(lab, state, i))
        .find(|key| key.verifying_key().as_bytes() == proposer.as_bytes())
        .unwrap();
    let mut kernel = naome_consensus::state::StateLockState::new(branch, proposer).unwrap();
    let intent = kernel
        .apply(
            branch,
            &StateLockEvent::Author {
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
fn canonical_sigkill_resends_exact_vote_then_resumes_selected_successor_with_fresh_quorum_vote() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    let proposal = alternate_proposal(&lab);
    lab.start(3);
    lab.wait(3, |_| true);
    // The authenticated fixture peer supplies a valid proposal but deliberately
    // withholds the receipt for the actual process's durably completed vote.
    let initial = StateBranch::from_genesis(LedgerState::new(genesis(&lab))).unwrap();
    let observed_vote = capture_vote_without_receipt(&lab, &initial, Some(proposal.clone()), 1);
    kill(&mut lab, 3);
    super::lifecycle::refuse_missing_stores(&lab, 3);
    let before = image(&lab, 3);
    let journal_path = journal(&lab, &initial, 3);
    let prefix = fs::read(&journal_path).unwrap();
    let mut recovered = signer(&lab, 3);
    assert_eq!(recovered.phase().unwrap(), StatePhase::Prevote);
    let publications = recovered.retry_publications().unwrap();
    assert_eq!(publications.len(), 1);
    let StatePublication::Vote(vote) = &publications[0] else {
        panic!("expected durable vote")
    };
    assert_eq!(vote.role(), ConsensusVoteRole::Prevote);
    assert!(matches!(vote.target(), ConsensusVoteTarget::Proposal(_)));
    assert_eq!(vote.encode(), observed_vote);
    assert_eq!(
        recovered
            .apply_and_sign(&StateLockEvent::Prevote {
                proposal: Some(proposal.clone())
            })
            .unwrap(),
        Some(publications[0].clone())
    );
    assert!(
        recovered
            .apply_and_sign(&StateLockEvent::ProposalTimeout)
            .is_err()
    );
    drop(recovered);
    assert_eq!(image(&lab, 3), before);
    lab.start(3);
    lab.wait(3, |status| {
        status["consensus_position"]["phase"] == "Prevote"
    });
    // A receive-only peer observes retransmission without supplying a new proposal.
    assert_eq!(
        capture_vote_without_receipt(&lab, &initial, None, 1),
        observed_vote
    );
    kill(&mut lab, 3);
    assert_eq!(signer(&lab, 3).retry_publications().unwrap(), publications);
    assert_eq!(image(&lab, 3), before);

    // The same proposal carries node 3's offer, anchored before the crash.
    // Select exactly one sealed successor while node 3 is offline. This is the
    // last period in which its existing offer can be activated after recovery.
    let selected = certify(&lab, &initial, &proposal);
    for node in 0..4 {
        let g = genesis(&lab);
        let mut history = naome_storage::state::StateHistory::open(
            lab.root.join(format!("node-{node}/history")),
            lab.root.join(format!("anchor-history-{node}")),
            g.clone(),
            g.profile().limits().consensus_rounds,
        )
        .unwrap();
        history
            .append_finality(&selected.encode().unwrap())
            .unwrap();
    }
    for node in [0, 2, 3] {
        lab.start(node);
    }
    let prior = lab.wait(3, |status| status["height"] == 1);
    lab.assert_same(&[0, 2, 3], &prior);
    assert!(!lab.root.join("node-3/consensus.key").exists());
    let recovered_key = ConsensusKey::from_bytes(fixture_public_key(
        &lab,
        selected.branch().state(),
        3,
        false,
    ));
    // With node 1 offline, a new record needs node 3's fresh period vote.
    lab.submit(0, 5, example("question-b.nao"), "crash-b");
    let next = lab.wait(0, |status| status["height"].as_u64().unwrap() >= 2);
    lab.assert_same(&[0, 2, 3], &next);
    let final_archive = exported(&lab, 0, "after-catch-up");
    let g = genesis(&lab);
    let maximum = g.profile().limits().consensus_rounds;
    let mut branch = initial;
    for height in 1..=next["height"].as_u64().unwrap() {
        let bytes = fs::read(final_archive.join(format!("{height:08}.finality"))).unwrap();
        let finality = branch.decode_finality(&bytes, maximum).unwrap();
        if height == 2 {
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
    startup_corruption_matrix(&lab, &before, &branch);
    lab.start(3);
    lab.assert_same(&[3], &next);
    lab.stop(3);
}

#[test]
fn canonical_vacant_slot_catches_up_without_reviving_retired_signing_key() {
    let _guard = process_guard();
    let mut lab = Lab::new();
    for node in 0..3 {
        lab.start(node);
    }
    for node in 0..3 {
        lab.wait(node, |_| true);
    }
    lab.submit(0, 4, example("question-a.nao"), "vacant-a");
    let prior = lab.wait(0, |status| {
        status["height"].as_u64().unwrap() >= 3
            && status["active"].is_null()
            && status["queued"] == 0
    });
    lab.assert_same(&[0, 1, 2], &prior);
    let provider = exported(&lab, 0, "vacant-provider");
    lab.start(3);
    lab.wait(3, |status| {
        status["height"].as_u64().unwrap() >= prior["height"].as_u64().unwrap()
            && status["consensus_position"].is_null()
    });
    let caught = exported(&lab, 3, "vacant-caught");
    for height in 1..=prior["height"].as_u64().unwrap() {
        let name = format!("{height:08}.finality");
        assert_eq!(
            fs::read(provider.join(&name)).unwrap(),
            fs::read(caught.join(name)).unwrap()
        );
    }
    assert!(!lab.root.join("node-3/consensus.key").exists());
    for node in 0..4 {
        lab.stop(node);
    }
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
fn startup_corruption_matrix(lab: &Lab, old: &BTreeMap<PathBuf, Vec<u8>>, branch: &StateBranch) {
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
    let signer_journal = journal(lab, branch, 3);
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
    branch: &StateBranch,
    proposal: Option<Vec<u8>>,
    expected_height: u64,
) -> Vec<u8> {
    use naome_network::{
        Keypair, NetworkEvent, PeerSessionEvent, StateNetwork, StateRequestBody as Request,
        StateResponseBody as Response, state_peer_id,
    };
    let g = genesis(lab);
    let mut seed = Zeroizing::new(fixture_period_transport_key(lab, branch.state(), 0).to_bytes());
    let identity = Keypair::ed25519_from_bytes(&mut *seed).unwrap();
    let peer = state_peer_id(fixture_public_key(lab, branch.state(), 3, true)).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut network = StateNetwork::new_for_parent(identity, branch.state()).unwrap();
            network
                .listen_on(network.state_listen_address().unwrap().clone())
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
                                    .request_state(
                                        peer,
                                        Request::Proposal(
                                            proposal.as_ref().unwrap().clone().into(),
                                        ),
                                    )
                                    .unwrap(),
                            );
                        }
                        NetworkEvent::InboundState(inbound) => {
                            assert_eq!(inbound.peer_id(), peer);
                            if let Request::Vote(bytes) = inbound.request().body() {
                                let vote = naome_consensus::state::StateVote::decode(
                                    bytes,
                                    &g,
                                    branch.authority(),
                                )
                                .unwrap();
                                assert_eq!(
                                    vote.signer(),
                                    ConsensusKey::from_bytes(fixture_public_key(
                                        lab,
                                        branch.state(),
                                        3,
                                        false
                                    ))
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
                            network.respond_state(inbound, response).unwrap();
                        }
                        NetworkEvent::OutboundState(event) => {
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
fn certify(lab: &Lab, branch: &StateBranch, bytes: &[u8]) -> naome_consensus::state::StateFinality {
    use naome_consensus::state::{StateLockState, StateQuorum};
    let maximum = branch.state().genesis().profile().limits().consensus_rounds;
    let proposal = branch.verify_proposal(bytes, maximum).unwrap();
    let keys = (0..3)
        .map(|i| key(lab, &format!("node-{i}/consensus.key"), 2))
        .collect::<Vec<_>>();
    let mut kernels = keys
        .iter()
        .map(|key| {
            StateLockState::new(
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
                &StateLockEvent::Prevote {
                    proposal: Some(bytes.to_vec()),
                },
                maximum,
            )
            .unwrap();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        let StatePublication::Vote(vote) = intent.complete(signature, branch, maximum).unwrap()
        else {
            panic!("vote")
        };
        votes.push(vote);
    }
    let prevotes =
        StateQuorum::from_votes(votes, branch.state().genesis(), branch.authority()).unwrap();
    let mut votes = Vec::new();
    for (kernel, key) in kernels.iter_mut().zip(&keys) {
        let intent = kernel
            .apply(
                branch,
                &StateLockEvent::Precommit {
                    proposal: Some(bytes.to_vec()),
                    quorum: prevotes.encode(),
                },
                maximum,
            )
            .unwrap();
        let signature = key.sign(&intent.signing_bytes().unwrap()).to_bytes();
        let StatePublication::Vote(vote) = intent.complete(signature, branch, maximum).unwrap()
        else {
            panic!("vote")
        };
        votes.push(vote);
    }
    let quorum =
        StateQuorum::from_votes(votes, branch.state().genesis(), branch.authority()).unwrap();
    let agreement = branch
        .verify_agreement(&proposal, &quorum, maximum)
        .unwrap();
    branch
        .verify_finality(
            &proposal,
            &quorum,
            &fixture_seal(lab, branch, &agreement),
            maximum,
        )
        .unwrap()
}

#[test]
fn canonical_authenticated_historical_conflict_stops_pending_publication_and_persists_halt() {
    use naome_storage::state::{StateHistory, StateObserver};
    let _guard = process_guard();
    let mut lab = Lab::new();
    lab.start(3);
    lab.wait(3, |_| true);
    lab.stop(3);
    let g = genesis(&lab);
    let maximum = g.profile().limits().consensus_rounds;
    let initial = StateBranch::from_genesis(LedgerState::new(g.clone())).unwrap();
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
    let mut history = StateHistory::open(
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
    let vote = capture_vote_without_receipt(&lab, selected.branch(), Some(pending), 2);
    let journal_path = journal(&lab, selected.branch(), 3);
    let prefix = fs::read(&journal_path).unwrap();
    let before = image(&lab, 3);
    deliver_conflict_until_process_stops(
        &mut lab,
        selected.branch(),
        conflicting.encode().unwrap(),
        &vote,
    );
    let observer = StateObserver::open(
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

fn deliver_conflict_until_process_stops(
    lab: &mut Lab,
    branch: &StateBranch,
    conflict: Vec<u8>,
    pending_vote: &[u8],
) {
    use naome_network::{
        Keypair, NetworkEvent, PeerSessionEvent, StateNetwork, StateRequestBody as Request,
        StateResponseBody as Response, state_peer_id,
    };
    let mut seed = Zeroizing::new(fixture_period_transport_key(lab, branch.state(), 0).to_bytes());
    let identity = Keypair::ed25519_from_bytes(&mut *seed).unwrap();
    let peer = state_peer_id(fixture_public_key(lab, branch.state(), 3, true)).unwrap();
    let child = lab.nodes[3].as_mut().unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut network=StateNetwork::new_for_parent(identity,branch.state()).unwrap();
        network.listen_on(network.state_listen_address().unwrap().clone()).unwrap();
        tokio::time::timeout(Duration::from_secs(20),async {
            let mut ticket=None;let mut sent=false;
            loop {tokio::select! {
                _=tokio::time::sleep(Duration::from_millis(10))=>if let Some(status)=child.try_wait().unwrap() {assert!(sent);assert!(!status.success());break;},
                event=network.next_event()=>match event {
                    NetworkEvent::PeerSession(PeerSessionEvent::Established{peer_id}) if peer_id==peer&&!sent=> {
                        ticket=Some(network.request_state(peer,Request::Finalized(conflict.clone().into())).unwrap());sent=true;
                    }
                    NetworkEvent::InboundState(inbound)=> {
                        assert_eq!(inbound.peer_id(),peer);
                        if let Request::Vote(bytes)=inbound.request().body() {assert_eq!(bytes.as_ref(),pending_vote);continue;}
                        let response=match inbound.request().body() {Request::Handshake=>Response::Ready,Request::History{..}=>Response::History(Vec::new()),Request::Proof{..}=>Response::Unavailable,_=>Response::Accepted};
                        network.respond_state(inbound,response).unwrap();
                    }
                    NetworkEvent::OutboundState(event)=>if let Some(active)=ticket.take() {let _ = active.complete(event).unwrap();},
                    _=>{}
                }
            }}
        }).await.expect("authenticated conflict must stop the live process");
    });
    let mut child = lab.nodes[3].take().unwrap();
    assert!(!child.wait().unwrap().success());
}
