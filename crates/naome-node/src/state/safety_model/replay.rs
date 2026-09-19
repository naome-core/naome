//! Explorer witnesses replayed through the real anchored canonical node.
//! Honest proposal/vote signatures only come from these same-execution journals.
use super::model::{self, Action, Local, Model, Rules, State, proof, proof_round, proposal_value};
use crate::state::*;
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_consensus::state::{ResearchIntent, ResearchLockState, ResearchValue};
use naome_ledger::{
    AccountId,
    operations::OperationBody,
    profile::{
        Genesis, Limits, Profile, RESEARCH_CHECKER_PROFILE, TimingKind, ValidatorRegistration,
    },
    question::CompiledQuestion,
    time::TimeCertificate,
};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const MAXIMUM_ROUND: u64 = 3;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "naome-state-model-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("model directory: {e}"),
            }
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Participant {
    node: Option<ResearchNode>,
    history: Directory,
    anchors: Directory,
}
fn consensus_key(key: &SigningKey) -> ConsensusKey {
    ConsensusKey::from_bytes(key.verifying_key().to_bytes())
}
fn genesis(keys: &[SigningKey; 4]) -> Genesis {
    let limits = Limits {
        consensus_rounds: MAXIMUM_ROUND,
        run_records: 65,
        record_bytes: 128 * 1024,
        package_bytes: 64 * 1024,
        transport_frame_bytes: 192 * 1024,
        ..Limits::default()
    };
    let accounts: Vec<_> = (0..6)
        .map(|i| {
            SigningKey::from_bytes(&[i + 1; 32])
                .verifying_key()
                .to_bytes()
        })
        .collect();
    Genesis::new(
        Profile::with_limits(TimingKind::ShortTest, limits).unwrap(),
        "naome:zfc".into(),
        RESEARCH_CHECKER_PROFILE.into(),
        1,
        100,
        [43; 32],
        accounts.clone(),
        (0..4)
            .map(|i| ValidatorRegistration {
                owner: AccountId::for_key(&accounts[i]),
                consensus_key: keys[i].verifying_key().to_bytes(),
                transport_key: SigningKey::from_bytes(&[i as u8 + 201; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 45000 + i),
            })
            .collect(),
    )
    .unwrap()
}
fn participant(genesis: &Genesis, key: &SigningKey) -> Participant {
    let history = Directory::new();
    let anchors = Directory::new();
    let selected =
        ResearchHistory::create(&history.0, &anchors.0, genesis.clone(), MAXIMUM_ROUND).unwrap();
    let signer = ResearchSigner::create(
        &history.0,
        &anchors.0,
        genesis.clone(),
        key.clone(),
        MAXIMUM_ROUND,
    )
    .unwrap();
    Participant {
        node: Some(ResearchNode::new(selected, Some(signer)).unwrap()),
        history,
        anchors,
    }
}
fn records(branch: &ResearchBranch, keys: &[SigningKey; 4]) -> [Vec<u8>; 2] {
    let state = branch.state();
    let genesis = state.genesis();
    let time = TimeCertificate::new(
        keys.iter()
            .take(3)
            .map(|key| SignedTimeReport::sign(genesis, state.head(), 1, 100, key).unwrap())
            .collect(),
        genesis,
        state.head(),
        1,
        100,
    )
    .unwrap();
    ["Canonical model value A", "Canonical model value B"].map(|purpose| {
        let operation = OperationBody::Submit {
            purpose: purpose.into(),
            question: CompiledQuestion::compile(
                "foundation = \"naome:zfc\" statement = forall(x,equal(x,x))",
                genesis.profile(),
            )
            .unwrap(),
        }
        .sign(genesis, 1, &SigningKey::from_bytes(&[5; 32]))
        .unwrap();
        state
            .prepare_record(time.clone(), vec![operation])
            .unwrap()
            .record()
            .encode()
            .unwrap()
    })
}
struct Replay {
    model: Model,
    state: State,
    branch: ResearchBranch,
    keys: [SigningKey; 4],
    records: [Vec<u8>; 2],
    values: [ResearchValue; 2],
    proposals: BTreeMap<u8, Vec<u8>>,
    votes: BTreeMap<(u8, u8, u8), ResearchVote>,
}
impl Replay {
    fn target(&self, value: u8) -> ConsensusVoteTarget {
        match value {
            1 | 2 => {
                ConsensusVoteTarget::Proposal(self.values[usize::from(value - 1)].signing_root())
            }
            3 => ConsensusVoteTarget::Nil,
            _ => panic!("absent is not NIL"),
        }
    }
    fn role(role: u8) -> ConsensusVoteRole {
        match role {
            0 => ConsensusVoteRole::Prevote,
            1 => ConsensusVoteRole::Precommit,
            _ => unreachable!(),
        }
    }
    fn faulty_vote(&self, round: u8, role: u8, value: u8) -> ResearchVote {
        let key = &self.keys[usize::from(self.model.faulty)];
        let genesis = self.branch.state().genesis();
        let mut body = b"NSCV1".to_vec();
        body.extend_from_slice(genesis.id().as_bytes());
        body.extend_from_slice(genesis.profile().id().as_bytes());
        body.extend_from_slice(&1u64.to_be_bytes());
        body.extend_from_slice(&u64::from(round).to_be_bytes());
        body.push(role + 1);
        match self.target(value) {
            ConsensusVoteTarget::Nil => {
                body.push(0);
                body.extend_from_slice(&[0; 32]);
            }
            ConsensusVoteTarget::Proposal(root) => {
                body.push(1);
                body.extend_from_slice(root.as_bytes());
            }
        }
        body.extend_from_slice(key.verifying_key().as_bytes());
        let mut transcript = if role == 0 {
            b"naome:state:prevote:v1\0".to_vec()
        } else {
            b"naome:state:precommit:v1\0".to_vec()
        };
        transcript.extend_from_slice(&body);
        body.extend_from_slice(&key.sign(&transcript).to_bytes());
        ResearchVote::decode(&body, genesis).unwrap()
    }
    fn quorum(&self, round: u8, role: u8, target: u8) -> ResearchQuorum {
        assert!(self.model.quorum(self.state, round, role, target));
        let votes = (0..4)
            .filter_map(|actor| {
                if actor == self.model.faulty {
                    Some(self.faulty_vote(round, role, target))
                } else if self.state.vote(actor, round, role) == target {
                    Some(self.votes[&(actor, round, role)].clone())
                } else {
                    None
                }
            })
            .collect();
        ResearchQuorum::from_votes(votes, self.branch.state().genesis()).unwrap()
    }
    fn progress(&self, round: u8, role: u8, minimum: usize) -> Vec<u8> {
        let mut votes = vec![self.faulty_vote(round, role, 3)];
        votes.extend(
            (0..4)
                .filter(|&actor| {
                    actor != self.model.faulty && self.state.vote(actor, round, role) != 0
                })
                .map(|actor| self.votes[&(actor, round, role)].clone()),
        );
        assert!(votes.len() >= minimum);
        if minimum == 2 {
            votes.truncate(2);
        }
        ResearchVoteSet::new(votes, self.branch.state().genesis())
            .unwrap()
            .encode()
    }
    fn proposal(&self, round: u8, encoded: u8) -> Vec<u8> {
        assert!(self.model.proposals(self.state, round).contains(&encoded));
        let index = usize::from(proposal_value(encoded) - 1);
        let value = self.values[index];
        let mut bytes = if self.model.proposers[usize::from(round)] == self.model.faulty {
            let key = &self.keys[usize::from(self.model.faulty)];
            let mut transcript = b"naome:state:proposal:v1\0".to_vec();
            transcript.extend(value.encode());
            transcript.extend_from_slice(&u64::from(round).to_be_bytes());
            transcript.extend_from_slice(key.verifying_key().as_bytes());
            let mut out = b"NSCP1".to_vec();
            out.extend(value.encode());
            out.extend_from_slice(&u64::from(round).to_be_bytes());
            out.extend_from_slice(key.verifying_key().as_bytes());
            out.extend_from_slice(&key.sign(&transcript).to_bytes());
            out
        } else {
            // The optional valid QC is outside the producer's signature. Only
            // reuse the actual signed honest prefix from this execution.
            self.proposals[&round][..5 + ResearchValue::BYTE_LENGTH + 8 + 32 + 64].to_vec()
        };
        let qc = if encoded <= 2 {
            Vec::new()
        } else {
            self.quorum(proof_round(encoded - 2), 0, proposal_value(encoded))
                .encode()
        };
        bytes.extend_from_slice(&(qc.len() as u32).to_be_bytes());
        bytes.extend(qc);
        bytes.extend_from_slice(&(self.records[index].len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.records[index]);
        assert_eq!(
            self.branch
                .verify_proposal(&bytes, MAXIMUM_ROUND)
                .unwrap()
                .value(),
            value
        );
        bytes
    }
    fn observe(&self, node: &ResearchNode) -> Local {
        let signer = node.signer.as_ref().unwrap();
        assert_eq!(signer.height().unwrap(), 1);
        let phase = match signer.phase().unwrap() {
            ResearchPhase::Proposal => 0,
            ResearchPhase::Prevote => 1,
            ResearchPhase::Precommit => 2,
        };
        let snapshot = signer.snapshot().unwrap();
        assert_eq!(&snapshot[..5], b"NSCS1");
        let mut offset = 5 + 32 + 32 + 8 + 8 + 1;
        let mut field = || {
            let present = snapshot[offset];
            offset += 1;
            if present == 0 {
                return 0;
            }
            assert_eq!(present, 1);
            let value =
                ResearchValue::decode(&snapshot[offset..offset + ResearchValue::BYTE_LENGTH])
                    .unwrap();
            offset += ResearchValue::BYTE_LENGTH;
            let round = u64::from_be_bytes(snapshot[offset..offset + 8].try_into().unwrap());
            offset += 8;
            let index = self.values.iter().position(|v| *v == value).unwrap();
            proof(round as u8, index as u8 + 1)
        };
        Local {
            cursor: signer.round().unwrap() as u8 * 3 + phase,
            locked: field(),
            valid: field(),
        }
    }
    fn step(&mut self, node: &mut ResearchNode, action: Action) {
        let actor = action.actor();
        let old = self.state.nodes[usize::from(actor)];
        assert_eq!(self.observe(node), old, "before {action:?}");
        assert!(self.model.actions(self.state).contains(&action));
        let next = self.model.apply(self.state, action).unwrap();
        let round = old.cursor / 3;
        let event = match action {
            Action::Author { proposal, .. } => ResearchLockEvent::Author {
                record: if old.valid == 0 {
                    Some(self.records[usize::from(proposal_value(proposal) - 1)].clone())
                } else {
                    assert_eq!(proposal, old.valid + 2);
                    None
                },
            },
            Action::Prevote { proposal: 0, .. } => ResearchLockEvent::ProposalTimeout,
            Action::Prevote { proposal, .. } => ResearchLockEvent::Prevote {
                proposal: Some(self.proposal(round, proposal)),
            },
            Action::Precommit { target: 0, .. } => ResearchLockEvent::PrevoteTimeout {
                votes: self.progress(round, 0, 3),
            },
            Action::Precommit { target, .. } => ResearchLockEvent::Precommit {
                proposal: if target == 3 {
                    None
                } else {
                    Some(
                        self.proposal(
                            round,
                            self.model
                                .proposals(self.state, round)
                                .into_iter()
                                .find(|&p| proposal_value(p) == target)
                                .unwrap(),
                        ),
                    )
                },
                quorum: self.quorum(round, 0, target).encode(),
            },
            Action::Advance {
                nil_quorum: true, ..
            } => ResearchLockEvent::NilPrecommit {
                quorum: self.quorum(round, 1, 3).encode(),
            },
            Action::Advance {
                nil_quorum: false, ..
            } => ResearchLockEvent::PrecommitTimeout {
                votes: self.progress(round, 1, 3),
            },
            Action::Higher { round, role, .. } => ResearchLockEvent::HigherRound {
                votes: self.progress(round, role, 2),
            },
        };
        node.apply(event).unwrap();
        match action {
            Action::Author { proposal, .. } => {
                let ResearchPublication::Proposal(p) = node
                    .signer
                    .as_ref()
                    .unwrap()
                    .last_publication()
                    .unwrap()
                    .unwrap()
                else {
                    panic!("missing durable proposal")
                };
                assert_eq!(
                    p.value(),
                    self.values[usize::from(proposal_value(proposal) - 1)]
                );
                assert!(self.proposals.insert(round, p.encode().unwrap()).is_none());
            }
            Action::Prevote { .. } | Action::Precommit { .. } => {
                let role = if matches!(action, Action::Prevote { .. }) {
                    0
                } else {
                    1
                };
                let ResearchPublication::Vote(v) = node
                    .signer
                    .as_ref()
                    .unwrap()
                    .last_publication()
                    .unwrap()
                    .unwrap()
                else {
                    panic!("missing durable vote")
                };
                assert_eq!(v.signer(), consensus_key(&self.keys[usize::from(actor)]));
                assert_eq!(v.height(), 1);
                assert_eq!(v.round(), u64::from(round));
                assert_eq!(v.role(), Self::role(role));
                assert_eq!(v.target(), self.target(next.vote(actor, round, role)));
                assert!(self.votes.insert((actor, round, role), v.clone()).is_none());
            }
            _ => {}
        }
        self.state = next;
        assert_eq!(
            self.observe(node),
            next.nodes[usize::from(actor)],
            "after {action:?}"
        );
    }
    fn reopen(&self, actor: u8, participant: &mut Participant) {
        let node = participant.node.take().unwrap();
        let snapshot = node.signer.as_ref().unwrap().snapshot().unwrap();
        let publications: Vec<_> = node
            .publications()
            .unwrap()
            .iter()
            .map(|p| p.encode().unwrap())
            .collect();
        drop(node);
        let history = ResearchHistory::open(
            &participant.history.0,
            &participant.anchors.0,
            self.branch.state().genesis().clone(),
            MAXIMUM_ROUND,
        )
        .unwrap();
        let signer = ResearchSigner::open(
            &participant.history.0,
            &participant.anchors.0,
            self.branch.state().genesis().clone(),
            self.keys[usize::from(actor)].clone(),
            MAXIMUM_ROUND,
        )
        .unwrap();
        let node = ResearchNode::new(history, Some(signer)).unwrap();
        assert_eq!(node.signer.as_ref().unwrap().snapshot().unwrap(), snapshot);
        assert_eq!(
            node.publications()
                .unwrap()
                .iter()
                .map(|p| p.encode().unwrap())
                .collect::<Vec<_>>(),
            publications
        );
        assert_eq!(self.observe(&node), self.state.nodes[usize::from(actor)]);
        participant.node = Some(node);
    }
    fn finalize(&self, participants: &mut [Option<Participant>; 4]) {
        let mut observed = Vec::new();
        for round in 0..model::ROUNDS {
            for value in 1..=2 {
                if !self.model.quorum(self.state, round, 1, value) {
                    continue;
                }
                let Some(proposal) = self
                    .model
                    .proposals(self.state, round)
                    .into_iter()
                    .find(|&p| proposal_value(p) == value)
                else {
                    continue;
                };
                let proposal = self
                    .branch
                    .verify_proposal(&self.proposal(round, proposal), MAXIMUM_ROUND)
                    .unwrap();
                let qc = self.quorum(round, 1, value);
                let finalized = self
                    .branch
                    .verify_finality(&proposal, &qc, MAXIMUM_ROUND)
                    .unwrap();
                for participant in participants.iter_mut().flatten() {
                    let node = participant.node.as_mut().unwrap();
                    let outcome = node.accept_finality(&finalized.encode().unwrap()).unwrap();
                    assert!(matches!(
                        outcome,
                        ResearchAppendOutcome::Finalized | ResearchAppendOutcome::AlreadyFinalized
                    ));
                    assert_eq!(
                        node.state().unwrap().head(),
                        self.values[usize::from(value - 1)].record_id()
                    );
                    assert_eq!(
                        node.position().unwrap(),
                        Some((2, 0, ResearchPhase::Proposal))
                    );
                    observed.push(node.branch().unwrap().commitment());
                }
            }
        }
        assert_eq!(
            !observed.is_empty(),
            self.model.certified_values(self.state) != 0
        );
        assert!(
            observed.iter().all(|v| *v == observed[0]),
            "honest selected full-state commitments diverged"
        );
    }
}

#[test]
fn explorer_witnesses_match_anchored_canonical_nodes_and_cold_reopen() {
    let mut keys = std::array::from_fn(|i| SigningKey::from_bytes(&[i as u8 + 101; 32]));
    keys.sort_by_key(consensus_key);
    let genesis = genesis(&keys);
    for (faulty, report) in model::protocol_explorations().iter().enumerate() {
        assert!(report.counterexample.is_none());
        for (&label, trace) in &report.witnesses {
            let (mut replay, mut participants) = fixture(faulty, &keys, &genesis);
            for (index, &action) in trace.iter().enumerate() {
                let actor = usize::from(action.actor());
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    replay.step(
                        participants[actor].as_mut().unwrap().node.as_mut().unwrap(),
                        action,
                    );
                    if matches!(
                        action,
                        Action::Precommit { .. } | Action::Advance { .. } | Action::Higher { .. }
                    ) {
                        replay.reopen(actor as u8, participants[actor].as_mut().unwrap());
                    }
                }));
                assert!(
                    result.is_ok(),
                    "canonical differential mismatch faulty={faulty} witness={label} prefix={:?}",
                    &trace[..=index]
                );
            }
            replay.finalize(&mut participants);
        }
    }
}

fn fixture(
    faulty: usize,
    keys: &[SigningKey; 4],
    genesis: &Genesis,
) -> (Replay, [Option<Participant>; 4]) {
    let participants = std::array::from_fn(|actor| {
        if actor == faulty {
            None
        } else {
            Some(participant(genesis, &keys[actor]))
        }
    });
    let branch = ResearchBranch::from_genesis(ResearchState::new(genesis.clone())).unwrap();
    let records = records(&branch, keys);
    let values = records.each_ref().map(|record| {
        let mut state = ResearchLockState::new(&branch, consensus_key(&keys[0])).unwrap();
        let ResearchIntent::Proposal(intent) = state
            .apply(
                &branch,
                &ResearchLockEvent::Author {
                    record: Some(record.clone()),
                },
                MAXIMUM_ROUND,
            )
            .unwrap()
        else {
            unreachable!()
        };
        intent.value()
    });
    let model = Model::unit(faulty as u8, Rules::Protocol);
    for (round, actor) in model.proposers.iter().enumerate() {
        assert_eq!(
            branch.proposer(round as u64, MAXIMUM_ROUND).unwrap(),
            consensus_key(&keys[usize::from(*actor)])
        );
    }
    let replay = Replay {
        model,
        state: State::default(),
        branch,
        keys: keys.clone(),
        records,
        values,
        proposals: BTreeMap::new(),
        votes: BTreeMap::new(),
    };
    (replay, participants)
}

#[test]
fn canonical_signed_quorum_subsets_match_four_unit_validator_boundary() {
    let mut keys = std::array::from_fn(|i| SigningKey::from_bytes(&[i as u8 + 101; 32]));
    keys.sort_by_key(consensus_key);
    let genesis = genesis(&keys);
    let mut checked = 0;
    for faulty in 0..4 {
        let (mut replay, mut participants) = fixture(faulty, &keys, &genesis);
        if faulty != 0 {
            replay.step(
                participants[0].as_mut().unwrap().node.as_mut().unwrap(),
                Action::Author {
                    actor: 0,
                    proposal: 1,
                },
            );
        }
        for role in 0..2 {
            for (actor, participant) in participants.iter_mut().enumerate() {
                if actor == faulty {
                    continue;
                }
                let action = if role == 0 {
                    Action::Prevote {
                        actor: actor as u8,
                        proposal: 1,
                    }
                } else {
                    Action::Precommit {
                        actor: actor as u8,
                        target: 1,
                    }
                };
                replay.step(participant.as_mut().unwrap().node.as_mut().unwrap(), action);
            }
            let votes: [ResearchVote; 4] = std::array::from_fn(|actor| {
                if actor == faulty {
                    replay.faulty_vote(0, role, 1)
                } else {
                    replay.votes[&(actor as u8, 0, role)].clone()
                }
            });
            for mask in 0_u16..16 {
                let selected = votes
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, vote)| vote.clone())
                    .collect();
                let quorum = ResearchQuorum::from_votes(selected, &genesis);
                assert_eq!(
                    quorum.is_ok(),
                    mask.count_ones() >= 3,
                    "faulty={faulty} role={role} mask={mask:04b}"
                );
                if let Ok(quorum) = quorum {
                    assert_eq!(quorum.target(), replay.target(1));
                    assert_eq!(quorum.role(), Replay::role(role));
                    let encoded = quorum.encode();
                    let decoded = ResearchQuorum::decode(&encoded, &genesis).unwrap();
                    assert_eq!(decoded.encode(), encoded);
                }
                checked += 1;
            }
        }
        replay.finalize(&mut participants);
    }
    assert_eq!(checked, 128);
}
