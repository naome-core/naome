use naome_storage::state::{StateHistory, StateObserver, StateAppendOutcome};
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_consensus::{
    ConsensusKey,
    state::{
        StateBranch, StateFinality, StateIntent, StateLockEvent, StateLockState,
        StateProposal, StatePublication, StateQuorum, StateVote,
    },
};
use naome_ledger::{
    AccountId, CommitmentId, LedgerState,
    authentication::SignedOperation,
    library::ProofPackage,
    operations::{OperationBody, SignedOriginal},
    profile::{Genesis, Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
    question::CompiledQuestion,
    time::{SignedTimeReport, TimeCertificate},
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_ROUND: u64 = 32;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        loop {
            let path = std::env::temp_dir().join(format!(
                "naome-authoring-finalized-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => panic!("test directory: {e}"),
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
fn validator(i: u8) -> SigningKey {
    SigningKey::from_bytes(&[i + 101; 32])
}
fn key(i: u8) -> ConsensusKey {
    ConsensusKey::from_bytes(validator(i).verifying_key().to_bytes())
}
fn author(i: u8) -> AccountId {
    AccountId::for_key(account(i).verifying_key().as_bytes())
}
fn signing_key(key: ConsensusKey) -> SigningKey {
    (0..4)
        .map(validator)
        .find(|sk| sk.verifying_key().as_bytes() == key.as_bytes())
        .unwrap()
}
fn genesis() -> Genesis {
    let retirement_registrations: Vec<_> = (0..4)
            .map(|i| ValidatorRegistration {
                owner: author(i),
                consensus_key: validator(i).verifying_key().to_bytes(),
                transport_key: SigningKey::from_bytes(&[i + 201; 32])
                    .verifying_key()
                    .to_bytes(),
                endpoint: format!("127.0.0.1:{}", 43000 + u16::from(i)),
            })
            .collect();
    let retirement_order = [2, 0, 3, 1].map(|i| retirement_registrations[i].id()).to_vec();
        Genesis::new(
        Profile::short_test(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        100,
        [9; 32],
        (0..6)
            .map(|i| account(i).verifying_key().to_bytes())
            .collect(),
    retirement_registrations,
    retirement_order,
    )
    .unwrap()
}
fn time(state: &LedgerState, now: u64) -> TimeCertificate {
    TimeCertificate::new(
        (0..3)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.head(),
                    state.height() + 1,
                    now,
                    &validator(i),
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap()
}
fn signed(state: &LedgerState, i: u8, body: OperationBody) -> SignedOperation {
    body.sign(
        state.genesis(),
        state.next_nonce(author(i)).unwrap(),
        &account(i),
    )
    .unwrap()
}
fn submission(state: &LedgerState, purpose: &str) -> SignedOperation {
    signed(
        state,
        4,
        OperationBody::Submit {
            purpose: purpose.into(),
            question: CompiledQuestion::compile(
                "foundation = \"naome:zfc\"\nstatement = forall(y,forall(x,equal(x,x)))",
                state.genesis().profile(),
            )
            .unwrap(),
        },
    )
}
fn proposal(branch: &StateBranch, record: Vec<u8>) -> StateProposal {
    let proposer = branch.proposer(0, MAX_ROUND).unwrap();
    let mut kernel = StateLockState::new(branch, proposer).unwrap();
    let intent = kernel
        .apply(
            branch,
            &StateLockEvent::Author {
                record: Some(record),
            },
            MAX_ROUND,
        )
        .unwrap();
    let signature = signing_key(proposer)
        .sign(&intent.signing_bytes().unwrap())
        .to_bytes();
    match intent.complete(signature, branch, MAX_ROUND).unwrap() {
        StatePublication::Proposal(p) => p,
        _ => panic!("proposal intent"),
    }
}
fn finish_vote(intent: StateIntent, branch: &StateBranch, i: u8) -> StateVote {
    let signature = validator(i)
        .sign(&intent.signing_bytes().unwrap())
        .to_bytes();
    match intent.complete(signature, branch, MAX_ROUND).unwrap() {
        StatePublication::Vote(v) => v,
        _ => panic!("vote intent"),
    }
}
fn certify(branch: &StateBranch, record: Vec<u8>) -> (StateFinality, StateQuorum) {
    certify_with_signers(branch, record, 0)
}
fn certify_with_signers(
    branch: &StateBranch,
    record: Vec<u8>,
    first: u8,
) -> (StateFinality, StateQuorum) {
    let proposal = proposal(branch, record);
    let encoded = proposal.encode().unwrap();
    let mut kernels: Vec<_> = (0..3)
        .map(|i| StateLockState::new(branch, key(i + first)).unwrap())
        .collect();
    let votes = (0..3)
        .map(|i| {
            let intent = kernels[i]
                .apply(
                    branch,
                    &StateLockEvent::Prevote {
                        proposal: Some(encoded.clone()),
                    },
                    MAX_ROUND,
                )
                .unwrap();
            finish_vote(intent, branch, i as u8 + first)
        })
        .collect();
    let prevotes = StateQuorum::from_votes(votes, branch.state().genesis()).unwrap();
    let votes = (0..3)
        .map(|i| {
            let intent = kernels[i]
                .apply(
                    branch,
                    &StateLockEvent::Precommit {
                        proposal: Some(encoded.clone()),
                        quorum: prevotes.encode(),
                    },
                    MAX_ROUND,
                )
                .unwrap();
            finish_vote(intent, branch, i as u8 + first)
        })
        .collect();
    let precommits = StateQuorum::from_votes(votes, branch.state().genesis()).unwrap();
    (
        branch
            .verify_finality(&proposal, &precommits, MAX_ROUND)
            .unwrap(),
        prevotes,
    )
}
fn record(branch: &StateBranch, now: u64, operations: Vec<SignedOperation>) -> Vec<u8> {
    branch
        .state()
        .prepare_record(time(branch.state(), now), operations)
        .unwrap()
        .record()
        .encode()
        .unwrap()
}
fn first_finality(branch: &StateBranch, purpose: &str) -> StateFinality {
    certify(
        branch,
        record(branch, 100, vec![submission(branch.state(), purpose)]),
    )
    .0
}
fn append(history: &mut StateHistory, now: u64, ops: Vec<SignedOperation>) -> Vec<u8> {
    let encoded = record(history.head().unwrap(), now, ops);
    let (finality, _) = certify(history.head().unwrap(), encoded);
    let expected = finality.branch().commitment();
    let bytes = finality.encode().unwrap();
    assert_eq!(
        history.append_finality(&bytes).unwrap(),
        StateAppendOutcome::Finalized
    );
    assert_eq!(history.head().unwrap().commitment(), expected);
    bytes
}
fn pending_two_proof_settlement() -> (Directory, Directory, Genesis, StateHistory, Vec<u8>) {
    use naome_checker::{ArtifactState, normalize_and_check_with_state};
    use naome_foundation::FreeVariable;
    use naome_proof::{ProofCertificate, ProofStep};
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let op = submission(
        history.head().unwrap().state(),
        "publish a root and its used helper",
    );
    append(&mut history, 100, vec![op]);
    append(&mut history, 100, vec![]);
    let active = history.head().unwrap().state().active().unwrap();
    let ops = (0..3)
        .map(|i| {
            signed(
                history.head().unwrap().state(),
                i,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    append(&mut history, 100, ops);
    append(&mut history, active.deadline.unwrap(), vec![]);
    let now = history.head().unwrap().state().time();
    append(&mut history, now, vec![]);
    let round = history
        .head()
        .unwrap()
        .state()
        .active()
        .unwrap()
        .solution_round
        .unwrap();
    let x = FreeVariable::new(0);
    let mut mathematical = ArtifactState::new();
    let helper = normalize_and_check_with_state(
        ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap(),
        &mathematical,
    )
    .unwrap();
    let h = (
        helper.proof_id(),
        helper.normal_form().canonical_bytes().to_vec(),
    );
    mathematical.register_proof(helper).unwrap();
    let root = normalize_and_check_with_state(
        ProofCertificate::new(vec![
            ProofStep::ProofReference { proof_id: h.0 },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap(),
        &mathematical,
    )
    .unwrap();
    let a = (
        root.proof_id(),
        root.normal_form().canonical_bytes().to_vec(),
    );
    let package = ProofPackage::new(author(4), a.0, vec![a, h], g.profile()).unwrap();
    let original = SignedOriginal::sign(&g, round, package, &account(4)).unwrap();
    let secret = [77; 32];
    let commitment =
        CommitmentId::for_original(&g, round, author(4), original.original_hash(), &secret);
    let op = signed(
        history.head().unwrap().state(),
        4,
        OperationBody::Commit { round, commitment },
    );
    let now = history.head().unwrap().state().time();
    append(&mut history, now, vec![op]);
    let deadline = history
        .head()
        .unwrap()
        .state()
        .active()
        .unwrap()
        .deadline
        .unwrap();
    append(&mut history, deadline, vec![]);
    append(&mut history, deadline, vec![]);
    let op = signed(
        history.head().unwrap().state(),
        4,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    append(&mut history, deadline, vec![op]);
    assert_eq!(history.head().unwrap().state().library().len(), 0);
    let deadline = history
        .head()
        .unwrap()
        .state()
        .active()
        .unwrap()
        .deadline
        .unwrap();
    append(&mut history, deadline, vec![]);
    assert_eq!(history.head().unwrap().state().library().len(), 0);
    let settlement = certify(
        history.head().unwrap(),
        record(history.head().unwrap(), deadline, vec![]),
    )
    .0
    .encode()
    .unwrap();
    (dir, anchors, g, history, settlement)
}
