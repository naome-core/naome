use super::*;
use ed25519_dalek::{Signer, SigningKey};
use naome_chain::StateRecordExecution;
use naome_consensus::{
    ConsensusKey,
    state::{
        SealRole, SealSignature, StateAgreement, StateBranch, StateFinality, StateIntent,
        StateLockEvent, StateLockState, StateProposal, StatePublication, StateQuorum, StateSeal,
        StateVote,
    },
};
use naome_ledger::{
    AccountId, CommitmentId, LedgerState,
    authentication::SignedOperation,
    authority::{HandoffPlan, NextPeriodKeys},
    library::ProofPackage,
    operations::{JoinIntent, OperationBody, SignedOriginal},
    profile::{Genesis, Profile, STATE_CHECKER_PROFILE, ValidatorRegistration},
    question::CompiledQuestion,
    time::{SignedTimeReport, TimeCertificate},
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
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
                "naome-state-storage-{}-{}",
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
fn period_key(i: u8, height: u64) -> SigningKey {
    if height == 1 {
        return validator(i);
    }
    let mut seed = [42; 32];
    seed[0] = i;
    seed[1..9].copy_from_slice(&height.to_be_bytes());
    SigningKey::from_bytes(&seed)
}
fn period_transport(i: u8, height: u64) -> SigningKey {
    let mut seed = [43; 32];
    seed[0] = i;
    seed[1..9].copy_from_slice(&height.to_be_bytes());
    SigningKey::from_bytes(&seed)
}
fn author(i: u8) -> AccountId {
    AccountId::for_key(account(i).verifying_key().as_bytes())
}
fn signing_key(key: ConsensusKey) -> SigningKey {
    (1..65)
        .flat_map(|height| (0..4).map(move |i| period_key(i, height)))
        .find(|sk| sk.verifying_key().as_bytes() == key.as_bytes())
        .unwrap()
}
fn plan(branch: &StateBranch) -> HandoffPlan {
    let state = branch.state();
    let mut offers: Vec<_> = state
        .authority()
        .units()
        .iter()
        .map(|unit| {
            let i = (0..4).find(|i| author(*i) == unit.owner()).unwrap();
            let height = state.authority().effective_height() + 1;
            NextPeriodKeys::sign(
                state.authority(),
                state.head(),
                state.commitment(),
                unit.id(),
                &account(i),
                &period_key(i, height),
                &period_transport(i, height),
                format!("127.0.0.1:{}", 43000 + u16::from(i)),
            )
            .unwrap()
        })
        .collect();
    offers.sort_by_key(NextPeriodKeys::unit);
    HandoffPlan::new(offers, None).unwrap()
}
fn seal_signature(agreement: &StateAgreement, role: SealRole, key: ConsensusKey) -> SealSignature {
    let context = agreement.seal_context();
    let signature = signing_key(key)
        .sign(&SealSignature::signing_bytes(role, context, key))
        .to_bytes();
    SealSignature::complete(
        role,
        context,
        key,
        signature,
        agreement.outgoing(),
        agreement.incoming(),
    )
    .unwrap()
}
fn seal(agreement: &StateAgreement) -> StateSeal {
    let signatures = |role, authority: &naome_ledger::authority::AuthoritySnapshot| {
        authority
            .units()
            .iter()
            .filter_map(|unit| unit.keys())
            .take(3)
            .map(|keys| {
                seal_signature(agreement, role, ConsensusKey::from_bytes(*keys.consensus()))
            })
            .collect()
    };
    StateSeal::new(
        signatures(SealRole::Ready, agreement.incoming()),
        signatures(SealRole::Terminal, agreement.outgoing()),
        agreement.seal_context(),
        agreement.outgoing(),
        agreement.incoming(),
    )
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
    let retirement_order = [2, 0, 3, 1]
        .map(|i| retirement_registrations[i].id())
        .to_vec();
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
        (0..4)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.authority(),
                    state.head(),
                    state.height() + 1,
                    now,
                    &period_key(i, state.authority().effective_height()),
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.authority(),
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
    submission_by(state, 4, purpose)
}
fn submission_by(state: &LedgerState, researcher: u8, purpose: &str) -> SignedOperation {
    signed(
        state,
        researcher,
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
    let proposer = branch.proposer(0, MAX_ROUND).unwrap().unwrap();
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
    let signature = period_key(i, branch.authority().effective_height())
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
        .map(|i| {
            let key = ConsensusKey::from_bytes(
                period_key(i + first, branch.authority().effective_height())
                    .verifying_key()
                    .to_bytes(),
            );
            StateLockState::new(branch, key).unwrap()
        })
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
    let prevotes =
        StateQuorum::from_votes(votes, branch.state().genesis(), branch.authority()).unwrap();
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
    let precommits =
        StateQuorum::from_votes(votes, branch.state().genesis(), branch.authority()).unwrap();
    let agreement = branch
        .verify_agreement(&proposal, &precommits, MAX_ROUND)
        .unwrap();
    (
        branch
            .verify_finality(&proposal, &precommits, &seal(&agreement), MAX_ROUND)
            .unwrap(),
        prevotes,
    )
}
fn record(branch: &StateBranch, now: u64, operations: Vec<SignedOperation>) -> Vec<u8> {
    branch
        .state()
        .prepare_record(time(branch.state(), now), operations, plan(branch))
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

#[cfg(unix)]
#[test]
fn handoff_journal_cold_reopen_preserves_exact_ready_and_private_terminal() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let branch = history.head().unwrap();
    let finality = first_finality(branch, "durable seal stages");
    let agreement = finality.agreement();
    let mut journal =
        StateHandoffJournal::create(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND).unwrap();
    journal.stage(agreement, &history).unwrap();
    let other = first_finality(branch, "different durable seal");
    assert!(journal.stage(other.agreement(), &history).is_err());
    drop(journal);
    let mut journal =
        StateHandoffJournal::open(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND, &history).unwrap();
    assert_eq!(
        journal.agreement().unwrap().encode().unwrap(),
        agreement.encode().unwrap()
    );

    let incoming = period_key(0, 2);
    let incoming_signer = ConsensusKey::from_bytes(incoming.verifying_key().to_bytes());
    let transcript = journal.prepare_ready(incoming_signer).unwrap();
    drop(journal);
    let mut journal =
        StateHandoffJournal::open(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND, &history).unwrap();
    assert!(journal.ready().is_none());
    assert_eq!(journal.prepare_ready(incoming_signer).unwrap(), transcript);
    assert!(
        journal
            .prepare_ready(ConsensusKey::from_bytes(
                period_key(1, 2).verifying_key().to_bytes()
            ))
            .is_err()
    );
    let ready = journal
        .complete_ready(incoming.sign(&transcript).to_bytes())
        .unwrap();
    drop(journal);
    let mut journal =
        StateHandoffJournal::open(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND, &history).unwrap();
    assert_eq!(journal.ready(), Some(&ready));
    assert_eq!(journal.sign_ready(&incoming).unwrap(), ready);

    let ready_quorum = seal(agreement).ready().to_vec();
    let outgoing_signer = key(0);
    let terminal_transcript = journal
        .prepare_terminal(outgoing_signer, &ready_quorum)
        .unwrap();
    drop(journal);
    let mut journal =
        StateHandoffJournal::open(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND, &history).unwrap();
    assert!(journal.terminal_prepared());
    assert_eq!(journal.ready_quorum(), Some(ready_quorum.as_slice()));
    assert_eq!(
        journal
            .prepare_terminal(outgoing_signer, &ready_quorum)
            .unwrap(),
        terminal_transcript
    );
    assert!(journal.terminal().is_none());
    let mut signer =
        StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND).unwrap();
    assert!(journal.release_terminal(&signer).is_err());
    signer
        .terminal_handoff(&mut journal, &ready_quorum)
        .unwrap();
    assert!(signer.stopped().unwrap());
    assert_eq!(
        signer.branch().unwrap().commitment(),
        history.head().unwrap().commitment()
    );
    assert!(signer.sign_time_report(101).is_err());
    assert!(
        signer
            .apply_and_sign(&StateLockEvent::ProposalTimeout)
            .is_err()
    );
    assert!(journal.terminal().is_none());
    drop((signer, journal));

    let signer = StateSigner::open(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND).unwrap();
    let mut journal =
        StateHandoffJournal::open(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND, &history).unwrap();
    assert!(signer.stopped().unwrap());
    assert_eq!(
        signer.branch().unwrap().commitment(),
        history.head().unwrap().commitment()
    );
    assert!(signer.sign_time_report(102).is_err());
    assert!(journal.terminal().is_none());
    let terminal = journal.release_terminal(&signer).unwrap();
    assert_eq!(terminal.role(), SealRole::Terminal);
    assert_eq!(journal.release_terminal(&signer).unwrap(), terminal);
    drop(journal);
    let journal = StateHandoffJournal::open(&dir.0, &anchors.0, g, 1, MAX_ROUND, &history).unwrap();
    assert_eq!(journal.terminal(), Some(&terminal));
}
#[cfg(unix)]
#[test]
fn selected_period_reuses_anchored_keys_and_missing_signer_cannot_regenerate() {
    let history_dir = Directory::new();
    let history_anchors = Directory::new();
    let g = genesis();
    let mut history =
        StateHistory::create(&history_dir.0, &history_anchors.0, g.clone(), MAX_ROUND).unwrap();
    let branch = history.head().unwrap();
    let mut custody = Vec::new();
    for i in 0..4 {
        let directory = Directory::new();
        let anchors = Directory::new();
        let unit = branch.authority().owner(author(i)).unwrap();
        let saved = StatePeriodCustody::stage_offer(
            &directory.0,
            &anchors.0,
            branch.state(),
            unit.id(),
            &account(i),
            format!("127.0.0.1:{}", 43000 + u16::from(i)),
        )
        .unwrap();
        custody.push((directory, anchors, saved));
    }
    let mut offers: Vec<_> = custody
        .iter()
        .map(|(_, _, saved)| saved.offer().unwrap().clone())
        .collect();
    offers.sort_by_key(NextPeriodKeys::unit);
    let plan = HandoffPlan::new(offers, None).unwrap();
    let record = branch
        .state()
        .prepare_record(time(branch.state(), 100), Vec::new(), plan)
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let proposal = proposal(branch, record);
    let encoded = proposal.encode().unwrap();
    let mut kernels: Vec<_> = (0..3)
        .map(|i| StateLockState::new(branch, key(i)).unwrap())
        .collect();
    let prevotes = StateQuorum::from_votes(
        (0..3)
            .map(|i| {
                finish_vote(
                    kernels[i]
                        .apply(
                            branch,
                            &StateLockEvent::Prevote {
                                proposal: Some(encoded.clone()),
                            },
                            MAX_ROUND,
                        )
                        .unwrap(),
                    branch,
                    i as u8,
                )
            })
            .collect(),
        &g,
        branch.authority(),
    )
    .unwrap();
    let precommits = StateQuorum::from_votes(
        (0..3)
            .map(|i| {
                finish_vote(
                    kernels[i]
                        .apply(
                            branch,
                            &StateLockEvent::Precommit {
                                proposal: Some(encoded.clone()),
                                quorum: prevotes.encode(),
                            },
                            MAX_ROUND,
                        )
                        .unwrap(),
                    branch,
                    i as u8,
                )
            })
            .collect(),
        &g,
        branch.authority(),
    )
    .unwrap();
    let agreement = branch
        .verify_agreement(&proposal, &precommits, MAX_ROUND)
        .unwrap();
    let signature = |role: SealRole, key: &SigningKey| {
        let signer = ConsensusKey::from_bytes(key.verifying_key().to_bytes());
        let context = agreement.seal_context();
        SealSignature::complete(
            role,
            context,
            signer,
            key.sign(&SealSignature::signing_bytes(role, context, signer))
                .to_bytes(),
            agreement.outgoing(),
            agreement.incoming(),
        )
        .unwrap()
    };
    let seal = StateSeal::new(
        custody[..3]
            .iter()
            .map(|(_, _, saved)| signature(SealRole::Ready, saved.consensus_key()))
            .collect(),
        (0..3)
            .map(|i| signature(SealRole::Terminal, &validator(i)))
            .collect(),
        agreement.seal_context(),
        agreement.outgoing(),
        agreement.incoming(),
    )
    .unwrap();
    let finality = branch
        .verify_finality(&proposal, &precommits, &seal, MAX_ROUND)
        .unwrap();
    assert_eq!(
        history
            .append_finality(&finality.encode().unwrap())
            .unwrap(),
        StateAppendOutcome::Finalized
    );
    let (dir, anchors, saved) = custody.remove(0);
    let original_offer = saved.offer().unwrap().clone();
    let original_consensus = saved.consensus_key().verifying_key().to_bytes();
    drop(saved);
    let mut selected =
        StatePeriodCustody::open_for_selected(&dir.0, &anchors.0, &history, &account(0))
            .unwrap()
            .unwrap();
    assert_eq!(selected.offer().unwrap(), &original_offer);
    assert_eq!(
        selected.consensus_key().verifying_key().to_bytes(),
        original_consensus
    );
    let signer = selected
        .open_or_create_selected_signer(&dir.0, &anchors.0, &history, MAX_ROUND)
        .unwrap();
    assert_eq!(signer.height().unwrap(), 2);
    let signer_file = dir.0.join(signer.journal_file_name());
    drop((signer, selected));
    let mut selected =
        StatePeriodCustody::open_for_selected(&dir.0, &anchors.0, &history, &account(0))
            .unwrap()
            .unwrap();
    let signer = selected
        .open_or_create_selected_signer(&dir.0, &anchors.0, &history, MAX_ROUND)
        .unwrap();
    assert_eq!(signer.signer().as_bytes(), &original_consensus);
    drop((signer, selected));
    fs::remove_file(signer_file).unwrap();
    let mut selected =
        StatePeriodCustody::open_for_selected(&dir.0, &anchors.0, &history, &account(0))
            .unwrap()
            .unwrap();
    assert!(
        selected
            .open_or_create_selected_signer(&dir.0, &anchors.0, &history, MAX_ROUND)
            .is_err()
    );
    drop(selected);
    fs::remove_file(dir.0.join("state-period-0.secret")).unwrap();
    assert!(
        StatePeriodCustody::stage_offer(
            &dir.0,
            &anchors.0,
            history.branch_at(0).unwrap().state(),
            original_offer.unit(),
            &account(0),
            "127.0.0.1:43000".into()
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn candidate_import_retries_exact_pair_and_fails_closed_on_mismatch_or_lost_secret() {
    let directory = Directory::new();
    let anchors = Directory::new();
    let genesis = genesis();
    let owner = account(5);
    let family = naome_ledger::ResolutionId::from_bytes([91; 32]);
    let consensus = validator(5);
    let transport = period_transport(5, 1);
    let import = || {
        StatePeriodCustody::import_candidate(
            &directory.0,
            &anchors.0,
            &genesis,
            family,
            &owner,
            &consensus,
            &transport,
        )
    };
    import().unwrap();
    import().unwrap();
    assert!(
        StatePeriodCustody::import_candidate(
            &directory.0,
            &anchors.0,
            &genesis,
            family,
            &owner,
            &validator(6),
            &transport,
        )
        .is_err()
    );
    assert!(
        StatePeriodCustody::stage_candidate(
            &directory.0,
            &anchors.0,
            &LedgerState::new(genesis.clone()),
            family,
            &owner,
        )
        .is_err()
    );
    fs::remove_file(directory.0.join(format!(
        "state-candidate-{}.secret",
        family.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>()
    )))
    .unwrap();
    assert!(import().is_err());
}
#[cfg(unix)]
#[test]
fn cold_restart_retires_closed_candidate_import_without_recreating_it() {
    let directory = Directory::new();
    let anchors = Directory::new();
    let genesis = genesis();
    let owner = account(5);
    let family = naome_ledger::ResolutionId::from_bytes([92; 32]);
    let consensus = validator(5);
    let transport = period_transport(5, 1);
    StatePeriodCustody::import_candidate(
        &directory.0,
        &anchors.0,
        &genesis,
        family,
        &owner,
        &consensus,
        &transport,
    )
    .unwrap();
    let family_hex: String = family
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let secret = directory
        .0
        .join(format!("state-candidate-{family_hex}.secret"));
    assert!(secret.exists());
    let selected = LedgerState::new(genesis.clone());
    for _ in 0..2 {
        StatePeriodCustody::retire_closed_candidate_import(
            &directory.0,
            &anchors.0,
            &selected,
            family,
            &owner,
        )
        .unwrap();
        assert!(!secret.exists());
    }
    assert!(
        StatePeriodCustody::import_candidate(
            &directory.0,
            &anchors.0,
            &genesis,
            family,
            &owner,
            &consensus,
            &transport,
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn live_unselected_candidate_rebinds_import_to_next_parent_then_expires_closed() {
    let (directory, anchors, genesis, mut history, settlement) = pending_two_proof_settlement();
    history.append_finality(&settlement).unwrap();
    let owner = account(4);
    let family = *history
        .head()
        .unwrap()
        .state()
        .claims()
        .keys()
        .next()
        .unwrap();
    let consensus = validator(5);
    let transport = period_transport(5, 1);
    let parent = history.head().unwrap().state();
    let intent = JoinIntent::new(
        &genesis,
        author(4),
        parent.next_nonce(author(4)).unwrap(),
        family,
        1,
        &consensus,
        &transport,
        "127.0.0.1:44005".into(),
    )
    .unwrap();
    let operation = signed(parent, 4, OperationBody::JoinIntent(intent));
    let now = parent.time();
    append(&mut history, now, vec![operation]);
    let parent = history.head().unwrap().state();
    assert_eq!(parent.join_queue().front(), Some(&family));

    StatePeriodCustody::import_candidate(
        &directory.0,
        &anchors.0,
        &genesis,
        family,
        &owner,
        &consensus,
        &transport,
    )
    .unwrap();
    let secret = directory.0.join(format!(
        "state-candidate-{}.secret",
        family
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let staged =
        StatePeriodCustody::stage_candidate(&directory.0, &anchors.0, parent, family, &owner)
            .unwrap();
    let first_offer = staged.candidate_offer().unwrap().clone();
    first_offer
        .verify(
            parent.authority(),
            parent.head(),
            parent.commitment(),
            owner.verifying_key().to_bytes(),
        )
        .unwrap();
    let now = parent.time();
    append(&mut history, now, vec![]);
    let selected = history.head().unwrap().state();
    assert!(selected.join_queue().contains(&family));
    assert!(!selected.consumed_claims().contains(&family));
    staged.abandon_unselected_candidate(selected).unwrap();
    assert!(
        secret.exists(),
        "a live queued claimant keeps its imported keys"
    );

    let restaged =
        StatePeriodCustody::stage_candidate(&directory.0, &anchors.0, selected, family, &owner)
            .unwrap();
    let next_offer = restaged.candidate_offer().unwrap().clone();
    assert_ne!(next_offer, first_offer, "a new parent needs a new offer");
    assert_eq!(next_offer.keys(), first_offer.keys());
    next_offer
        .verify(
            selected.authority(),
            selected.head(),
            selected.commitment(),
            owner.verifying_key().to_bytes(),
        )
        .unwrap();
    assert!(
        first_offer
            .verify(
                selected.authority(),
                selected.head(),
                selected.commitment(),
                owner.verifying_key().to_bytes(),
            )
            .is_err()
    );

    let expired_at = selected.join_intent(family).unwrap().expires();
    append(&mut history, expired_at, vec![]);
    let expired = history.head().unwrap().state();
    assert!(!expired.join_queue().contains(&family));
    restaged.abandon_unselected_candidate(expired).unwrap();
    assert!(!secret.exists(), "expired import must be retired");
    assert!(
        StatePeriodCustody::stage_candidate(&directory.0, &anchors.0, expired, family, &owner,)
            .is_err()
    );
    assert!(
        StatePeriodCustody::import_candidate(
            &directory.0,
            &anchors.0,
            &genesis,
            family,
            &owner,
            &consensus,
            &transport,
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn ready_anchor_failures_never_expose_unacknowledged_signature() {
    for point in faults::POINTS {
        let dir = Directory::new();
        let anchors = Directory::new();
        let g = genesis();
        let history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
        let agreement = first_finality(history.head().unwrap(), "ready anchor fault");
        let mut journal =
            StateHandoffJournal::create(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND).unwrap();
        journal.stage(agreement.agreement(), &history).unwrap();
        let incoming = period_key(0, 2);
        let signer = ConsensusKey::from_bytes(incoming.verifying_key().to_bytes());
        let transcript = journal.prepare_ready(signer).unwrap();
        let injection = faults::inject(&anchors.0.join("state-handoff-1.anchor"), point);
        assert!(
            journal
                .complete_ready(incoming.sign(&transcript).to_bytes())
                .is_err()
        );
        injection.assert_fired();
        assert!(journal.ready().is_none());
        drop(injection);
        drop(journal);
        let reopened = StateHandoffJournal::open(&dir.0, &anchors.0, g, 1, MAX_ROUND, &history);
        if point == faults::Point::DirectorySync {
            let recovered = reopened.unwrap();
            assert_eq!(recovered.ready().unwrap().role(), SealRole::Ready);
        } else {
            assert!(reopened.is_err());
        }
    }
}
#[cfg(unix)]
#[test]
fn terminal_anchor_failures_keep_signature_private_until_recovered_stop() {
    for point in faults::POINTS {
        let dir = Directory::new();
        let anchors = Directory::new();
        let g = genesis();
        let history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
        let finality = first_finality(history.head().unwrap(), "terminal anchor fault");
        let agreement = finality.agreement();
        let mut journal =
            StateHandoffJournal::create(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND).unwrap();
        journal.stage(agreement, &history).unwrap();
        let ready = seal(agreement).ready().to_vec();
        let transcript = journal.prepare_terminal(key(0), &ready).unwrap();
        let signer =
            StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND).unwrap();
        let injection = faults::inject(&anchors.0.join("state-handoff-1.anchor"), point);
        assert!(
            journal
                .complete_terminal(validator(0).sign(&transcript).to_bytes())
                .is_err()
        );
        injection.assert_fired();
        assert!(journal.terminal().is_none());
        assert!(!signer.stopped().unwrap());
        drop(injection);
        drop((journal, signer));
        let reopened =
            StateHandoffJournal::open(&dir.0, &anchors.0, g.clone(), 1, MAX_ROUND, &history);
        if point == faults::Point::DirectorySync {
            let mut journal = reopened.unwrap();
            let mut signer =
                StateSigner::open(&dir.0, &anchors.0, g, validator(0), MAX_ROUND).unwrap();
            assert!(journal.terminal().is_none());
            assert!(journal.release_terminal(&signer).is_err());
            signer.terminal_handoff(&mut journal, &ready).unwrap();
            assert!(signer.stopped().unwrap());
            let released = journal.release_terminal(&signer).unwrap();
            assert_eq!(released.role(), SealRole::Terminal);
        } else {
            assert!(reopened.is_err());
        }
    }
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

#[test]
fn selected_transition_visit_replays_each_height_once_with_exact_neighbors() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    #[cfg(unix)]
    drop(StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND).unwrap());
    for _ in 0..12 {
        append(&mut history, 100, vec![]);
    }
    let head = history.head().unwrap().commitment();
    let mut visited = 0u64;
    history
        .visit_selected_transitions(|preceding, parent, child| {
            assert_eq!(parent.state().height(), visited);
            assert_eq!(child.state().height(), visited + 1);
            assert_eq!(
                preceding.map(|branch| branch.state().height()),
                visited.checked_sub(1)
            );
            visited += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(visited, 12);
    assert_eq!(history.historical_replay_count(), 0);
    assert_eq!(history.head().unwrap().commitment(), head);
    drop(history);

    let history = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    let mut reopened_visits = 0;
    history
        .visit_selected_transitions(|_, _, _| {
            reopened_visits += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(reopened_visits, 12);
    assert_eq!(history.historical_replay_count(), 0);
    assert_eq!(history.head().unwrap().commitment(), head);

    #[cfg(unix)]
    {
        let mut cleanup_calls = 0;
        assert!(
            StateSigner::retire_predecessors(
                &dir.0,
                &anchors.0,
                &history,
                author(0),
                MAX_ROUND,
                |retired, preceding, selected, _successor| {
                    let Some(retired) = retired else {
                        return Ok(());
                    };
                    assert!(preceding.is_none());
                    assert_eq!(selected.state().height(), 0);
                    assert!(retired.stopped()?);
                    cleanup_calls += 1;
                    Err(StateStorageError::Invalid("simulated cleanup failure"))
                }
            )
            .is_err()
        );
        assert_eq!(cleanup_calls, 1);
        let retired = StateSigner::open(
            &dir.0,
            &anchors.0,
            history.head().unwrap().state().genesis().clone(),
            validator(0),
            MAX_ROUND,
        )
        .unwrap();
        assert!(retired.stopped().unwrap());
        assert!(retired.sign_time_report(100).is_err());
        drop(retired);
        StateSigner::retire_predecessors(
            &dir.0,
            &anchors.0,
            &history,
            author(0),
            MAX_ROUND,
            |retired, _, selected, _successor| {
                let Some(retired) = retired else {
                    return Ok(());
                };
                assert_eq!(selected.state().height(), 0);
                assert!(retired.stopped()?);
                cleanup_calls += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(cleanup_calls, 2);
        assert_eq!(history.historical_replay_count(), 0);
    }
}

#[cfg(unix)]
fn selected_period_without_ordinary_signer(
    activated: bool,
) -> (Directory, Directory, StateHistory, PathBuf) {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    let parent = history.head().unwrap().state();
    let unit = parent.authority().owner(author(3)).unwrap().id();
    let mut custody = StatePeriodCustody::stage_offer_with_keys_for_test(
        &dir.0,
        &anchors.0,
        parent,
        unit,
        &account(3),
        &period_key(3, 2),
        &period_transport(3, 2),
        "127.0.0.1:43003".into(),
    )
    .unwrap();
    let secret = dir.0.join("state-period-0.secret");
    assert!(secret.exists());
    append(&mut history, 100, vec![]);
    if activated {
        let signer = custody
            .open_or_create_selected_signer(&dir.0, &anchors.0, &history, MAX_ROUND)
            .unwrap();
        drop(signer);
    }
    drop(custody);
    append(&mut history, 100, vec![]);
    assert_eq!(history.head().unwrap().state().height(), 2);
    drop(history);
    let history = StateHistory::open(&dir.0, &anchors.0, genesis(), MAX_ROUND).unwrap();
    (dir, anchors, history, secret)
}

#[cfg(unix)]
#[test]
fn cold_catchup_retires_selected_custody_without_an_ordinary_signer() {
    let (dir, anchors, history, secret) = selected_period_without_ordinary_signer(false);
    for _ in 0..2 {
        StateSigner::retire_predecessors(
            &dir.0,
            &anchors.0,
            &history,
            author(3),
            MAX_ROUND,
            |retired, preceding, selected, _successor| {
                if selected.state().height() == 0 {
                    assert!(retired.is_none());
                    return Ok(());
                }
                assert!(retired.is_none());
                StatePeriodCustody::retire_unactivated_for_selected_branch(
                    &dir.0,
                    &anchors.0,
                    selected,
                    preceding.unwrap().state(),
                    &account(3),
                )
            },
        )
        .unwrap();
        assert!(!secret.exists());
    }
}

#[cfg(unix)]
#[test]
fn cold_catchup_retires_outgoing_offer_when_successor_did_not_select_it() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let parent = history.head().unwrap();
    let unit = parent.authority().owner(author(3)).unwrap().id();
    let custody = StatePeriodCustody::stage_offer(
        &dir.0,
        &anchors.0,
        parent.state(),
        unit,
        &account(3),
        "127.0.0.1:43003".into(),
    )
    .unwrap();
    let secret = dir.0.join("state-period-0.secret");
    assert!(secret.exists());
    drop(custody);
    let offers = plan(parent)
        .offers()
        .iter()
        .filter(|offer| offer.unit() != unit)
        .cloned()
        .collect();
    let no_offer = HandoffPlan::new(offers, None).unwrap();
    let record = parent
        .state()
        .prepare_record(time(parent.state(), 100), vec![], no_offer)
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let (finality, _) = certify(parent, record);
    history
        .append_finality(&finality.encode().unwrap())
        .unwrap();
    drop(history);
    let history = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    for _ in 0..2 {
        StateSigner::retire_predecessors(
            &dir.0,
            &anchors.0,
            &history,
            author(3),
            MAX_ROUND,
            |_retired, _preceding, outgoing, selected| {
                StatePeriodCustody::retire_unselected_offer_for_transition(
                    &dir.0,
                    &anchors.0,
                    outgoing.state(),
                    selected,
                    &account(3),
                )
            },
        )
        .unwrap();
        assert!(!secret.exists());
    }
}

#[cfg(unix)]
#[test]
fn selected_signer_marker_rejects_missing_signer_journal_during_catchup() {
    let (dir, anchors, history, secret) = selected_period_without_ordinary_signer(true);
    assert!(secret.exists());
    let key = period_key(3, 2).verifying_key().to_bytes();
    let key_hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    fs::remove_file(dir.0.join(format!("state-signer-{key_hex}.journal"))).unwrap();
    assert!(
        StateSigner::retire_predecessors(
            &dir.0,
            &anchors.0,
            &history,
            author(3),
            MAX_ROUND,
            |retired, preceding, selected, _successor| {
                if selected.state().height() == 0 {
                    return Ok(());
                }
                assert!(retired.is_none());
                StatePeriodCustody::retire_unactivated_for_selected_branch(
                    &dir.0,
                    &anchors.0,
                    selected,
                    preceding.unwrap().state(),
                    &account(3),
                )
            },
        )
        .is_err()
    );
    assert!(secret.exists());
}

#[test]
fn complete_control_history_reopens_and_observer_uses_same_full_state() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let op = submission(history.head().unwrap().state(), "actual queued question");
    let first = append(&mut history, 100, vec![op]);
    assert_eq!(
        history.append_finality(&first).unwrap(),
        StateAppendOutcome::AlreadyFinalized
    );
    append(&mut history, 100, vec![]);
    let active = history.head().unwrap().state().active().unwrap();
    let op = signed(
        history.head().unwrap().state(),
        0,
        OperationBody::Vote {
            question: active.question,
            attempt: active.number,
            yes: true,
        },
    );
    append(&mut history, 100, vec![op]);
    assert_eq!(history.head().unwrap().state().library().len(), 0);
    let expected = history.head().unwrap().commitment();
    let observed = StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    assert_eq!(observed.branch().commitment(), expected);
    assert!(!observed.halted());
    assert_eq!(history.finality_bytes(1).unwrap(), first);
    drop(history);
    let reopened = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    assert_eq!(reopened.head().unwrap().commitment(), expected);
    assert_eq!(reopened.head().unwrap().state().height(), 3);
}

fn pending_two_proof_settlement() -> (Directory, Directory, Genesis, StateHistory, Vec<u8>) {
    pending_two_proof_settlement_for(4)
}
fn pending_two_proof_settlement_for(
    researcher: u8,
) -> (Directory, Directory, Genesis, StateHistory, Vec<u8>) {
    use naome_checker::{ArtifactState, normalize_and_check_with_state};
    use naome_foundation::FreeVariable;
    use naome_proof::{ProofCertificate, ProofStep};
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    if g.account_key(author(researcher)).is_none() {
        let registration = OperationBody::Register
            .sign(&g, 1, &account(researcher))
            .unwrap();
        let registration_id = registration.id();
        append(&mut history, 100, vec![registration]);
        let expected = history.head().unwrap().commitment();
        drop(history);
        history = StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
        assert_eq!(history.head().unwrap().commitment(), expected);
        let state = history.head().unwrap().state();
        assert_eq!(
            state.account_key(author(researcher)),
            Some(account(researcher).verifying_key().as_bytes())
        );
        assert_eq!(state.balances().account(author(researcher)), Some(0));
        assert_eq!(state.next_nonce(author(researcher)), Some(2));
        assert_eq!(state.receipt(registration_id).unwrap().nonce, 1);
    }
    let op = submission_by(
        history.head().unwrap().state(),
        researcher,
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
    let package = ProofPackage::new(author(researcher), a.0, vec![a, h], g.profile()).unwrap();
    let original = SignedOriginal::sign(&g, round, package, &account(researcher)).unwrap();
    let secret = [77; 32];
    let commitment = CommitmentId::for_original(
        &g,
        round,
        author(researcher),
        original.original_hash(),
        &secret,
    );
    let op = signed(
        history.head().unwrap().state(),
        researcher,
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
        researcher,
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

#[test]
fn real_two_proof_settlement_survives_complete_cold_replay() {
    let (dir, anchors, g, mut history, settlement) = pending_two_proof_settlement();
    assert_eq!(
        history.append_finality(&settlement).unwrap(),
        StateAppendOutcome::Finalized
    );
    let expected = history.head().unwrap().commitment();
    assert_eq!(history.head().unwrap().state().library().len(), 2);
    assert_eq!(
        history
            .head()
            .unwrap()
            .state()
            .balances()
            .account(author(4)),
        Some(700_000_000)
    );
    assert_eq!(history.head().unwrap().state().claims().len(), 1);
    drop(history);
    let observed = StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let reopened = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    assert_eq!(observed.branch().commitment(), expected);
    assert_eq!(reopened.head().unwrap().commitment(), expected);
    assert_eq!(observed.branch().state().library().len(), 2);
    assert_eq!(observed.branch().state().balances().paid_completions(), 1);
}

#[test]
fn registered_researcher_restarts_completes_and_replays_without_duplicate_issuance() {
    // The fixture closes and reopens the journal immediately after registration,
    // then uses that recovered account to submit, commit and reveal real proofs.
    let (dir, anchors, g, mut history, settlement) = pending_two_proof_settlement_for(6);
    assert!(g.account_key(author(6)).is_none());
    let registration = OperationBody::Register.sign(&g, 1, &account(6)).unwrap();
    let registration_finality = history.finality_bytes(1).unwrap();
    let pending = history.head().unwrap().commitment();
    let before = history.head().unwrap().state();
    assert_eq!(before.accounts().len(), g.accounts().len() + 1);
    assert_eq!(before.balances().account(author(6)), Some(0));
    assert_eq!(before.next_nonce(author(6)), Some(5));
    assert_eq!(
        before.receipt(registration.id()).unwrap().coordinate.height,
        1
    );
    assert_eq!(before.balances().paid_completions(), 0);
    before
        .balances()
        .verify_conservation(&g, before.accounts())
        .unwrap();
    assert_eq!(
        history.receive_finality(1, &registration_finality).unwrap(),
        StateAppendOutcome::AlreadyFinalized
    );
    assert_eq!(history.head().unwrap().commitment(), pending);
    assert_eq!(
        history.append_finality(&settlement).unwrap(),
        StateAppendOutcome::Finalized
    );
    let expected = history.head().unwrap().commitment();
    let settled_height = history.head().unwrap().state().height();
    drop(history);

    let observed = StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let mut reopened = StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    for branch in [observed.branch(), reopened.head().unwrap()] {
        assert_eq!(branch.commitment(), expected);
        let state = branch.state();
        assert_eq!(state.accounts().len(), g.accounts().len() + 1);
        assert_eq!(
            state.account_key(author(6)),
            Some(account(6).verifying_key().as_bytes())
        );
        assert_eq!(state.next_nonce(author(6)), Some(5));
        assert_eq!(state.receipt(registration.id()).unwrap().nonce, 1);
        assert_eq!(state.library().len(), 2);
        assert_eq!(state.balances().account(author(6)), Some(700_000_000));
        assert_eq!(state.balances().account(author(4)), Some(0));
        assert_eq!(state.balances().paid_completions(), 1);
        assert_eq!(state.balances().reserve(), 100_000_000);
        for index in 0..4 {
            assert_eq!(state.balances().account(author(index)), Some(50_000_000));
        }
        assert_eq!(state.claims().len(), 1);
        assert_eq!(state.claims().values().next().unwrap().author, author(6));
        state
            .balances()
            .verify_conservation(&g, state.accounts())
            .unwrap();
    }
    let journal = dir.0.join(crate::JOURNAL_FILE_NAME);
    let journal_bytes = fs::metadata(&journal).unwrap().len();
    for (height, finality) in [(1, &registration_finality), (settled_height, &settlement)] {
        assert_eq!(
            reopened.receive_finality(height, finality).unwrap(),
            StateAppendOutcome::AlreadyFinalized
        );
        assert_eq!(reopened.head().unwrap().commitment(), expected);
        assert_eq!(
            reopened.head().unwrap().state().next_nonce(author(6)),
            Some(5)
        );
        assert_eq!(fs::metadata(&journal).unwrap().len(), journal_bytes);
    }
}

fn assert_two_proof_settlement(branch: &StateBranch, completed: bool) {
    let state = branch.state();
    assert_eq!(state.library().len(), if completed { 2 } else { 0 });
    assert_eq!(state.claims().len(), usize::from(completed));
    assert_eq!(state.balances().paid_completions(), u64::from(completed));
    assert_eq!(
        state.balances().account(author(4)),
        Some(if completed { 700_000_000 } else { 0 })
    );
    assert_eq!(
        state.balances().reserve(),
        if completed { 100_000_000 } else { 0 }
    );
    for index in 0..4 {
        assert_eq!(
            state.balances().account(author(index)),
            Some(if completed { 50_000_000 } else { 0 })
        );
    }
    assert_eq!(state.active().is_none(), completed);
    if !completed {
        let active = state.active().unwrap();
        assert_eq!(active.phase, naome_ledger::state::Phase::SettlementPending);
        assert_eq!(active.reveals, 1);
    }
}

#[test]
fn actual_settlement_anchor_failures_never_expose_partial_proofs_rewards_or_claims() {
    for point in faults::POINTS {
        let (dir, anchors, g, mut history, settlement) = pending_two_proof_settlement();
        assert_two_proof_settlement(history.head().unwrap(), false);
        let expected = history
            .head()
            .unwrap()
            .decode_finality(&settlement, MAX_ROUND)
            .unwrap()
            .into_branch();
        let injection = faults::inject(&anchors.0.join("state-finality.anchor"), point);
        assert!(history.append_finality(&settlement).is_err(), "{point:?}");
        injection.assert_fired();
        assert!(matches!(history.head(), Err(StateStorageError::Poisoned)));
        drop(injection);
        drop(history);
        let observed = StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND);
        let reopened = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND);
        if point == faults::Point::DirectorySync {
            // The final rename was visible; a lost directory-sync acknowledgement
            // may recover the complete new state, but never a partial settlement.
            let observed = observed.unwrap();
            let mut reopened = reopened.unwrap();
            assert_eq!(observed.branch().commitment(), expected.commitment());
            assert_eq!(reopened.head().unwrap().commitment(), expected.commitment());
            assert_two_proof_settlement(observed.branch(), true);
            assert_two_proof_settlement(reopened.head().unwrap(), true);
            let length = fs::metadata(dir.0.join(crate::JOURNAL_FILE_NAME))
                .unwrap()
                .len();
            assert_eq!(
                reopened
                    .receive_finality(expected.state().height(), &settlement)
                    .unwrap(),
                StateAppendOutcome::AlreadyFinalized
            );
            assert_two_proof_settlement(reopened.head().unwrap(), true);
            assert_eq!(
                fs::metadata(dir.0.join(crate::JOURNAL_FILE_NAME))
                    .unwrap()
                    .len(),
                length
            );
        } else {
            // A complete journal frame with an older anchor is an explicit halt.
            assert!(observed.is_err(), "{point:?}");
            assert!(reopened.is_err(), "{point:?}");
        }
    }
}

#[test]
fn actual_settlement_journal_crash_images_recover_only_old_complete_or_halted_state() {
    let (dir, anchors, g, mut history, settlement) = pending_two_proof_settlement();
    let journal = dir.0.join(crate::JOURNAL_FILE_NAME);
    let anchor = anchors.0.join("state-finality.anchor");
    let before = history.head().unwrap().commitment();
    let old_journal = fs::read(&journal).unwrap();
    let old_anchor = fs::read(&anchor).unwrap();
    history.append_finality(&settlement).unwrap();
    let after = history.head().unwrap().commitment();
    let height = history.head().unwrap().state().height();
    let full_journal = fs::read(&journal).unwrap();
    let new_anchor = fs::read(&anchor).unwrap();
    drop(history);

    let frame_bytes = full_journal.len() - old_journal.len();
    let body_end = frame_bytes - 32;
    // Genuine bytes from the actual settlement append: before/after the length,
    // partial payload, body sync boundary, every footer byte, and final sync.
    // Generic ScriptedIo tests separately inject each body byte and sync error.
    let mut cuts = std::collections::BTreeSet::from([0, 1, 2, 3, 4, 5, body_end / 2, body_end - 1]);
    cuts.extend(body_end..=frame_bytes);
    for new_anchor_visible in [false, true] {
        for &cut in &cuts {
            let crash_bytes = &full_journal[..old_journal.len() + cut];
            fs::write(&journal, crash_bytes).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&journal)
                .unwrap()
                .sync_all()
                .unwrap();
            fs::write(
                &anchor,
                if new_anchor_visible {
                    &new_anchor
                } else {
                    &old_anchor
                },
            )
            .unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&anchor)
                .unwrap()
                .sync_all()
                .unwrap();
            let observed = StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND);
            // Observation never repairs even a harmless uncommitted tail.
            assert_eq!(fs::read(&journal).unwrap(), crash_bytes);
            let reopened = StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND);
            let complete = cut == frame_bytes;
            if new_anchor_visible != complete {
                assert!(
                    observed.is_err(),
                    "cut={cut} new_anchor={new_anchor_visible}"
                );
                assert!(
                    reopened.is_err(),
                    "cut={cut} new_anchor={new_anchor_visible}"
                );
                assert_eq!(fs::read(&journal).unwrap(), crash_bytes);
                continue;
            }
            let observed = observed.unwrap();
            let mut reopened = reopened.unwrap();
            let expected = if complete { after } else { before };
            assert_eq!(observed.branch().commitment(), expected);
            assert_eq!(reopened.head().unwrap().commitment(), expected);
            assert_two_proof_settlement(observed.branch(), complete);
            assert_two_proof_settlement(reopened.head().unwrap(), complete);
            if !complete {
                assert_eq!(fs::read(&journal).unwrap(), old_journal);
                assert_eq!(
                    reopened.append_finality(&settlement).unwrap(),
                    StateAppendOutcome::Finalized
                );
            }
            for _ in 0..2 {
                assert_eq!(
                    reopened.receive_finality(height, &settlement).unwrap(),
                    StateAppendOutcome::AlreadyFinalized
                );
            }
            assert_eq!(reopened.head().unwrap().commitment(), after);
            assert_two_proof_settlement(reopened.head().unwrap(), true);
            assert_eq!(fs::read(&journal).unwrap(), full_journal);
            drop(reopened);
        }
    }
}

#[test]
fn torn_tail_is_read_only_for_observer_and_recovered_only_by_owner() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let op = submission(history.head().unwrap().state(), "recover tail");
    append(&mut history, 100, vec![op]);
    let expected = history.head().unwrap().commitment();
    drop(history);
    let path = dir.0.join(crate::JOURNAL_FILE_NAME);
    let complete = fs::read(&path).unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0, 0]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let observer = StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    assert_eq!(observer.branch().commitment(), expected);
    assert_eq!(
        fs::metadata(&path).unwrap().len(),
        complete.len() as u64 + 2
    );
    let history = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    assert_eq!(history.head().unwrap().commitment(), expected);
    assert_eq!(fs::read(path).unwrap(), complete);
}

#[test]
fn shared_selected_history_and_anchor_locks_exclude_other_owners() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    assert!(matches!(
        crate::open_exclusive_lock(&dir.0, crate::LOCK_FILE_NAME),
        Err(crate::ExclusiveLockError::Locked)
    ));
    assert!(matches!(
        StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND),
        Err(StateStorageError::Locked)
    ));
    drop(history);
    let reopened = StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    drop(reopened);
    assert!(StateHistory::create(&dir.0, &anchors.0, g, MAX_ROUND).is_err());
}

#[test]
fn historical_replay_requires_complete_authenticated_finality_first() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    let op = submission(
        history.head().unwrap().state(),
        "authenticated history routing",
    );
    append(&mut history, 100, vec![op]);
    append(&mut history, 100, vec![]);
    let mut alternative = None;
    for owner in 0..2 {
        let active = history.head().unwrap().state().active().unwrap();
        let vote = signed(
            history.head().unwrap().state(),
            owner,
            OperationBody::Vote {
                question: active.question,
                attempt: active.number,
                yes: true,
            },
        );
        if owner == 0 {
            let bytes = record(history.head().unwrap(), 100, vec![vote.clone()]);
            alternative = Some(
                certify_with_signers(history.head().unwrap(), bytes, 1)
                    .0
                    .encode()
                    .unwrap(),
            );
        }
        append(&mut history, 100, vec![vote]);
    }
    let valid = history.finality_bytes(3).unwrap();
    let head = history.head().unwrap().commitment();
    let journal = dir.0.join(crate::JOURNAL_FILE_NAME);
    let length = fs::metadata(&journal).unwrap().len();
    let value_bytes = naome_consensus::state::StateValue::BYTE_LENGTH;
    // A complete outer envelope containing only an unsigned proposal header
    // used to pass claimed_height and trigger historical mathematical replay.
    let header_length = 5 + value_bytes;
    let mut unsigned = b"NSCF5".to_vec();
    unsigned.extend_from_slice(&(header_length as u32).to_be_bytes());
    unsigned.extend_from_slice(&valid[9..9 + header_length]);
    unsigned.extend_from_slice(&0u32.to_be_bytes());
    unsigned.extend_from_slice(&0u32.to_be_bytes());
    assert_eq!(
        StateFinality::claimed_height(&unsigned, valid.len()).unwrap(),
        3
    );
    let mut bad_producer = valid.clone();
    bad_producer[9 + 5 + value_bytes + 8 + 32] ^= 1;
    let mut bad_quorum = valid.clone();
    *bad_quorum.last_mut().unwrap() ^= 1;
    let mut stale_signature = valid.clone();
    let height_offset = 9 + 5 + 5 + 32 + 32 + 32;
    stale_signature[height_offset..height_offset + 8].copy_from_slice(&2u64.to_be_bytes());
    // Framing errors fail before historical parent lookup.
    let bad = valid[..300].to_vec();
    assert!(history.receive_finality(3, &bad).is_err());
    assert!(history.report_conflict(3, &bad).is_err());
    assert_eq!(history.historical_replay_count(), 0);
    assert_eq!(history.head().unwrap().commitment(), head);
    assert_eq!(fs::metadata(&journal).unwrap().len(), length);
    // Cryptographic checks need the selected parent and its authority, so a
    // bounded historical replay can precede rejection.
    for bad in [unsigned, bad_producer, bad_quorum, stale_signature] {
        assert!(history.receive_finality(3, &bad).is_err());
        assert!(history.report_conflict(3, &bad).is_err());
        assert_eq!(history.head().unwrap().commitment(), head);
        assert_eq!(fs::metadata(&journal).unwrap().len(), length);
    }
    let verified_lookup_count = history.historical_replay_count();
    assert!(history.receive_finality(2, &valid).is_err());
    assert_eq!(history.historical_replay_count(), verified_lookup_count);
    assert_eq!(
        history.receive_finality(3, &valid).unwrap(),
        StateAppendOutcome::AlreadyFinalized
    );
    assert_eq!(history.historical_replay_count(), verified_lookup_count);
    let alternative = alternative.unwrap();
    assert_ne!(alternative, valid);
    assert_eq!(
        history.receive_finality(3, &alternative).unwrap(),
        StateAppendOutcome::AlreadyFinalized
    );
    assert_eq!(history.historical_replay_count(), verified_lookup_count + 1);
    assert_eq!(history.head().unwrap().commitment(), head);
    assert_eq!(fs::metadata(&journal).unwrap().len(), length);
}

#[test]
fn historical_conflicting_finality_is_verified_and_persistently_halts() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    let sibling = first_finality(history.head().unwrap(), "different first question context")
        .encode()
        .unwrap();
    let op = submission(history.head().unwrap().state(), "selected first context");
    let selected = append(&mut history, 100, vec![op]);
    append(&mut history, 100, vec![]);
    assert!(history.report_conflict(1, &selected).is_err());
    assert_eq!(
        history.report_conflict(1, &sibling).unwrap(),
        StateAppendOutcome::ConflictHalt
    );
    assert!(history.head().is_err());
    assert!(history.halted().unwrap());
    let expected = history.last_finalized().unwrap().commitment();
    drop(history);
    let reopened = StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
    assert!(reopened.halted().unwrap());
    assert_eq!(reopened.last_finalized().unwrap().commitment(), expected);
    let observed = StateObserver::open(&dir.0, &anchors.0, g, MAX_ROUND).unwrap();
    assert!(observed.halted());
    assert_eq!(observed.branch().commitment(), expected);
}

#[test]
fn all_history_anchor_failure_boundaries_withhold_live_selection() {
    for point in faults::POINTS {
        let dir = Directory::new();
        let anchors = Directory::new();
        let g = genesis();
        let mut history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
        let finality = first_finality(history.head().unwrap(), "durability boundary")
            .encode()
            .unwrap();
        let injection = faults::inject(&anchors.0.join("state-finality.anchor"), point);
        assert!(history.append_finality(&finality).is_err());
        injection.assert_fired();
        assert!(matches!(history.head(), Err(StateStorageError::Poisoned)));
        drop(injection);
        drop(history);
        let reopened = StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND);
        if point == faults::Point::DirectorySync {
            assert_eq!(reopened.unwrap().head().unwrap().state().height(), 1);
        } else {
            assert!(reopened.is_err());
        }
    }
}

#[cfg(unix)]
#[test]
fn prepared_intent_survives_restart_and_exact_completion_retry_never_resigns() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let mut signer =
        StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND).unwrap();
    let event = StateLockEvent::ProposalTimeout;
    assert_eq!(signer.prepare(&event).unwrap(), StatePreparation::Prepared);
    assert_eq!(signer.key_use_count(), 0);
    let checkpoint = signer.snapshot().unwrap();
    let journal_path = dir.0.join(signer.journal_file_name());
    drop(signer);
    let mut signer =
        StateSigner::open(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND).unwrap();
    assert_eq!(signer.snapshot().unwrap(), checkpoint);
    assert!(signer.pending().unwrap());
    assert!(
        signer
            .prepare(&StateLockEvent::Prevote { proposal: None })
            .is_err()
    );
    let publication = signer.apply_and_sign(&event).unwrap().unwrap();
    assert_eq!(signer.key_use_count(), 1);
    let length = fs::metadata(&journal_path).unwrap().len();
    assert_eq!(signer.apply_and_sign(&event).unwrap().unwrap(), publication);
    assert_eq!(signer.key_use_count(), 1);
    assert_eq!(fs::metadata(&journal_path).unwrap().len(), length);
    drop(signer);
    let mut reopened = StateSigner::open(&dir.0, &anchors.0, g, validator(0), MAX_ROUND).unwrap();
    assert_eq!(
        reopened.apply_and_sign(&event).unwrap().unwrap(),
        publication
    );
    assert_eq!(reopened.key_use_count(), 0);
    let bytes = fs::read(journal_path).unwrap();
    assert!(!bytes.windows(32).any(|w| w == validator(0).to_bytes()));
}

#[cfg(unix)]
#[test]
fn exhausted_signing_bytes_or_frames_never_use_key_and_pending_intent_recovers() {
    for bytes in [false, true] {
        for pending in [false, true] {
            let dir = Directory::new();
            let anchors = Directory::new();
            let g = genesis();
            let mut signer =
                StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND)
                    .unwrap();
            let event = StateLockEvent::ProposalTimeout;
            if pending {
                signer.prepare(&event).unwrap();
            }
            let snapshot = signer.snapshot().unwrap();
            let journal = dir.0.join(signer.journal_file_name());
            let length = fs::metadata(&journal).unwrap().len();
            signer.exhaust_capacity(bytes);
            let result = if pending {
                signer.sign_prepared().map(|_| ())
            } else {
                signer.prepare(&event).map(|_| ())
            };
            assert!(matches!(result, Err(StateStorageError::Limit(_))));
            assert_eq!(signer.key_use_count(), 0);
            assert_eq!(signer.pending().unwrap(), pending);
            assert_eq!(signer.snapshot().unwrap(), snapshot);
            assert_eq!(fs::metadata(&journal).unwrap().len(), length);
            drop(signer);
            // The injected local capacity fault changed no durable authority.
            let mut recovered =
                StateSigner::open(&dir.0, &anchors.0, g, validator(0), MAX_ROUND).unwrap();
            assert_eq!(recovered.pending().unwrap(), pending);
            let publication = recovered.apply_and_sign(&event).unwrap().unwrap();
            assert_eq!(recovered.key_use_count(), 1);
            assert_eq!(
                recovered.apply_and_sign(&event).unwrap().unwrap(),
                publication
            );
            assert_eq!(recovered.key_use_count(), 1);
        }
    }
}

#[cfg(unix)]
#[test]
fn signing_anchor_faults_never_publish_and_preparation_faults_never_use_key() {
    for during_completion in [false, true] {
        for point in faults::POINTS {
            let dir = Directory::new();
            let anchors = Directory::new();
            let g = genesis();
            let mut signer =
                StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND)
                    .unwrap();
            if during_completion {
                signer.prepare(&StateLockEvent::ProposalTimeout).unwrap();
            }
            let injection = faults::inject(&anchors.0.join(signer.anchor_file_name()), point);
            if during_completion {
                assert!(signer.sign_prepared().is_err());
                assert_eq!(signer.key_use_count(), 1);
            } else {
                assert!(
                    signer
                        .apply_and_sign(&StateLockEvent::ProposalTimeout)
                        .is_err()
                );
                assert_eq!(signer.key_use_count(), 0);
            }
            injection.assert_fired();
            assert!(signer.last_publication().is_err());
            drop(injection);
            drop(signer);
            let reopened = StateSigner::open(&dir.0, &anchors.0, g, validator(0), MAX_ROUND);
            if point == faults::Point::DirectorySync {
                let signer = reopened.unwrap();
                assert_eq!(signer.pending().unwrap(), !during_completion);
                assert_eq!(
                    signer.last_publication().unwrap().is_some(),
                    during_completion
                );
            } else {
                assert!(reopened.is_err());
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn signer_height_handoff_uses_selected_durable_finality_and_conflict_preempts_pending() {
    let history_dir = Directory::new();
    let history_anchors = Directory::new();
    let signer_dir = Directory::new();
    let signer_anchors = Directory::new();
    let g = genesis();
    let mut history =
        StateHistory::create(&history_dir.0, &history_anchors.0, g.clone(), MAX_ROUND).unwrap();
    let conflict = first_finality(history.head().unwrap(), "conflict evidence")
        .encode()
        .unwrap();
    let mut signer = StateSigner::create(
        &signer_dir.0,
        &signer_anchors.0,
        g.clone(),
        validator(0),
        MAX_ROUND,
    )
    .unwrap();
    let op = submission(history.head().unwrap().state(), "selected value");
    append(&mut history, 100, vec![op]);
    signer.advance_to_history(&mut history).unwrap();
    assert!(signer.stopped().unwrap());
    assert!(signer.snapshot().is_err());
    drop(signer);
    let mut signer = StateSigner::open(
        &signer_dir.0,
        &signer_anchors.0,
        g.clone(),
        validator(0),
        MAX_ROUND,
    )
    .unwrap();
    assert!(signer.stopped().unwrap());
    assert!(signer.prepare(&StateLockEvent::ProposalTimeout).is_err());
    drop(signer);
    let pending_dir = Directory::new();
    let pending_anchors = Directory::new();
    let mut signer = StateSigner::create(
        &pending_dir.0,
        &pending_anchors.0,
        g.clone(),
        validator(1),
        MAX_ROUND,
    )
    .unwrap();
    signer.prepare(&StateLockEvent::ProposalTimeout).unwrap();
    history.report_conflict(1, &conflict).unwrap();
    assert!(signer.advance_to_history(&mut history).is_err());
    assert!(signer.stopped().unwrap());
    assert!(signer.sign_prepared().is_err());
    drop(signer);
    let mut reopened = StateSigner::open(
        &pending_dir.0,
        &pending_anchors.0,
        g,
        validator(1),
        MAX_ROUND,
    )
    .unwrap();
    assert!(reopened.stopped().unwrap());
    assert!(
        reopened
            .apply_and_sign(&StateLockEvent::ProposalTimeout)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn selected_seal_discards_recovered_old_intent_without_using_retired_key() {
    let history_dir = Directory::new();
    let history_anchors = Directory::new();
    let signer_dir = Directory::new();
    let signer_anchors = Directory::new();
    let g = genesis();
    let mut history =
        StateHistory::create(&history_dir.0, &history_anchors.0, g.clone(), MAX_ROUND).unwrap();
    let mut signer = StateSigner::create(
        &signer_dir.0,
        &signer_anchors.0,
        g.clone(),
        validator(0),
        MAX_ROUND,
    )
    .unwrap();
    signer.prepare(&StateLockEvent::ProposalTimeout).unwrap();
    assert!(signer.pending().unwrap());
    assert_eq!(signer.key_use_count(), 0);
    drop(signer);

    let mut signer = StateSigner::open(
        &signer_dir.0,
        &signer_anchors.0,
        g.clone(),
        validator(0),
        MAX_ROUND,
    )
    .unwrap();
    assert!(signer.pending().unwrap());
    append(&mut history, 100, vec![]);
    signer.advance_to_history(&mut history).unwrap();
    assert_eq!(signer.key_use_count(), 0);
    assert!(signer.stopped().unwrap());
    assert!(signer.sign_prepared().is_err());
    drop(signer);

    let signer =
        StateSigner::open(&signer_dir.0, &signer_anchors.0, g, validator(0), MAX_ROUND).unwrap();
    assert!(signer.stopped().unwrap());
    assert!(signer.pending().is_err());
    assert!(signer.last_publication().is_err());
}

#[cfg(unix)]
#[test]
fn proposal_and_both_votes_replay_for_exact_resend_until_round_changes() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let branch = StateBranch::from_genesis(LedgerState::new(g.clone())).unwrap();
    let record = record(
        &branch,
        100,
        vec![submission(branch.state(), "resend proposal")],
    );
    let (finality, prevotes) = certify(&branch, record.clone());
    let scheduled = branch.proposer(0, MAX_ROUND).unwrap().unwrap();
    let mut signer = StateSigner::create(
        &dir.0,
        &anchors.0,
        g.clone(),
        signing_key(scheduled),
        MAX_ROUND,
    )
    .unwrap();
    let mut expected = Vec::new();
    for event in [
        StateLockEvent::Author {
            record: Some(record),
        },
        StateLockEvent::Prevote {
            proposal: Some(finality.proposal().encode().unwrap()),
        },
        StateLockEvent::Precommit {
            proposal: Some(finality.proposal().encode().unwrap()),
            quorum: prevotes.encode(),
        },
    ] {
        expected.push(signer.apply_and_sign(&event).unwrap().unwrap());
        assert_eq!(signer.current_publications().unwrap(), expected);
    }
    assert_eq!(expected.len(), 3);
    assert_eq!(signer.retry_publications().unwrap(), expected);
    let previous_votes: Vec<_> = expected
        .iter()
        .filter(|p| matches!(p, StatePublication::Vote(_)))
        .cloned()
        .collect();
    assert_eq!(previous_votes.len(), 2);
    drop(signer);
    let mut recovered = StateSigner::open(
        &dir.0,
        &anchors.0,
        g.clone(),
        signing_key(scheduled),
        MAX_ROUND,
    )
    .unwrap();
    assert_eq!(recovered.current_publications().unwrap(), expected);
    assert_eq!(recovered.key_use_count(), 0);
    recovered
        .apply_and_sign(&StateLockEvent::PrecommitTimeout {
            votes: finality.quorum().encode(),
        })
        .unwrap();
    assert!(recovered.current_publications().unwrap().is_empty());
    assert_eq!(recovered.retry_publications().unwrap(), previous_votes);
    drop(recovered);
    let mut recovered = StateSigner::open(
        &dir.0,
        &anchors.0,
        g.clone(),
        signing_key(scheduled),
        MAX_ROUND,
    )
    .unwrap();
    assert_eq!(recovered.round().unwrap(), 1);
    assert!(recovered.current_publications().unwrap().is_empty());
    assert_eq!(recovered.retry_publications().unwrap(), previous_votes);
    assert_eq!(recovered.key_use_count(), 0);
    let history_dir = Directory::new();
    let history_anchors = Directory::new();
    let mut history =
        StateHistory::create(&history_dir.0, &history_anchors.0, g.clone(), MAX_ROUND).unwrap();
    history
        .append_finality(&finality.encode().unwrap())
        .unwrap();
    recovered.advance_to_history(&mut history).unwrap();
    assert!(recovered.stopped().unwrap());
    assert!(recovered.retry_publications().is_err());
    assert_eq!(recovered.key_use_count(), 0);
    drop(recovered);
    let recovered =
        StateSigner::open(&dir.0, &anchors.0, g, signing_key(scheduled), MAX_ROUND).unwrap();
    assert!(recovered.stopped().unwrap());
    assert!(recovered.retry_publications().is_err());
}

#[cfg(unix)]
#[test]
fn locked_valid_body_and_quorum_survive_restart_and_reproposal() {
    let dir = Directory::new();
    let anchors = Directory::new();
    let g = genesis();
    let branch = StateBranch::from_genesis(LedgerState::new(g.clone())).unwrap();
    let record = record(
        &branch,
        100,
        vec![submission(branch.state(), "retained body")],
    );
    let (finality, prevotes) = certify(&branch, record.clone());
    let proposal = finality.proposal().encode().unwrap();
    let scheduled = branch.proposer(1, MAX_ROUND).unwrap().unwrap();
    let mut signer = StateSigner::create(
        &dir.0,
        &anchors.0,
        g.clone(),
        signing_key(scheduled),
        MAX_ROUND,
    )
    .unwrap();
    signer
        .apply_and_sign(&StateLockEvent::Prevote {
            proposal: Some(proposal.clone()),
        })
        .unwrap();
    signer
        .apply_and_sign(&StateLockEvent::Precommit {
            proposal: Some(proposal),
            quorum: prevotes.encode(),
        })
        .unwrap();
    assert_eq!(signer.retained_record().unwrap(), Some(record.as_slice()));
    drop(signer);
    let mut signer = StateSigner::open(
        &dir.0,
        &anchors.0,
        g.clone(),
        signing_key(scheduled),
        MAX_ROUND,
    )
    .unwrap();
    assert_eq!(signer.retained_record().unwrap(), Some(record.as_slice()));
    assert_eq!(signer.retained_quorum().unwrap(), Some(&prevotes));
    assert!(
        signer
            .apply_and_sign(&StateLockEvent::PrecommitTimeout {
                votes: finality.quorum().encode()
            })
            .unwrap()
            .is_none()
    );
    assert_eq!(signer.round().unwrap(), 1);
    assert!(
        signer
            .prepare(&StateLockEvent::Author {
                record: Some(record.clone())
            })
            .is_err()
    );
    let publication = signer
        .apply_and_sign(&StateLockEvent::Author { record: None })
        .unwrap()
        .unwrap();
    let round_one_proposal = publication.encode().unwrap();
    match publication {
        StatePublication::Proposal(p) => {
            assert_eq!(p.record_bytes(), record);
            assert_eq!(p.round(), 1);
            assert_eq!(p.valid_quorum(), Some(&prevotes));
        }
        _ => panic!("retained proposal"),
    }
    let prior = signer.retry_publications().unwrap();
    assert_eq!(prior.len(), 3); // current proposal plus two preceding-round votes
    signer
        .apply_and_sign(&StateLockEvent::Prevote {
            proposal: Some(round_one_proposal.clone()),
        })
        .unwrap();
    let mut round_one_votes = Vec::new();
    for i in 0..3 {
        let mut kernel = StateLockState::new(&branch, key(i)).unwrap();
        kernel
            .apply(
                &branch,
                &StateLockEvent::Prevote {
                    proposal: Some(finality.proposal().encode().unwrap()),
                },
                MAX_ROUND,
            )
            .unwrap();
        kernel
            .apply(
                &branch,
                &StateLockEvent::Precommit {
                    proposal: Some(finality.proposal().encode().unwrap()),
                    quorum: prevotes.encode(),
                },
                MAX_ROUND,
            )
            .unwrap();
        kernel
            .apply(
                &branch,
                &StateLockEvent::PrecommitTimeout {
                    votes: finality.quorum().encode(),
                },
                MAX_ROUND,
            )
            .unwrap();
        let intent = kernel
            .apply(
                &branch,
                &StateLockEvent::Prevote {
                    proposal: Some(round_one_proposal.clone()),
                },
                MAX_ROUND,
            )
            .unwrap();
        round_one_votes.push(finish_vote(intent, &branch, i));
    }
    let round_one_quorum =
        StateQuorum::from_votes(round_one_votes, &g, branch.authority()).unwrap();
    signer
        .apply_and_sign(&StateLockEvent::Precommit {
            proposal: Some(round_one_proposal),
            quorum: round_one_quorum.encode(),
        })
        .unwrap();
    assert_eq!(signer.current_publications().unwrap().len(), 3);
    let exact_retry = signer.retry_publications().unwrap();
    assert_eq!(exact_retry.len(), 5);
    assert_eq!(&exact_retry[3..], &prior[1..]);
    drop(signer);
    let signer =
        StateSigner::open(&dir.0, &anchors.0, g, signing_key(scheduled), MAX_ROUND).unwrap();
    assert_eq!(signer.retry_publications().unwrap(), exact_retry);
    assert_eq!(signer.current_publications().unwrap().len(), 3);
    assert_eq!(signer.key_use_count(), 0);
}

#[cfg(not(unix))]
#[test]
fn signing_remains_fail_closed_on_unsupported_platform() {
    let dir = Directory::new();
    let anchors = Directory::new();
    assert!(matches!(
        StateSigner::create(&dir.0, &anchors.0, genesis(), validator(0), MAX_ROUND),
        Err(StateStorageError::Platform(_))
    ));
    assert!(fs::read_dir(&dir.0).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn legacy_history_and_signer_prefixes_fail_closed_without_rewriting() {
    for signing in [false, true] {
        let dir = Directory::new();
        let anchors = Directory::new();
        let g = genesis();
        let (path, old_magic) = if signing {
            let signer =
                StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND)
                    .unwrap();
            (dir.0.join(signer.journal_file_name()), b"NAORSIG1")
        } else {
            let history = StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND).unwrap();
            drop(history);
            (dir.0.join(crate::JOURNAL_FILE_NAME), b"NAORHIS1")
        };
        let mut bytes = fs::read(&path).unwrap();
        bytes[..8].copy_from_slice(old_magic);
        fs::write(&path, &bytes).unwrap();
        if signing {
            assert!(StateSigner::open(&dir.0, &anchors.0, g, validator(0), MAX_ROUND).is_err());
        } else {
            assert!(StateHistory::open(&dir.0, &anchors.0, g, MAX_ROUND).is_err());
        }
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn legacy_storage_names_refuse_creation_reopen_and_observation_without_writes() {
    use std::collections::BTreeMap;
    fn image(path: &std::path::Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_str().unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    for name in [
        "artifact-chain.journal",
        "ARTIFACT-CHAIN.JOURNAL",
        "Research-Finality.Anchor",
        "Fixed-Validator-Vote-Safety-fixture.journal",
        "artifact-chain.lock",
        "research-finality.anchor",
        "research-signer-fixture.journal",
        "fixed-validator-finality.anchor",
        "candidate-blocks.journal",
        "payload-store.journal",
    ] {
        for anchor in [false, true] {
            let dir = Directory::new();
            let anchors = Directory::new();
            fs::write(
                if anchor { &anchors.0 } else { &dir.0 }.join(name),
                b"retained old authority",
            )
            .unwrap();
            let before = (image(&dir.0), image(&anchors.0));
            let g = genesis();
            assert!(matches!(
                StateHistory::create(&dir.0, &anchors.0, g.clone(), MAX_ROUND),
                Err(StateStorageError::Invalid(_))
            ));
            assert!(matches!(
                StateHistory::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND),
                Err(StateStorageError::Invalid(_))
            ));
            assert!(matches!(
                StateObserver::open(&dir.0, &anchors.0, g.clone(), MAX_ROUND),
                Err(StateStorageError::Invalid(_))
            ));
            #[cfg(unix)]
            {
                assert!(matches!(
                    StateSigner::create(&dir.0, &anchors.0, g.clone(), validator(0), MAX_ROUND),
                    Err(StateStorageError::Invalid(_))
                ));
                assert!(matches!(
                    StateSigner::open(&dir.0, &anchors.0, g, validator(0), MAX_ROUND),
                    Err(StateStorageError::Invalid(_))
                ));
            }
            assert_eq!((image(&dir.0), image(&anchors.0)), before);
        }
    }
}
