use super::*;
use naome_ledger::state::Phase;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn select_exact(
    runtime: &mut StateRuntime,
    directory: &Directory,
    anchors: &Directory,
    bytes: &[u8],
) {
    let old_key = runtime.node.signer_key().unwrap();
    let index = owner_index(
        runtime
            .state()
            .unwrap()
            .authority()
            .consensus_unit(old_key.as_bytes())
            .unwrap()
            .owner(),
    );
    runtime.node.accept_finality(bytes).unwrap();
    let selected = runtime.state().unwrap();
    let key = period_key(index, selected.authority().effective_height(), 1);
    let signer =
        StateSigner::create_for_selected(&directory.0, &anchors.0, runtime.history(), key, 8)
            .unwrap();
    let journal = StateHandoffJournal::create(
        &directory.0,
        &anchors.0,
        selected.genesis().clone(),
        selected.height() + 1,
        8,
    )
    .unwrap();
    runtime
        .node
        .install_selected_signer(signer, journal)
        .unwrap();
    runtime.on_height().unwrap();
}

#[test]
fn newer_preview_does_not_dispose_parent_valid_ballot_before_selected_phase_closes() {
    let (directory, anchors, mut runtime) = registration::registration_runtime();
    let genesis = runtime.state().unwrap().genesis().clone();
    registration::finalize(
        &mut runtime,
        &directory,
        &anchors,
        101,
        vec![operation(&genesis, 1)],
    );
    registration::finalize(&mut runtime, &directory, &anchors, 102, vec![]);
    runtime.pending_store =
        Some(StatePendingActions::create(&directory.0, &anchors.0, genesis.clone()).unwrap());
    let active = runtime.state().unwrap().active().unwrap();
    let deadline = active.deadline.unwrap();
    let owner = AccountId::for_key(account(0).verifying_key().as_bytes());
    let vote = OperationBody::Vote {
        question: active.question,
        attempt: active.number,
        yes: true,
    }
    .sign(
        &genesis,
        runtime.state().unwrap().next_nonce(owner).unwrap(),
        &account(0),
    )
    .unwrap();
    let id = runtime.submit_operation(vote.clone()).unwrap();
    assert_eq!(runtime.pending.get(&id).unwrap().encode(), vote.encode());
    assert!(matches!(
        runtime.pending_store.as_ref().unwrap().status(id),
        Some(PendingActionStatus::Pending)
    ));
    // A different proposer has already prepared this fully sealed, valid record.
    // Its exact signed certificate remains before the unchanged voting deadline.
    let older = proof_fetch::finality(runtime.history().head().unwrap(), deadline - 1, vec![]);
    let verified = runtime
        .history()
        .head()
        .unwrap()
        .decode_finality(&older, 8)
        .unwrap();
    let older_head = verified.branch().state().head();
    assert_eq!(
        verified.branch().state().active().unwrap().phase,
        Phase::Voting
    );
    assert_eq!(
        verified.branch().state().active().unwrap().deadline,
        Some(deadline)
    );
    let local_evidence = Directory::new();
    let evidence = &local_evidence.0;
    fs::write(evidence.join("parent-valid-ballot.bin"), vote.encode()).unwrap();
    fs::write(evidence.join("older-valid-foreign-finality.bin"), &older).unwrap();
    fs::write(evidence.join("profile.bin"), genesis.profile().encode()).unwrap();
    if let Ok(destination) = std::env::var("NAOME_COUNTERCASE_EVIDENCE") {
        let destination = PathBuf::from(destination);
        for name in [
            "parent-valid-ballot.bin",
            "older-valid-foreign-finality.bin",
            "profile.bin",
        ] {
            fs::copy(evidence.join(name), destination.join(name)).unwrap();
        }
    }
    println!(
        "frozen_fixture action_sha256={} foreign_finality_sha256={} parent_height={} deadline={} older_certificate_time={}",
        digest(&vote.encode()),
        digest(&older),
        runtime.state().unwrap().height(),
        deadline,
        verified.branch().state().time()
    );
    drop(verified);
    let selected_before = runtime.state().unwrap().head();
    let preview = registration::prepare(&mut runtime, deadline);
    assert_eq!(
        runtime
            .state()
            .unwrap()
            .validate_record(&preview)
            .unwrap()
            .state()
            .time(),
        deadline
    );
    assert_eq!(runtime.state().unwrap().head(), selected_before);
    println!(
        "after_future_preview pending={} local_rejection={:?}",
        runtime.pending.contains_key(&id),
        runtime.operation_rejection(id)
    );
    // Select the exact older bytes frozen before the preview, not a rebuilt record.
    select_exact(&mut runtime, &directory, &anchors, &older);
    assert_eq!(runtime.state().unwrap().head(), older_head);
    assert_eq!(
        runtime.state().unwrap().active().unwrap().phase,
        Phase::Voting
    );
    assert_eq!(
        runtime.state().unwrap().active().unwrap().deadline,
        Some(deadline)
    );
    assert_eq!(
        runtime.state().unwrap().next_nonce(owner),
        Some(vote.nonce())
    );
    println!(
        "older_foreign_selected=true current_ballot_phase_valid={}",
        runtime
            .validate_queue_phase(
                &OperationBody::decode(vote.payload(), &genesis).unwrap(),
                owner
            )
            .is_ok()
    );
    assert_eq!(
        runtime.pending.get(&id).map(SignedOperation::encode),
        Some(vote.encode()),
        "a future local preview must retain exact parent-valid custody until selected phase or nonce disposes it"
    );
    assert!(runtime.operation_rejection(id).is_none());
    assert!(matches!(
        runtime.pending_store.as_ref().unwrap().status(id),
        Some(PendingActionStatus::Pending)
    ));
    let included =
        proof_fetch::finality(runtime.history().head().unwrap(), deadline - 1, vec![vote]);
    select_exact(&mut runtime, &directory, &anchors, &included);
    assert!(runtime.state().unwrap().receipt(id).is_some());
    assert!(!runtime.pending.contains_key(&id));
    println!("retained_exact_ballot_finalized=true");
}

fn pending_ballot() -> (
    Directory,
    Directory,
    StateRuntime,
    Genesis,
    SignedOperation,
    u64,
) {
    let (directory, anchors, mut runtime) = registration::registration_runtime();
    let genesis = runtime.state().unwrap().genesis().clone();
    registration::finalize(
        &mut runtime,
        &directory,
        &anchors,
        101,
        vec![operation(&genesis, 1)],
    );
    registration::finalize(&mut runtime, &directory, &anchors, 102, vec![]);
    runtime.pending_store =
        Some(StatePendingActions::create(&directory.0, &anchors.0, genesis.clone()).unwrap());
    let active = runtime.state().unwrap().active().unwrap();
    let owner = AccountId::for_key(account(0).verifying_key().as_bytes());
    let vote = OperationBody::Vote {
        question: active.question,
        attempt: active.number,
        yes: true,
    }
    .sign(
        &genesis,
        runtime.state().unwrap().next_nonce(owner).unwrap(),
        &account(0),
    )
    .unwrap();
    runtime.submit_operation(vote.clone()).unwrap();
    (
        directory,
        anchors,
        runtime,
        genesis,
        vote,
        active.deadline.unwrap(),
    )
}

fn seed_time(runtime: &mut StateRuntime, now: u64) {
    seed_offers(runtime);
    let state = runtime.state().unwrap();
    let reports: Vec<_> = (0..3)
        .map(|i| {
            SignedTimeReport::sign(
                state.genesis(),
                state.authority(),
                state.head(),
                state.height() + 1,
                now,
                &period_key(i, state.authority().effective_height(), 1),
            )
            .unwrap()
        })
        .collect();
    runtime.time_reports.clear();
    for report in reports {
        runtime.time_reports.insert(report.validator(), report);
    }
}

fn local_owner(runtime: &StateRuntime) -> u8 {
    owner_index(
        runtime
            .state()
            .unwrap()
            .authority()
            .consensus_unit(runtime.node.signer_key().unwrap().as_bytes())
            .unwrap()
            .owner(),
    )
}

fn reopen_pending(
    directory: &Directory,
    anchors: &Directory,
    genesis: &Genesis,
    owner: u8,
) -> StateRuntime {
    let history = StateHistory::open(&directory.0, &anchors.0, genesis.clone(), 8).unwrap();
    let selected = history.head().unwrap().state().clone();
    let period = selected.authority().effective_height();
    let signer = StateSigner::open_for_selected(
        &directory.0,
        &anchors.0,
        &history,
        period_key(owner, period, 1),
        8,
    )
    .unwrap();
    let mut seed = period_key(owner, period, 2).to_bytes();
    let network =
        StateNetwork::new_for_parent(Keypair::ed25519_from_bytes(&mut seed).unwrap(), &selected)
            .unwrap();
    let local = network.local_peer_id();
    let peers = selected
        .authority()
        .units()
        .iter()
        .filter_map(|unit| unit.keys())
        .map(|keys| naome_network::state_peer_id(*keys.transport()).unwrap())
        .filter(|peer| *peer != local)
        .collect();
    StateRuntime::new(
        history,
        Some(signer),
        network,
        peers,
        StateRuntimeConfig {
            pending_store: Some((directory.0.clone(), anchors.0.clone())),
            ..StateRuntimeConfig::default()
        },
    )
    .unwrap()
}

#[test]
fn selected_phase_closure_disposes_retained_ballot_without_finalized_receipt() {
    let (directory, anchors, mut runtime, genesis, vote, deadline) = pending_ballot();
    let id = vote.id();
    let closed = proof_fetch::finality(runtime.history().head().unwrap(), deadline, vec![]);
    registration::prepare(&mut runtime, deadline);
    assert_eq!(runtime.pending.get(&id).unwrap().encode(), vote.encode());
    select_exact(&mut runtime, &directory, &anchors, &closed);
    assert!(runtime.state().unwrap().active().is_none());
    assert!(runtime.state().unwrap().receipt(id).is_none());
    seed_time(&mut runtime, deadline);
    assert!(runtime.prepare_record().unwrap().is_none());
    assert!(!runtime.pending.contains_key(&id));
    assert!(
        runtime
            .operation_rejection(id)
            .unwrap()
            .contains("parent attempt")
    );
    let owner = local_owner(&runtime);
    let selected_head = runtime.state().unwrap().head();
    drop(runtime);
    let reopened = reopen_pending(&directory, &anchors, &genesis, owner);
    assert_eq!(reopened.state().unwrap().head(), selected_head);
    assert!(!reopened.pending.contains_key(&id));
    assert!(reopened.operation_rejection(id).is_some());
    assert!(reopened.state().unwrap().receipt(id).is_none());
}

#[test]
fn selected_nonce_conflict_durably_disposes_only_the_unselected_exact_ballot() {
    let (directory, anchors, mut runtime, genesis, vote, deadline) = pending_ballot();
    let active = runtime.state().unwrap().active().unwrap();
    let competing = OperationBody::Vote {
        question: active.question,
        attempt: active.number,
        yes: false,
    }
    .sign(&genesis, vote.nonce(), &account(0))
    .unwrap();
    assert_ne!(competing.id(), vote.id());
    let selected = proof_fetch::finality(
        runtime.history().head().unwrap(),
        deadline - 1,
        vec![competing.clone()],
    );
    registration::prepare(&mut runtime, deadline);
    assert_eq!(
        runtime.pending.get(&vote.id()).unwrap().encode(),
        vote.encode()
    );
    select_exact(&mut runtime, &directory, &anchors, &selected);
    assert!(runtime.state().unwrap().receipt(competing.id()).is_some());
    assert!(runtime.state().unwrap().receipt(vote.id()).is_none());
    assert!(!runtime.pending.contains_key(&vote.id()));
    assert!(
        runtime
            .operation_rejection(vote.id())
            .unwrap()
            .contains("nonce consumed")
    );
    let owner = local_owner(&runtime);
    drop(runtime);
    let reopened = reopen_pending(&directory, &anchors, &genesis, owner);
    assert!(!reopened.pending.contains_key(&vote.id()));
    assert!(
        reopened
            .operation_rejection(vote.id())
            .unwrap()
            .contains("nonce consumed")
    );
    assert!(reopened.state().unwrap().receipt(competing.id()).is_some());
    assert!(reopened.state().unwrap().receipt(vote.id()).is_none());
}

#[test]
fn retained_ballot_survives_actual_runtime_restart_and_selected_history_replay() {
    let (directory, anchors, mut runtime, genesis, vote, deadline) = pending_ballot();
    let older = proof_fetch::finality(runtime.history().head().unwrap(), deadline - 1, vec![]);
    registration::prepare(&mut runtime, deadline);
    let selected_before = runtime.state().unwrap().head();
    let owner = local_owner(&runtime);
    drop(runtime);
    let mut reopened = reopen_pending(&directory, &anchors, &genesis, owner);
    assert_eq!(reopened.state().unwrap().head(), selected_before);
    assert_eq!(
        reopened.pending.get(&vote.id()).unwrap().encode(),
        vote.encode()
    );
    assert!(reopened.operation_rejection(vote.id()).is_none());
    select_exact(&mut reopened, &directory, &anchors, &older);
    assert_eq!(
        reopened.pending.get(&vote.id()).unwrap().encode(),
        vote.encode()
    );
    let included = proof_fetch::finality(
        reopened.history().head().unwrap(),
        deadline - 1,
        vec![vote.clone()],
    );
    select_exact(&mut reopened, &directory, &anchors, &included);
    let selected_head = reopened.state().unwrap().head();
    assert!(reopened.state().unwrap().receipt(vote.id()).is_some());
    let owner = local_owner(&reopened);
    drop(reopened);
    let replayed = reopen_pending(&directory, &anchors, &genesis, owner);
    assert_eq!(replayed.state().unwrap().head(), selected_head);
    assert!(replayed.state().unwrap().receipt(vote.id()).is_some());
    assert!(!replayed.pending.contains_key(&vote.id()));
}

#[test]
fn intrinsic_ballot_signature_phase_and_nonce_errors_never_enter_durable_custody() {
    let (directory, anchors, mut runtime, genesis, vote, deadline) = pending_ballot();
    let body = OperationBody::decode(vote.payload(), &genesis).unwrap();
    let wrong_nonce = body.sign(&genesis, vote.nonce() + 1, &account(0)).unwrap();
    assert!(runtime.submit_operation(wrong_nonce.clone()).is_err());
    assert!(
        runtime
            .pending_store
            .as_ref()
            .unwrap()
            .status(wrong_nonce.id())
            .is_none()
    );
    let active = runtime.state().unwrap().active().unwrap();
    let wrong_attempt = OperationBody::Vote {
        question: active.question,
        attempt: active.number + 1,
        yes: true,
    }
    .sign(&genesis, vote.nonce(), &account(0))
    .unwrap();
    assert!(runtime.submit_operation(wrong_attempt.clone()).is_err());
    assert!(
        runtime
            .pending_store
            .as_ref()
            .unwrap()
            .status(wrong_attempt.id())
            .is_none()
    );
    let mut bad_bytes = vote.encode();
    *bad_bytes.last_mut().unwrap() ^= 1;
    let bad_signature = SignedOperation::decode(&bad_bytes).unwrap();
    assert!(runtime.submit_operation(bad_signature.clone()).is_err());
    assert_eq!(runtime.pending.len(), 1);
    assert_eq!(
        runtime.pending.get(&vote.id()).unwrap().encode(),
        vote.encode()
    );
    registration::prepare(&mut runtime, deadline);
    assert_eq!(
        runtime.pending.get(&vote.id()).unwrap().encode(),
        vote.encode()
    );
    let owner = local_owner(&runtime);
    drop(runtime);
    let reopened = reopen_pending(&directory, &anchors, &genesis, owner);
    assert_eq!(reopened.pending.len(), 1);
    assert_eq!(
        reopened.pending.get(&vote.id()).unwrap().encode(),
        vote.encode()
    );
    assert!(
        reopened
            .pending_store
            .as_ref()
            .unwrap()
            .status(wrong_nonce.id())
            .is_none()
    );
    assert!(
        reopened
            .pending_store
            .as_ref()
            .unwrap()
            .status(wrong_attempt.id())
            .is_none()
    );
}
