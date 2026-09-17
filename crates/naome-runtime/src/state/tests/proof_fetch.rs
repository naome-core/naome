use super::*;
use ed25519_dalek::Signer;
use naome_consensus::state::{
    ResearchLockEvent, ResearchLockState, ResearchPublication, ResearchQuorum,
};
use naome_ledger::{
    CommitmentId, library::ProofPackage, operations::SignedOriginal, time::TimeCertificate,
};
use naome_network::{NetworkEvent, PeerSessionEvent};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use naome_protocol::state_exchange::ResearchResponseBody;

fn append(history: &mut ResearchHistory, now: u64, operations: Vec<SignedOperation>) {
    let branch = history.head().unwrap();
    let state = branch.state();
    let time = TimeCertificate::new(
        (0..3)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.head(),
                    state.height() + 1,
                    now,
                    &consensus(i),
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap();
    let record = state
        .prepare_record(time, operations)
        .unwrap()
        .record()
        .encode()
        .unwrap();
    let proposer = branch.proposer(0, 8).unwrap();
    let signer = (0..4)
        .map(consensus)
        .find(|key| key.verifying_key().as_bytes() == proposer.as_bytes())
        .unwrap();
    let mut kernel = ResearchLockState::new(branch, proposer).unwrap();
    let intent = kernel
        .apply(
            branch,
            &ResearchLockEvent::Author {
                record: Some(record),
            },
            8,
        )
        .unwrap();
    let signature = signer.sign(&intent.signing_bytes().unwrap()).to_bytes();
    let ResearchPublication::Proposal(proposal) = intent.complete(signature, branch, 8).unwrap()
    else {
        panic!("proposal")
    };
    let encoded = proposal.encode().unwrap();
    let mut kernels: Vec<_> = (0..3)
        .map(|i| {
            ResearchLockState::new(
                branch,
                ConsensusKey::from_bytes(consensus(i).verifying_key().to_bytes()),
            )
            .unwrap()
        })
        .collect();
    let mut votes = Vec::new();
    for (i, kernel) in kernels.iter_mut().enumerate() {
        let intent = kernel
            .apply(
                branch,
                &ResearchLockEvent::Prevote {
                    proposal: Some(encoded.clone()),
                },
                8,
            )
            .unwrap();
        let signature = consensus(i as u8)
            .sign(&intent.signing_bytes().unwrap())
            .to_bytes();
        let ResearchPublication::Vote(vote) = intent.complete(signature, branch, 8).unwrap() else {
            panic!("prevote")
        };
        votes.push(vote);
    }
    let prevotes = ResearchQuorum::from_votes(votes, state.genesis()).unwrap();
    let mut votes = Vec::new();
    for (i, kernel) in kernels.iter_mut().enumerate() {
        let intent = kernel
            .apply(
                branch,
                &ResearchLockEvent::Precommit {
                    proposal: Some(encoded.clone()),
                    quorum: prevotes.encode(),
                },
                8,
            )
            .unwrap();
        let signature = consensus(i as u8)
            .sign(&intent.signing_bytes().unwrap())
            .to_bytes();
        let ResearchPublication::Vote(vote) = intent.complete(signature, branch, 8).unwrap() else {
            panic!("precommit")
        };
        votes.push(vote);
    }
    let precommits = ResearchQuorum::from_votes(votes, state.genesis()).unwrap();
    let finality = branch
        .verify_finality(&proposal, &precommits, 8)
        .unwrap()
        .encode()
        .unwrap();
    history.append_finality(&finality).unwrap();
}
fn sign(history: &ResearchHistory, index: u8, body: OperationBody) -> SignedOperation {
    let state = history.head().unwrap().state();
    let id = AccountId::for_key(account(index).verifying_key().as_bytes());
    body.sign(
        state.genesis(),
        state.next_nonce(id).unwrap(),
        &account(index),
    )
    .unwrap()
}
fn selected_history(
    g: Genesis,
) -> (
    Directory,
    Directory,
    ResearchHistory,
    ProofId,
    ProofId,
    Vec<u8>,
) {
    let directory = Directory::new();
    let anchors = Directory::new();
    let mut history = ResearchHistory::create(&directory.0, &anchors.0, g.clone(), 8).unwrap();
    let question = CompiledQuestion::compile(
        "foundation = \"naome:zfc\"\nstatement = forall(y,forall(x,equal(x,x)))",
        g.profile(),
    )
    .unwrap();
    let op = sign(
        &history,
        4,
        OperationBody::Submit {
            purpose: "actual remote proof retrieval".into(),
            question,
        },
    );
    append(&mut history, 100, vec![op]);
    append(&mut history, 100, vec![]);
    let active = history.head().unwrap().state().active().unwrap();
    let votes = (0..3)
        .map(|i| {
            sign(
                &history,
                i,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    append(&mut history, 100, votes);
    let voting_deadline = active.deadline.unwrap();
    append(&mut history, voting_deadline, vec![]);
    append(&mut history, voting_deadline, vec![]);
    let round = history
        .head()
        .unwrap()
        .state()
        .active()
        .unwrap()
        .solution_round
        .unwrap();
    let x = naome_foundation::FreeVariable::new(0);
    let mut context = naome_checker::ArtifactState::new();
    let helper = naome_checker::check_normal_form_with_state(
        ProofCertificate::new(vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap()
        .into_unchecked_normal_form(),
        &context,
    )
    .unwrap();
    let proof = helper.proof_id();
    let bytes = helper.normal_form().canonical_bytes().to_vec();
    context.register_proof(helper).unwrap();
    let root = naome_checker::check_normal_form_with_state(
        ProofCertificate::new(vec![
            ProofStep::ProofReference { proof_id: proof },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap()
        .into_unchecked_normal_form(),
        &context,
    )
    .unwrap();
    let root_id = root.proof_id();
    let author = AccountId::for_key(account(4).verifying_key().as_bytes());
    let package = ProofPackage::new(
        author,
        root_id,
        vec![
            (proof, bytes.clone()),
            (root_id, root.normal_form().canonical_bytes().to_vec()),
        ],
        g.profile(),
    )
    .unwrap();
    let original = SignedOriginal::sign(&g, round, package, &account(4)).unwrap();
    let secret = [4; 32];
    let commitment =
        CommitmentId::for_original(&g, round, author, original.original_hash(), &secret);
    let op = sign(&history, 4, OperationBody::Commit { round, commitment });
    let now = history.head().unwrap().state().time();
    append(&mut history, now, vec![op]);
    let commitment_deadline = history
        .head()
        .unwrap()
        .state()
        .active()
        .unwrap()
        .deadline
        .unwrap();
    append(&mut history, commitment_deadline, vec![]);
    append(&mut history, commitment_deadline, vec![]);
    let op = sign(
        &history,
        4,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    append(&mut history, commitment_deadline, vec![op]);
    let reveal_deadline = history
        .head()
        .unwrap()
        .state()
        .active()
        .unwrap()
        .deadline
        .unwrap();
    append(&mut history, reveal_deadline, vec![]);
    append(&mut history, reveal_deadline, vec![]);
    assert_eq!(
        history
            .head()
            .unwrap()
            .state()
            .library()
            .lookup(proof)
            .unwrap()
            .canonical_bytes(),
        bytes
    );
    (directory, anchors, history, proof, root_id, bytes)
}
async fn pair() -> (
    Directory,
    Directory,
    ResearchRuntime,
    StaticArtifactNetwork,
    ProofId,
    ProofId,
    Vec<u8>,
) {
    let listeners: Vec<_> = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let base = genesis();
    let mut validators = base.validators().to_vec();
    // Genesis sorts registrations by consensus key, so find the transport index.
    for validator in &mut validators {
        let index = (0..4)
            .find(|i| {
                SigningKey::from_bytes(&[201 + *i; 32])
                    .verifying_key()
                    .as_bytes()
                    == &validator.transport_key
            })
            .unwrap();
        validator.endpoint = listeners[index as usize].local_addr().unwrap().to_string();
    }
    let mut limits = base.profile().limits().clone();
    limits.run_records = 66;
    let g = Genesis::new(
        Profile::with_limits(TimingKind::ShortTest, limits).unwrap(),
        base.foundation().into(),
        base.checker_profile().into(),
        1,
        100,
        [9; 32],
        base.accounts().iter().map(|a| *a.key()).collect(),
        validators,
    )
    .unwrap();
    drop(listeners);
    let (directory, anchors, history, proof, root, bytes) = selected_history(g.clone());
    let mut a = StaticArtifactNetwork::new_research(transport(0), &g).unwrap();
    let mut b = StaticArtifactNetwork::new_research(transport(1), &g).unwrap();
    a.listen_on(a.research_listen_address().unwrap().clone())
        .unwrap();
    b.listen_on(b.research_listen_address().unwrap().clone())
        .unwrap();
    let (pa, pb) = (a.local_peer_id(), b.local_peer_id());
    let (mut ready_a, mut ready_b) = (false, false);
    tokio::time::timeout(Duration::from_secs(10),async {while !ready_a || !ready_b {tokio::select! {
        event=a.next_event()=>if let NetworkEvent::PeerSession(PeerSessionEvent::Established{peer_id})=event {ready_a|=peer_id==pb;},
        event=b.next_event()=>if let NetworkEvent::PeerSession(PeerSessionEvent::Established{peer_id})=event {ready_b|=peer_id==pa;},
    }}}).await.unwrap();
    let runtime = ResearchRuntime::new(
        history,
        None,
        a,
        (1..4).map(|i| transport(i).public().to_peer_id()).collect(),
        ResearchRuntimeConfig {
            allow_simulation_controls: true,
            ..ResearchRuntimeConfig::default()
        },
    )
    .unwrap();
    (directory, anchors, runtime, b, proof, root, bytes)
}
async fn respond(
    runtime: &mut ResearchRuntime,
    server: &mut StaticArtifactNetwork,
    response: ResearchResponseBody,
) {
    runtime.flush().unwrap();
    let mut response = Some(response);
    tokio::time::timeout(Duration::from_secs(10),async {loop {tokio::select! {
        event=runtime.network.next_event()=>{
            let done=matches!(event,NetworkEvent::OutboundResearch(_));runtime.network_event(event).unwrap();if done {break;}
        },
        event=server.next_event()=>if let NetworkEvent::InboundResearch(inbound)=event {
            assert_eq!(inbound.peer_id(),runtime.local_peer_id());assert!(matches!(inbound.request().body(),ResearchRequestBody::Proof{..}));
            server.respond_research(inbound,response.take().unwrap()).unwrap();
        },
    }}}).await.unwrap();
}
#[tokio::test]
async fn actual_noise_proof_fetch_checks_selected_bytes_and_bounds_retention() {
    let (_directory, _anchors, mut runtime, mut server, proof, root, bytes) = pair().await;
    let peer = server.local_peer_id();
    assert!(runtime.take_proof_fetch(peer, proof).is_err());
    runtime.start_proof_fetch(peer, proof).unwrap();
    runtime.start_proof_fetch(peer, proof).unwrap();
    assert_eq!(runtime.proof_fetches.len(), 1);
    assert!(runtime.take_proof_fetch(peer, proof).unwrap().is_none());
    runtime.on_height().unwrap();
    assert_eq!(runtime.proof_fetches.len(), 1);
    respond(
        &mut runtime,
        &mut server,
        ResearchResponseBody::Proof {
            proof_id: proof,
            certificate: bytes.clone().into(),
        },
    )
    .await;
    assert_eq!(
        runtime.take_proof_fetch(peer, proof).unwrap(),
        Some(bytes.clone())
    );
    assert!(runtime.proof_fetches.is_empty());
    runtime.start_proof_fetch(peer, proof).unwrap();
    let mut altered = bytes.clone();
    altered[0] ^= 1;
    respond(
        &mut runtime,
        &mut server,
        ResearchResponseBody::Proof {
            proof_id: proof,
            certificate: altered.into(),
        },
    )
    .await;
    assert!(
        runtime
            .take_proof_fetch(peer, proof)
            .unwrap_err()
            .to_string()
            .contains("differs")
    );
    runtime.start_proof_fetch(peer, proof).unwrap();
    respond(&mut runtime, &mut server, ResearchResponseBody::Unavailable).await;
    assert!(
        runtime
            .take_proof_fetch(peer, proof)
            .unwrap_err()
            .to_string()
            .contains("unavailable")
    );
    runtime.start_proof_fetch(peer, proof).unwrap();
    assert!(
        runtime
            .validate_proof_fetch_response(
                0,
                &ResearchResponseBody::Proof {
                    proof_id: root,
                    certificate: bytes.into()
                }
            )
            .is_err()
    );
    for remote in runtime.peers.clone().into_iter().filter(|p| *p != peer) {
        runtime.start_proof_fetch(remote, proof).unwrap();
    }
    runtime.start_proof_fetch(peer, root).unwrap();
    assert_eq!(runtime.proof_fetches.len(), 4);
    let remote = *runtime.peers.iter().find(|p| **p != peer).unwrap();
    assert!(runtime.start_proof_fetch(remote, root).is_err());
    // Four abandoned terminal results cannot wedge future local requests.
    // A completed result remains retained until its original deadline.
    for fetch in &mut runtime.proof_fetches {
        fetch.outcome = Some(Err("orphaned completion".into()));
    }
    assert!(runtime.start_proof_fetch(remote, root).is_err());
    assert_eq!(runtime.proof_fetches.len(), 4);
    let retained = (
        runtime.proof_fetches[1].peer,
        runtime.proof_fetches[1].proof,
    );
    runtime.proof_fetches[1].outcome = None;
    for (index, fetch) in runtime.proof_fetches.iter_mut().enumerate() {
        if index != 1 {
            fetch.deadline = Instant::now();
        }
    }
    runtime.start_proof_fetch(peer, proof).unwrap();
    assert_eq!(runtime.proof_fetches.len(), 2);
    assert!(
        runtime
            .proof_fetches
            .iter()
            .any(|fetch| (fetch.peer, fetch.proof) == retained && fetch.outcome.is_none())
    );
    for fetch in &mut runtime.proof_fetches {
        fetch.deadline = Instant::now();
    }
    // Expired pending jobs become explicit terminal timeouts, then are also
    // reclaimable when a new caller starts another request.
    runtime.start_proof_fetch(peer, root).unwrap();
    assert_eq!(runtime.proof_fetches.len(), 1);
    runtime.proof_fetches[0].deadline = Instant::now();
    assert!(
        runtime
            .take_proof_fetch(peer, root)
            .unwrap_err()
            .to_string()
            .contains("timed out")
    );
    runtime.start_proof_fetch(peer, proof).unwrap();
    runtime.proof_fetches[0].deadline = Instant::now();
    assert!(
        runtime
            .take_proof_fetch(peer, proof)
            .unwrap_err()
            .to_string()
            .contains("timed out")
    );
    runtime.start_proof_fetch(peer, root).unwrap();
    runtime.set_peer_enabled(peer, false).unwrap();
    assert!(runtime.start_proof_fetch(peer, proof).is_err());
    assert!(
        runtime
            .take_proof_fetch(peer, root)
            .unwrap_err()
            .to_string()
            .contains("disabled")
    );
}
