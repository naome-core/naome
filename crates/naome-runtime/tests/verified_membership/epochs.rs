use super::*;
use naome_foundation::{Formula, FreeVariable};

fn numbered_payload(number: u64) -> Vec<u8> {
    let x = FreeVariable::new(0);
    let mut formula = Formula::equal(x, x);
    for bit in 0..16 {
        let atom = if number & (1 << bit) == 0 {
            Formula::equal(x, x)
        } else {
            Formula::member(x, x)
        };
        formula = Formula::implies(atom, formula);
    }
    ArtifactPayload::Proof(
        ProofCertificate::new(vec![
            ProofStep::Simplification {
                antecedent: formula.into(),
                consequent: Formula::equal(x, x).into(),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ])
        .unwrap()
        .into_unchecked_normal_form()
        .certificate()
        .clone(),
    )
    .to_canonical_bytes()
}

fn approved(
    request: MembershipRequest,
    snapshot: &MembershipSnapshot,
) -> ApprovedMembershipRequest {
    let approvals = snapshot
        .members()
        .iter()
        .take(snapshot.quorum())
        .map(|member| {
            MembershipApproval::sign(
                &request,
                snapshot,
                member.organization,
                &keys(member.organization[0])[1],
            )
            .unwrap()
        })
        .collect();
    ApprovedMembershipRequest::new(request, approvals, snapshot).unwrap()
}

fn finalized(
    branch: &MembershipBranch,
    artifacts: &mut ArtifactChainState,
    height: u64,
    operation: Option<ApprovedMembershipRequest>,
) -> MembershipFinalityProof {
    let payload = numbered_payload(height);
    let id = ArtifactDag::new()
        .apply_canonical_artifact_bytes(payload.clone())
        .unwrap()
        .artifact_id();
    let artifact = artifacts.prepare_block(id).unwrap();
    let value = branch.value(artifact, operation).unwrap();
    let proposer = branch.proposer(0, 64).unwrap();
    let signer = (1..=5)
        .map(keys)
        .find(|key| key[0].verifying_key().to_bytes() == proposer)
        .unwrap();
    let coordinate = branch
        .vote_coordinate(0, MembershipVoteRole::Precommit, Some(value.root()))
        .unwrap();
    let votes = branch
        .next_snapshot()
        .unwrap()
        .members()
        .iter()
        .take(branch.next_snapshot().unwrap().quorum())
        .map(|member| MembershipVote::sign(coordinate, &keys(member.organization[0])[0]))
        .collect::<Vec<_>>();
    let proof = MembershipFinalityProof {
        proposal: MembershipProposal::sign(value, 0, None, &signer[0]),
        payload: payload.clone(),
        certificate: MembershipCertificate::from_votes(&votes, branch.next_snapshot().unwrap())
            .unwrap(),
    };
    artifacts.apply_block(&artifact, payload).unwrap();
    proof
}

/// Full public protocol epochs, without synthetic heights or shortened activation.
/// This expensive qualification is run explicitly by required Linux CI.
#[tokio::test(flavor = "current_thread")]
#[ignore = "full 32770-height membership qualification; run explicitly in release"]
async fn full_epochs_join_removal_and_independent_durable_replay() {
    let directory = Directory::new();
    let mut nodes: Vec<_> = (1..=5)
        .map(|id| {
            MembershipNode::new(
                MembershipJournal::create(
                    &directory.0.join(format!("j{id}")),
                    &directory.0.join(format!("a{id}")),
                    genesis(),
                    Some(keys(id)[0].clone()),
                    limits(),
                )
                .unwrap(),
            )
            .unwrap()
        })
        .collect();
    let mut branch = genesis();
    let mut artifacts = ArtifactChainState::new(definition());
    let start = std::time::Instant::now();
    for height in 1..=32770 {
        let operation = if height == 1 {
            let applicant = keys(5);
            Some(approved(
                MembershipRequest::join(
                    branch.next_snapshot().unwrap(),
                    member(5),
                    [&applicant[0], &applicant[1], &applicant[2]],
                )
                .unwrap(),
                branch.next_snapshot().unwrap(),
            ))
        } else if height == 16385 {
            Some(approved(
                MembershipRequest::remove(branch.next_snapshot().unwrap(), [1; 32]).unwrap(),
                branch.next_snapshot().unwrap(),
            ))
        } else {
            None
        };
        let mut proof = finalized(&branch, &mut artifacts, height, operation);
        if height == 16385 {
            assert_eq!(branch.next_snapshot().unwrap().quorum(), 4);
            let old_votes = (1..=3)
                .map(|id| MembershipVote::sign(proof.certificate.coordinate(), &keys(id)[0]))
                .collect::<Vec<_>>();
            assert!(
                MembershipCertificate::from_votes(&old_votes, branch.next_snapshot().unwrap())
                    .is_err()
            );
        }
        if height == 32769 {
            let removed = MembershipVote::sign(proof.certificate.coordinate(), &keys(1)[0]);
            assert!(branch.verify_vote(&removed, 64).is_err());
        }
        if [16384, 16385, 32768, 32769].contains(&height) {
            (nodes, proof) = live_boundary(nodes, &proof, height == 16385 || height == 32769).await;
        } else {
            // Distinct journal/anchor owners verify and synchronize every
            // height independently; overlap their I/O instead of serializing it.
            std::thread::scope(|workers| {
                for node in &mut nodes {
                    let proof = &proof;
                    workers.spawn(move || {
                        node.receive(MembershipPublication::Finality(proof.clone()))
                            .unwrap();
                    });
                }
            });
        }
        branch = branch
            .verify_finality(
                proof.proposal.clone(),
                proof.payload.clone(),
                proof.certificate.clone(),
                64,
            )
            .unwrap()
            .into_branch();
        for node in &nodes {
            assert_eq!(
                node.machine().unwrap().branch().ancestry(),
                branch.ancestry()
            );
        }
        if [16383, 16384, 16385, 32767, 32768, 32769].contains(&height) {
            assert_eq!(nodes[4].machine().unwrap().is_active(), height >= 16384);
            assert_eq!(nodes[0].machine().unwrap().is_active(), height < 32768);
        }
        if height % 1024 == 0 {
            eprintln!(
                "membership qualification height={height} seconds={:.1}",
                start.elapsed().as_secs_f64()
            );
        }
    }
    drop(nodes);
    eprintln!(
        "membership prefix complete seconds={:.1}",
        start.elapsed().as_secs_f64()
    );
    let expected_ancestry = branch.ancestry();
    std::thread::scope(|workers| {
        for id in 1..=5 {
            let directory = &directory.0;
            workers.spawn(move || {
                let replay_started = std::time::Instant::now();
                let journal = MembershipJournal::open(
                    &directory.join(format!("j{id}")),
                    &directory.join(format!("a{id}")),
                    genesis(),
                    Some(keys(id)[0].clone()),
                    limits(),
                )
                .unwrap();
                assert_eq!(
                    journal.machine().unwrap().branch().ancestry(),
                    expected_ancestry
                );
                assert_eq!(journal.machine().unwrap().is_active(), id != 1);
                assert_eq!(
                    journal
                        .machine()
                        .unwrap()
                        .branch()
                        .next_snapshot()
                        .unwrap()
                        .members()
                        .len(),
                    4
                );
                assert_eq!(
                    journal
                        .machine()
                        .unwrap()
                        .branch()
                        .membership()
                        .pending_activation(),
                    None
                );
                eprintln!(
                    "membership independent replay organization={id} seconds={:.1}",
                    replay_started.elapsed().as_secs_f64()
                );
            });
        }
    });
    eprintln!(
        "membership qualification complete seconds={:.1}",
        start.elapsed().as_secs_f64()
    );
}

async fn pump(runtimes: &mut [MembershipRuntime; 5], partition_first: bool) {
    let [a, b, c, d, e] = runtimes;
    tokio::select! {
        result = a.next_event(), if !partition_first => { result.unwrap(); },
        result = b.next_event() => { result.unwrap(); },
        result = c.next_event() => { result.unwrap(); },
        result = d.next_event() => { result.unwrap(); },
        result = e.next_event() => { result.unwrap(); },
        _ = tokio::time::sleep(Duration::from_secs(10)) => panic!("activation network stopped"),
    }
}

async fn live_boundary(
    nodes: Vec<MembershipNode>,
    expected: &MembershipFinalityProof,
    partition_first: bool,
) -> (Vec<MembershipNode>, MembershipFinalityProof) {
    let sockets: Vec<_> = (0..5)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let addresses: Vec<naome_network::Multiaddr> = sockets
        .iter()
        .map(|socket| {
            format!("/ip4/127.0.0.1/tcp/{}", socket.local_addr().unwrap().port())
                .parse()
                .unwrap()
        })
        .collect();
    drop(sockets);
    let peers: Vec<_> = (1..=5)
        .map(|id| network_key(id).public().to_peer_id())
        .collect();
    let mut runtimes: [MembershipRuntime; 5] = nodes
        .into_iter()
        .enumerate()
        .map(|(index, mut node)| {
            if let Some(operation) = expected.proposal.value.operation() {
                node.ingest_request(operation.request().clone()).unwrap();
                for approval in operation.approvals() {
                    node.ingest_approval(approval.clone()).unwrap();
                }
            }
            let bootstrap = (0..5)
                .filter(|peer| *peer != index)
                .map(|peer| StaticPeer::new(peers[peer], addresses[peer].clone()))
                .collect();
            let mut network = MembershipNetwork::new(
                network_key(index as u8 + 1),
                bootstrap,
                node.snapshot().unwrap(),
            )
            .unwrap();
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
        })
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .unwrap();
    runtimes[1]
        .node_mut()
        .ingest_candidate(MembershipCandidate {
            context: expected.proposal.value.context(),
            artifact: expected.proposal.value.artifact(),
            payload: expected.payload.clone(),
        })
        .unwrap();
    let height = expected.proposal.value.height();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    while runtimes.iter().enumerate().any(|(index, runtime)| {
        (!partition_first || index != 0)
            && runtime.node().machine().unwrap().branch().height() < height
    }) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "activation finality {height}"
        );
        pump(&mut runtimes, partition_first).await;
    }
    let proof = runtimes[1]
        .node_mut()
        .finalized_proof(height)
        .unwrap()
        .unwrap();
    assert_eq!(proof.proposal.value, expected.proposal.value);
    if partition_first {
        assert_eq!(
            runtimes[0].node().machine().unwrap().branch().height(),
            height - 1
        );
    }
    while runtimes[0].node().machine().unwrap().branch().height() < height {
        assert!(
            tokio::time::Instant::now() < deadline,
            "activation partition heal {height}"
        );
        pump(&mut runtimes, false).await;
    }
    eprintln!(
        "membership live activation height={height} partition_first={partition_first} round={}",
        proof.proposal.round
    );
    (
        runtimes
            .into_iter()
            .map(MembershipRuntime::into_node)
            .collect(),
        proof,
    )
}
