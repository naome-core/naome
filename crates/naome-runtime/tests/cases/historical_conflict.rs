use super::*;

struct HistoricalProof {
    proof: Proof,
    envelope: Vec<u8>,
    prevote: ConsensusPushMessage,
}

fn make_proof(
    fixture: &Fixture,
    prefix: &[&HistoricalProof],
    axiom: u8,
    minimum_round: u64,
) -> HistoricalProof {
    let prefix: Vec<_> = prefix
        .iter()
        .map(|proof| (proof.envelope.as_slice(), proof.proof.payload.as_slice()))
        .collect();
    let mut branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    for (envelope, payload) in &prefix {
        branch = branch
            .decode_and_verify_envelope_with_round_limit(
                envelope,
                payload.to_vec(),
                ConsensusRound::new(4),
            )
            .unwrap()
            .into_branch();
    }
    let payload = naome_proof::ArtifactPayload::Proof(
        naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom]).unwrap(),
    )
    .to_canonical_bytes();
    let [proposal, prevote, precommit] =
        source_messages_after_prefix(fixture, payload, &prefix, minimum_round, 3)
            .try_into()
            .unwrap();
    let proof = proof_at_branch(&branch, proposal, precommit, ConsensusVoteRole::Precommit);
    let mut round = branch.begin_round_zero().unwrap();
    while round.position().round() != proof.round {
        round = round.advance_round().unwrap();
    }
    let envelope = round
        .decode_and_verify_proposal_control(&proof.control, proof.payload.clone())
        .unwrap()
        .seal_with_precommit_vote_batch(&[&proof.vote])
        .unwrap()
        .into_owned()
        .canonical_envelope_bytes()
        .to_vec();
    HistoricalProof {
        proof,
        envelope,
        prevote,
    }
}

fn selected_scope<'node>(
    mut scope: naome_node::FixedValidatorNodeSigningScopeV0<'node>,
    prefix: &[&HistoricalProof],
) -> naome_node::FixedValidatorNodeSigningScopeV0<'node> {
    for proof in prefix {
        let transition = scope
            .branch()
            .decode_and_verify_envelope_with_round_limit(
                &proof.envelope,
                proof.proof.payload.clone(),
                ConsensusRound::new(4),
            )
            .unwrap();
        let naome_node::FixedValidatorNodeFinalityOutcomeV0::Continues { scope: next, .. } =
            scope.commit_verified_finality(transition).unwrap()
        else {
            panic!("selected prefix")
        };
        scope = *next;
    }
    scope
}

fn submit<'node>(owner: &mut Runtime<'node>, proof: &HistoricalProof, batch: bool) -> Event<'node> {
    if batch {
        owner.commit_historical_finality_conflict_vote_batch(
            &proof.proof.control,
            proof.proof.payload.clone(),
            &[&proof.proof.vote],
            proof.proof.round,
        )
    } else {
        owner.commit_historical_finality_conflict(&proof.envelope, proof.proof.payload.clone())
    }
    .unwrap()
}

fn assert_refund(owner: &mut Runtime<'_>, reason: Refusal) {
    for batch in [false, true] {
        let mut payload = vec![7; 13];
        payload.reserve(31);
        let original = allocations(&payload);
        let outcome = if batch {
            owner.commit_historical_finality_conflict_vote_batch(
                &[0],
                payload,
                &[],
                ConsensusRound::new(u64::MAX),
            )
        } else {
            owner.commit_historical_finality_conflict(&[0], payload)
        };
        let Err((actual, payload)) = outcome else {
            panic!("pre-invocation refund")
        };
        assert_eq!(actual, reason);
        assert_eq!(allocations(&payload), original);
        assert_eq!(payload, vec![7; 13]);
    }
}

#[test]
fn historical_conflict_preserves_current_some_publication_timer_and_inflight_input_through_halt_or_consuming_error()
 {
    let fixture = Fixture::new();
    let first = make_proof(&fixture, &[], 1, 0);
    let sibling = make_proof(&fixture, &[], 2, 2);
    let second = make_proof(&fixture, &[&first], 3, 0);
    let current = make_proof(&fixture, &[&first, &second], 2, 1);
    for batch in [false, true] {
        for distinct in [false, true] {
            for in_flight in [false, true] {
                let layout = TestLayout::new("runtime-historical-custody");
                let ready = provision(
                    fixture.definition,
                    fixture.context,
                    &fixture.entries,
                    &layout,
                )
                .create(fixture.keys[1].clone())
                .unwrap();
                let executor = Builder::new_current_thread().enable_all().build().unwrap();
                let idle = Keypair::generate_ed25519().public().to_peer_id();
                let (mut peer, network, _) =
                    executor.block_on(connected_pair_with_extra(Some(idle)));
                let peer_id = peer.local_peer_id();
                let stopped = ready.run_with_signing_session(|scope| executor.block_on(async {
                let scope = selected_scope(scope, &[&first, &second]);
                let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id, idle], timeouts(Duration::from_secs(60))).unwrap();
                assert_eq!(owner.driver().unwrap().position().height().value(), 3);
                let before = layout.authority_images();
                assert_refund(&mut owner, Refusal::Busy);
                assert_eq!(layout.authority_images(), before);
                let proposal = ConsensusPushMessage::Proposal { canonical_proposal: current.proof.control.clone(), canonical_artifact: current.proof.payload.clone() };
                assert!(raw_exchange(&mut peer, &mut owner, proposal, check_local).await.all_admitted());
                assert!(raw_exchange(&mut peer, &mut owner, copy_message(&current.prevote), check_local).await.all_admitted());
                assert!(matches!(owner.next_event().await, Event::Transitioned { position, phase: FixedValidatorLockPhaseV0::Precommit } if position.height().value() == 3 && position.round() == current.proof.round));
                assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
                let token = token_observation(owner.pending_publication().unwrap());
                let before = layout.authority_images();
                assert_refund(&mut owner, Refusal::Busy);
                assert_eq!(layout.authority_images(), before);
                let Event::TimerArmed(timer) = owner.next_event().await else { panic!("pending arm transfer") };
                assert!(!owner.pending_publication().unwrap().local_admission_attempted());
                if in_flight {
                check_local(owner.next_event().await);
                loop {
                    match owner.next_event().await {
                        Event::PeerAttempted { peer_id: actual, started } => { assert_eq!(actual, peer_id); assert!(started); break; }
                        Event::Network(_) => {},
                        _ => panic!("first peer attempt"),
                    }
                }
                }
                let queued = queued_input(&mut owner);
                if in_flight { assert_inflight(owner.pending_publication().unwrap(), peer_id, idle); }
                else { assert!(owner.pending_publication().unwrap().deliveries().all(|delivery| matches!(delivery.state(), Delivery::NotAttempted))); }
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(120)).await;
                assert!(timer.deadline() < tokio::time::Instant::now());
                let before = layout.authority_images();
                let Event::Fatal(error) = submit(&mut owner, if distinct { &sibling } else { &first }, batch) else { panic!("terminal result") };
                let stopped = match *error {
                    Failure::FinalityStopped(stopped) if distinct => {
                        assert_eq!(stopped.finality_halt().kind(), naome_storage::FixedValidatorFinalityHaltKindV0::SelectedSibling);
                        assert_eq!(stopped.finality_halt().height().value(), 1);
                        assert_eq!(stopped.finality_halt().first_ancestry(), first.proof.value.ancestry_id());
                        assert_eq!(stopped.finality_halt().second_ancestry(), sibling.proof.value.ancestry_id());
                        assert_eq!(stopped.signer_stop().finality_state_id(), stopped.finality_halt().state_id());
                        assert!(before.iter().zip(layout.authority_images()).all(|(before, after)| before != &after));
                        Some(*stopped)
                    }
                    Failure::HistoricalFinalityConflict(naome_node::FixedValidatorNodeFinalityErrorV0::HistoricalFinalityConflict(source)) if !distinct => {
                        assert!(matches!(*source, naome_storage::FixedValidatorHistoricalFinalityConflictErrorV0::SelectedValueNotDistinct { .. }));
                        assert_eq!(layout.authority_images(), before);
                        None
                    }
                    other => panic!("unexpected terminal outcome {other:?}"),
                };
                assert!(owner.driver().is_none());
                assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
                assert_refund(&mut owner, Refusal::DriverUnavailable);
                assert_eq!(owner.timer(), Some(timer));
                let parts = owner.into_parts();
                assert!(parts.driver.is_none());
                assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == queued));
                let publication = parts.publication.unwrap();
                assert_eq!(token_observation(&publication), token);
                assert_eq!(publication.local_admission_attempted(), in_flight);
                if in_flight { assert_inflight(&publication, peer_id, idle); }
                else { assert!(publication.deliveries().all(|delivery| matches!(delivery.state(), Delivery::NotAttempted))); }
                stopped
            })).unwrap();
                let before = layout.authority_images();
                match provision(
                    fixture.definition,
                    fixture.context,
                    &fixture.entries,
                    &layout,
                )
                .open(fixture.keys[1].clone())
                .unwrap()
                {
                    FixedValidatorNodeStartupV0::FinalityStopped(reopened) => {
                        assert_eq!(Some(reopened), stopped)
                    }
                    FixedValidatorNodeStartupV0::Ready(ready) => {
                        assert!(stopped.is_none());
                        ready
                            .run_with_signing_session(|scope| {
                                let driver = node_driver(scope);
                                assert_eq!(driver.position().height().value(), 3);
                                assert_eq!(driver.position().round(), current.proof.round);
                                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Precommit);
                            })
                            .unwrap();
                    }
                    _ => panic!("strict terminal or Ready restart"),
                }
                assert_eq!(layout.authority_images(), before);
            }
        }
    }
}
