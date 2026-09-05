use super::*;

fn higher_pairs(fixture: &Fixture) -> [Proof; 2] {
    [1, 2].map(|axiom| {
        let payload = naome_proof::ArtifactPayload::Proof(
            naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom])
                .unwrap(),
        )
        .to_canonical_bytes();
        let [proposal, _, vote]: [ConsensusPushMessage; 3] =
            higher_messages_for_payload(fixture, payload, 3)
                .try_into()
                .unwrap();
        proof(fixture, proposal, vote, ConsensusVoteRole::Precommit)
    })
}

fn submit_current<'node>(
    owner: &mut Runtime<'node>,
    first: &Proof,
    second: &Proof,
) -> Event<'node> {
    owner
        .commit_current_round_preselection_conflict_vote_batches(
            &first.control,
            first.payload.clone(),
            &[&first.vote],
            &second.control,
            second.payload.clone(),
            &[&second.vote],
        )
        .unwrap()
}

fn assert_refund(owner: &mut Runtime<'_>, reason: Refusal) {
    let mut first = vec![1; 11];
    first.reserve(19);
    let mut second = vec![2; 13];
    second.reserve(29);
    let originals = [allocations(&first), allocations(&second)];
    let Err((actual, first, second)) = owner
        .commit_current_round_preselection_conflict_vote_batches(
            &[0],
            first,
            &[],
            &[0],
            second,
            &[],
        )
    else {
        panic!("pre-invocation refusal must refund both payloads")
    };
    assert_eq!(actual, reason);
    assert_eq!([allocations(&first), allocations(&second)], originals);
    assert_eq!(first, vec![1; 11]);
    assert_eq!(second, vec![2; 13]);
}

#[test]
fn current_pair_preserves_publication_before_and_after_admission_through_rejection_and_stop() {
    let fixture = Fixture::new();
    let [first, second] = higher_pairs(&fixture);
    let [higher_proposal, higher_prevote] = higher_messages(&fixture);
    assert_eq!(first.round, second.round);
    for distinct in [false, true] {
        let layout = TestLayout::new("runtime-current-pair-custody");
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
        let (mut peer, network, _) = executor.block_on(connected_pair_with_extra(Some(idle)));
        let peer_id = peer.local_peer_id();
        let stopped = ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id, idle], timeouts(Duration::from_secs(60))).unwrap();
            let initial = layout.authority_images();
            assert_refund(&mut owner, Refusal::Busy);
            assert_eq!(layout.authority_images(), initial);
            assert!(raw_exchange(&mut peer, &mut owner, copy_message(&higher_proposal), check_local).await.all_admitted());
            assert!(raw_exchange(&mut peer, &mut owner, copy_message(&higher_prevote), check_local).await.all_admitted());
            assert!(matches!(owner.next_event().await, Event::Transitioned { position, phase: FixedValidatorLockPhaseV0::Precommit } if position.round() == first.round));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            let original = token_observation(owner.pending_publication().unwrap());
            let images = layout.authority_images();
            assert_refund(&mut owner, Refusal::Busy);
            assert_eq!(layout.authority_images(), images);
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("successor command transfer") };
            assert!(!owner.pending_publication().unwrap().local_admission_attempted());
            assert!(matches!(owner.advance_to_higher_round_quorum(&[0]), Err(Refusal::Busy)));
            let position = owner.driver().unwrap().position();
            let phase = owner.driver().unwrap().phase();
            let reject = owner.commit_current_round_preselection_conflict_vote_batches(
                &first.control, first.payload.clone(), &[&first.vote], &[0], second.payload.clone(), &[&second.vote],
            ).unwrap();
            assert!(matches!(reject, Event::CurrentRoundPreselectionConflictRejected(_)));
            assert!(!owner.pending_publication().unwrap().local_admission_attempted());
            assert_eq!(owner.driver().unwrap().position(), position);
            assert_eq!(owner.driver().unwrap().phase(), phase);
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert_eq!(layout.authority_images(), images);
            check_local(owner.next_event().await);
            loop {
                match owner.next_event().await {
                    Event::PeerAttempted { peer_id: actual, started } => { assert_eq!(actual, peer_id); assert!(started); break; }
                    Event::Network(_) => {}, _ => panic!("first peer attempt"),
                }
            }
            let queued = queued_input(&mut owner);
            assert_inflight(owner.pending_publication().unwrap(), peer_id, idle);
            let images = layout.authority_images();
            let rejected = owner.commit_current_round_preselection_conflict_vote_batches(
                &[0], first.payload.clone(), &[&first.vote], &second.control, second.payload.clone(), &[&second.vote],
            ).unwrap();
            assert!(matches!(rejected, Event::CurrentRoundPreselectionConflictRejected(_)));
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(owner.driver().unwrap().position(), position);
            assert_eq!(owner.driver().unwrap().phase(), phase);
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert_inflight(owner.pending_publication().unwrap(), peer_id, idle);
            assert_eq!(layout.authority_images(), images);
            let Event::Fatal(error) = submit_current(&mut owner, &first, if distinct { &second } else { &first }) else {
                panic!("terminal operation must consume driver")
            };
            let stopped = match *error {
                Failure::FinalityStopped(stopped) if distinct => {
                    let expected = if first.value.proposal_signing_root() < second.value.proposal_signing_root() {
                        [first.value.ancestry_id(), second.value.ancestry_id()]
                    } else { [second.value.ancestry_id(), first.value.ancestry_id()] };
                    assert_eq!(stopped.finality_halt().kind(), naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair);
                    assert_eq!(stopped.finality_halt().first_ancestry(), expected[0]);
                    assert_eq!(stopped.finality_halt().second_ancestry(), expected[1]);
                    assert_eq!(stopped.signer_stop().finality_state_id(), stopped.finality_halt().state_id());
                    assert!(images.iter().zip(layout.authority_images()).all(|(before, after)| before != &after));
                    Some(*stopped)
                }
                Failure::CurrentRoundPreselectionConflict(naome_node::FixedValidatorNodeCurrentRoundFinalityErrorV0::Finality(error)) if !distinct => {
                    assert!(matches!(*error, naome_node::FixedValidatorNodeFinalityErrorV0::Commit(error)
                        if matches!(*error, naome_storage::FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct { .. })));
                    assert_eq!(layout.authority_images(), images);
                    None
                }
                error => panic!("unexpected terminal result: {error:?}"),
            };
            assert!(owner.driver().is_none());
            assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
            assert_refund(&mut owner, Refusal::DriverUnavailable);
            assert_eq!(owner.timer(), Some(timer));
            let parts = owner.into_parts();
            assert!(parts.driver.is_none());
            assert!(parts.pending_network_event.is_none());
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == queued));
            let publication = parts.publication.unwrap();
            assert_eq!(token_observation(&publication), original);
            assert!(publication.local_admission_attempted());
            assert_inflight(&publication, peer_id, idle);
            stopped
        })).unwrap();
        let images = layout.authority_images();
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
                drop(ready);
            }
            _ => panic!("strict restart must classify exact halted or unchanged prefix"),
        }
        assert_eq!(layout.authority_images(), images);
    }
}
