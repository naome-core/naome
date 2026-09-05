use super::*;
use naome_runtime::FixedValidatorRuntimeFailureV0 as Failure;

#[path = "current_pair.rs"]
mod current_pair;

fn conflicting_proofs(fixture: &Fixture) -> [Proof; 2] {
    [1, 2].map(|axiom| {
        let payload = naome_proof::ArtifactPayload::Proof(
            naome_proof::ProofCertificate::from_canonical_bytes(&[0, 0, 0, 1, 0x10, axiom])
                .unwrap(),
        )
        .to_canonical_bytes();
        let [proposal, _, vote] = source_messages_for_payload(fixture, payload);
        proof(fixture, proposal, vote, ConsensusVoteRole::Precommit)
    })
}

fn pair<'node>(owner: &mut Runtime<'node>, first: &Proof, second: &Proof) -> Event<'node> {
    owner
        .commit_lower_round_preselection_conflict_vote_batches(
            &first.control,
            first.payload.clone(),
            &[&first.vote],
            &second.control,
            second.payload.clone(),
            &[&second.vote],
            first.round,
        )
        .unwrap()
}

fn assert_pair_busy(owner: &mut Runtime<'_>) {
    let mut first = vec![1; 11];
    first.reserve(19);
    let mut second = vec![2; 13];
    second.reserve(29);
    let originals = [allocations(&first), allocations(&second)];
    let Err((Refusal::Busy, first, second)) = owner
        .commit_lower_round_preselection_conflict_vote_batches(
            &[0],
            first,
            &[&[0]],
            &[0],
            second,
            &[&[0]],
            ConsensusRound::new(0),
        )
    else {
        panic!("pending command must refund both payloads")
    };
    assert_eq!([allocations(&first), allocations(&second)], originals);
    assert_eq!(first, vec![1; 11]);
    assert_eq!(second, vec![2; 13]);
}

fn queued_input(owner: &mut Runtime<'_>) -> (usize, usize, usize) {
    let mut bytes = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES];
    bytes.reserve(31);
    let original = allocations(&bytes);
    owner
        .queue_input(ConsensusPushMessage::Vote {
            canonical_vote: bytes,
        })
        .unwrap();
    original
}

fn assert_inflight(
    publication: &Publication,
    peer: naome_network::PeerId,
    idle: naome_network::PeerId,
) {
    let deliveries = publication.deliveries().collect::<Vec<_>>();
    assert_eq!(deliveries.len(), 2);
    assert_eq!(deliveries[0].peer_id(), peer);
    assert!(matches!(deliveries[0].state(), Delivery::InFlight(_)));
    assert_eq!(deliveries[1].peer_id(), idle);
    assert!(matches!(deliveries[1].state(), Delivery::NotAttempted));
}

#[test]
fn lower_pair_halt_or_consuming_error_preserves_some_publication_and_inflight_custody() {
    let fixture = Fixture::new();
    let [first, second] = conflicting_proofs(&fixture);
    let [higher_proposal, higher_prevote] = higher_messages(&fixture);
    for distinct in [false, true] {
        let layout = TestLayout::new("runtime-terminal-lower-pair");
        let (mut candidates, mut payloads) =
            super::super::store_authoring::sources(&layout, &fixture);
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
            assert!(raw_exchange(&mut peer, &mut owner, copy_message(&higher_proposal), check_local).await.all_admitted());
            assert!(raw_exchange(&mut peer, &mut owner, copy_message(&higher_prevote), check_local).await.all_admitted());
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Precommit, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            let original = token_observation(owner.pending_publication().unwrap());
            let images = layout.authority_images();
            assert_pair_busy(&mut owner);
            assert!(matches!(owner.commit_candidate_backed_finality_conflict_vote_batch(&mut candidates, &mut payloads, first.value.artifact_block().id(), &[0], &[&[0]], first.round), Err(Refusal::Busy)));
            assert_eq!(layout.authority_images(), images);
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("successor command transfer") };
            assert!(!owner.pending_publication().unwrap().local_admission_attempted());
            // After command transfer, even a not-yet-admitted publication does
            // not delay explicit pair verification. Positive proofs still wait.
            assert_positive_busy(&mut owner, &mut candidates, &mut payloads, first.value.artifact_block().id());
            let reject = owner.commit_lower_round_preselection_conflict_vote_batches(&first.control, first.payload.clone(), &[&first.vote], &[0], second.payload.clone(), &[&second.vote], first.round).unwrap();
            assert!(matches!(reject, Event::LowerRoundPreselectionConflictRejected(_)));
            assert!(!owner.pending_publication().unwrap().local_admission_attempted());
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(layout.authority_images(), images);
            check_local(owner.next_event().await);
            loop {
                match owner.next_event().await {
                    Event::PeerAttempted { peer_id: actual, started } => { assert_eq!(actual, peer_id); assert!(started); break; }
                    Event::Network(_) => {},
                    _ => panic!("first peer attempt"),
                }
            }
            let queued = queued_input(&mut owner);
            let images = layout.authority_images();
            let source_images = layout.source_images();
            assert_inflight(owner.pending_publication().unwrap(), peer_id, idle);
            let reject = owner.commit_lower_round_preselection_conflict_vote_batches(&first.control, first.payload.clone(), &[&first.vote], &[0], second.payload.clone(), &[&second.vote], first.round).unwrap();
            assert!(matches!(reject, Event::LowerRoundPreselectionConflictRejected(_)));
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(layout.authority_images(), images);
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert_inflight(owner.pending_publication().unwrap(), peer_id, idle);
            let Event::Fatal(error) = pair(&mut owner, &first, if distinct { &second } else { &first }) else { panic!("terminal operation must consume driver") };
            let stopped = match *error {
                Failure::FinalityStopped(stopped) if distinct => {
                    assert_eq!(stopped.finality_halt().kind(), naome_storage::FixedValidatorFinalityHaltKindV0::PreselectionPair);
                    let expected = if first.value.proposal_signing_root() < second.value.proposal_signing_root() { [first.value.ancestry_id(), second.value.ancestry_id()] } else { [second.value.ancestry_id(), first.value.ancestry_id()] };
                    assert_eq!(stopped.finality_halt().first_ancestry(), expected[0]);
                    assert_eq!(stopped.finality_halt().second_ancestry(), expected[1]);
                    assert_eq!(stopped.signer_stop().kind(), stopped.finality_halt().kind());
                    assert_eq!(stopped.signer_stop().finality_state_id(), stopped.finality_halt().state_id());
                    assert!(images.iter().zip(layout.authority_images()).all(|(before, after)| before != &after));
                    Some(*stopped)
                }
                Failure::LowerRoundPreselectionConflict(naome_node::FixedValidatorNodeLowerRoundFinalityErrorV0::Finality(error)) if !distinct => {
                    assert!(matches!(*error, naome_node::FixedValidatorNodeFinalityErrorV0::Commit(error) if matches!(*error, naome_storage::FixedValidatorFinalityJournalErrorV0::PreselectionConflictNotDistinct { .. })));
                    assert_eq!(layout.authority_images(), images);
                    None
                }
                error => panic!("unexpected terminal result: {error:?}"),
            };
            assert!(owner.driver().is_none());
            assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(layout.source_images(), source_images);
            let payload = first.payload.clone(); let allocation = allocations(&payload);
            let Err((Refusal::DriverUnavailable, payload)) = owner.commit_lower_round_finality(&first.control, payload, &first.certificate) else { panic!("no driver") };
            assert_eq!(allocations(&payload), allocation);
            assert!(matches!(owner.advance_to_higher_round_quorum(&[0]), Err(Refusal::DriverUnavailable)));
            assert!(matches!(owner.author_payload_store_backed_retained_proposal(&mut payloads), Event::StoreAuthoringUnavailable));
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

#[test]
fn historical_candidate_conflict_halt_or_source_error_preserves_inflight_publication() {
    let fixture = Fixture::new();
    let [first, sibling] = conflicting_proofs(&fixture);
    for retain_sibling in [false, true] {
        let layout = TestLayout::new("runtime-terminal-candidate");
        let (mut candidates, mut payloads) =
            super::super::store_authoring::sources(&layout, &fixture);
        let selected = ArtifactChainState::new(fixture.definition);
        let retained = if retain_sibling {
            vec![&first, &sibling]
        } else {
            vec![&first]
        };
        for proof in retained {
            let block = proof.value.artifact_block();
            let _ = candidates.insert(&block).unwrap();
            let _ = payloads
                .validate_and_insert_branch_payload(
                    &selected.branch_snapshot(),
                    &block,
                    proof.payload.clone(),
                )
                .unwrap();
        }
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
        let (peer, network, _) = executor.block_on(connected_pair_with_extra(Some(idle)));
        let peer_id = peer.local_peer_id();
        let stopped = ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id, idle], timeouts(Duration::from_millis(1))).unwrap();
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            assert!(matches!(owner.commit_candidate_backed_finality_vote_batch(&mut candidates, &mut payloads, first.value.artifact_block().id(), &first.control, &[&first.vote], first.round).unwrap(), Event::Finality(_)));
            assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), first.value.artifact_block().id());
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            prepare_vote(&mut owner, ConsensusVoteRole::Prevote).await;
            let original = owner.pending_publication().unwrap().message().copy_message().unwrap();
            assert!(matches!(owner.pending_publication().unwrap().message(), Message::Vote { vote, released_proposal: None } if vote.target() == ConsensusVoteTarget::Nil && vote.position().height().value() == 2));
            let images = layout.authority_images();
            let source_images = layout.source_images();
            assert!(matches!(owner.commit_candidate_backed_finality_conflict_vote_batch(&mut candidates, &mut payloads, sibling.value.artifact_block().id(), &sibling.control, &[&sibling.vote], sibling.round), Err(Refusal::Busy)));
            assert_eq!(layout.authority_images(), images);
            assert_eq!(layout.source_images(), source_images);
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("successor arm") };
            check_local(owner.next_event().await);
            loop {
                match owner.next_event().await {
                    Event::PeerAttempted { peer_id: actual, started } => { assert_eq!(actual, peer_id); assert!(started); break; }
                    Event::Network(_) => {},
                    _ => panic!("first send must start"),
                }
            }
            let queued = queued_input(&mut owner);
            // A due wall-clock deadline does not add a terminal-proof gate.
            tokio::time::sleep_until(timer.deadline()).await;
            let images = layout.authority_images();
            assert_positive_busy(&mut owner, &mut candidates, &mut payloads, first.value.artifact_block().id());
            let Event::Fatal(error) = owner.commit_candidate_backed_finality_conflict_vote_batch(&mut candidates, &mut payloads, sibling.value.artifact_block().id(), &sibling.control, &[&sibling.vote], sibling.round).unwrap() else { panic!("candidate conflict consumes driver") };
            let stopped = match *error {
                Failure::FinalityStopped(stopped) if retain_sibling => {
                    assert_eq!(stopped.finality_halt().kind(), naome_storage::FixedValidatorFinalityHaltKindV0::SelectedSibling);
                    assert_eq!(stopped.finality_halt().first_ancestry(), first.value.ancestry_id());
                    assert_eq!(stopped.finality_halt().second_ancestry(), sibling.value.ancestry_id());
                    assert_eq!(stopped.signer_stop().finality_state_id(), stopped.finality_halt().state_id());
                    assert!(images.iter().zip(layout.authority_images()).all(|(before, after)| before != &after));
                    Some(*stopped)
                }
                Failure::CandidateBackedConflict(naome_node::FixedValidatorNodeFinalityErrorV0::CandidateBackedFinality(error)) if !retain_sibling => {
                    assert!(matches!(*error, naome_storage::CandidateBackedFinalityErrorV0::CandidateUnavailable { target } if target == sibling.value.artifact_block().id()));
                    assert_eq!(layout.authority_images(), images);
                    None
                }
                error => panic!("unexpected candidate terminal result: {error:?}"),
            };
            assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(layout.source_images(), source_images);
            assert!(matches!(owner.commit_candidate_backed_finality_conflict_vote_batch(&mut candidates, &mut payloads, sibling.value.artifact_block().id(), &[0], &[&[0]], sibling.round), Err(Refusal::DriverUnavailable)));
            let parts = owner.into_parts();
            assert!(parts.driver.is_none());
            assert!(parts.pending_network_event.is_none());
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == queued));
            let publication = parts.publication.unwrap();
            assert_eq!(publication.message().copy_message().unwrap(), original);
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
                ready
                    .run_with_signing_session(|scope| {
                        let driver = node_driver(scope);
                        assert_eq!(
                            driver
                                .selected_artifact_history()
                                .selected_head_block_id()
                                .unwrap(),
                            first.value.artifact_block().id()
                        );
                        assert_eq!(driver.position().height().value(), 2);
                        assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
                    })
                    .unwrap();
            }
            _ => panic!("strict reopen classifies halted or unchanged prefix"),
        }
        assert_eq!(layout.authority_images(), images);
    }
}
