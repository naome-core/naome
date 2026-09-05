use super::*;
use naome_consensus::ConsensusVoteTarget;
use naome_node::FixedValidatorNodeProposalAuthoringRejectionV0 as AuthoringRejection;
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactPayloadStoreLimits,
    CanonicalArtifactPayloadStore, CanonicalArtifactPayloadStoreError,
};

pub(super) fn sources(
    layout: &TestLayout,
    fixture: &Fixture,
) -> (ArtifactBlockCandidateStore, CanonicalArtifactPayloadStore) {
    (
        ArtifactBlockCandidateStore::create(
            &layout.candidate_store,
            fixture.definition,
            ArtifactBlockCandidateStoreLimits::new(16).unwrap(),
        )
        .unwrap(),
        CanonicalArtifactPayloadStore::create(
            &layout.payload_store,
            ArtifactPayloadStoreLimits::new(16, 1 << 20).unwrap(),
        )
        .unwrap(),
    )
}

#[test]
fn fresh_store_authoring_retries_only_after_explicit_source_insertion() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("runtime-source-retry");
    let (mut candidates, mut payloads) = sources(&layout, &fixture);
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = pairing_payload();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let branch = scope.branch().clone();
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![],
            timeouts(Duration::from_secs(60))).unwrap();
        assert!(matches!(owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()), Event::StoreAuthoringBusy));
        let Event::TimerArmed(timer) = owner.next_event().await else { panic!("arm") };
        let images = layout.authority_images();
        for missing_candidate in [true, false] {
            let source_images = layout.source_images();
            let Event::ProposalRejected(error) = owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()) else { panic!("source missing") };
            if missing_candidate {
                assert!(matches!(*error, AuthoringRejection::CandidateUnavailable { target } if target == block.id()));
            } else {
                assert!(matches!(*error, AuthoringRejection::PayloadUnavailable { target } if target == block.id()));
            }
            assert_eq!(owner.timer(), Some(timer));
            assert!(!owner.driver().unwrap().has_pending_command());
            assert!(owner.pending_publication().is_none());
            assert_eq!(layout.authority_images(), images);
            assert_eq!(layout.source_images(), source_images);
            if missing_candidate { let _ = candidates.insert(&block).unwrap(); }
        }
        let _ = payloads.validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload.clone()).unwrap();
        let source_images = layout.source_images();
        assert!(matches!(owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()), Event::ProposalAuthored));
        assert_eq!(owner.timer(), Some(timer));
        assert_eq!(&layout.authority_images()[..2], &images[..2]);
        assert_ne!(&layout.authority_images()[2..], &images[2..]);
        assert_eq!(layout.source_images(), source_images);
        assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
        let Message::Proposal { proposal, canonical_artifact_bytes } = owner.pending_publication().unwrap().message() else { panic!("proposal") };
        assert_eq!(canonical_artifact_bytes, &payload);
        let round = branch.begin_round_zero().unwrap();
        let verified = round.decode_and_verify_proposal_control(proposal.canonical_proposal_control_bytes(), payload).unwrap();
        assert_eq!(verified.value().artifact_block(), block);
        assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
        assert!(matches!(owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()), Event::StoreAuthoringBusy));
        assert!(matches!(owner.author_payload_store_backed_retained_proposal(&mut payloads), Event::StoreAuthoringBusy));
    })).unwrap();
}

#[test]
fn runtime_backpressure_precedes_the_first_corrupt_source_read() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("runtime-corrupt-source");
    let (mut candidates, mut payloads) = sources(&layout, &fixture);
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = pairing_payload();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let _ = candidates.insert(&block).unwrap();
    let _ = payloads
        .validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload.clone())
        .unwrap();
    let path = std::fs::read_dir(&layout.payload_store)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "log"))
        .unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(path, bytes).unwrap();
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![],
            timeouts(Duration::from_secs(60))).unwrap();
        let images = layout.authority_images();
        let source_images = layout.source_images();
        assert!(matches!(owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()), Event::StoreAuthoringBusy));
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        owner.queue_input(ConsensusPushMessage::Vote { canonical_vote: vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES] }).unwrap();
        assert!(matches!(owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()), Event::StoreAuthoringBusy));
        assert!(matches!(owner.author_payload_store_backed_retained_proposal(&mut payloads), Event::StoreAuthoringBusy));
        assert!(payloads.contains(block.artifact_id()).unwrap());
        assert!(matches!(owner.next_event().await, Event::Admission(report) if report.source == InputSource::CallerInput && report.routing_error.is_some() && !report.completed()));
        let Event::ProposalRejected(error) = owner.author_candidate_backed_fresh_proposal(&mut candidates, &mut payloads, block.id()) else { panic!("first source read must reject") };
        assert!(matches!(*error, AuthoringRejection::PayloadStore(error) if matches!(*error, CanonicalArtifactPayloadStoreError::StoredEntryChanged { .. })));
        assert!(matches!(payloads.contains(block.artifact_id()), Err(CanonicalArtifactPayloadStoreError::Poisoned)));
        assert_eq!(layout.source_images(), source_images);
        assert_eq!(layout.authority_images(), images);
        // A source failure is pre-effect and still permits explicit direct input.
        assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload }), Event::ProposalAuthored));
    })).unwrap();
}

#[test]
fn retained_store_authoring_preserves_real_certificate_through_round_and_strict_reopen() {
    let fixture = Fixture::new();
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&fixture.keys[0]),
        AgreementWeight::new(1),
    )];
    let layout = TestLayout::new("runtime-retained-source");
    let (_, mut payloads) = sources(&layout, &fixture);
    let selected = ArtifactChainState::new(fixture.definition);
    let payload = pairing_payload();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    let ready = provision(fixture.definition, fixture.context, &entries, &layout)
        .create(fixture.keys[0].clone())
        .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (authored, certificate, root) = ready.run_with_signing_session(|scope| executor.block_on(async {
        tokio::time::pause();
        let branch = scope.branch().clone();
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![],
            timeouts(Duration::from_secs(60))).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload.clone() }), Event::ProposalAuthored));
        let mut messages = Vec::new();
        for _ in 0..20 {
            match owner.next_event().await {
                Event::PublicationComplete(publication) => {
                    messages.push(publication.message().copy_message().unwrap());
                    if messages.len() == 3 { break; }
                }
                event => check_local(event),
            }
        }
        assert_eq!(messages.len(), 3);
        let ConsensusPushMessage::Proposal { canonical_proposal, .. } = &messages[0] else { panic!("proposal") };
        let round_zero = branch.begin_round_zero().unwrap();
        let original = round_zero.decode_and_verify_proposal_control(canonical_proposal, payload.clone()).unwrap();
        let root = original.proposal_signing_root();
        let ConsensusPushMessage::Vote { canonical_vote } = &messages[1] else { panic!("prevote") };
        let certificate = round_zero.build_quorum_certificate_from_signed_votes(&[canonical_vote], ConsensusVoteRole::Prevote, ConsensusVoteTarget::Proposal(root)).unwrap().to_canonical_bytes();
        // The caller explicitly removes retained finality before the next step;
        // the real signed lock and complete valid certificate remain durable.
        assert_eq!(owner.drain_current_finality_inbox_and_reset().unwrap().len(), 2);
        let timer = owner.timer().unwrap();
        assert_eq!(timer.ticket().phase(), FixedValidatorLockPhaseV0::Precommit);
        tokio::time::sleep_until(timer.deadline()).await;
        assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
        assert!(matches!(owner.next_event().await, Event::Transitioned { position, phase: FixedValidatorLockPhaseV0::Proposal } if position.round() == ConsensusRound::new(1)));
        let Event::TimerArmed(timer) = owner.next_event().await else { panic!("round one arm") };
        let images = layout.authority_images();
        let source_images = layout.source_images();
        assert!(matches!(owner.author_payload_store_backed_retained_proposal(&mut payloads), Event::ProposalRejected(error) if matches!(*error, AuthoringRejection::PayloadUnavailable { target } if target == block.id())));
        assert_eq!(owner.timer(), Some(timer));
        assert_eq!(layout.authority_images(), images);
        assert_eq!(layout.source_images(), source_images);
        let _ = payloads.validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, payload.clone()).unwrap();
        let source_images = layout.source_images();
        assert!(matches!(owner.author_payload_store_backed_retained_proposal(&mut payloads), Event::ProposalAuthored));
        assert_eq!(owner.timer(), Some(timer));
        assert_eq!(&layout.authority_images()[..2], &images[..2]);
        assert_ne!(&layout.authority_images()[2..], &images[2..]);
        assert_eq!(layout.source_images(), source_images);
        assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
        let authored = owner.pending_publication().unwrap().message().copy_message().unwrap();
        let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = &authored else { panic!("retained proposal") };
        assert_eq!(canonical_artifact, &payload);
        let round_one = branch.begin_round_zero().unwrap().advance_round().unwrap();
        let verified = round_one.decode_and_verify_proposal_control(canonical_proposal, payload.clone()).unwrap();
        assert_eq!(verified.proposal_signing_root(), root);
        assert_eq!(verified.valid_round_certificate_bytes(), Some(certificate.as_slice()));
        (authored, certificate, root)
    })).unwrap();
    let images = layout.authority_images();
    let FixedValidatorNodeStartupV0::Ready(ready) =
        provision(fixture.definition, fixture.context, &entries, &layout)
            .open(fixture.keys[0].clone())
            .unwrap()
    else {
        panic!("strict reopen")
    };
    ready
        .run_with_signing_session(|mut scope| {
            let session = scope.signing_session();
            assert_eq!(
                session.locked_value().unwrap().proposal_signing_root(),
                root
            );
            assert_eq!(
                session
                    .valid_value()
                    .unwrap()
                    .value()
                    .proposal_signing_root(),
                root
            );
            assert_eq!(
                session.valid_value().unwrap().round(),
                ConsensusRound::new(0)
            );
            assert_eq!(
                session
                    .valid_value()
                    .unwrap()
                    .canonical_prevote_certificate(),
                certificate
            );
            executor.block_on(async {
                let mut owner = Runtime::new(
                    node_driver(scope),
                    isolated_network(),
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                assert!(matches!(
                    owner.author_payload_store_backed_retained_proposal(&mut payloads),
                    Event::ProposalAuthored
                ));
                assert!(matches!(
                    owner.next_event().await,
                    Event::PublicationPrepared(_)
                ));
                assert_eq!(
                    owner
                        .pending_publication()
                        .unwrap()
                        .message()
                        .copy_message()
                        .unwrap(),
                    authored
                );
            });
        })
        .unwrap();
    assert_eq!(layout.authority_images(), images);
}
