use super::*;

#[test]
fn payload_snapshot_completion_requires_separate_live_finality_verification() {
    let fixture = Fixture::new();
    let selected_proof = lower_proof(&fixture);
    let checkpoint = higher_proof(&fixture);
    let sibling = sibling_proof(&fixture);
    let target = sibling.value.artifact_block().id();
    let client_layout = TestLayout::new("payload-interleaving");
    let server_layout = TestLayout::new("payload-interleaving-server");
    let (mut candidates, mut payloads) = sources(&client_layout, &fixture, None);
    let _ = candidates.insert(&sibling.value.artifact_block()).unwrap();
    let (mut serving_candidates, mut serving_payloads) =
        sources(&server_layout, &fixture, Some(&sibling.payload));
    let client_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &client_layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let server_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &server_layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (client_network, server_network, peer) = executor.block_on(connected_pair());
    let stopped = client_ready.run_with_signing_session(|client_scope| {
        server_ready.run_with_signing_session(|server_scope| executor.block_on(async {
            let mut client = Runtime::new(node_driver(client_scope), client_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
            let genesis = client.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap();
            let PayloadProgress::AwaitingResponse(fill) = client.start_artifact_block_candidate_branch_payload_fill(&mut candidates, &mut payloads, peer, target, limits()).unwrap() else { panic!("payload miss") };
            let event = terminal(&mut client, &mut server, &mut serving_candidates, &mut serving_payloads, |event| fill.accepts_event(event)).await;
            assert!(matches!(higher(&mut client, &checkpoint, false), Event::Transitioned { .. }));
            assert!(matches!(client.next_event().await, Event::TimerArmed(_)));
            assert!(matches!(lower(&mut client, &selected_proof, false, selected_proof.payload.clone()), Event::Finality(_)));
            assert!(matches!(client.next_event().await, Event::TimerArmed(_)));
            let after_selection = client_layout.authority_images();
            let before_fill = client_layout.source_images();
            let timer = client.timer();
            let PayloadProgress::Complete(branch) = client.advance_artifact_block_candidate_branch_payload_fill(fill, event).unwrap() else { panic!("snapshot must complete") };
            assert_eq!(branch.anchor_block_id(), genesis);
            assert_eq!(branch.target_block_id(), target);
            assert_eq!(branch.snapshot().head_block_id(), target);
            assert_eq!(branch.snapshot().artifact_set_root(), sibling.value.artifact_block().resulting_artifact_set_root());
            assert_eq!(client_layout.source_images()[0], before_fill[0]);
            assert_ne!(client_layout.source_images()[1], before_fill[1]);
            assert_eq!(client.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), selected_proof.value.artifact_block().id());
            assert_eq!(client_layout.authority_images(), after_selection);
            assert_eq!(client.timer(), timer);
            let sources_complete = client_layout.source_images();
            assert!(matches!(client.commit_candidate_backed_finality_vote_batch(&mut candidates, &mut payloads, target, &sibling.control, &[&sibling.vote], sibling.round).unwrap(), Event::CandidateBackedFinalityRejected(error) if matches!(*error, naome_node::FixedValidatorNodeCandidateBackedFinalityRejectionV0::Proposal(_))));
            assert_eq!(client_layout.authority_images(), after_selection);
            assert_eq!(client_layout.source_images(), sources_complete);
            // Only the separately selected complete historical proof can halt.
            let Event::Fatal(error) = client.commit_candidate_backed_finality_conflict_vote_batch(&mut candidates, &mut payloads, target, &sibling.control, &[&sibling.vote], sibling.round).unwrap() else { panic!("verified historical conflict") };
            let naome_runtime::FixedValidatorRuntimeFailureV0::FinalityStopped(stopped) = *error else { panic!("paired stop") };
            assert_eq!(stopped.finality_halt().first_ancestry(), selected_proof.value.ancestry_id());
            assert_eq!(stopped.finality_halt().second_ancestry(), sibling.value.ancestry_id());
            assert_eq!(stopped.signer_stop().finality_state_id(), stopped.finality_halt().state_id());
            assert_eq!(client_layout.source_images(), sources_complete);
            assert!(matches!(client.next_event().await, Event::DriverUnavailable));
            assert!(matches!(client.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, target), Err(StartError::DriverUnavailable)));
            assert!(matches!(client.start_artifact_block_candidate_branch_payload_fill(&mut candidates, &mut payloads, peer, target, limits()), Err(StartError::DriverUnavailable)));
            *stopped
        })).unwrap()
    }).unwrap();
    let images = client_layout.authority_images();
    let FixedValidatorNodeStartupV0::FinalityStopped(reopened) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &client_layout,
    )
    .open(fixture.keys[1].clone())
    .unwrap() else {
        panic!("strict terminal reopen")
    };
    assert_eq!(reopened, stopped);
    assert_eq!(client_layout.authority_images(), images);
}

#[test]
fn ancestry_uses_existing_current_head_and_explicit_anchor_interleaving_rules() {
    let fixture = Fixture::new();
    let selected_proof = lower_proof(&fixture);
    let checkpoint = higher_proof(&fixture);
    let sibling = sibling_proof(&fixture);
    let target = sibling.value.artifact_block().id();
    // Round-only progression does not change the artifact anchor. Height
    // progression differs between current-head and explicit-anchor modes.
    for (change_height, explicit, fallback) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
    ] {
        let client_layout = TestLayout::new("ancestry-interleaving");
        let server_layout = TestLayout::new("ancestry-interleaving-server");
        let (mut candidates, _payloads) = sources(&client_layout, &fixture, None);
        let (mut serving_candidates, mut serving_payloads) =
            sources(&server_layout, &fixture, Some(&sibling.payload));
        let client_ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &client_layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let server_ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &server_layout,
        )
        .create(fixture.keys[0].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let (client_network, server_network, peer) = executor.block_on(connected_pair());
        client_ready.run_with_signing_session(|client_scope| {
            server_ready.run_with_signing_session(|server_scope| executor.block_on(async {
                let mut client = Runtime::new(node_driver(client_scope), client_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
                let mut server = Runtime::new(node_driver(server_scope), server_network, vec![], timeouts(Duration::from_secs(60))).unwrap();
                let genesis = client.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap();
                let fill = match (explicit, fallback) {
                    (true, true) => client.start_artifact_block_candidate_ancestry_fill_from_selected_anchor_with_peer_fallback(&mut candidates, &[peer], genesis, target),
                    (true, false) => client.start_artifact_block_candidate_ancestry_fill_from_selected_anchor(&mut candidates, peer, genesis, target),
                    (false, _) => client.start_artifact_block_candidate_ancestry_fill(&mut candidates, peer, target),
                }.unwrap().unwrap();
                let event = terminal(&mut client, &mut server, &mut serving_candidates, &mut serving_payloads, |event| fill.accepts_event(event)).await;
                let sources_before = client_layout.source_images();
                assert!(matches!(higher(&mut client, &checkpoint, true), Event::Transitioned { .. }));
                assert!(matches!(client.next_event().await, Event::TimerArmed(_)));
                if change_height {
                    assert!(matches!(lower(&mut client, &selected_proof, true, selected_proof.payload.clone()), Event::Finality(_)));
                    assert!(matches!(client.next_event().await, Event::TimerArmed(_)));
                }
                let expected_head = if change_height { selected_proof.value.artifact_block().id() } else { genesis };
                let images_after_transition = client_layout.authority_images();
                let timer = client.timer();
                let position = client.driver().unwrap().position();
                let result = client.advance_artifact_block_candidate_ancestry_fill(fill, event);
                if change_height && !explicit {
                    assert!(matches!(*result.unwrap_err(), AncestryAdvanceError::Operation(AncestryError::SelectedHeadChanged { expected, actual }) if expected == genesis && actual == expected_head));
                    assert_eq!(client_layout.source_images(), sources_before);
                    assert!(candidates.get(target).unwrap().is_none());
                } else {
                    assert!(result.unwrap().is_none());
                    assert_eq!(candidates.get(target).unwrap(), Some(sibling.value.artifact_block()));
                    assert_eq!(client_layout.source_images()[1], sources_before[1]);
                }
                assert_eq!(client.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), expected_head);
                assert_eq!(client.driver().unwrap().position(), position);
                assert_eq!(client.timer(), timer);
                assert_eq!(client_layout.authority_images(), images_after_transition);
            })).unwrap();
        }).unwrap();
    }
}
