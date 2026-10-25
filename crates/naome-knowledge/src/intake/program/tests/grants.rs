use super::*;

#[test]
fn expired_primary_program_response_cannot_extend_durable_input() {
    let graph = Graph::default();
    let checked = source(&graph);
    let metadata = metadata(&checked);
    let manifest = metadata.manifest.clone();
    let id = manifest.proof_id();
    let peer = PeerId::random();
    graph.ownership().start_program(&manifest).unwrap();
    let mut programs = Programs {
        active: Some(Root {
            authority: QuestionAuthority {
                question: metadata.question().unwrap().unwrap(),
                assessment: None,
                pending: None,
                until: Instant::now(),
                finalized: false,
                pending_final: false,
            },
            offer: Offer {
                metadata,
                transfer: TransferGrant::new(peer, id, None),
            },
            stage: Stage::Fetch,
            refresh: false,
            allowed: true,
            budget: Observer::fixed_for_test(crate::resources::tests::snapshot(false)),
            helpers: Helpers::default(),
            scanned: 0,
            input_complete: false,
        }),
        ..Programs::default()
    };
    programs
        .active
        .as_mut()
        .unwrap()
        .offer
        .transfer
        .set_received_for_test(Instant::now() - crate::resources::limits().root_timeout);
    assert!(programs.request(&graph).unwrap().is_none());
    let before = graph.ownership().program_progress(&manifest).unwrap();
    let chunk = checked
        .proof()
        .unwrap()
        .input_chunk(0, 64, CHUNK_BYTES)
        .unwrap();
    assert!(programs.payload(peer, id, chunk, &graph).is_err());
    let after = graph.ownership().program_progress(&manifest).unwrap();
    assert_eq!(after.commands, before.commands);
    assert_eq!(after.input_bytes, before.input_bytes);
    assert_eq!(after.hash, before.hash);
    assert_eq!(graph.accepted_count(), 0);
}

#[test]
fn denied_traffic_preserves_the_prefix_and_fresh_metadata_does_not_renew_interest() {
    let graph = Graph::default();
    let checked = source(&graph);
    let metadata = metadata(&checked);
    let manifest = metadata.manifest.clone();
    let id = manifest.proof_id();
    let peer = PeerId::random();
    let capability = crate::publication::PeerGrant::new();
    graph.ownership().start_program(&manifest).unwrap();
    let first = checked
        .proof()
        .unwrap()
        .input_chunk(0, 64, CHUNK_BYTES)
        .unwrap();
    graph.ownership().append_program(&manifest, &first).unwrap();
    let original_until = Instant::now() + std::time::Duration::from_secs(30);
    let mut intake = Intake::default();
    intake.programs.active = Some(Root {
        authority: QuestionAuthority {
            question: metadata.question().unwrap().unwrap(),
            assessment: None,
            pending: None,
            until: original_until,
            finalized: false,
            pending_final: false,
        },
        offer: Offer {
            metadata: metadata.clone(),
            transfer: TransferGrant::new(peer, id, Some(capability.clone())),
        },
        stage: Stage::Fetch,
        refresh: false,
        allowed: true,
        budget: Observer::fixed_for_test(crate::resources::tests::snapshot(false)),
        helpers: Helpers::default(),
        scanned: 0,
        input_complete: false,
    });
    let before = graph.ownership().program_progress(&manifest).unwrap();
    let next = checked
        .proof()
        .unwrap()
        .input_chunk(before.commands, 64, CHUNK_BYTES)
        .unwrap();
    let wrong = ProofId::from_bytes([9; 32]);
    assert!(
        intake
            .program_payload(PeerId::random(), id, id, next.clone(), &graph)
            .is_err()
    );
    assert!(
        intake
            .program_payload(peer, wrong, id, next.clone(), &graph)
            .is_err()
    );
    capability
        .0
        .store(false, std::sync::atomic::Ordering::Release);
    assert!(intake.program_request(&graph).unwrap().is_none());
    assert!(
        intake
            .program_payload(peer, id, id, next.clone(), &graph)
            .is_err()
    );
    let after = graph.ownership().program_progress(&manifest).unwrap();
    assert_eq!(after, before);
    let replacement_peer = PeerId::random();
    assert_eq!(
        intake
            .enqueue_program(
                replacement_peer,
                metadata,
                &graph,
                Some(crate::publication::PeerGrant::new())
            )
            .unwrap(),
        "metadata_refreshed"
    );
    assert_eq!(
        intake.programs.active.as_ref().unwrap().authority.until,
        original_until
    );
    assert!(
        intake
            .program_payload(peer, id, id, next.clone(), &graph)
            .is_err()
    );
    intake
        .program_payload(replacement_peer, id, id, next.clone(), &graph)
        .unwrap();
    let resumed = graph.ownership().program_progress(&manifest).unwrap();
    assert_eq!(
        resumed.commands,
        before.commands + next.records.len() as u64
    );
    assert_eq!(
        resumed.hash,
        checked
            .proof()
            .unwrap()
            .input_chunk(resumed.commands, 1, CHUNK_BYTES)
            .unwrap()
            .previous
    );
    assert_eq!(resumed.remaining, next.next);
    assert_eq!(graph.accepted_count(), 0);
}

#[tokio::test]
async fn expired_queued_program_metadata_cannot_start_interest_or_input_staging() {
    let mut graph = Graph::default();
    let checked = source(&graph);
    let metadata = metadata(&checked);
    let manifest = metadata.manifest.clone();
    let id = manifest.proof_id();
    let mut transfer = TransferGrant::new(PeerId::random(), id, None);
    transfer.set_received_for_test(Instant::now() - crate::resources::limits().root_timeout);
    let mut programs = Programs::default();
    programs.queue.push_back(Offer { metadata, transfer });
    let mut questions = LocalQuestions::new(Some(accepting as fn(_) -> _));
    assert!(
        matches!(programs.advance(&mut graph, &mut questions), Progress::Skipped(skipped, _) if skipped == id)
    );
    assert!(programs.active.is_none());
    assert!(questions.available());
    assert!(graph.ownership().program_progress(&manifest).is_err());
    assert_eq!(graph.accepted_count(), 0);
}
