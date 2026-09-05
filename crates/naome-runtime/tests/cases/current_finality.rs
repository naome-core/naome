use super::*;

fn current<'node>(
    owner: &mut Runtime<'node>,
    input: &Proof,
    batch: bool,
    payload: Vec<u8>,
) -> Event<'node> {
    if batch {
        owner
            .commit_current_round_finality_vote_batch(&input.control, payload, &[&input.vote])
            .unwrap()
    } else {
        owner
            .commit_current_round_finality(&input.control, payload, &input.certificate)
            .unwrap()
    }
}

#[test]
fn direct_current_proofs_select_from_each_due_phase_and_preserve_buffered_input() {
    let fixture = Fixture::new();
    let input = lower_proof(&fixture);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&input.payload))
        .unwrap();
    for (batch, phases) in [false, true]
        .into_iter()
        .flat_map(|batch| (0..3).map(move |phases| (batch, phases)))
    {
        let layout = TestLayout::new("runtime-current-proof");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        ready.run_with_signing_session(|scope| executor.block_on(async {
            tokio::time::pause();
            // Public driver calls provide each anchored source phase; runtime
            // timing, buffering, proof processing and child handoff follow here.
            let mut driver = arm_driver(node_driver(scope));
            for _ in 0..phases { driver = empty_phase(driver); }
            let mut owner = Runtime::new(driver, isolated_network(), vec![], timeouts(Duration::from_millis(1))).unwrap();
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("adopt source arm") };
            assert_eq!(timer.ticket().position().round(), ConsensusRound::new(0));
            let mut bytes = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES];
            bytes.reserve(31);
            let allocation = allocations(&bytes);
            let raw = ConsensusPushMessage::Vote { canonical_vote: bytes };
            owner.queue_input(raw).unwrap();
            tokio::time::sleep_until(timer.deadline()).await;
            assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
            let images = layout.authority_images();
            assert!(matches!(current(&mut owner, &input, batch, vec![0]), Event::CurrentRoundFinalityRejected(_)));
            assert_eq!(owner.driver().unwrap().position(), timer.ticket().position());
            assert_eq!(owner.driver().unwrap().phase(), timer.ticket().phase());
            assert!(owner.driver().unwrap().timeout_is_due());
            assert_eq!(layout.authority_images(), images);
            assert!(matches!(current(&mut owner, &input, batch, input.payload.clone()), Event::Finality(naome_node::FixedValidatorNodeFinalitySelectionV0::Finalized { .. })));
            assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), block.id());
            assert_eq!(owner.driver().unwrap().position().height().value(), 2);
            assert_eq!(owner.driver().unwrap().position().round(), ConsensusRound::new(0));
            assert!(!owner.driver().unwrap().timeout_is_due());
            assert!(owner.timer().is_none());
            assert!(matches!(owner.next_event().await, Event::TimerArmed(next) if next.ticket().generation() == timer.ticket().generation() + 1));
            let parts = owner.into_parts();
            assert!(parts.pending_network_event.is_none());
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == allocation && canonical_vote == vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES]));
        })).unwrap();
        let images = layout.authority_images();
        let FixedValidatorNodeStartupV0::Ready(ready) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .open(fixture.keys[1].clone())
        .unwrap() else {
            panic!("child reopen")
        };
        ready
            .run_with_signing_session(|scope| {
                let driver = node_driver(scope);
                assert_eq!(
                    driver
                        .selected_artifact_history()
                        .selected_head_block_id()
                        .unwrap(),
                    block.id()
                );
                assert_eq!(driver.position().round(), ConsensusRound::new(0));
            })
            .unwrap();
        assert_eq!(layout.authority_images(), images);
    }
}

#[test]
fn current_finality_handoff_failure_drops_driver_and_preserves_independent_custody() {
    let fixture = Fixture::new();
    let input = lower_proof(&fixture);
    for batch in [false, true] {
        let layout = TestLayout::new("runtime-current-finality-fatal");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let name = std::fs::read_dir(&layout.vote_anchor)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .find(|name| name.ends_with(".anchor"))
            .unwrap();
        let bytes = std::fs::read(layout.vote_anchor.join(&name)).unwrap();
        let next = u64::from_be_bytes(bytes[184..192].try_into().unwrap()) + 1;
        let collision = layout.vote_anchor.join(format!("{name}.tmp-{next:016x}"));
        std::fs::write(&collision, b"current finality handoff collision").unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![], timeouts(Duration::from_secs(60))).unwrap();
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            let timer = owner.timer();
            let mut bytes = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES]; bytes.reserve(17);
            let original = allocations(&bytes);
            owner.queue_input(ConsensusPushMessage::Vote { canonical_vote: bytes }).unwrap();
            assert!(matches!(current(&mut owner, &input, batch, input.payload.clone()),
                Event::Fatal(error) if matches!(*error, naome_runtime::FixedValidatorRuntimeFailureV0::Step(
                    naome_node::FixedValidatorNodeDriverStepErrorV0::CurrentFinality(_)))));
            assert!(owner.driver().is_none());
            assert_eq!(owner.timer(), timer);
            assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
            let parts = owner.into_parts();
            assert!(parts.driver.is_none());
            assert_eq!(parts.timer, timer);
            assert!(parts.publication.is_none());
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == original));
        })).unwrap();
        std::fs::remove_file(collision).unwrap();
        assert!(
            matches!(provision(fixture.definition, fixture.context, &fixture.entries, &layout).open(fixture.keys[1].clone()),
            Err(naome_node::FixedValidatorNodeStartupErrorV0::VotePair(source))
            if matches!(source.as_ref(), naome_storage::FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
                if matches!(inner.as_ref(), naome_storage::FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. })))
        );
    }
}
