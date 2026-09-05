use super::*;
use naome_runtime::{
    FixedValidatorRuntimeQueueFailureV0 as QueueFailure,
    FixedValidatorRuntimeTransportPollV0 as TransportPoll,
};

fn allocations(input: &ConsensusPushMessage) -> Vec<(usize, usize, usize)> {
    let observe = |bytes: &Vec<u8>| (bytes.as_ptr() as usize, bytes.len(), bytes.capacity());
    match input {
        ConsensusPushMessage::Proposal {
            canonical_proposal,
            canonical_artifact,
        } => vec![observe(canonical_proposal), observe(canonical_artifact)],
        ConsensusPushMessage::Vote { canonical_vote } => vec![observe(canonical_vote)],
    }
}

pub(super) async fn admit<'node>(
    owner: &mut Runtime<'node>,
    input: ConsensusPushMessage,
    mut observe: impl FnMut(Event<'node>),
) -> Box<FixedValidatorRuntimeAdmissionReportV0> {
    let original = allocations(&input);
    owner.queue_input(input).unwrap();
    for _ in 0..20 {
        match owner.next_event().await {
            Event::Admission(report) if report.source == InputSource::CallerInput => {
                assert_eq!(report.receipt_queued, None);
                assert_eq!(allocations(report.input.as_ref().unwrap()), original);
                return report;
            }
            event => observe(event),
        }
    }
    panic!("caller input was not admitted");
}

#[test]
fn queue_checks_lengths_and_one_slot_without_admission_or_transport_work() {
    let fixture = Fixture::new();
    let [proposal, _, _] = source_messages(&fixture);
    let layout = TestLayout::new("caller-queue-custody");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let mut owner = Runtime::new(
                    node_driver(scope),
                    isolated_network(),
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap();
                let images = layout.authority_images();
                for input in [
                    ConsensusPushMessage::Vote {
                        canonical_vote: vec![],
                    },
                    ConsensusPushMessage::Proposal {
                        canonical_proposal: vec![
                            0;
                            naome_network::CONSENSUS_PUSH_MAX_PROPOSAL_BYTES
                                + 1
                        ],
                        canonical_artifact: vec![1],
                    },
                ] {
                    let original = allocations(&input);
                    let error = owner.queue_input(input).unwrap_err();
                    assert!(matches!(error.reason, QueueFailure::Length(_)));
                    assert_eq!(allocations(&error.input), original);
                }
                let original = allocations(&proposal);
                owner.queue_input(proposal).unwrap();
                // Occupancy takes priority even over invalid lengths. No second slot.
                let other = ConsensusPushMessage::Vote {
                    canonical_vote: Vec::with_capacity(17),
                };
                let other_original = allocations(&other);
                let error = owner.queue_input(other).unwrap_err();
                assert_eq!(error.reason, QueueFailure::InputSlotOccupied);
                assert_eq!(allocations(&error.input), other_original);
                assert_eq!(
                    owner.poll_transport_once().await,
                    TransportPoll::InputSlotOccupied
                );
                assert!(owner.timer().is_none());
                assert!(owner.driver().unwrap().has_pending_command());
                assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
                assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
                assert_eq!(layout.authority_images(), images);
                let parts = owner.into_parts();
                assert!(parts.pending_network_event.is_none());
                assert_eq!(
                    allocations(parts.pending_caller_input.as_ref().unwrap()),
                    original
                );
            })
        })
        .unwrap();
}

#[test]
fn caller_input_uses_strict_dual_admission_and_returns_corruption_intact() {
    let fixture = Fixture::new();
    let [proposal, _, _] = source_messages(&fixture);
    for corruption in 0..3 {
        let layout = TestLayout::new("caller-corruption");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        ready
            .run_with_signing_session(|scope| {
                executor.block_on(async {
                    let mut owner = Runtime::new(
                        node_driver(scope),
                        isolated_network(),
                        vec![],
                        timeouts(Duration::from_secs(60)),
                    )
                    .unwrap();
                    let images = layout.authority_images();
                    let mut input = copy_message(&proposal);
                    let ConsensusPushMessage::Proposal {
                        canonical_proposal,
                        canonical_artifact,
                    } = &mut input
                    else {
                        panic!("proposal")
                    };
                    match corruption {
                        0 => {
                            let last = canonical_proposal.len() - 2;
                            canonical_proposal[last] ^= 0x80;
                        }
                        1 => {
                            *canonical_artifact.last_mut().unwrap() = 0xff;
                        }
                        2 => {
                            canonical_proposal[0] ^= 0x80;
                        }
                        _ => unreachable!(),
                    }
                    let expected = copy_message(&input);
                    let report = admit(&mut owner, input, check_local).await;
                    assert_eq!(report.input, Some(expected));
                    assert!(report.completed());
                    assert!(!report.all_admitted());
                    assert_eq!(report.results.iter().flatten().count(), 2);
                    assert!(
                        report
                            .results
                            .iter()
                            .flatten()
                            .all(|result| result.result.is_err())
                    );
                    assert!(report.routing_error.is_none());
                    assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
                    assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
                    assert_eq!(layout.authority_images(), images);
                })
            })
            .unwrap();
    }
}

#[test]
fn caller_input_waits_behind_pending_arm_and_original_due_deadline() {
    let fixture = Fixture::new();
    let [proposal, _, _] = source_messages(&fixture);
    let layout = TestLayout::new("caller-input-due");
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
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![],
            timeouts(Duration::from_millis(1))).unwrap();
        let original = allocations(&proposal);
        owner.queue_input(proposal).unwrap();
        let Event::TimerArmed(timer) = owner.next_event().await else { panic!("command precedes input") };
        let images = layout.authority_images();
        tokio::time::sleep_until(timer.deadline()).await;
        assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
        assert!(owner.driver().unwrap().timeout_is_due());
        assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
        assert_eq!(layout.authority_images(), images);
        let parts = owner.into_parts();
        assert!(parts.pending_network_event.is_none());
        assert_eq!(allocations(parts.pending_caller_input.as_ref().unwrap()), original);
    })).unwrap();
}
