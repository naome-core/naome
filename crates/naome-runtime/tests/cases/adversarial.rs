use super::*;
use naome_network::{Keypair, NetworkEvent, StaticArtifactNetwork};
use naome_node::{
    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0,
    FixedValidatorNodeCurrentRoundInboxLimitsV0,
    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0,
    FixedValidatorNodeDriverAdmissionDispositionV0 as Disposition,
    FixedValidatorNodeDriverAdmissionOutcomeV0 as Admission,
    FixedValidatorNodeDriverAdmissionRejectionV0 as Rejection,
    FixedValidatorNodeDriverCommandV0 as Command, FixedValidatorNodeDriverEventV0 as Input,
    FixedValidatorNodeDriverStepOutcomeV0 as Step, FixedValidatorNodeDriverV0 as Driver,
    FixedValidatorNodeHigherRoundInboxLimitsV0,
};
use naome_runtime::FixedValidatorRuntimeRouteV0 as Route;

#[path = "recovery.rs"]
mod recovery;

#[path = "async_lifecycle.rs"]
mod async_lifecycle;
#[path = "caller_input.rs"]
mod caller_input;
#[path = "explicit_proofs.rs"]
mod explicit_proofs;
#[path = "store_authoring.rs"]
mod store_authoring;

fn copy_message(message: &ConsensusPushMessage) -> ConsensusPushMessage {
    match message {
        ConsensusPushMessage::Proposal {
            canonical_proposal,
            canonical_artifact,
        } => ConsensusPushMessage::Proposal {
            canonical_proposal: canonical_proposal.clone(),
            canonical_artifact: canonical_artifact.clone(),
        },
        ConsensusPushMessage::Vote { canonical_vote } => ConsensusPushMessage::Vote {
            canonical_vote: canonical_vote.clone(),
        },
    }
}

fn isolated_network() -> StaticArtifactNetwork {
    StaticArtifactNetwork::new(Keypair::generate_ed25519(), []).unwrap()
}

fn source_messages(fixture: &Fixture) -> [ConsensusPushMessage; 3] {
    source_messages_for_payload(fixture, pairing_payload())
}

fn source_messages_for_payload(fixture: &Fixture, payload: Vec<u8>) -> [ConsensusPushMessage; 3] {
    let layout = TestLayout::new("anchored-fixture");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
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
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                let block = ArtifactChainState::new(fixture.definition)
                    .prepare_block(artifact_id(&payload))
                    .unwrap();
                assert!(matches!(
                    owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                        artifact_block: block,
                        canonical_artifact_bytes: payload
                    }),
                    Event::ProposalAuthored
                ));
                let mut messages = Vec::new();
                for _ in 0..20 {
                    match owner.next_event().await {
                        Event::PublicationComplete(publication) => {
                            messages.push(publication.message().copy_message().unwrap());
                            if messages.len() == 3 {
                                return messages.try_into().unwrap();
                            }
                        }
                        event => check_local(event),
                    }
                }
                panic!("three real anchored publications missing")
            })
        })
        .unwrap()
}

fn arm_driver(driver: Driver<'_>) -> Driver<'_> {
    match driver.step().unwrap() {
        Step::Command {
            driver,
            command: Command::ArmPhaseTimeout(_),
        } => *driver,
        _ => panic!("initial arm missing"),
    }
}

fn admit_driver(driver: Driver<'_>, event: Input) -> Driver<'_> {
    match driver.admit_event(event).unwrap() {
        Admission::Admitted { driver, .. } => *driver,
        Admission::Rejected { rejection, .. } => panic!("fixture admission: {rejection:?}"),
        _ => panic!("fixture admission failed"),
    }
}

fn vote_input(message: &ConsensusPushMessage, precommit: bool) -> Input {
    let ConsensusPushMessage::Vote { canonical_vote } = message else {
        panic!("vote expected")
    };
    if precommit {
        Input::CurrentRoundProposalPrecommit {
            canonical_signed_precommit: canonical_vote.clone().into_boxed_slice(),
        }
    } else {
        Input::CurrentRoundProposalPrevote {
            canonical_signed_prevote: canonical_vote.clone().into_boxed_slice(),
        }
    }
}

async fn raw_exchange<'node>(
    sender: &mut StaticArtifactNetwork,
    receiver: &mut Runtime<'node>,
    message: ConsensusPushMessage,
    mut observe: impl FnMut(Event<'node>),
) -> Box<FixedValidatorRuntimeAdmissionReportV0> {
    let ticket = sender
        .push_consensus(receiver.local_peer_id(), message)
        .unwrap();
    timeout(Duration::from_secs(10), async {
        let mut report = None;
        loop {
            tokio::select! {
                event = sender.next_event() => if let NetworkEvent::OutboundConsensusPush(event) = event {
                    assert_eq!(ticket.complete(event).unwrap().unwrap().peer_id(), receiver.local_peer_id());
                    return report.expect("receipt follows input admission");
                },
                event = async {
                    if report.is_some() {
                        receiver.poll_transport_once().await;
                        tokio::task::yield_now().await;
                        None
                    } else { Some(receiver.next_event().await) }
                } => if let Some(event) = event {
                    match event {
                        Event::Admission(admitted) if matches!(admitted.source, InputSource::Peer(_)) => {
                            assert_eq!(admitted.receipt_queued, Some(true));
                            report = Some(admitted);
                        }
                        event => observe(event),
                    }
                },
            }
        }
    }).await.expect("raw fixture delivery timed out")
}

#[test]
fn stream_receipt_does_not_make_corrupted_proposals_authoritative() {
    let fixture = Fixture::new();
    let [message, _, _] = source_messages(&fixture);
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = message
    else {
        panic!("proposal expected")
    };
    let layout = TestLayout::new("malformed-receiver");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut sender, receiver, _) = executor.block_on(connected_pair());
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let mut owner = Runtime::new(
                    node_driver(scope),
                    receiver,
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                let images = layout.authority_images();
                for corruption in 0..3 {
                    let mut control = canonical_proposal.clone();
                    let mut artifact = canonical_artifact.clone();
                    match corruption {
                        0 => {
                            let index = control.len() - 2;
                            control[index] ^= 0x80;
                        }
                        1 => {
                            *artifact.last_mut().unwrap() = 0xff;
                        }
                        2 => {
                            control[0] ^= 0x80;
                        }
                        _ => unreachable!(),
                    }
                    let expected = ConsensusPushMessage::Proposal {
                        canonical_proposal: control,
                        canonical_artifact: artifact,
                    };
                    let report = raw_exchange(
                        &mut sender,
                        &mut owner,
                        copy_message(&expected),
                        check_local,
                    )
                    .await;
                    assert_eq!(report.input, Some(expected));
                    assert!(report.completed());
                    assert!(!report.all_admitted());
                    assert_eq!(report.results.iter().flatten().count(), 2);
                    assert!(report.results.iter().flatten().all(|r| r.result.is_err()));
                    assert!(report.routing_error.is_none());
                    assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
                    assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
                    assert_eq!(layout.authority_images(), images);
                }
            })
        })
        .unwrap();
}

#[test]
fn current_proposal_reports_each_partial_admission_without_rolling_back_or_dropping_input() {
    partial_admission(false);
}

#[test]
fn caller_proposal_preserves_each_partial_admission_and_original_allocations() {
    partial_admission(true);
}

fn partial_admission(caller_input: bool) {
    let fixture = Fixture::new();
    let [proposal, prevote, precommit] = source_messages(&fixture);
    for full_finality in [false, true] {
        let layout = TestLayout::new("partial-admission");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let (mut sender, receiver, _) = executor.block_on(connected_pair());
        ready
            .run_with_signing_session(|scope| {
                executor.block_on(async {
                    let driver = Driver::new(
                        scope,
                        FixedValidatorNodeHigherRoundInboxLimitsV0::new(8, 1 << 20).unwrap(),
                        FixedValidatorNodeCurrentRoundInboxLimitsV0::new(
                            if full_finality { 8 } else { 1 },
                            1 << 20,
                        )
                        .unwrap(),
                        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(
                            if full_finality { 1 } else { 8 },
                            1 << 20,
                        )
                        .unwrap(),
                        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(8, 1 << 20)
                            .unwrap(),
                        ConsensusRound::new(4),
                    )
                    .unwrap();
                    let driver = admit_driver(
                        arm_driver(driver),
                        vote_input(
                            if full_finality { &precommit } else { &prevote },
                            full_finality,
                        ),
                    );
                    let mut owner =
                        Runtime::new(driver, receiver, vec![], timeouts(Duration::from_secs(60)))
                            .unwrap();
                    let images = layout.authority_images();
                    let observe = |event| match event {
                        Event::DriverBlocked(_) | Event::TimerArmed(_) | Event::Network(_) => {}
                        event => check_local(event),
                    };
                    let report = if caller_input {
                        caller_input::admit(&mut owner, copy_message(&proposal), observe).await
                    } else {
                        raw_exchange(&mut sender, &mut owner, copy_message(&proposal), observe)
                            .await
                    };
                    assert_eq!(report.input, Some(copy_message(&proposal)));
                    assert!(report.completed());
                    assert!(!report.all_admitted());
                    let first = report.results[0].as_ref().unwrap();
                    let second = report.results[1].as_ref().unwrap();
                    assert_eq!(first.route, Route::CurrentFinalityProposal);
                    assert_eq!(second.route, Route::CurrentVotingProposal);
                    if full_finality {
                        assert!(matches!(
                            first.result.as_ref().unwrap_err().as_ref(),
                            Rejection::CurrentFinalityInboxSaturated { .. }
                        ));
                        assert_eq!(second.result.as_ref().unwrap(), &Disposition::Inserted);
                        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
                        assert_eq!(owner.driver().unwrap().current_inbox_len(), 1);
                    } else {
                        assert_eq!(first.result.as_ref().unwrap(), &Disposition::Inserted);
                        assert!(matches!(
                            second.result.as_ref().unwrap_err().as_ref(),
                            Rejection::CurrentInboxSaturated { .. }
                        ));
                        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
                        assert_eq!(owner.driver().unwrap().current_inbox_len(), 1);
                    }
                    assert_eq!(layout.authority_images(), images);
                })
            })
            .unwrap();
    }
}

#[test]
fn blocked_missing_finality_proposal_can_receive_the_proposal_and_select() {
    let fixture = Fixture::new();
    let [proposal, _, precommit] = source_messages(&fixture);
    let layout = TestLayout::new("blocked-finality");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut sender, receiver, _) = executor.block_on(connected_pair());
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let driver = admit_driver(arm_driver(node_driver(scope)), vote_input(&precommit, true));
        let mut owner = Runtime::new(driver, receiver, vec![], timeouts(Duration::from_secs(60))).unwrap();
        let mut blockers = 0;
        let report = raw_exchange(&mut sender, &mut owner, proposal, |event| match event {
            Event::DriverBlocked(naome_node::FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing { .. }) => blockers += 1,
            Event::TimerArmed(_) | Event::Network(_) => {},
            _ => check_local(event),
        }).await;
        assert_eq!(blockers, 1);
        assert!(report.all_admitted());
        assert!(matches!(owner.next_event().await, Event::Finality(_)));
        let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&pairing_payload())).unwrap();
        assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), block.id());
    })).unwrap();
}

#[test]
fn pending_publication_preserves_due_and_buffered_input_across_explicit_drains() {
    let fixture = Fixture::new();
    let [proposal, _, _] = source_messages(&fixture);
    for drain in [false, true] {
        let layout = TestLayout::new("publication-deadline");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[0].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let (network, mut peer, peer_id) = executor.block_on(connected_pair());
        ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(scope), network, vec![peer_id], timeouts(Duration::from_millis(100))).unwrap();
        let Event::TimerArmed(timer) = owner.next_event().await else { panic!("arm missing") };
        let payload = pairing_payload();
        let block = ArtifactChainState::new(fixture.definition).prepare_block(artifact_id(&payload)).unwrap();
        assert!(matches!(owner.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload }), Event::ProposalAuthored));
        assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
        check_local(owner.next_event().await);
        let ticket = peer.push_consensus(owner.local_peer_id(), copy_message(&proposal)).unwrap();
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = peer.next_event() => if matches!(event, NetworkEvent::OutboundConsensusPush(_)) { panic!("receipt cannot precede admission") },
                    buffered = async { let result = owner.poll_transport_once().await; tokio::task::yield_now().await; result } => {
                        if matches!(buffered, naome_runtime::FixedValidatorRuntimeTransportPollV0::BufferedEvent) { break; }
                    }
                }
            }
        }).await.unwrap();
        let refused = owner.queue_input(copy_message(&proposal)).unwrap_err();
        assert_eq!(refused.reason, naome_runtime::FixedValidatorRuntimeQueueFailureV0::InputSlotOccupied);
        assert_eq!(refused.input, proposal);
        tokio::time::sleep_until(timer.deadline()).await;
        let images = layout.authority_images();
        if drain {
            assert_eq!(owner.drain_current_inbox_and_reset().unwrap().len(), 1);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
            assert_eq!(owner.drain_current_finality_inbox_and_reset().unwrap().len(), 1);
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(owner.pending_publication().unwrap().message().copy_message().unwrap(), proposal);
            assert!(owner.pending_publication().unwrap().local_admission_attempted());
            assert_eq!(owner.poll_transport_once().await, naome_runtime::FixedValidatorRuntimeTransportPollV0::InputSlotOccupied);
            assert_eq!(layout.authority_images(), images);
        }
        assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(Disposition::TimeoutMarkedDue) } if ticket == timer.ticket()));
        if drain {
            assert_eq!(owner.drain_current_inbox_and_reset().unwrap().len(), 0);
            assert!(owner.driver().unwrap().timeout_is_due());
        }
        assert!(owner.pending_publication().unwrap().deliveries().all(|d| matches!(d.state(), Delivery::NotAttempted)));
        let Event::Admission(report) = owner.next_event().await else { panic!("buffered input missing") };
        assert_eq!(report.input.as_ref(), Some(&proposal));
        assert_eq!(report.results[0].as_ref().unwrap().result.as_ref().unwrap(), if drain { &Disposition::Inserted } else { &Disposition::AlreadyRetained });
        assert!(matches!(report.results[1].as_ref().unwrap().result.as_ref().unwrap_err().as_ref(), Rejection::CurrentEvidenceAfterDue { .. }));
        assert!(!report.all_admitted());
        assert_eq!(owner.driver().unwrap().phase(), FixedValidatorLockPhaseV0::Proposal);
        assert!(owner.driver().unwrap().timeout_is_due());
        assert_eq!(layout.authority_images(), images);
        // Explicit teardown preserves publication custody and the live driver.
        let parts = owner.into_parts();
        assert!(parts.publication.is_some());
        assert!(parts.driver.is_some());
        drop(ticket);
    })).unwrap();
    }
}

#[test]
fn exact_phase_timers_yield_to_pending_commands_and_retained_quorum_work() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("timer-priority");
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
        tokio::time::pause();
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![], timeouts(Duration::from_secs(1))).unwrap();
        let Event::TimerArmed(first) = owner.next_event().await else { panic!("first arm") };
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(Disposition::TimeoutMarkedDue) } if ticket == first.ticket()));
        assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Prevote, .. }));
        assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
        // Delay while successor Arm remains queued: its deadline begins at the
        // runtime's actual observation, and the old exact ticket cannot fire.
        tokio::time::advance(Duration::from_secs(20)).await;
        let Event::TimerArmed(second) = owner.next_event().await else { panic!("successor arm has priority") };
        assert_ne!(second.ticket(), first.ticket());
        assert_eq!(second.deadline() - tokio::time::Instant::now(), Duration::from_secs(1));
        check_local(owner.next_event().await);
        assert!(matches!(owner.next_event().await, Event::PublicationComplete(_)));
        tokio::time::advance(Duration::from_secs(2)).await;
        // The retained heavy nil-prevote quorum executes before observing the
        // otherwise expired prevote timer, through the ordinary driver step.
        assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Precommit, .. }));
        assert!(owner.timer().is_none());
        assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
        let Event::TimerArmed(third) = owner.next_event().await else { panic!("precommit arm") };
        assert_ne!(third.ticket(), second.ticket());
    })).unwrap();
}

#[test]
fn construction_refuses_invalid_targets_and_overflow_without_consuming_driver_or_network() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("runtime-preflight");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let driver = node_driver(scope);
                let network = isolated_network();
                let network_id = network.local_peer_id();
                let unknown = Keypair::generate_ed25519().public().to_peer_id();
                let images = layout.authority_images();
                let error = Runtime::new(
                    driver,
                    network,
                    vec![unknown; naome_network::MAX_STATIC_PEERS + 1],
                    timeouts(Duration::from_secs(1)),
                )
                .err()
                .unwrap();
                assert_eq!(
                    error.reason,
                    naome_runtime::FixedValidatorRuntimeCreateFailureV0::TooManyPeers {
                        actual: naome_network::MAX_STATIC_PEERS + 1,
                        maximum: naome_network::MAX_STATIC_PEERS
                    }
                );
                let error = Runtime::new(
                    error.driver,
                    error.network,
                    vec![unknown],
                    timeouts(Duration::from_secs(1)),
                )
                .err()
                .unwrap();
                assert_eq!(
                    error.reason,
                    naome_runtime::FixedValidatorRuntimeCreateFailureV0::UnconfiguredPeer(unknown)
                );
                assert_eq!(error.network.local_peer_id(), network_id);
                assert!(error.driver.has_pending_command());
                let phase =
                    FixedValidatorPhaseDurationV0::new(Duration::MAX, Duration::from_nanos(1))
                        .unwrap();
                let error = Runtime::new(
                    error.driver,
                    error.network,
                    vec![],
                    FixedValidatorRuntimeTimeoutsV0::new(phase, phase, phase),
                )
                .err()
                .unwrap();
                assert!(matches!(
                    error.reason,
                    naome_runtime::FixedValidatorRuntimeCreateFailureV0::Timing(
                        naome_runtime::FixedValidatorRuntimeTimingErrorV0::DurationOverflow { .. }
                    )
                ));
                let phase = FixedValidatorPhaseDurationV0::new(
                    Duration::from_secs(u64::MAX / 2),
                    Duration::from_nanos(1),
                )
                .unwrap();
                let error = Runtime::new(
                    error.driver,
                    error.network,
                    vec![],
                    FixedValidatorRuntimeTimeoutsV0::new(phase, phase, phase),
                )
                .err()
                .unwrap();
                assert_eq!(
                    error.reason,
                    naome_runtime::FixedValidatorRuntimeCreateFailureV0::Timing(
                        naome_runtime::FixedValidatorRuntimeTimingErrorV0::DeadlineOverflow
                    )
                );
                assert_eq!(error.network.local_peer_id(), network_id);
                assert!(error.driver.has_pending_command());
                let configured_network = StaticArtifactNetwork::new(
                    Keypair::generate_ed25519(),
                    [naome_network::StaticPeer::new(
                        unknown,
                        "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    )],
                )
                .unwrap();
                let error = Runtime::new(
                    error.driver,
                    configured_network,
                    vec![unknown, unknown],
                    timeouts(Duration::from_secs(1)),
                )
                .err()
                .unwrap();
                assert_eq!(
                    error.reason,
                    naome_runtime::FixedValidatorRuntimeCreateFailureV0::DuplicatePeer(unknown)
                );
                assert_eq!(error.peers, vec![unknown, unknown]);
                assert!(error.driver.has_pending_command());
                assert_eq!(layout.authority_images(), images);
            })
        })
        .unwrap();
}

#[test]
fn fatal_anchored_vote_failure_returns_no_driver_and_strict_reopen_refuses_lagging_anchor() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("fatal-anchor");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let name = std::fs::read_dir(&layout.vote_anchor)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .find(|name| name.ends_with(".anchor"))
        .unwrap();
    let collision = layout.vote_anchor.join(format!("{name}.tmp-{:016x}", 3));
    std::fs::write(&collision, b"deterministic runtime anchor collision").unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready.run_with_signing_session(|scope| executor.block_on(async {
        tokio::time::pause();
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![], timeouts(Duration::from_secs(1))).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(owner.next_event().await, Event::TimerDue { result: Ok(_), .. }));
        let queued = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES];
        let queued_original = (queued.as_ptr(), queued.len(), queued.capacity());
        owner.queue_input(ConsensusPushMessage::Vote { canonical_vote: queued }).unwrap();
        assert!(matches!(owner.next_event().await, Event::Fatal(error) if matches!(*error, naome_runtime::FixedValidatorRuntimeFailureV0::Step(naome_node::FixedValidatorNodeDriverStepErrorV0::Vote(_)))));
        assert!(owner.driver().is_none());
        assert!(owner.pending_publication().is_none());
        let timer = owner.timer();
        assert!(owner.drain_inbox_and_reset().is_none());
        assert!(owner.drain_current_inbox_and_reset().is_none());
        assert!(owner.drain_current_finality_inbox_and_reset().is_none());
        assert!(owner.drain_current_nil_precommit_inbox_and_reset().is_none());
        assert_eq!(owner.timer(), timer);
        let input = ConsensusPushMessage::Vote { canonical_vote: Vec::with_capacity(19) };
        let original = match &input { ConsensusPushMessage::Vote { canonical_vote } => (canonical_vote.as_ptr(), canonical_vote.capacity()), _ => unreachable!() };
        let error = owner.queue_input(input).unwrap_err();
        assert_eq!(error.reason, naome_runtime::FixedValidatorRuntimeQueueFailureV0::DriverUnavailable);
        assert!(matches!(&error.input, ConsensusPushMessage::Vote { canonical_vote } if (canonical_vote.as_ptr(), canonical_vote.capacity()) == original));
        assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
        let parts = owner.into_parts();
        assert!(parts.driver.is_none());
        assert!(parts.publication.is_none());
        assert!(parts.pending_network_event.is_none());
        assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if (canonical_vote.as_ptr(), canonical_vote.len(), canonical_vote.capacity()) == queued_original));
    })).unwrap();
    std::fs::remove_file(collision).unwrap();
    assert!(
        matches!(provision(fixture.definition, fixture.context, &fixture.entries, &layout).open(fixture.keys[0].clone()),
        Err(naome_node::FixedValidatorNodeStartupErrorV0::VotePair(source))
        if matches!(source.as_ref(), naome_storage::FixedValidatorAnchoredVoteSafetyJournalErrorV0::Journal(inner)
            if matches!(inner.as_ref(), naome_storage::FixedValidatorVoteSafetyJournalErrorV0::AnchorBehind { .. })))
    );
}

fn empty_round(mut driver: Driver<'_>) -> Driver<'_> {
    for _ in 0..3 {
        let ticket = driver.active_timeout().unwrap();
        driver = admit_driver(driver, Input::TimeoutDue(ticket));
        driver = match driver.step().unwrap() {
            Step::Transitioned { driver } => *driver,
            _ => panic!("empty transition missing"),
        };
        if driver.phase() != FixedValidatorLockPhaseV0::Proposal {
            driver = match driver.step().unwrap() {
                Step::Command {
                    driver,
                    command:
                        Command::PublishVote {
                            vote,
                            released_proposal,
                        },
                } => {
                    assert_eq!(vote.target(), naome_consensus::ConsensusVoteTarget::Nil);
                    assert!(released_proposal.is_none());
                    *driver
                }
                _ => panic!("empty round vote missing"),
            };
        }
        driver = arm_driver(driver);
    }
    driver
}

fn higher_messages(fixture: &Fixture) -> [ConsensusPushMessage; 2] {
    let layout = TestLayout::new("higher-fixture");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let selected = ArtifactChainState::new(fixture.definition);
                let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
                    fixture.context,
                    &fixture.entries,
                    selected.branch_snapshot(),
                )
                .unwrap();
                let mut round = branch.begin_round_zero().unwrap().advance_round().unwrap();
                while round.proposer() != consensus_key(&fixture.keys[0]) {
                    round = round.advance_round().unwrap();
                }
                assert!(round.position().round().value() <= 4);
                let mut driver = arm_driver(node_driver(scope));
                while driver.position().round() != round.position().round() {
                    driver = empty_round(driver);
                }
                let mut owner = Runtime::new(
                    driver,
                    isolated_network(),
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                let payload = pairing_payload();
                let block = selected.prepare_block(artifact_id(&payload)).unwrap();
                assert!(matches!(
                    owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                        artifact_block: block,
                        canonical_artifact_bytes: payload
                    }),
                    Event::ProposalAuthored
                ));
                let mut messages = Vec::new();
                for _ in 0..16 {
                    match owner.next_event().await {
                        Event::PublicationComplete(publication) => {
                            messages.push(publication.message().copy_message().unwrap());
                            if messages.len() == 2 {
                                return messages.try_into().unwrap();
                            }
                        }
                        event => check_local(event),
                    }
                }
                panic!("higher proposal and prevote missing")
            })
        })
        .unwrap()
}

fn token_observation(publication: &Publication) -> (Vec<u8>, Vec<u8>, usize, usize, Vec<u8>) {
    let Message::Vote {
        vote,
        released_proposal: Some(token),
    } = publication.message()
    else {
        panic!("higher-round token required")
    };
    (
        token.canonical_proposal_control_bytes().to_vec(),
        token.canonical_artifact_bytes().to_vec(),
        token.canonical_proposal_control_bytes().as_ptr() as usize,
        token.canonical_artifact_bytes().as_ptr() as usize,
        vote.canonical_bytes().to_vec(),
    )
}

#[test]
fn higher_round_publication_preserves_some_token_across_drains_cancel_and_delivery_outcomes() {
    let fixture = Fixture::new();
    let [proposal, prevote] = higher_messages(&fixture);
    for asynchronous_failure in [false, true] {
        let layout = TestLayout::new("higher-custody");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let idle_peer = Keypair::generate_ed25519().public().to_peer_id();
        let (mut sender, network, _) =
            executor.block_on(connected_pair_with_extra(Some(idle_peer)));
        let sender_peer = sender.local_peer_id();
        ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), network, vec![idle_peer, sender_peer], timeouts(Duration::from_secs(60))).unwrap();
            let initial = layout.authority_images();
            let report = raw_exchange(&mut sender, &mut owner, copy_message(&proposal), check_local).await;
            assert_eq!(report.results[0].as_ref().unwrap().route, Route::HigherProposal);
            assert!(report.all_admitted());
            let report = raw_exchange(&mut sender, &mut owner, copy_message(&prevote), check_local).await;
            assert_eq!(report.results[0].as_ref().unwrap().route, Route::HigherProposalPrevote);
            assert!(report.all_admitted());
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Precommit, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            let original = token_observation(owner.pending_publication().unwrap());
            let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = &proposal else { panic!("proposal") };
            assert_eq!(&original.0, canonical_proposal);
            assert_eq!(&original.1, canonical_artifact);
            let pending_ticket = owner.driver().unwrap().active_timeout();
            assert!(owner.driver().unwrap().has_pending_command());
            let images = layout.authority_images();
            let higher_len = owner.driver().unwrap().inbox_len();
            let queued = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES];
            let queued_original = (queued.as_ptr(), queued.len(), queued.capacity());
            owner.queue_input(ConsensusPushMessage::Vote { canonical_vote: queued }).unwrap();
            assert_eq!(owner.poll_transport_once().await, naome_runtime::FixedValidatorRuntimeTransportPollV0::InputSlotOccupied);
            assert_eq!(owner.drain_inbox_and_reset().unwrap().count(), higher_len);
            assert!(owner.driver().unwrap().has_pending_command());
            assert_eq!(owner.driver().unwrap().active_timeout(), pending_ticket);
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert_eq!(layout.authority_images(), images);
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            check_local(owner.next_event().await);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
            // Token retention does not silently insert its proposal for finality.
            assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
            assert_eq!(&layout.authority_images()[..2], &initial[..2]);
            assert_ne!(&layout.authority_images()[2..], &initial[2..]);
            let timer = owner.timer();
            let images = layout.authority_images();
            let Event::Admission(report) = owner.next_event().await else { panic!("caller input precedes a new peer attempt") };
            assert_eq!(report.source, InputSource::CallerInput);
            assert_eq!(report.receipt_queued, None);
            assert!(report.routing_error.is_some());
            assert!(matches!(report.input, Some(ConsensusPushMessage::Vote { canonical_vote }) if (canonical_vote.as_ptr(), canonical_vote.len(), canonical_vote.capacity()) == queued_original));
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert_eq!(owner.timer(), timer);
            assert!(owner.pending_publication().unwrap().local_admission_attempted());
            assert!(owner.pending_publication().unwrap().deliveries().all(|d| matches!(d.state(), Delivery::NotAttempted)));
            assert_eq!(layout.authority_images(), images);
            let mut attempted = Vec::new();
            while attempted.len() != 2 {
                match owner.next_event().await {
                    Event::PeerAttempted { peer_id, started } => attempted.push((peer_id, started)),
                    Event::Network(_) => {},
                    _ => panic!("expected one ordered peer attempt"),
                }
                assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            }
            assert_eq!(attempted, vec![(idle_peer, false), (sender_peer, true)]);
            let states = owner.pending_publication().unwrap().deliveries().collect::<Vec<_>>();
            assert!(matches!(states[0].state(), Delivery::Refused(naome_network::ConsensusPushStartFailure::RequestStart(naome_network::RequestStartError::PeerDisconnected(peer))) if *peer == idle_peer));
            assert!(matches!(states[1].state(), Delivery::InFlight(_)));
            // Poll and drop a genuinely pending borrowed future. Its original
            // vote, exact Some token, and opaque in-flight ticket stay owned.
            let mut cancelled = false;
            for _ in 0..16 {
                match timeout(Duration::from_millis(2), owner.next_event()).await {
                    Err(_) => { cancelled = true; break; }
                    Ok(Event::Network(_)) => {},
                    Ok(_) => panic!("peer has not been polled to receive this vote"),
                }
            }
            assert!(cancelled);
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert!(owner.pending_publication().unwrap().deliveries().any(|d| matches!(d.state(), Delivery::InFlight(_))));
            let timer = owner.timer();
            let images = layout.authority_images();
            let mut drained = owner.drain_current_finality_inbox_and_reset().unwrap();
            assert!(matches!(drained.next(), Some(naome_node::FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0::ProposalPrecommit(bytes)) if bytes.as_slice() == original.4));
            assert!(drained.next().is_none());
            assert_eq!(owner.drain_current_inbox_and_reset().unwrap().len(), 0);
            assert_eq!(owner.drain_current_nil_precommit_inbox_and_reset().unwrap().len(), 0);
            assert_eq!(owner.timer(), timer);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
            assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
            assert!(owner.pending_publication().unwrap().local_admission_attempted());
            assert!(owner.pending_publication().unwrap().deliveries().any(|d| matches!(d.state(), Delivery::InFlight(_))));
            assert_eq!(layout.authority_images(), images);
            let mut sender = Some(sender);
            if asynchronous_failure { drop(sender.take()); }
            let mut received_bytes = false;
            let mut correlated = false;
            let completed = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        event = owner.next_event() => match event {
                            Event::PeerCompleted { peer_id, received } => {
                                assert_eq!(peer_id, sender_peer);
                                assert_eq!(received, !asynchronous_failure);
                                correlated = true;
                            }
                            Event::PublicationComplete(publication) => break publication,
                            Event::Network(_) => {},
                            _ => panic!("unexpected publication completion event"),
                        },
                        event = async { sender.as_mut().unwrap().next_event().await }, if sender.is_some() => {
                            if let NetworkEvent::InboundConsensusPush(inbound) = event {
                                assert!(matches!(inbound.message(), ConsensusPushMessage::Vote { canonical_vote } if canonical_vote == &original.4));
                                let _ = sender.as_mut().unwrap().acknowledge_consensus_push(inbound).unwrap();
                                received_bytes = true;
                            }
                        },
                    }
                    assert_eq!(token_observation(owner.pending_publication().unwrap()), original);
                }
            }).await.unwrap();
            assert!(correlated);
            assert_eq!(received_bytes, !asynchronous_failure);
            assert_eq!(token_observation(&completed), original);
            let states = completed.deliveries().collect::<Vec<_>>();
            assert_eq!(states[0].peer_id(), idle_peer);
            assert_eq!(states[1].peer_id(), sender_peer);
            if asynchronous_failure { assert!(matches!(states[1].state(), Delivery::Failed(_))); }
            else { assert!(matches!(states[1].state(), Delivery::Received(_))); }
            assert!(owner.pending_publication().is_none());
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
            let mut idle_again = false;
            for _ in 0..16 {
                match timeout(Duration::from_millis(2), owner.next_event()).await {
                    Err(_) => { idle_again = true; break; }
                    Ok(Event::Network(_)) => {},
                    Ok(_) => panic!("completed peer failures and receipts must never restart publication"),
                }
            }
            assert!(idle_again);
            assert_eq!(token_observation(&completed), original);
            assert_eq!(&layout.authority_images()[..2], &initial[..2]);
        })).unwrap();
    }
}

#[test]
fn higher_saturation_yields_one_rejected_deadline_and_keeps_strict_finality_escape_open() {
    let fixture = Fixture::new();
    let [higher_proposal, higher_prevote] = higher_messages(&fixture);
    let [proposal, _, precommit] = source_messages(&fixture);
    for drain in [false, true] {
        let layout = TestLayout::new("higher-blocked-timer");
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let (mut sender, network, _) = executor.block_on(connected_pair());
        ready.run_with_signing_session(|scope| executor.block_on(async {
        let driver = Driver::new(scope,
            FixedValidatorNodeHigherRoundInboxLimitsV0::new(1, 1 << 20).unwrap(),
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(8, 1 << 20).unwrap(),
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(8, 1 << 20).unwrap(),
            FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(8, 1 << 20).unwrap(), ConsensusRound::new(4)).unwrap();
        let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = copy_message(&higher_proposal) else { panic!("proposal") };
        let round = naome_consensus::UnverifiedFixedConsensusProposalRouteV0::inspect(&canonical_proposal).unwrap().position().round();
        let driver = admit_driver(arm_driver(driver), Input::HigherRoundProposal { proposal_round: round,
            canonical_proposal_control_bytes: canonical_proposal.into_boxed_slice(), canonical_artifact_bytes: canonical_artifact.into_boxed_slice() });
        let ConsensusPushMessage::Vote { canonical_vote } = copy_message(&higher_prevote) else { panic!("prevote") };
        let driver = match driver.admit_event(Input::HigherRoundProposalPrevote { canonical_signed_prevote: canonical_vote.into_boxed_slice() }).unwrap() {
            Admission::Rejected { driver, rejection, .. } => {
                assert!(matches!(*rejection, Rejection::PrevoteInbox(ref error) if error.newly_saturated())); *driver
            }
            _ => panic!("higher inbox must saturate"),
        };
        let mut owner = Runtime::new(driver, network, vec![], timeouts(Duration::from_millis(1))).unwrap();
        assert!(matches!(owner.next_event().await, Event::DriverBlocked(naome_node::FixedValidatorNodeDriverBlockReasonV0::Saturated(_))));
        let Event::TimerArmed(timer) = owner.next_event().await else { panic!("existing arm adopted") };
        tokio::time::sleep_until(timer.deadline()).await;
        assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Err(error) }
            if ticket == timer.ticket() && matches!(*error, Rejection::Blocked(naome_node::FixedValidatorNodeDriverBlockReasonV0::Saturated(_)))));
        assert_eq!(owner.timer().unwrap(), timer);
        assert!(!owner.driver().unwrap().timeout_is_due());
        let report = raw_exchange(&mut sender, &mut owner, copy_message(&proposal), |event| match event {
            Event::Network(_) => {},
            _ => panic!("the rejected exact deadline must not spin or restart"),
        }).await;
        assert_eq!(report.results[0].as_ref().unwrap().result.as_ref().unwrap(), &Disposition::Inserted);
        assert!(matches!(report.results[1].as_ref().unwrap().result.as_ref().unwrap_err().as_ref(), Rejection::Blocked(_)));
        assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
        assert_eq!(owner.driver().unwrap().inbox_len(), 1);
        let mut repeated_blockers = 0;
        let report = raw_exchange(&mut sender, &mut owner, copy_message(&precommit), |event| match event {
            Event::DriverBlocked(_) => repeated_blockers += 1,
            Event::Network(_) => {},
            _ => panic!("only strict input should re-enable one classification"),
        }).await;
        assert_eq!(repeated_blockers, 1);
        assert!(report.all_admitted());
        if drain {
            let images = layout.authority_images();
            assert_eq!(owner.drain_inbox_and_reset().unwrap().len(), 1);
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 2);
            assert_eq!(layout.authority_images(), images);
        }
        // A higher drain restores normal classification. Ready retained
        // finality still precedes the original expired deadline.
        assert!(matches!(owner.next_event().await, Event::Finality(_)));
        let Event::TimerArmed(next) = owner.next_event().await else { panic!("child timer") };
        assert_ne!(next.ticket(), timer.ticket());
        let parts = owner.into_parts();
        assert!(parts.rejected_due_ticket.is_none());
        assert_eq!(parts.driver.unwrap().inbox_len(), usize::from(!drain));
    })).unwrap();
    }
}

#[test]
fn unsupported_untrusted_headers_return_original_bytes_without_admission() {
    let fixture = Fixture::new();
    let [_, current_prevote, current_precommit] = source_messages(&fixture);
    let [_, higher_prevote] = higher_messages(&fixture);
    let layout = TestLayout::new("unsupported-routes");
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut sender, network, _) = executor.block_on(connected_pair());
    ready.run_with_signing_session(|scope| executor.block_on(async {
        let mut owner = Runtime::new(node_driver(scope), network, vec![], timeouts(Duration::from_secs(60))).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        let images = layout.authority_images();
        for variant in 0..3 {
            let ConsensusPushMessage::Vote { mut canonical_vote } = copy_message(if variant == 0 { &current_prevote } else { &higher_prevote }) else { panic!("vote") };
            if variant == 0 { canonical_vote[1] ^= 0x80; } // descriptive chain identity only
            else {
                let ConsensusPushMessage::Vote { canonical_vote: precommit } = &current_precommit else { panic!("precommit") };
                canonical_vote[0] = if variant == 1 { precommit[0] } else { 0xff };
            }
            let message = ConsensusPushMessage::Vote { canonical_vote };
            let report = raw_exchange(&mut sender, &mut owner, copy_message(&message), check_local).await;
            assert_eq!(report.input, Some(message));
            assert!(!report.all_admitted());
            assert!(!report.completed());
            assert!(report.results.iter().all(Option::is_none));
            assert!(matches!((variant, report.routing_error),
                (0, Some(naome_runtime::FixedValidatorRuntimeRoutingErrorV0::OtherContext { .. })) |
                (1, Some(naome_runtime::FixedValidatorRuntimeRoutingErrorV0::UnsupportedHigherVote { role: ConsensusVoteRole::Precommit, .. })) |
                (2, Some(naome_runtime::FixedValidatorRuntimeRoutingErrorV0::Vote(naome_consensus::ConsensusVoteDecodeError::UnknownRoleTag { actual: 0xff })))));
            assert_eq!(owner.driver().unwrap().inbox_len(), 0);
            assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
            assert_eq!(layout.authority_images(), images);
        }
    })).unwrap();
}
