#![cfg(unix)]

#[path = "cases/adversarial.rs"]
mod adversarial;
mod support;

use ed25519_dalek::SigningKey;
use naome_chain::{ArtifactChainDefinition, ArtifactChainState};
use naome_consensus::{
    ActiveAgreementEntry, AgreementWeight, ConsensusContextV0, ConsensusGenesisId,
    ConsensusProtocolVersion, ConsensusRound, ConsensusVoteRole, FixedConsensusBranchV0,
    FixedValidatorLockPhaseV0, FixedValidatorProposalSourceV0,
};
use naome_network::ConsensusPushMessage;
use naome_node::FixedValidatorNodeStartupV0;
use naome_runtime::{
    FixedValidatorPhaseDurationV0, FixedValidatorRuntimeAdmissionReportV0,
    FixedValidatorRuntimeDeliveryStateV0 as Delivery, FixedValidatorRuntimeEventV0 as Event,
    FixedValidatorRuntimeInputSourceV0 as InputSource,
    FixedValidatorRuntimePublicationMessageV0 as Message,
    FixedValidatorRuntimePublicationV0 as Publication, FixedValidatorRuntimeTimeoutsV0,
    FixedValidatorRuntimeV0 as Runtime,
};
use std::time::Duration;
use support::*;
use tokio::{runtime::Builder, time::timeout};

struct Fixture {
    definition: ArtifactChainDefinition,
    context: ConsensusContextV0,
    keys: [SigningKey; 2],
    entries: [ActiveAgreementEntry; 2],
}

impl Fixture {
    fn new() -> Self {
        Self::weighted(3)
    }

    fn weighted(first_weight: u128) -> Self {
        let definition = ArtifactChainDefinition::new([0x71; 32]);
        let context = ConsensusContextV0::new(
            definition.id(),
            ConsensusGenesisId::from_bytes([0x72; 32]),
            ConsensusProtocolVersion::new(7),
        );
        let keys = [
            SigningKey::from_bytes(&[0x73; 32]),
            SigningKey::from_bytes(&[0x74; 32]),
        ];
        let entries = [
            ActiveAgreementEntry::new(consensus_key(&keys[0]), AgreementWeight::new(first_weight)),
            ActiveAgreementEntry::new(consensus_key(&keys[1]), AgreementWeight::new(1)),
        ];
        let selected = ArtifactChainState::new(definition);
        let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
            context,
            &entries,
            selected.branch_snapshot(),
        )
        .unwrap();
        let proposer = branch.begin_round_zero().unwrap().proposer();
        let mut keys = keys;
        if proposer != consensus_key(&keys[0]) {
            keys.swap(0, 1);
        }
        Self {
            definition,
            context,
            keys,
            entries,
        }
    }
}

fn timeouts(base: Duration) -> FixedValidatorRuntimeTimeoutsV0 {
    let phase = FixedValidatorPhaseDurationV0::new(base, Duration::from_millis(1)).unwrap();
    FixedValidatorRuntimeTimeoutsV0::new(phase, phase, phase)
}

fn check_local(event: Event<'_>) {
    match event {
        Event::Admission(report) => {
            assert_eq!(report.source, InputSource::LocalPublication);
            assert!(
                report.all_admitted(),
                "local routes: {:?}; error: {:?}",
                report.results,
                report.routing_error
            );
            assert!(report.input.is_none());
        }
        Event::TimerArmed(_) | Event::Transitioned { .. } => {}
        Event::PublicationComplete(publication) => {
            assert_eq!(publication.deliveries().count(), 0);
            assert!(publication.is_complete());
        }
        Event::PublicationPrepared(_) | Event::Network(_) => {}
        Event::Fatal(error) => panic!("fatal: {error}"),
        Event::DriverRejected(error) => panic!("driver rejected: {error:?}"),
        Event::DriverBlocked(error) => panic!("driver blocked: {error:?}"),
        _ => panic!("unexpected runtime event"),
    }
}

/// Finish exactly one one-way publication. After receiver admission, service
/// transport alone until the sender observes its correlated stream receipt.
async fn exchange<'a, 'b>(
    sender: &mut Runtime<'a>,
    receiver: &mut Runtime<'b>,
) -> (
    Box<Publication>,
    Box<FixedValidatorRuntimeAdmissionReportV0>,
) {
    timeout(Duration::from_secs(10), async {
        let mut admitted = None;
        let mut receipt = false;
        loop {
            if let Some(report) = admitted.take() {
                tokio::select! {
                    event = sender.next_event() => match event {
                        Event::PeerCompleted { received, .. } => { assert!(received); receipt = true; }
                        Event::PublicationComplete(publication) => {
                            assert!(receipt);
                            assert!(publication.is_complete());
                            assert!(publication.deliveries().all(|d| matches!(d.state(), Delivery::Received(_))));
                            return (publication, report);
                        }
                        event => check_local(event),
                    },
                    _ = async { receiver.poll_transport_once().await; tokio::task::yield_now().await; } => {}
                }
                admitted = Some(report);
            } else {
                tokio::select! {
                    event = sender.next_event() => match event {
                        Event::PeerAttempted { started, .. } => assert!(started),
                        Event::PeerCompleted { received, .. } => { assert!(received); receipt = true; }
                        event => check_local(event),
                    },
                    event = receive_without_crossed_send(receiver) => match event {
                        Event::Admission(report) if matches!(report.source, InputSource::Peer(_)) => {
                            assert_eq!(report.source, InputSource::Peer(sender.local_peer_id()));
                            assert_eq!(report.receipt_queued, Some(true));
                            assert!(report.all_admitted(), "routes: {:?}; error: {:?}", report.results, report.routing_error);
                            admitted = Some(report);
                        }
                        event => check_local(event),
                    },
                }
            }
        }
    }).await.expect("one-shot publication did not complete")
}

// A caller may hold its own publication while explicitly servicing transport.
// Once input is buffered, normal next_event still owns admission and its timer.
async fn receive_without_crossed_send<'node>(receiver: &mut Runtime<'node>) -> Event<'node> {
    if receiver
        .pending_publication()
        .is_some_and(|p| p.local_admission_attempted() && p.deliveries().count() > 0)
    {
        loop {
            if matches!(
                receiver.poll_transport_once().await,
                naome_runtime::FixedValidatorRuntimeTransportPollV0::BufferedEvent
                    | naome_runtime::FixedValidatorRuntimeTransportPollV0::InputSlotOccupied
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    }
    receiver.next_event().await
}

async fn hold_local_vote(owner: &mut Runtime<'_>, role: ConsensusVoteRole) {
    prepare_vote(owner, role).await;
    assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
    check_local(owner.next_event().await);
    assert!(
        owner
            .pending_publication()
            .unwrap()
            .deliveries()
            .all(|d| matches!(d.state(), Delivery::NotAttempted))
    );
}

async fn prepare_vote(owner: &mut Runtime<'_>, role: ConsensusVoteRole) {
    for _ in 0..8 {
        if let Event::PublicationPrepared(_) = owner.next_event().await {
            let Message::Vote {
                vote,
                released_proposal,
            } = owner.pending_publication().unwrap().message()
            else {
                panic!("expected vote")
            };
            assert_eq!(vote.role(), role);
            assert!(released_proposal.is_none());
            return;
        }
    }
    panic!("vote publication missing");
}

#[test]
fn two_runtime_owners_deliver_anchored_publications_select_and_strictly_reopen() {
    let fixture = Fixture::new();
    let source_layout = TestLayout::new("source");
    let receiver_layout = TestLayout::new("receiver");
    let source_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &source_layout,
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let receiver_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &receiver_layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (source_network, receiver_network, receiver_peer) = executor.block_on(connected_pair());
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
    source_ready
        .run_with_signing_session(|source_scope| {
            receiver_ready
                .run_with_signing_session(|receiver_scope| {
                    executor.block_on(async {
                        // Explicit one-way publication targets. The heavy validator owns a
                        // quorum; the receiver still requires its real remote evidence.
                        let mut source = Runtime::new(
                            node_driver(source_scope),
                            source_network,
                            vec![receiver_peer],
                            timeouts(Duration::from_secs(60)),
                        )
                        .unwrap();
                        let mut receiver = Runtime::new(
                            node_driver(receiver_scope),
                            receiver_network,
                            vec![],
                            timeouts(Duration::from_secs(60)),
                        )
                        .unwrap();
                        assert!(matches!(source.next_event().await, Event::TimerArmed(_)));
                        assert!(matches!(receiver.next_event().await, Event::TimerArmed(_)));
                        let source_initial = source_layout.authority_images();
                        let receiver_initial = receiver_layout.authority_images();
                        assert!(matches!(
                            source.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                                artifact_block: block,
                                canonical_artifact_bytes: payload.clone()
                            }),
                            Event::ProposalAuthored
                        ));
                        assert!(matches!(
                            source.next_event().await,
                            Event::PublicationPrepared(_)
                        ));
                        assert_eq!(&source_layout.authority_images()[..2], &source_initial[..2]);
                        assert_ne!(&source_layout.authority_images()[2..], &source_initial[2..]);
                        let (publication, report) = exchange(&mut source, &mut receiver).await;
                        assert_eq!(report.results.iter().flatten().count(), 2);
                        assert_eq!(
                            publication.message().copy_message().unwrap(),
                            report.input.unwrap()
                        );
                        assert_eq!(receiver_layout.authority_images(), receiver_initial);
                        assert_eq!(source.driver().unwrap().current_inbox_len(), 1);
                        assert_eq!(receiver.driver().unwrap().current_inbox_len(), 1);

                        prepare_vote(&mut source, ConsensusVoteRole::Prevote).await;
                        let (_, report) = exchange(&mut source, &mut receiver).await;
                        assert!(matches!(
                            report.input,
                            Some(ConsensusPushMessage::Vote { .. })
                        ));
                        assert_eq!(
                            &receiver_layout.authority_images()[..2],
                            &receiver_initial[..2]
                        );
                        prepare_vote(&mut source, ConsensusVoteRole::Precommit).await;
                        let (_, report) = exchange(&mut source, &mut receiver).await;
                        assert!(matches!(
                            report.input,
                            Some(ConsensusPushMessage::Vote { .. })
                        ));

                        for owner in [&mut source, &mut receiver] {
                            let mut finalized = false;
                            for _ in 0..12 {
                                match owner.next_event().await {
                                    Event::Finality(_) => {
                                        finalized = true;
                                        break;
                                    }
                                    event => check_local(event),
                                }
                            }
                            assert!(finalized);
                            assert_eq!(
                                owner
                                    .driver()
                                    .unwrap()
                                    .selected_artifact_history()
                                    .selected_head_block_id()
                                    .unwrap(),
                                block.id()
                            );
                            assert_eq!(
                                owner.driver().unwrap().position().round(),
                                ConsensusRound::new(0)
                            );
                            assert_eq!(
                                owner.driver().unwrap().phase(),
                                FixedValidatorLockPhaseV0::Proposal
                            );
                        }
                        assert_ne!(&source_layout.authority_images()[..2], &source_initial[..2]);
                        assert_ne!(
                            &receiver_layout.authority_images()[..2],
                            &receiver_initial[..2]
                        );
                    })
                })
                .unwrap();
        })
        .unwrap();
    for (index, layout) in [&source_layout, &receiver_layout].into_iter().enumerate() {
        let images = layout.authority_images();
        let FixedValidatorNodeStartupV0::Ready(ready) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            layout,
        )
        .open(fixture.keys[index].clone())
        .unwrap() else {
            panic!("strict restart must be ready")
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
fn equal_weight_runtime_peers_require_both_remote_votes_for_finality() {
    let fixture = Fixture::weighted(1);
    let layouts = [
        TestLayout::new("equal-source"),
        TestLayout::new("equal-peer"),
    ];
    let first_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layouts[0],
    )
    .create(fixture.keys[0].clone())
    .unwrap();
    let second_ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layouts[1],
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (first_network, second_network, second_peer) = executor.block_on(connected_pair());
    let first_peer = first_network.local_peer_id();
    let payload = pairing_payload();
    let selected = ArtifactChainState::new(fixture.definition);
    let initial_head = selected.head_block_id();
    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
    first_ready.run_with_signing_session(|first_scope| second_ready.run_with_signing_session(|second_scope| executor.block_on(async {
        let mut first = Runtime::new(node_driver(first_scope), first_network, vec![second_peer], timeouts(Duration::from_secs(60))).unwrap();
        let mut second = Runtime::new(node_driver(second_scope), second_network, vec![first_peer], timeouts(Duration::from_secs(60))).unwrap();
        assert!(matches!(first.next_event().await, Event::TimerArmed(_)));
        assert!(matches!(second.next_event().await, Event::TimerArmed(_)));
        assert!(matches!(first.author_proposal(FixedValidatorProposalSourceV0::Fresh { artifact_block: block, canonical_artifact_bytes: payload }), Event::ProposalAuthored));
        assert!(matches!(first.next_event().await, Event::PublicationPrepared(_)));
        let _ = exchange(&mut first, &mut second).await;

        hold_local_vote(&mut second, ConsensusVoteRole::Prevote).await;
        hold_local_vote(&mut first, ConsensusVoteRole::Prevote).await;
        let _ = exchange(&mut first, &mut second).await;
        assert!(second.pending_publication().unwrap().deliveries().all(|d| matches!(d.state(), Delivery::NotAttempted)));
        let _ = exchange(&mut second, &mut first).await;
        for owner in [&first, &second] {
            assert_eq!(owner.driver().unwrap().phase(), FixedValidatorLockPhaseV0::Prevote);
            assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), initial_head);
        }

        hold_local_vote(&mut second, ConsensusVoteRole::Precommit).await;
        hold_local_vote(&mut first, ConsensusVoteRole::Precommit).await;
        let _ = exchange(&mut first, &mut second).await;
        // One local precommit alone cannot select on the first equal-weight node.
        assert_eq!(first.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), initial_head);
        assert!(second.pending_publication().unwrap().deliveries().all(|d| matches!(d.state(), Delivery::NotAttempted)));
        let _ = exchange(&mut second, &mut first).await;
        for owner in [&mut first, &mut second] {
            assert!(matches!(owner.next_event().await, Event::Finality(_)));
            assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), block.id());
            assert!(matches!(owner.next_event().await, Event::TimerArmed(timer) if timer.ticket().position().round() == ConsensusRound::new(0)));
        }
    })).unwrap()).unwrap();
}
