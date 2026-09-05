use super::*;
use naome_consensus::ConsensusVoteTarget;
use naome_runtime::{
    FixedValidatorRuntimeProofRefusalV0 as Refusal,
    FixedValidatorRuntimeRoutingErrorV0 as RoutingError,
};

#[path = "current_finality.rs"]
mod current_finality;

#[path = "terminal_proofs.rs"]
mod terminal_proofs;

#[path = "artifact_exchange.rs"]
mod artifact_exchange;

fn allocations(bytes: &Vec<u8>) -> (usize, usize, usize) {
    (bytes.as_ptr() as usize, bytes.len(), bytes.capacity())
}

fn assert_positive_busy(
    owner: &mut Runtime<'_>,
    candidates: &mut naome_storage::ArtifactBlockCandidateStore,
    payloads: &mut naome_storage::CanonicalArtifactPayloadStore,
    target: naome_chain::ArtifactBlockId,
) {
    assert!(matches!(
        owner.advance_to_higher_round_quorum(&[0]),
        Err(Refusal::Busy)
    ));
    assert!(matches!(
        owner.advance_to_higher_round_vote_batch(
            &[&[0]],
            ConsensusRound::new(3),
            ConsensusVoteRole::Prevote,
            ConsensusVoteTarget::Nil
        ),
        Err(Refusal::Busy)
    ));
    for batch in [false, true] {
        let mut payload = vec![7; 13];
        payload.reserve(23);
        let original = allocations(&payload);
        let outcome = if batch {
            owner.commit_current_round_finality_vote_batch(&[0], payload, &[&[0]])
        } else {
            owner.commit_current_round_finality(&[0], payload, &[0])
        };
        let Err((Refusal::Busy, payload)) = outcome else {
            panic!("preflight must return payload")
        };
        assert_eq!(allocations(&payload), original);
        assert_eq!(payload, vec![7; 13]);
    }
    for batch in [false, true] {
        let mut payload = vec![7; 13];
        payload.reserve(23);
        let original = allocations(&payload);
        let outcome = if batch {
            owner.commit_lower_round_finality_vote_batch(
                &[0],
                payload,
                &[&[0]],
                ConsensusRound::new(0),
            )
        } else {
            owner.commit_lower_round_finality(&[0], payload, &[0])
        };
        let Err((Refusal::Busy, payload)) = outcome else {
            panic!("preflight must return payload")
        };
        assert_eq!(allocations(&payload), original);
        assert_eq!(payload, vec![7; 13]);
    }
    assert!(matches!(
        owner.commit_candidate_backed_finality_vote_batch(
            candidates,
            payloads,
            target,
            &[0],
            &[&[0]],
            ConsensusRound::new(0)
        ),
        Err(Refusal::Busy)
    ));
}

#[test]
fn positive_proof_backpressure_preserves_commands_publication_and_owned_payloads() {
    let fixture = Fixture::new();
    let layout = TestLayout::new("runtime-proof-backpressure");
    let (mut candidates, mut payloads) = super::store_authoring::sources(&layout, &fixture);
    let payload = pairing_payload();
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&payload))
        .unwrap();
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
                let images = layout.authority_images();
                let source_images = layout.source_images();
                assert_positive_busy(&mut owner, &mut candidates, &mut payloads, block.id());
                assert_eq!(layout.authority_images(), images);
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                assert!(matches!(
                    owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                        artifact_block: block,
                        canonical_artifact_bytes: payload
                    }),
                    Event::ProposalAuthored
                ));
                let images = layout.authority_images();
                let timer = owner.timer();
                assert_positive_busy(&mut owner, &mut candidates, &mut payloads, block.id());
                assert!(owner.driver().unwrap().has_pending_command());
                assert!(matches!(
                    owner.next_event().await,
                    Event::PublicationPrepared(_)
                ));
                let original = owner
                    .pending_publication()
                    .unwrap()
                    .message()
                    .copy_message()
                    .unwrap();
                owner
                    .queue_input(ConsensusPushMessage::Vote {
                        canonical_vote: vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES],
                    })
                    .unwrap();
                assert_positive_busy(&mut owner, &mut candidates, &mut payloads, block.id());
                assert_eq!(owner.timer(), timer);
                assert!(
                    !owner
                        .pending_publication()
                        .unwrap()
                        .local_admission_attempted()
                );
                assert_eq!(
                    owner
                        .pending_publication()
                        .unwrap()
                        .message()
                        .copy_message()
                        .unwrap(),
                    original
                );
                assert_eq!(layout.authority_images(), images);
                assert_eq!(layout.source_images(), source_images);
                let parts = owner.into_parts();
                assert!(parts.pending_caller_input.is_some());
                assert!(parts.pending_network_event.is_none());
            })
        })
        .unwrap();
}

struct Proof {
    value: naome_consensus::ConsensusValueV0,
    control: Vec<u8>,
    payload: Vec<u8>,
    vote: Vec<u8>,
    certificate: Vec<u8>,
    round: ConsensusRound,
    target: ConsensusVoteTarget,
}

fn proof(
    fixture: &Fixture,
    proposal: ConsensusPushMessage,
    vote: ConsensusPushMessage,
    role: ConsensusVoteRole,
) -> Proof {
    let ConsensusPushMessage::Proposal {
        canonical_proposal: control,
        canonical_artifact: payload,
    } = proposal
    else {
        panic!("proposal")
    };
    let ConsensusPushMessage::Vote {
        canonical_vote: vote,
    } = vote
    else {
        panic!("vote")
    };
    let observed = naome_consensus::UnverifiedFixedConsensusProposalRouteV0::inspect(&control)
        .unwrap()
        .position()
        .round();
    let branch = FixedConsensusBranchV0::try_from_virtual_genesis(
        fixture.context,
        &fixture.entries,
        ArtifactChainState::new(fixture.definition).branch_snapshot(),
    )
    .unwrap();
    let mut round = branch.begin_round_zero().unwrap();
    while round.position().round() != observed {
        round = round.advance_round().unwrap();
    }
    let proposal = round
        .decode_and_verify_proposal_control(&control, payload.clone())
        .unwrap();
    let target = ConsensusVoteTarget::Proposal(proposal.proposal_signing_root());
    let certificate = round
        .build_quorum_certificate_from_signed_votes(&[&vote], role, target)
        .unwrap()
        .to_canonical_bytes();
    Proof {
        value: proposal.value(),
        control,
        payload,
        vote,
        certificate,
        round: observed,
        target,
    }
}

fn lower_proof(fixture: &Fixture) -> Proof {
    let [proposal, _, vote] = source_messages(fixture);
    proof(fixture, proposal, vote, ConsensusVoteRole::Precommit)
}

fn higher_proof(fixture: &Fixture) -> Proof {
    let [proposal, vote] = higher_messages(fixture);
    proof(fixture, proposal, vote, ConsensusVoteRole::Prevote)
}

fn higher<'node>(owner: &mut Runtime<'node>, input: &Proof, batch: bool) -> Event<'node> {
    if batch {
        owner
            .advance_to_higher_round_vote_batch(
                &[&input.vote],
                input.round,
                ConsensusVoteRole::Prevote,
                input.target,
            )
            .unwrap()
    } else {
        owner
            .advance_to_higher_round_quorum(&input.certificate)
            .unwrap()
    }
}

fn lower<'node>(
    owner: &mut Runtime<'node>,
    input: &Proof,
    batch: bool,
    payload: Vec<u8>,
) -> Event<'node> {
    if batch {
        owner
            .commit_lower_round_finality_vote_batch(
                &input.control,
                payload,
                &[&input.vote],
                input.round,
            )
            .unwrap()
    } else {
        owner
            .commit_lower_round_finality(&input.control, payload, &input.certificate)
            .unwrap()
    }
}

#[test]
fn higher_proofs_checkpoint_ahead_of_buffered_input_with_expired_or_accepted_due() {
    let fixture = Fixture::new();
    let input = higher_proof(&fixture);
    let [buffered, _, _] = source_messages(&fixture);
    for (batch, observe_due) in [false, true]
        .into_iter()
        .flat_map(|batch| [false, true].map(move |due| (batch, due)))
    {
        let layout = TestLayout::new("runtime-higher-proof");
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
            let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![], timeouts(Duration::from_millis(1))).unwrap();
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("initial arm") };
            owner.queue_input(copy_message(&buffered)).unwrap();
            tokio::time::sleep_until(timer.deadline()).await;
            if observe_due {
                assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
            }
            let retained_timer = owner.timer();
            let images = layout.authority_images();
            let mut damaged = if batch { input.vote.clone() } else { input.certificate.clone() };
            *damaged.last_mut().unwrap() ^= 1;
            let event = if batch {
                owner.advance_to_higher_round_vote_batch(&[&damaged], input.round, ConsensusVoteRole::Prevote, input.target).unwrap()
            } else { owner.advance_to_higher_round_quorum(&damaged).unwrap() };
            assert!(matches!(event, Event::HigherRoundAdvanceRejected(_)));
            assert_eq!(owner.timer(), retained_timer);
            assert_eq!(owner.driver().unwrap().timeout_is_due(), observe_due);
            assert_eq!(layout.authority_images(), images);
            assert!(matches!(higher(&mut owner, &input, batch), Event::Transitioned { position, phase: FixedValidatorLockPhaseV0::Prevote } if position.round() == input.round));
            assert!(owner.timer().is_none());
            assert!(!owner.driver().unwrap().timeout_is_due());
            assert!(owner.driver().unwrap().has_pending_command());
            assert_eq!(owner.poll_transport_once().await, naome_runtime::FixedValidatorRuntimeTransportPollV0::InputSlotOccupied);
            assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
            assert_eq!(&layout.authority_images()[..2], &images[..2]);
            assert_ne!(&layout.authority_images()[2..], &images[2..]);
            let Event::TimerArmed(next) = owner.next_event().await else { panic!("destination arm precedes input") };
            assert_eq!(next.ticket().position().round(), input.round);
            assert_eq!(next.ticket().generation(), timer.ticket().generation() + 1);
            let Event::Admission(report) = owner.next_event().await else { panic!("buffered input") };
            assert_eq!(report.source, InputSource::CallerInput);
            assert_eq!(report.receipt_queued, None);
            assert_eq!(report.input, Some(copy_message(&buffered)));
            assert!(matches!(report.routing_error, Some(RoutingError::UnsupportedPosition { .. })));
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
            panic!("checkpoint reopen")
        };
        ready
            .run_with_signing_session(|scope| {
                let driver = node_driver(scope);
                assert_eq!(driver.position().round(), input.round);
                assert_eq!(driver.phase(), FixedValidatorLockPhaseV0::Prevote);
                assert!(!driver.timeout_is_due());
            })
            .unwrap();
        assert_eq!(layout.authority_images(), images);
    }
}

fn empty_phase(driver: Driver<'_>) -> Driver<'_> {
    let ticket = driver.active_timeout().unwrap();
    let driver = admit_driver(driver, Input::TimeoutDue(ticket));
    let Step::Transitioned { driver } = driver.step().unwrap() else {
        panic!("empty phase")
    };
    let Step::Command {
        driver,
        command: Command::PublishVote { .. },
    } = driver.step().unwrap()
    else {
        panic!("nil publication")
    };
    arm_driver(*driver)
}

#[test]
fn direct_lower_proofs_select_from_each_due_phase_and_preserve_buffered_input() {
    let fixture = Fixture::new();
    let input = lower_proof(&fixture);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&input.payload))
        .unwrap();
    for (batch, phases) in [false, true]
        .into_iter()
        .flat_map(|batch| (0..3).map(move |phases| (batch, phases)))
    {
        let layout = TestLayout::new("runtime-lower-proof");
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
            let mut driver = empty_round(arm_driver(node_driver(scope)));
            for _ in 0..phases { driver = empty_phase(driver); }
            let mut owner = Runtime::new(driver, isolated_network(), vec![], timeouts(Duration::from_millis(1))).unwrap();
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("adopt source arm") };
            assert_eq!(timer.ticket().position().round(), ConsensusRound::new(1));
            let raw = ConsensusPushMessage::Vote { canonical_vote: vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES] };
            owner.queue_input(raw).unwrap();
            tokio::time::sleep_until(timer.deadline()).await;
            assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(_) } if ticket == timer.ticket()));
            let images = layout.authority_images();
            assert!(matches!(lower(&mut owner, &input, batch, vec![0]), Event::LowerRoundFinalityRejected(_)));
            assert_eq!(owner.driver().unwrap().position(), timer.ticket().position());
            assert_eq!(owner.driver().unwrap().phase(), timer.ticket().phase());
            assert!(owner.driver().unwrap().timeout_is_due());
            assert_eq!(layout.authority_images(), images);
            assert!(matches!(lower(&mut owner, &input, batch, input.payload.clone()), Event::Finality(naome_node::FixedValidatorNodeFinalitySelectionV0::Finalized { .. })));
            assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), block.id());
            assert_eq!(owner.driver().unwrap().position().height().value(), 2);
            assert_eq!(owner.driver().unwrap().position().round(), ConsensusRound::new(0));
            assert!(!owner.driver().unwrap().timeout_is_due());
            assert!(owner.timer().is_none());
            assert!(matches!(owner.next_event().await, Event::TimerArmed(next) if next.ticket().generation() == timer.ticket().generation() + 1));
            let parts = owner.into_parts();
            assert!(parts.pending_network_event.is_none());
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if canonical_vote == vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES]));
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
fn retained_current_finality_precedes_all_seven_explicit_positive_proofs_without_a_step() {
    let fixture = Fixture::new();
    let input = lower_proof(&fixture);
    let layout = TestLayout::new("runtime-proof-priority");
    let (mut candidates, mut payloads) = super::store_authoring::sources(&layout, &fixture);
    let block = ArtifactChainState::new(fixture.definition)
        .prepare_block(artifact_id(&input.payload))
        .unwrap();
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
        let driver = admit_driver(arm_driver(node_driver(scope)), Input::CurrentRoundProposalPrecommit { canonical_signed_precommit: input.vote.clone().into_boxed_slice() });
        let ticket = driver.active_timeout();
        let mut owner = Runtime::new(driver, isolated_network(), vec![], timeouts(Duration::from_secs(60))).unwrap();
        owner.queue_input(ConsensusPushMessage::Proposal { canonical_proposal: input.control.clone(), canonical_artifact: input.payload.clone() }).unwrap();
        let images = layout.authority_images();
        let source_images = layout.source_images();
        assert!(matches!(owner.advance_to_higher_round_quorum(&[0]).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(matches!(owner.advance_to_higher_round_vote_batch(&[&[0]], ConsensusRound::new(2), ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(matches!(owner.commit_current_round_finality(&[0], vec![0], &[0]).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(matches!(owner.commit_current_round_finality_vote_batch(&[0], vec![0], &[&[0]]).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(matches!(owner.commit_lower_round_finality(&[0], vec![0], &[0]).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(matches!(owner.commit_lower_round_finality_vote_batch(&[0], vec![0], &[&[0]], ConsensusRound::new(0)).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(matches!(owner.commit_candidate_backed_finality_vote_batch(&mut candidates, &mut payloads, block.id(), &[0], &[&[0]], ConsensusRound::new(0)).unwrap(), Event::CurrentFinalityUnresolved));
        assert!(owner.timer().is_none());
        assert_eq!(owner.driver().unwrap().active_timeout(), ticket);
        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
        assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
        assert_eq!(layout.authority_images(), images);
        assert_eq!(layout.source_images(), source_images);
        assert!(matches!(owner.next_event().await, Event::DriverBlocked(naome_node::FixedValidatorNodeDriverBlockReasonV0::CurrentFinalityProposalMissing { .. })));
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        assert!(matches!(owner.next_event().await, Event::Admission(report) if report.source == InputSource::CallerInput && report.all_admitted()));
        assert!(matches!(owner.next_event().await, Event::Finality(_)));
    })).unwrap();
}

#[test]
fn candidate_finality_retries_explicit_sources_and_strictly_reopens_the_child() {
    let fixture = Fixture::new();
    let input = lower_proof(&fixture);
    let layout = TestLayout::new("runtime-candidate-proof");
    let (mut candidates, mut payloads) = super::store_authoring::sources(&layout, &fixture);
    let selected = ArtifactChainState::new(fixture.definition);
    let block = selected.prepare_block(artifact_id(&input.payload)).unwrap();
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
        let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![], timeouts(Duration::from_secs(60))).unwrap();
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        owner.queue_input(ConsensusPushMessage::Proposal { canonical_proposal: input.control.clone(), canonical_artifact: input.payload.clone() }).unwrap();
        let timer = owner.timer();
        let images = layout.authority_images();
        for missing_candidate in [true, false] {
            let source_images = layout.source_images();
            let Event::CandidateBackedFinalityRejected(error) = owner.commit_candidate_backed_finality_vote_batch(&mut candidates, &mut payloads, block.id(), &input.control, &[&input.vote], input.round).unwrap() else { panic!("source unavailable") };
            if missing_candidate { assert!(matches!(*error, naome_node::FixedValidatorNodeCandidateBackedFinalityRejectionV0::CandidateUnavailable { .. })); }
            else { assert!(matches!(*error, naome_node::FixedValidatorNodeCandidateBackedFinalityRejectionV0::PayloadUnavailable { .. })); }
            assert_eq!(owner.timer(), timer);
            assert_eq!(layout.authority_images(), images);
            assert_eq!(layout.source_images(), source_images);
            if missing_candidate { let _ = candidates.insert(&block).unwrap(); }
        }
        let _ = payloads.validate_and_insert_branch_payload(&selected.branch_snapshot(), &block, input.payload.clone()).unwrap();
        let source_images = layout.source_images();
        assert!(matches!(owner.commit_candidate_backed_finality_vote_batch(&mut candidates, &mut payloads, block.id(), &input.control, &[&input.vote], input.round).unwrap(), Event::Finality(naome_node::FixedValidatorNodeFinalitySelectionV0::CandidateBackedFinalized { target, .. }) if target == block.id()));
        assert_eq!(owner.driver().unwrap().selected_artifact_history().selected_head_block_id().unwrap(), block.id());
        assert_eq!(layout.source_images(), source_images);
        assert!(owner.timer().is_none());
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
        let Event::Admission(report) = owner.next_event().await else { panic!("old-height input") };
        assert_eq!(report.source, InputSource::CallerInput);
        assert_eq!(report.receipt_queued, None);
        assert!(matches!(report.routing_error, Some(RoutingError::UnsupportedPosition { .. })));
        assert!(matches!(report.input, Some(ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact }) if canonical_proposal == input.control && canonical_artifact == input.payload));
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
        panic!("candidate child reopen")
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
            assert_eq!(driver.position().height().value(), 2);
            assert_eq!(driver.position().round(), ConsensusRound::new(0));
        })
        .unwrap();
    assert_eq!(layout.authority_images(), images);
}
