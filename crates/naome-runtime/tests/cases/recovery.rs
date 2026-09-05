use super::*;
use naome_node::{
    FixedValidatorNodeCurrentRoundFinalityInboxDrainItemV0 as FinalityItem,
    FixedValidatorNodeCurrentRoundInboxDrainItemV0 as CurrentItem,
    FixedValidatorNodeHigherRoundInboxDrainItemV0 as HigherItem,
};

fn saturated_higher_driver<'node>(
    scope: naome_node::FixedValidatorNodeSigningScopeV0<'node>,
    proposal: &ConsensusPushMessage,
    prevote: &ConsensusPushMessage,
) -> Driver<'node> {
    let driver = Driver::new(
        scope,
        FixedValidatorNodeHigherRoundInboxLimitsV0::new(1, 1 << 20).unwrap(),
        FixedValidatorNodeCurrentRoundInboxLimitsV0::new(2, 1 << 20).unwrap(),
        FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(2, 1 << 20).unwrap(),
        FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(1, 1 << 20).unwrap(),
        ConsensusRound::new(4),
    )
    .unwrap();
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = proposal
    else {
        panic!("proposal")
    };
    let round =
        naome_consensus::UnverifiedFixedConsensusProposalRouteV0::inspect(canonical_proposal)
            .unwrap()
            .position()
            .round();
    let driver = admit_driver(
        arm_driver(driver),
        Input::HigherRoundProposal {
            proposal_round: round,
            canonical_proposal_control_bytes: canonical_proposal.clone().into_boxed_slice(),
            canonical_artifact_bytes: canonical_artifact.clone().into_boxed_slice(),
        },
    );
    let ConsensusPushMessage::Vote { canonical_vote } = prevote else {
        panic!("prevote")
    };
    match driver
        .admit_event(Input::HigherRoundProposalPrevote {
            canonical_signed_prevote: canonical_vote.clone().into_boxed_slice(),
        })
        .unwrap()
    {
        Admission::Rejected {
            driver, rejection, ..
        } => {
            assert!(
                matches!(*rejection, Rejection::PrevoteInbox(ref error) if error.newly_saturated())
            );
            *driver
        }
        _ => panic!("one-entry higher inbox must saturate"),
    }
}

async fn rejected_deadline(owner: &mut Runtime<'_>) -> naome_runtime::FixedValidatorRuntimeTimerV0 {
    assert!(matches!(owner.next_event().await, Event::DriverBlocked(_)));
    let Event::TimerArmed(timer) = owner.next_event().await else {
        panic!("arm")
    };
    tokio::time::sleep_until(timer.deadline()).await;
    assert!(
        matches!(owner.next_event().await, Event::TimerDue { ticket, result: Err(error) }
        if ticket == timer.ticket() && matches!(*error, Rejection::Blocked(_)))
    );
    timer
}

#[test]
fn only_higher_drain_reopens_the_same_rejected_deadline() {
    let fixture = Fixture::new();
    let [proposal, prevote] = higher_messages(&fixture);
    for class in 0..4 {
        let layout = TestLayout::new("drain-suppression");
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
            let driver = saturated_higher_driver(scope, &proposal, &prevote);
            let mut owner = Runtime::new(driver, isolated_network(), vec![], timeouts(Duration::from_secs(1))).unwrap();
            let timer = rejected_deadline(&mut owner).await;
            let images = layout.authority_images();
            match class {
                0 => {
                    let mut drained = owner.drain_inbox_and_reset().unwrap();
                    let Some(HigherItem::Proposal(token)) = drained.next() else { panic!("original proposal") };
                    let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = &proposal else { panic!("proposal") };
                    assert_eq!(token.canonical_proposal_control_bytes(), canonical_proposal);
                    assert_eq!(token.canonical_artifact_bytes(), canonical_artifact);
                    assert!(drained.next().is_none());
                }
                1 => assert_eq!(owner.drain_current_inbox_and_reset().unwrap().len(), 0),
                2 => assert_eq!(owner.drain_current_finality_inbox_and_reset().unwrap().len(), 0),
                3 => assert_eq!(owner.drain_current_nil_precommit_inbox_and_reset().unwrap().len(), 0),
                _ => unreachable!(),
            }
            assert_eq!(owner.timer(), Some(timer));
            assert!(!owner.driver().unwrap().timeout_is_due());
            assert_eq!(layout.authority_images(), images);
            if class == 0 {
                assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(Disposition::TimeoutMarkedDue) } if ticket == timer.ticket()));
                assert!(owner.timer().is_none());
            } else {
                assert!(matches!(owner.next_event().await, Event::DriverBlocked(_)));
                assert!(timeout(Duration::from_secs(2), owner.next_event()).await.is_err());
                assert_eq!(owner.timer(), Some(timer));
            }
            let parts = owner.into_parts();
            assert_eq!(parts.rejected_due_ticket, if class == 0 { None } else { Some(timer.ticket()) });
            assert_eq!(parts.driver.unwrap().inbox_len(), usize::from(class != 0));
        })).unwrap();
    }
}

#[test]
fn higher_recovery_observes_original_due_before_buffered_voting_input() {
    let fixture = Fixture::new();
    let [higher_proposal, higher_prevote] = higher_messages(&fixture);
    let [proposal, _, _] = source_messages(&fixture);
    let layout = TestLayout::new("drain-buffered-due");
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
        let driver = saturated_higher_driver(scope, &higher_proposal, &higher_prevote);
        let mut owner = Runtime::new(driver, network, vec![], timeouts(Duration::from_millis(1))).unwrap();
        let timer = rejected_deadline(&mut owner).await;
        let ticket = sender.push_consensus(owner.local_peer_id(), copy_message(&proposal)).unwrap();
        timeout(Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = sender.next_event() => if matches!(event, NetworkEvent::OutboundConsensusPush(_)) { panic!("unadmitted input cannot have a receipt") },
                    outcome = async { let outcome = owner.poll_transport_once().await; tokio::task::yield_now().await; outcome } => {
                        if outcome == naome_runtime::FixedValidatorRuntimeTransportPollV0::BufferedEvent { break; }
                    }
                }
            }
        }).await.unwrap();
        let images = layout.authority_images();
        assert_eq!(owner.drain_inbox_and_reset().unwrap().len(), 1);
        assert_eq!(owner.timer(), Some(timer));
        assert_eq!(owner.poll_transport_once().await, naome_runtime::FixedValidatorRuntimeTransportPollV0::InputSlotOccupied);
        assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(Disposition::TimeoutMarkedDue) } if ticket == timer.ticket()));
        assert_eq!(owner.driver().unwrap().phase(), FixedValidatorLockPhaseV0::Proposal);
        assert!(owner.driver().unwrap().timeout_is_due());
        assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
        assert_eq!(layout.authority_images(), images);
        assert_eq!(owner.driver().unwrap().inbox_len(), 0);
        let parts = owner.into_parts();
        let Some(NetworkEvent::InboundConsensusPush(inbound)) = parts.pending_network_event else { panic!("exact unacknowledged input stays buffered") };
        assert_eq!(inbound.message(), &proposal);
        drop(ticket);
    })).unwrap();
}

fn assert_current_drain(
    owner: &mut Runtime<'_>,
    proposal: &ConsensusPushMessage,
    prevote: &ConsensusPushMessage,
) {
    let mut drained = owner.drain_current_inbox_and_reset().unwrap();
    let Some(CurrentItem::Proposal {
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    }) = drained.next()
    else {
        panic!("proposal drain")
    };
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = proposal
    else {
        panic!("proposal")
    };
    assert_eq!(&*canonical_proposal_control_bytes, canonical_proposal);
    assert_eq!(&*canonical_artifact_bytes, canonical_artifact);
    let ConsensusPushMessage::Vote { canonical_vote } = prevote else {
        panic!("prevote")
    };
    assert!(
        matches!(drained.next(), Some(CurrentItem::ProposalPrevote(bytes)) if bytes.as_slice() == canonical_vote)
    );
    assert!(drained.next().is_none());
}

fn assert_finality_drain(
    owner: &mut Runtime<'_>,
    proposal: &ConsensusPushMessage,
    precommit: &ConsensusPushMessage,
) {
    let mut drained = owner.drain_current_finality_inbox_and_reset().unwrap();
    let Some(FinalityItem::Proposal {
        canonical_proposal_control_bytes,
        canonical_artifact_bytes,
    }) = drained.next()
    else {
        panic!("finality proposal drain")
    };
    let ConsensusPushMessage::Proposal {
        canonical_proposal,
        canonical_artifact,
    } = proposal
    else {
        panic!("proposal")
    };
    assert_eq!(&*canonical_proposal_control_bytes, canonical_proposal);
    assert_eq!(&*canonical_artifact_bytes, canonical_artifact);
    let ConsensusPushMessage::Vote { canonical_vote } = precommit else {
        panic!("precommit")
    };
    assert!(
        matches!(drained.next(), Some(FinalityItem::ProposalPrecommit(bytes)) if bytes.as_slice() == canonical_vote)
    );
    assert!(drained.next().is_none());
}

#[test]
fn explicit_stale_evidence_recovery_allows_a_second_height_with_two_entry_budgets() {
    let fixture = Fixture::new();
    let entries = [ActiveAgreementEntry::new(
        consensus_key(&fixture.keys[0]),
        AgreementWeight::new(1),
    )];
    let layout = TestLayout::new("drain-two-heights");
    let ready = provision(fixture.definition, fixture.context, &entries, &layout)
        .create(fixture.keys[0].clone())
        .unwrap();
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut sender, network, _) = executor.block_on(connected_pair());
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let driver = Driver::new(
                    scope,
                    FixedValidatorNodeHigherRoundInboxLimitsV0::new(1, 1 << 20).unwrap(),
                    FixedValidatorNodeCurrentRoundInboxLimitsV0::new(2, 1 << 20).unwrap(),
                    FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(2, 1 << 20).unwrap(),
                    FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(1, 1 << 20)
                        .unwrap(),
                    ConsensusRound::new(4),
                )
                .unwrap();
                let mut owner =
                    Runtime::new(driver, network, vec![], timeouts(Duration::from_secs(60)))
                        .unwrap();
                let mut selected = ArtifactChainState::new(fixture.definition);
                let mut first_messages = Vec::new();
                for axiom in [1, 2] {
                    assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                    let payload = naome_proof::ArtifactPayload::Proof(
                        naome_proof::ProofCertificate::from_canonical_bytes(&[
                            0, 0, 0, 1, 0x10, axiom,
                        ])
                        .unwrap(),
                    )
                    .to_canonical_bytes();
                    let block = selected.prepare_block(artifact_id(&payload)).unwrap();
                    assert!(matches!(
                        owner.author_proposal(FixedValidatorProposalSourceV0::Fresh {
                            artifact_block: block,
                            canonical_artifact_bytes: payload.clone()
                        }),
                        Event::ProposalAuthored
                    ));
                    assert!(matches!(
                        owner.next_event().await,
                        Event::PublicationPrepared(_)
                    ));
                    if axiom == 2 {
                        let Event::Admission(report) = owner.next_event().await else {
                            panic!("second proposal self-admission")
                        };
                        assert!(matches!(
                            report.results[0]
                                .as_ref()
                                .unwrap()
                                .result
                                .as_ref()
                                .unwrap_err()
                                .as_ref(),
                            Rejection::CurrentFinalityInboxSaturated {
                                newly_saturated: true,
                                ..
                            }
                        ));
                        assert!(matches!(
                            report.results[1]
                                .as_ref()
                                .unwrap()
                                .result
                                .as_ref()
                                .unwrap_err()
                                .as_ref(),
                            Rejection::CurrentInboxSaturated {
                                newly_saturated: true,
                                ..
                            }
                        ));
                        let Event::PublicationComplete(publication) = owner.next_event().await
                        else {
                            panic!("caller retains rejected publication")
                        };
                        let timer = owner.timer();
                        let images = layout.authority_images();
                        assert_current_drain(&mut owner, &first_messages[0], &first_messages[1]);
                        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 2);
                        assert_finality_drain(&mut owner, &first_messages[0], &first_messages[2]);
                        assert_eq!(owner.timer(), timer);
                        assert_eq!(layout.authority_images(), images);
                        // The caller explicitly re-supplies the rejected proposal over
                        // the real network. Neither drain silently re-admits it.
                        assert_eq!(owner.driver().unwrap().current_inbox_len(), 0);
                        assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 0);
                        let report = raw_exchange(
                            &mut sender,
                            &mut owner,
                            publication.message().copy_message().unwrap(),
                            check_local,
                        )
                        .await;
                        assert!(report.all_admitted());
                    }
                    let mut finalized = false;
                    for _ in 0..20 {
                        match owner.next_event().await {
                            Event::PublicationComplete(publication) => {
                                if axiom == 1 {
                                    first_messages
                                        .push(publication.message().copy_message().unwrap());
                                }
                            }
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
                    assert_eq!(owner.driver().unwrap().current_inbox_len(), 2);
                    assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 2);
                    selected.apply_block(&block, payload).unwrap();
                }
            })
        })
        .unwrap();
}

#[test]
fn class_drains_preserve_siblings_and_pending_arms_across_two_nil_rounds() {
    let fixture = Fixture::new();
    let [proposal, _, _] = source_messages(&fixture);
    let [higher_proposal, _] = higher_messages(&fixture);
    let layout = TestLayout::new("drain-nil-rounds");
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
        let driver = Driver::new(scope,
            FixedValidatorNodeHigherRoundInboxLimitsV0::new(1, 1 << 20).unwrap(),
            FixedValidatorNodeCurrentRoundInboxLimitsV0::new(1, 1 << 20).unwrap(),
            FixedValidatorNodeCurrentRoundFinalityInboxLimitsV0::new(1, 1 << 20).unwrap(),
            FixedValidatorNodeCurrentRoundNilPrecommitInboxLimitsV0::new(1, 1 << 20).unwrap(),
            ConsensusRound::new(4)).unwrap();
        let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = &higher_proposal else { panic!("higher proposal") };
        let round = naome_consensus::UnverifiedFixedConsensusProposalRouteV0::inspect(canonical_proposal).unwrap().position().round();
        let driver = admit_driver(arm_driver(driver), Input::HigherRoundProposal {
            proposal_round: round, canonical_proposal_control_bytes: canonical_proposal.clone().into_boxed_slice(), canonical_artifact_bytes: canonical_artifact.clone().into_boxed_slice()
        });
        let ConsensusPushMessage::Proposal { canonical_proposal, canonical_artifact } = &proposal else { panic!("proposal") };
        let driver = admit_driver(driver, Input::CurrentRoundFinalityProposal {
            canonical_proposal_control_bytes: canonical_proposal.clone().into_boxed_slice(), canonical_artifact_bytes: canonical_artifact.clone().into_boxed_slice()
        });
        let mut owner = Runtime::new(driver, isolated_network(), vec![], timeouts(Duration::from_secs(1))).unwrap();
        let initial = layout.authority_images();
        let mut previous_prevote: Option<Vec<u8>> = None;
        let mut previous_precommit: Option<Vec<u8>> = None;
        for round in 0..2 {
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("round arm") };
            assert_eq!(owner.driver().unwrap().position().round(), ConsensusRound::new(round));
            tokio::time::sleep_until(timer.deadline()).await;
            assert!(matches!(owner.next_event().await, Event::TimerDue { ticket, result: Ok(Disposition::TimeoutMarkedDue) } if ticket == timer.ticket()));
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Prevote, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            let active = owner.driver().unwrap().active_timeout();
            let images = layout.authority_images();
            let mut current = owner.drain_current_inbox_and_reset().unwrap();
            if let Some(bytes) = &previous_prevote {
                assert!(matches!(current.next(), Some(CurrentItem::NilPrevote(retained)) if retained.as_slice() == bytes));
            }
            assert!(current.next().is_none());
            assert_eq!(owner.driver().unwrap().current_inbox_canonical_input_bytes(), 0);
            assert_eq!(owner.driver().unwrap().current_nil_precommit_inbox_len(), usize::from(round != 0));
            assert!(owner.driver().unwrap().has_pending_command());
            assert_eq!(owner.driver().unwrap().active_timeout(), active);
            assert_eq!(layout.authority_images(), images);
            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
            check_local(owner.next_event().await);
            let Event::PublicationComplete(publication) = owner.next_event().await else { panic!("nil prevote") };
            let Message::Vote { vote, .. } = publication.message() else { panic!("vote") };
            assert_eq!(vote.target(), naome_consensus::ConsensusVoteTarget::Nil);
            previous_prevote = Some(vote.canonical_bytes().to_vec());
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Precommit, .. }));
            assert!(matches!(owner.next_event().await, Event::PublicationPrepared(_)));
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("precommit arm") };
            let images = layout.authority_images();
            let mut nil = owner.drain_current_nil_precommit_inbox_and_reset().unwrap();
            if let Some(bytes) = &previous_precommit { assert_eq!(nil.next().unwrap().as_slice(), bytes); }
            assert!(nil.next().is_none());
            assert_eq!(owner.driver().unwrap().current_nil_precommit_inbox_canonical_input_bytes(), 0);
            assert_eq!(owner.driver().unwrap().current_inbox_len(), 1);
            assert_eq!(owner.driver().unwrap().current_finality_inbox_len(), 1);
            assert_eq!(owner.driver().unwrap().inbox_len(), 1);
            assert_eq!(owner.timer(), Some(timer));
            assert_eq!(layout.authority_images(), images);
            check_local(owner.next_event().await);
            let Event::PublicationComplete(publication) = owner.next_event().await else { panic!("nil precommit") };
            let Message::Vote { vote, .. } = publication.message() else { panic!("vote") };
            assert_eq!(vote.target(), naome_consensus::ConsensusVoteTarget::Nil);
            previous_precommit = Some(vote.canonical_bytes().to_vec());
            assert!(matches!(owner.next_event().await, Event::Transitioned { phase: FixedValidatorLockPhaseV0::Proposal, .. }));
            assert_eq!(owner.driver().unwrap().position().round(), ConsensusRound::new(round + 1));
        }
        let images = layout.authority_images();
        let active = owner.driver().unwrap().active_timeout();
        let mut finality = owner.drain_current_finality_inbox_and_reset().unwrap();
        assert!(matches!(finality.next(), Some(FinalityItem::Proposal { canonical_proposal_control_bytes, canonical_artifact_bytes })
            if canonical_proposal_control_bytes.as_ref() == canonical_proposal && canonical_artifact_bytes.as_ref() == canonical_artifact));
        assert!(finality.next().is_none());
        assert_eq!(owner.driver().unwrap().current_finality_inbox_canonical_input_bytes(), 0);
        assert_eq!(owner.driver().unwrap().inbox_len(), 1);
        assert_eq!(owner.drain_inbox_and_reset().unwrap().len(), 1);
        assert_eq!(owner.driver().unwrap().current_inbox_len(), 1);
        assert_eq!(owner.driver().unwrap().current_nil_precommit_inbox_len(), 1);
        assert!(owner.driver().unwrap().has_pending_command());
        assert_eq!(owner.driver().unwrap().active_timeout(), active);
        assert_eq!(layout.authority_images(), images);
        assert_eq!(&images[..2], &initial[..2]);
        assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
    })).unwrap();
}
