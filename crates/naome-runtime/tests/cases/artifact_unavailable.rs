use super::*;

enum Work<'store> {
    Ancestry(naome_network::ArtifactBlockCandidateAncestryFill<'store>),
    Payload(naome_network::ArtifactBlockCandidateBranchPayloadFill<'store>),
}

impl Work<'_> {
    fn accepts(&self, event: &NetworkEvent) -> bool {
        match self {
            Self::Ancestry(fill) => fill.accepts_event(event),
            Self::Payload(fill) => fill.accepts_event(event),
        }
    }
}

#[test]
fn terminal_driver_loss_refunds_both_kinds_of_inflight_acquisition() {
    let fixture = Fixture::new();
    let first = lower_proof(&fixture);
    let second = sibling_proof(&fixture);
    let checkpoint = higher_proof(&fixture);
    for payload_phase in [false, true] {
        let layout = TestLayout::new("artifact-unavailable");
        let server_layout = TestLayout::new("artifact-unavailable-server");
        let (mut candidates, mut payloads) = sources(&layout, &fixture, None);
        if payload_phase {
            let _ = candidates.insert(&first.value.artifact_block()).unwrap();
        }
        let (mut serving_candidates, mut serving_payloads) =
            sources(&server_layout, &fixture, Some(&first.payload));
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
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
        let (network, server_network, peer) = executor.block_on(connected_pair());
        let stopped = ready
            .run_with_signing_session(|scope| {
                server_ready
                    .run_with_signing_session(|server_scope| {
                        executor.block_on(async {
                            let mut owner = Runtime::new(
                                node_driver(scope),
                                network,
                                vec![],
                                timeouts(Duration::from_secs(60)),
                            )
                            .unwrap();
                            let mut server = Runtime::new(
                                node_driver(server_scope),
                                server_network,
                                vec![],
                                timeouts(Duration::from_secs(60)),
                            )
                            .unwrap();
                            let target = first.value.artifact_block().id();
                            let work = if payload_phase {
                                let PayloadProgress::AwaitingResponse(fill) = owner
                                    .start_artifact_block_candidate_branch_payload_fill(
                                        &mut candidates,
                                        &mut payloads,
                                        peer,
                                        target,
                                        limits(),
                                    )
                                    .unwrap()
                                else {
                                    panic!("payload miss")
                                };
                                Work::Payload(fill)
                            } else {
                                Work::Ancestry(
                                    owner
                                        .start_artifact_block_candidate_ancestry_fill(
                                            &mut candidates,
                                            peer,
                                            target,
                                        )
                                        .unwrap()
                                        .unwrap(),
                                )
                            };
                            let event = terminal(
                                &mut owner,
                                &mut server,
                                &mut serving_candidates,
                                &mut serving_payloads,
                                |event| work.accepts(event),
                            )
                            .await;
                            assert!(matches!(
                                higher(&mut owner, &checkpoint, false),
                                Event::Transitioned { .. }
                            ));
                            assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                            let Event::Fatal(error) = owner
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
                            else {
                                panic!("verified pair")
                            };
                            let naome_runtime::FixedValidatorRuntimeFailureV0::FinalityStopped(
                                stopped,
                            ) = *error
                            else {
                                panic!("paired stop")
                            };
                            let authority = layout.authority_images();
                            let sources_before = layout.source_images();
                            let timer = owner.timer();
                            match work {
                                Work::Ancestry(fill) => {
                                    let AncestryAdvanceError::Refused {
                                        reason,
                                        progress,
                                        event,
                                    } = *owner
                                        .advance_artifact_block_candidate_ancestry_fill(fill, event)
                                        .unwrap_err()
                                    else {
                                        panic!("ancestry refund")
                                    };
                                    assert_eq!(reason, AcquisitionRefusal::DriverUnavailable);
                                    assert!(progress.accepts_event(&event));
                                    progress.cancel();
                                }
                                Work::Payload(fill) => {
                                    let PayloadAdvanceError::Refused {
                                        reason,
                                        progress,
                                        event,
                                    } = *owner
                                        .advance_artifact_block_candidate_branch_payload_fill(
                                            fill, event,
                                        )
                                        .unwrap_err()
                                    else {
                                        panic!("payload refund")
                                    };
                                    assert_eq!(reason, AcquisitionRefusal::DriverUnavailable);
                                    assert!(progress.accepts_event(&event));
                                    progress.cancel();
                                }
                            }
                            assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
                            assert_eq!(owner.timer(), timer);
                            assert_eq!(layout.authority_images(), authority);
                            assert_eq!(layout.source_images(), sources_before);
                            *stopped
                        })
                    })
                    .unwrap()
            })
            .unwrap();
        let images = layout.authority_images();
        let FixedValidatorNodeStartupV0::FinalityStopped(reopened) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .open(fixture.keys[1].clone())
        .unwrap() else {
            panic!("strict stop reopen")
        };
        assert_eq!(reopened, stopped);
        assert_eq!(layout.authority_images(), images);
    }
}
