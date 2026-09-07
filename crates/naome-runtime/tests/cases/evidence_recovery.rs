use super::*;

#[test]
fn durable_evidence_failed_admission_save_keeps_incomplete_report_and_consumes_driver() {
    let fixture = Fixture::new();
    let [proposal, _] = higher_messages(&fixture);
    let layout = TestLayout::new("durable-evidence-admission-fault");
    let directory = &layout.payload_store;
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let mut owner = Runtime::new(
                    node_driver(scope),
                    isolated_network(),
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap()
                .with_evidence_journal(directory, true)
                .unwrap();
                assert!(matches!(owner.next_event().await, Event::TimerArmed(_)));
                let image =
                    std::fs::read(directory.join("fixed-validator-retained.evidence")).unwrap();
                let moved = directory.with_extension("moved");
                std::fs::rename(directory, &moved).unwrap();
                owner.queue_input(copy_message(&proposal)).unwrap();
                assert!(matches!(owner.next_event().await, Event::Fatal(error)
            if matches!(*error, naome_runtime::FixedValidatorRuntimeFailureV0::Evidence(_))));
                let parts = owner.into_parts();
                assert!(parts.driver.is_none());
                let report = parts.failed_admission.unwrap();
                assert!(!report.completed());
                assert_eq!(report.input.as_ref().unwrap(), &proposal);
                assert!(report.results.iter().flatten().all(|r| r.result.is_ok()));
                std::fs::rename(moved, directory).unwrap();
                assert_eq!(
                    std::fs::read(directory.join("fixed-validator-retained.evidence")).unwrap(),
                    image
                );
            })
        })
        .unwrap();
    let FixedValidatorNodeStartupV0::Ready(ready) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .open(fixture.keys[1].clone())
    .unwrap() else {
        panic!("ready reopen")
    };
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let owner = Runtime::new(
                    node_driver(scope),
                    isolated_network(),
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap()
                .with_evidence_journal(directory, false)
                .unwrap();
                assert_eq!(owner.driver().unwrap().inbox_len(), 0);
            })
        })
        .unwrap();
}

#[test]
fn durable_evidence_partial_peer_delivery_reopens_then_finalizes_without_proposal_redelivery() {
    let fixture = Fixture::new();
    let [proposal, _, precommit]: [ConsensusPushMessage; 3] =
        higher_messages_for_payload(&fixture, pairing_payload(), 3)
            .try_into()
            .unwrap();
    let layout = TestLayout::new("durable-evidence-peer");
    let directory = &layout.payload_store;
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    let (mut peer, network, _) = executor.block_on(connected_pair());
    let ready = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .create(fixture.keys[1].clone())
    .unwrap();
    let image = ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let mut owner = Runtime::new(
                    node_driver(scope),
                    network,
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap()
                .with_evidence_journal(directory, true)
                .unwrap();
                let before = layout.authority_images();
                let report =
                    raw_exchange(&mut peer, &mut owner, copy_message(&proposal), check_local).await;
                assert!(report.all_admitted());
                assert_eq!(report.input.as_ref().unwrap(), &proposal);
                assert_eq!(owner.driver().unwrap().inbox_len(), 1);
                assert_eq!(layout.authority_images(), before);
                owner.driver().unwrap().retained_evidence_image().unwrap()
            })
        })
        .unwrap();
    let FixedValidatorNodeStartupV0::Ready(ready) = provision(
        fixture.definition,
        fixture.context,
        &fixture.entries,
        &layout,
    )
    .open(fixture.keys[1].clone())
    .unwrap() else {
        panic!("ready reopen")
    };
    ready
        .run_with_signing_session(|scope| {
            executor.block_on(async {
                let mut owner = Runtime::new(
                    node_driver(scope),
                    isolated_network(),
                    vec![],
                    timeouts(Duration::from_secs(60)),
                )
                .unwrap()
                .with_evidence_journal(directory, false)
                .unwrap();
                assert_eq!(
                    owner.driver().unwrap().retained_evidence_image().unwrap(),
                    image
                );
                assert!(
                    caller_input::admit(&mut owner, precommit, check_local)
                        .await
                        .all_admitted()
                );
                let mut finalized = false;
                for _ in 0..8 {
                    match owner.next_event().await {
                        Event::Finality(_) => {
                            finalized = true;
                            break;
                        }
                        event => check_local(event),
                    }
                }
                assert!(finalized);
                assert_eq!(owner.driver().unwrap().position().height().value(), 2);
                assert_eq!(
                    owner
                        .driver()
                        .unwrap()
                        .publication_history()
                        .unwrap()
                        .entries()
                        .count(),
                    0
                );
            })
        })
        .unwrap();
}

#[test]
fn durable_evidence_disposal_is_acknowledged_only_after_save_and_never_reappears_on_reopen() {
    let fixture = Fixture::new();
    let [proposal, _] = higher_messages(&fixture);
    for fail in [false, true] {
        let layout = TestLayout::new("durable-evidence-disposal");
        let directory = &layout.payload_store;
        let executor = Builder::new_current_thread().enable_all().build().unwrap();
        let ready = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .create(fixture.keys[1].clone())
        .unwrap();
        let old_image = ready.run_with_signing_session(|scope| executor.block_on(async {
            let mut owner = Runtime::new(node_driver(scope), isolated_network(), vec![], timeouts(Duration::from_secs(60)))
                .unwrap().with_evidence_journal(directory, true).unwrap();
            assert!(caller_input::admit(&mut owner, copy_message(&proposal), check_local).await.all_admitted());
            let old_image = std::fs::read(directory.join("fixed-validator-retained.evidence")).unwrap();
            let moved = directory.with_extension("moved");
            if fail { std::fs::rename(directory, &moved).unwrap(); }
            let before = layout.authority_images();
            let drained = owner.drain_inbox_and_reset();
            if fail {
                assert!(drained.is_none(), "failed save must not acknowledge disposal");
                assert!(owner.driver().is_none());
                assert!(matches!(owner.next_event().await, Event::Fatal(error)
                    if matches!(*error, naome_runtime::FixedValidatorRuntimeFailureV0::Evidence(_))));
                assert!(matches!(owner.next_event().await, Event::DriverUnavailable));
                std::fs::rename(&moved, directory).unwrap();
                assert_eq!(std::fs::read(directory.join("fixed-validator-retained.evidence")).unwrap(), old_image);
            } else {
                assert_eq!(drained.unwrap().len(), 1);
            }
            assert_eq!(layout.authority_images(), before);
            old_image
        })).unwrap();
        let FixedValidatorNodeStartupV0::Ready(ready) = provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout,
        )
        .open(fixture.keys[1].clone())
        .unwrap() else {
            panic!("ready reopen")
        };
        ready
            .run_with_signing_session(|scope| {
                executor.block_on(async {
                    let owner = Runtime::new(
                        node_driver(scope),
                        isolated_network(),
                        vec![],
                        timeouts(Duration::from_secs(60)),
                    )
                    .unwrap()
                    .with_evidence_journal(directory, false)
                    .unwrap();
                    assert_eq!(owner.driver().unwrap().inbox_len(), usize::from(fail));
                    assert_eq!(
                        std::fs::read(directory.join("fixed-validator-retained.evidence")).unwrap()
                            == old_image,
                        fail
                    );
                })
            })
            .unwrap();
    }
}
