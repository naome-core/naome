use super::*;
use naome_runtime::FixedValidatorRuntimeProofRefusalV0 as Refusal;

#[test]
fn envelope_runtime_preserves_refunded_and_buffered_allocations_across_due_phase_handoff() {
    let fixture = Fixture::new();
    let input = make_proof(&fixture, &[], 1, 0);
    for phases in 0..3 {
        let layout = TestLayout::new("runtime-envelope-due-phases");
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
            let mut driver = arm_driver(node_driver(scope));
            for _ in 0..phases { driver = empty_phase(driver); }
            let mut owner = Runtime::new(driver, isolated_network(), vec![], timeouts(Duration::from_millis(1))).unwrap();
            let payload = input.proof.payload.clone();
            let Event::TimerArmed(timer) = owner.next_event().await else { panic!("initial arm") };
            let mut raw = vec![0; naome_network::CONSENSUS_PUSH_VOTE_BYTES]; raw.reserve(61); let raw_allocation = allocations(&raw);
            owner.queue_input(ConsensusPushMessage::Vote { canonical_vote: raw }).unwrap();
            tokio::time::sleep_until(timer.deadline()).await;
            assert!(matches!(owner.next_event().await, Event::TimerDue { .. }));
            let images = layout.authority_images();
            let timer_state = owner.timer();
            assert!(matches!(owner.commit_finality_envelope(&input.envelope, vec![0]).unwrap(), Event::FinalityEnvelopeRejected(_)));
            assert_eq!(layout.authority_images(), images); assert_eq!(owner.timer(), timer_state);
            assert!(owner.driver().unwrap().timeout_is_due());
            assert!(matches!(owner.commit_finality_envelope(&input.envelope, payload).unwrap(), Event::Finality(_)));
            assert_eq!(owner.driver().unwrap().position().height().value(), 2);
            assert_eq!(owner.driver().unwrap().phase(), FixedValidatorLockPhaseV0::Proposal);
            assert!(owner.timer().is_none());
            let mut refunded = input.proof.payload.clone(); refunded.reserve(83); let allocation = allocations(&refunded);
            let (reason, returned) = owner.commit_finality_envelope(&[], refunded).err().expect("pending child arm refunds input before bad proof work");
            assert_eq!(reason, Refusal::Busy); assert_eq!(allocations(&returned), allocation);
            assert!(matches!(owner.next_event().await, Event::TimerArmed(next) if next.ticket().generation() == timer.ticket().generation() + 1));
            let parts = owner.into_parts();
            assert!(matches!(parts.pending_caller_input, Some(ConsensusPushMessage::Vote { canonical_vote }) if allocations(&canonical_vote) == raw_allocation));
        })).unwrap();
    }
}

#[test]
fn envelope_runtime_anchor_failure_drops_authority_and_refunds_later_requests() {
    let fixture = Fixture::new();
    let input = make_proof(&fixture, &[], 1, 0);
    let layout = TestLayout::new("runtime-envelope-anchor-failure");
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
    std::fs::write(&collision, b"envelope handoff failure").unwrap();
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
                let timer = owner.timer();
                assert!(matches!(
                    owner
                        .commit_finality_envelope(&input.envelope, input.proof.payload.clone())
                        .unwrap(),
                    Event::Fatal(_)
                ));
                assert!(owner.driver().is_none());
                assert_eq!(owner.timer(), timer);
                let mut payload = vec![0];
                payload.reserve(51);
                let allocation = allocations(&payload);
                let (reason, returned) =
                    owner.commit_finality_envelope(&[], payload).err().unwrap();
                assert_eq!(reason, Refusal::DriverUnavailable);
                assert_eq!(allocations(&returned), allocation);
                let request = naome_network::FinalityProofRequest::new(
                    fixture.context,
                    naome_consensus::ConsensusHeight::new(1),
                )
                .unwrap();
                assert!(matches!(
                    owner.request_finality_proof(owner.local_peer_id(), request),
                    Err(
                        naome_runtime::FixedValidatorRuntimeFinalityProofRequestErrorV0::Refused(
                            Refusal::DriverUnavailable
                        )
                    )
                ));
            })
        })
        .unwrap();
    std::fs::remove_file(collision).unwrap();
    assert!(
        provision(
            fixture.definition,
            fixture.context,
            &fixture.entries,
            &layout
        )
        .open(fixture.keys[1].clone())
        .is_err()
    );
}
