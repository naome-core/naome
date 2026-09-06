use super::*;
use naome_consensus::{ActiveAgreementSnapshot, VerifiedQuorumCertificateV0};
use naome_node::FixedValidatorNodeReadyV0;

fn check_recovered(
    scope: &mut FixedValidatorNodeSigningScopeV0<'_>,
    sim: &Simulation<'_>,
    round_number: u64,
    admitted: &BTreeMap<ConsensusKey, Vec<u8>>,
) -> Vec<u8> {
    assert_eq!(sim.scenario.weights, [1; 4]);
    assert_eq!(scope.branch().coordinate(), sim.branch.coordinate());
    let session = scope.signing_session();
    assert_eq!(session.position().height().value(), 2);
    assert_eq!(session.position().round().value(), round_number);
    assert_eq!(session.phase(), FixedValidatorLockPhaseV0::Precommit);
    let locked = session.locked_value().unwrap();
    let valid = session.valid_value().unwrap();
    assert_eq!(locked.value(), sim.values[1]);
    assert_eq!(valid.value(), sim.values[1]);
    assert_eq!(locked.round(), ConsensusRound::new(0));
    assert_eq!(valid.round(), ConsensusRound::new(0));

    let round = sim.branch.begin_round_zero().unwrap();
    let entries = std::array::from_fn::<_, 4, _>(|actor| {
        ActiveAgreementEntry::new(
            sim.keys[actor],
            AgreementWeight::new(u128::from(sim.scenario.weights[actor])),
        )
    });
    let snapshot =
        ActiveAgreementSnapshot::try_from_preselected(round.position(), &entries).unwrap();
    let certificate = VerifiedQuorumCertificateV0::decode_and_verify(
        valid.canonical_prevote_certificate(),
        sim.branch.context(),
        &snapshot,
    )
    .unwrap();
    assert_eq!(certificate.role(), ConsensusVoteRole::Prevote);
    assert_eq!(certificate.position(), round.position());
    assert_eq!(
        certificate.target(),
        ConsensusVoteTarget::Proposal(sim.values[1].proposal_signing_root())
    );
    // Use only this recipient's successfully admitted pre-transition inputs.
    // The verifier may have selected any supported strict-quorum subset.
    let votes = certificate
        .signer_keys()
        .map(|key| {
            admitted
                .get(&key)
                .expect("recovered certificate signer was never admitted by this owner")
                .as_slice()
        })
        .collect::<Vec<_>>();
    assert!(
        3 * votes.len() > 2 * 4,
        "unit-weight lock requires a real distributed quorum"
    );
    let rebuilt = round
        .build_quorum_certificate_from_signed_votes(
            &votes,
            ConsensusVoteRole::Prevote,
            certificate.target(),
        )
        .unwrap();
    assert_eq!(
        rebuilt.to_canonical_bytes(),
        valid.canonical_prevote_certificate()
    );
    assert_eq!(rebuilt.id(), valid.prevote_certificate_id());
    valid.canonical_prevote_certificate().to_vec()
}

async fn exercise_restart(
    sim: &mut Simulation<'_>,
    first: &mut Runtime<'_>,
    second: &mut Runtime<'_>,
    third: &mut Runtime<'_>,
    fourth_ready: FixedValidatorNodeReadyV0,
    reopen: impl Fn() -> FixedValidatorNodeReadyV0,
) {
    let (old_timer, admitted, before_restart) =
        Box::pin(fourth_ready.run_with_signing_session_async(async |scope| {
            let mut fourth = runtime_owner(scope);
            sim.pump(first, second, third, &mut fourth).await;
            sim.author(1, first, second, third, &mut fourth);
            sim.pump(first, second, third, &mut fourth).await;
            sim.prepare_second_height();
            sim.author(2, first, second, third, &mut fourth);
            sim.pump(first, second, third, &mut fourth).await;
            let root = sim.values[1].proposal_signing_root();
            for actor in 0..4 {
                assert_eq!(
                    sim.intents[&(sim.keys[actor], 2, 0, 0)].target,
                    ConsensusVoteTarget::Proposal(root)
                );
                assert_eq!(
                    sim.intents[&(sim.keys[actor], 2, 0, 1)].target,
                    ConsensusVoteTarget::Proposal(root)
                );
                let component = if actor < 2 { 0b0011 } else { 0b1100 };
                assert_eq!(sim.received[actor][&(2, 0, root)], component);
            }
            assert_eq!(sim.finalized, [1; 4]);
            assert!(sim.dropped > 0 && sim.caller_precommits > 0 && sim.local_precommits > 0);
            assert_eq!(sim.due, 0, "restart point must precede all H2 deadlines");
            let timer = fourth.timer().unwrap();
            assert_eq!(timer.ticket().position().height().value(), 2);
            assert_eq!(timer.ticket().position().round().value(), 0);
            assert_eq!(timer.ticket().phase(), FixedValidatorLockPhaseV0::Precommit);
            assert!(
                Simulation::accounting(&fourth)
                    .0
                    .into_iter()
                    .any(|count| count > 0)
            );
            assert!(fourth.pending_publication().is_none());
            let admitted = sim.precommit_inputs[3][&(2, 0, root)].clone();
            assert!(admitted.len() >= 3);
            // All proposal/prevote work is drained. From this point every new
            // cross-component message is lost, including later-round prevotes.
            sim.scenario.cut = Cut::Cold;
            (
                timer,
                admitted,
                sim.layouts.each_ref().map(TestLayout::authority_images),
            )
        }))
        .await
        .unwrap();
    // Returning from the owning callback drops the runtime AND both journals.
    // The other three runtimes remain in their original outer callbacks.
    assert_eq!(
        sim.layouts.each_ref().map(TestLayout::authority_images),
        before_restart
    );
    let intents = sim.intents.clone();
    let other_receipts = [
        sim.received[0].clone(),
        sim.received[1].clone(),
        sim.received[2].clone(),
    ];
    let other_custody = [
        Simulation::accounting(first),
        Simulation::accounting(second),
        Simulation::accounting(third),
    ];
    assert!(sim.queues.iter().all(VecDeque::is_empty));
    assert!(sim.queued.iter().all(Option::is_none));
    assert!(sim.local.iter().all(Option::is_none));
    // Only this recipient's volatile evidence disappears. The saved admitted
    // inputs below verify its durable lock; they are never supplied to a runtime.
    sim.generations[3] += 1;
    sim.received[3].clear();
    sim.prevotes[3].clear();
    sim.precommit_inputs[3].clear();
    let ready = reopen();
    assert_eq!(
        sim.layouts.each_ref().map(TestLayout::authority_images),
        before_restart
    );

    let certificate = Box::pin(ready.run_with_signing_session_async(async |mut scope| {
        let certificate = check_recovered(&mut scope, sim, 0, &admitted);
        assert_eq!(
            sim.layouts.each_ref().map(TestLayout::authority_images),
            before_restart
        );
        let mut fourth = runtime_owner(scope);
        assert_eq!(Simulation::accounting(&fourth), ([0; 4], [0; 3]));
        assert!(fourth.timer().is_none());
        assert!(fourth.pending_publication().is_none());
        assert!(fourth.failed_admission().is_none());
        assert_eq!(
            fourth.poll_transport_once().await,
            FixedValidatorRuntimeTransportPollV0::PolledPending
        );
        assert_eq!(sim.intents, intents);
        assert!(sim.received[3].is_empty());
        assert_eq!(
            [
                sim.received[0].clone(),
                sim.received[1].clone(),
                sim.received[2].clone()
            ],
            other_receipts
        );
        assert_eq!(
            [
                Simulation::accounting(first),
                Simulation::accounting(second),
                Simulation::accounting(third)
            ],
            other_custody
        );
        assert!(sim.poll(3, &mut fourth).await);
        let fresh = fourth.timer().unwrap();
        assert_eq!(fresh.ticket().position(), old_timer.ticket().position());
        assert_eq!(fresh.ticket().phase(), old_timer.ticket().phase());
        assert_eq!(fresh.ticket().generation(), 0);
        assert_ne!(fresh.ticket(), old_timer.ticket());
        assert!(fresh.deadline() > Instant::now());
        assert!(
            !sim.poll(3, &mut fourth).await,
            "reopen must not reconstruct publication or input"
        );
        assert_eq!(
            sim.layouts.each_ref().map(TestLayout::authority_images),
            before_restart
        );

        let publications_before = sim.produced.len();
        for _ in 0..12 {
            if fourth.driver().unwrap().position().round().value() >= 2 {
                break;
            }
            sim.advance_deadline(first, second, third, &mut fourth)
                .await;
        }
        assert_eq!(fourth.driver().unwrap().position().round().value(), 2);
        assert_eq!(
            fourth.driver().unwrap().phase(),
            FixedValidatorLockPhaseV0::Proposal
        );
        assert_eq!(sim.finalized, [1; 4]);
        assert!(sim.due > 0);
        for (position, phase) in [
            (
                first.driver().unwrap().position(),
                first.driver().unwrap().phase(),
            ),
            (
                second.driver().unwrap().position(),
                second.driver().unwrap().phase(),
            ),
            (
                third.driver().unwrap().position(),
                third.driver().unwrap().phase(),
            ),
        ] {
            assert_eq!(position.height().value(), 2);
            assert_eq!(position.round().value(), 2);
            assert_eq!(phase, FixedValidatorLockPhaseV0::Proposal);
        }
        for actor in 0..4 {
            assert_eq!(
                sim.intents[&(sim.keys[actor], 2, 1, 0)].target,
                ConsensusVoteTarget::Proposal(sim.values[1].proposal_signing_root())
            );
            assert_eq!(
                sim.intents[&(sim.keys[actor], 2, 1, 1)].target,
                ConsensusVoteTarget::Nil
            );
            let coordinate = (2, 1, sim.values[1].proposal_signing_root());
            let actual = sim.prevotes[actor][&coordinate]
                .keys()
                .copied()
                .collect::<Vec<_>>();
            let expected = (0..4)
                .filter(|&peer| sim.scenario.groups[peer] == sim.scenario.groups[actor])
                .map(|peer| sim.keys[peer])
                .collect::<Vec<_>>();
            assert_eq!(
                actual, expected,
                "continued voting must admit the internal peer's prevote"
            );
        }
        let new_votes = &sim.produced[publications_before..];
        for role in [ConsensusVoteRole::Prevote, ConsensusVoteRole::Precommit] {
            assert!(new_votes.iter().any(|e| e.from == 3
                && e.position.round().value() == 1
                && matches!(e.kind, Kind::Vote(actual, _) if actual == role)));
        }
        // No old proposal-precommit is resupplied or counted in the new owner.
        assert!(sim.received[3].is_empty());
        assert_ne!(
            &sim.layouts[3].authority_images()[2..],
            &before_restart[3][2..]
        );
        sim.history();
        certificate
    }))
    .await
    .unwrap();

    let completed = sim.layouts.each_ref().map(TestLayout::authority_images);
    let ready = reopen();
    assert_eq!(
        sim.layouts.each_ref().map(TestLayout::authority_images),
        completed
    );
    Box::pin(ready.run_with_signing_session_async(async |mut scope| {
        // R2 Proposal was volatile. The last anchored signature is R1's nil
        // precommit; recovery must preserve the R0 lock and complete valid proof.
        assert_eq!(check_recovered(&mut scope, sim, 1, &admitted), certificate);
        assert_eq!(
            sim.layouts.each_ref().map(TestLayout::authority_images),
            completed
        );
    }))
    .await
    .unwrap();
    sim.history();
    eprintln!(
        "runtime_partition_restart events={} publications={} due={} finalized={:?}",
        sim.events,
        sim.produced.len(),
        sim.due,
        sim.finalized
    );
}

#[test]
fn restarted_owner_keeps_distributed_lock_while_partitioned_voting_continues() {
    let scenario = Scenario {
        name: "restart-lock",
        weights: [1; 4],
        groups: [0, 0, 1, 1],
        winners: 0,
        cut: Cut::Precommit,
    };
    let total: u16 = scenario.weights.iter().sum();
    for actor in 0..4 {
        let available: u16 = (0..4)
            .filter(|&peer| scenario.groups[peer] == scenario.groups[actor])
            .map(|peer| scenario.weights[peer])
            .sum();
        assert!(3 * available <= 2 * total);
    }
    let definition = ArtifactChainDefinition::new([0x93; 32]);
    let context = ConsensusContextV0::new(
        definition.id(),
        ConsensusGenesisId::from_bytes([0x94; 32]),
        ConsensusProtocolVersion::new(7),
    );
    let mut keys =
        std::array::from_fn::<_, 4, _>(|actor| SigningKey::from_bytes(&[0xa0 + actor as u8; 32]));
    keys.sort_by_key(consensus_key);
    let public_keys = keys.each_ref().map(consensus_key);
    let entries = public_keys.map(|key| ActiveAgreementEntry::new(key, AgreementWeight::new(1)));
    let layouts = std::array::from_fn::<_, 4, _>(|actor| {
        TestLayout::new(&format!("partition-restart-{actor}"))
    });
    let [first, second, third, fourth] = std::array::from_fn::<_, 4, _>(|actor| {
        provision(definition, context, &entries, &layouts[actor])
            .create(keys[actor].clone())
            .unwrap()
    });
    let mut sim = simulation(
        &layouts,
        scenario,
        false,
        definition,
        context,
        public_keys,
        &entries,
    );
    let executor = Builder::new_current_thread().enable_all().build().unwrap();
    first
        .run_with_signing_session(|scope| {
            let mut first = runtime_owner(scope);
            second
                .run_with_signing_session(|scope| {
                    let mut second = runtime_owner(scope);
                    third
                        .run_with_signing_session(|scope| {
                            let mut third = runtime_owner(scope);
                            executor.block_on(async {
                                tokio::time::pause();
                                exercise_restart(
                                    &mut sim,
                                    &mut first,
                                    &mut second,
                                    &mut third,
                                    fourth,
                                    || {
                                        let FixedValidatorNodeStartupV0::Ready(ready) =
                                            provision(definition, context, &entries, &layouts[3])
                                                .open(keys[3].clone())
                                                .unwrap()
                                        else {
                                            panic!("strict owner restart must be ready")
                                        };
                                        *ready
                                    },
                                )
                                .await;
                            });
                        })
                        .unwrap();
                })
                .unwrap();
        })
        .unwrap();
}
