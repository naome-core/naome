use super::*;

#[test]
fn agreement_is_provisional_until_both_distinct_seal_quorums_verify() {
    let parent = branch();
    let p = proposal(&parent, record(&parent, "seal quorum"), 0, None);
    let qc = quorum(&parent, 0, ConsensusVoteRole::Precommit, target(&p));
    let agreement = parent.verify_agreement(&p, &qc, MAX_ROUND).unwrap();
    assert_eq!(agreement.state().height(), 1);
    assert_eq!(parent.state().height(), 0);
    let ready = seal(&agreement);
    assert!(
        StateSeal::new(
            ready.ready()[..2].to_vec(),
            ready.terminal().to_vec(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming()
        )
        .is_err()
    );
    assert!(
        StateSeal::new(
            ready.ready().to_vec(),
            ready.terminal()[..2].to_vec(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming()
        )
        .is_err()
    );
    assert!(
        StateSeal::new(
            vec![ready.ready()[0].clone(); 3],
            ready.terminal().to_vec(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming()
        )
        .is_err()
    );
    assert!(
        StateSeal::new(
            ready.terminal().to_vec(),
            ready.ready().to_vec(),
            agreement.seal_context(),
            agreement.outgoing(),
            agreement.incoming()
        )
        .is_err()
    );
    let unsealed =
        naome_chain::FinalizedStateRecord::encode_evidence(&p.encode().unwrap(), &qc.encode(), &[])
            .unwrap();
    assert!(parent.decode_finality(&unsealed, MAX_ROUND).is_err());
    let decoded = parent
        .decode_agreement(&agreement.encode().unwrap(), MAX_ROUND)
        .unwrap();
    assert_eq!(decoded.seal_context(), agreement.seal_context());
    let finality = parent.verify_finality(&p, &qc, &ready, MAX_ROUND).unwrap();
    assert_eq!(
        finality.branch().state().commitment(),
        agreement.state().commitment()
    );
}

#[test]
fn seal_evidence_cannot_cross_records_roles_or_authority_periods() {
    let parent = branch();
    let a = proposal(&parent, record(&parent, "a"), 0, None);
    let b = proposal(&parent, record(&parent, "b"), 0, None);
    let aq = quorum(&parent, 0, ConsensusVoteRole::Precommit, target(&a));
    let bq = quorum(&parent, 0, ConsensusVoteRole::Precommit, target(&b));
    let agreement = parent.verify_agreement(&a, &aq, MAX_ROUND).unwrap();
    let evidence = seal(&agreement);
    assert!(
        parent
            .verify_finality(&b, &bq, &evidence, MAX_ROUND)
            .is_err()
    );
    let old = validator_key(0);
    let signature = validator(0)
        .sign(&SealSignature::signing_bytes(
            SealRole::Ready,
            agreement.seal_context(),
            old,
        ))
        .to_bytes();
    assert!(
        SealSignature::complete(
            SealRole::Ready,
            agreement.seal_context(),
            old,
            signature,
            agreement.outgoing(),
            agreement.incoming()
        )
        .is_err()
    );
    let wire = evidence.ready()[0].encode();
    for index in 0..wire.len() {
        let mut bad = wire.clone();
        bad[index] ^= 1;
        if let Ok(signature) = SealSignature::decode(&bad) {
            assert!(
                signature
                    .verify(
                        SealRole::Ready,
                        agreement.seal_context(),
                        agreement.outgoing(),
                        agreement.incoming()
                    )
                    .is_err(),
                "byte {index}"
            );
        }
    }
    let wire = evidence.encode();
    for end in 0..wire.len() {
        assert!(StateSeal::decode(&wire[..end]).is_err());
    }
}

#[test]
fn sealed_rotation_rejects_old_signers_and_preserves_slot_proposer_order() {
    let parent = branch();
    let p = proposal(&parent, record(&parent, "first period"), 0, None);
    let qc = quorum(&parent, 0, ConsensusVoteRole::Precommit, target(&p));
    let finality = parent.finalize(&p, &qc, MAX_ROUND).unwrap();
    let child = finality.branch();
    for i in 0..4 {
        assert!(StateLockState::new(child, validator_key(i)).is_err());
    }
    for round in 0..4 {
        let old = parent.proposer(round + 1, MAX_ROUND).unwrap().unwrap();
        let new = child.proposer(round, MAX_ROUND).unwrap().unwrap();
        assert_ne!(old, new);
        let slot = |branch: &StateBranch, key: ConsensusKey| {
            branch
                .authority()
                .units()
                .iter()
                .find(|u| u.keys().is_some_and(|k| k.consensus() == key.as_bytes()))
                .unwrap()
                .slot()
        };
        assert_eq!(slot(&parent, old), slot(child, new));
    }
    let state = child.state();
    let reports = (0..4)
        .map(|i| {
            SignedTimeReport::sign(
                state.genesis(),
                state.authority(),
                state.head(),
                2,
                state.time(),
                &period_key(i, 2),
            )
            .unwrap()
        })
        .collect();
    let time = TimeCertificate::new(
        reports,
        state.genesis(),
        state.authority(),
        state.head(),
        2,
        state.time(),
    )
    .unwrap();
    let record = state.prepare_record(time, Vec::new(), plan(child)).unwrap();
    let p2 = proposal(child, record.record().encode().unwrap(), 0, None);
    let q2 = quorum(child, 0, ConsensusVoteRole::Precommit, target(&p2));
    let second = child.finalize(&p2, &q2, MAX_ROUND).unwrap();
    assert_eq!(second.branch().state().height(), 2);
    assert!(
        StateFinality::authenticate(&second.encode().unwrap(), parent.state(), MAX_ROUND).is_err()
    );
    assert!(
        StateVote::decode(
            &vote(
                &parent,
                0,
                ConsensusVoteRole::Prevote,
                ConsensusVoteTarget::Nil,
                0
            )
            .encode(),
            child.state().genesis(),
            child.authority()
        )
        .is_err()
    );
    assert_eq!(
        child
            .decode_finality(&second.encode().unwrap(), MAX_ROUND)
            .unwrap()
            .branch()
            .commitment(),
        second.branch().commitment()
    );
}

#[test]
fn a_missing_slot_keeps_its_proposer_turn_and_four_slot_quorum_denominator() {
    let parent = branch();
    let base = naome_chain::StateRecord::decode(
        &record(&parent, "vacant next period"),
        parent.state().genesis(),
    )
    .unwrap();
    let missing = AccountId::for_key(account(3).verifying_key().as_bytes());
    let offers = plan(&parent)
        .offers()
        .iter()
        .filter(|offer| parent.authority().unit(offer.unit()).unwrap().owner() != missing)
        .cloned()
        .collect();
    let plan = HandoffPlan::new(offers, None).unwrap();
    let record = parent
        .state()
        .prepare_record(
            base.time_certificate().clone(),
            base.operations().to_vec(),
            plan,
        )
        .unwrap();
    let p = proposal(&parent, record.record().encode().unwrap(), 0, None);
    let qc = quorum(&parent, 0, ConsensusVoteRole::Precommit, target(&p));
    let finality = parent.finalize(&p, &qc, MAX_ROUND).unwrap();
    let child = finality.branch();
    assert_eq!(child.authority().active_count(), 3);
    assert_eq!(
        (0..4)
            .filter(|round| child.proposer(*round, MAX_ROUND).unwrap().is_none())
            .count(),
        1
    );
    let target = ConsensusVoteTarget::Nil;
    let two: Vec<_> = (0..2)
        .map(|i| vote(child, 0, ConsensusVoteRole::Precommit, target, i))
        .collect();
    assert!(StateQuorum::from_votes(two, child.state().genesis(), child.authority()).is_err());
    assert!(
        StateQuorum::from_votes(
            (0..3)
                .map(|i| vote(child, 0, ConsensusVoteRole::Precommit, target, i))
                .collect(),
            child.state().genesis(),
            child.authority()
        )
        .is_ok()
    );
    assert!(
        StateLockState::new(
            child,
            ConsensusKey::from_bytes(period_key(3, 2).verifying_key().to_bytes())
        )
        .is_err()
    );
}
