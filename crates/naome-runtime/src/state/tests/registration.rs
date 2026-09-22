use super::*;

pub(super) fn registration_runtime() -> (Directory, Directory, StateRuntime) {
    let base = genesis();
    let mut limits = base.profile().limits().clone();
    limits.run_records = 128;
    let genesis = Genesis::new(
        Profile::with_limits(TimingKind::ShortTest, limits).unwrap(),
        base.foundation().into(),
        base.checker_profile().into(),
        naome_ledger::profile::STATE_PROTOCOL_VERSION,
        base.start_utc(),
        [9; 32],
        base.accounts().iter().map(|a| *a.key()).collect(),
        base.validators().to_vec(),
        base.retirement_order().to_vec(),
    )
    .unwrap();
    runtime_with_genesis(genesis)
}

pub(super) fn finalize(runtime: &mut StateRuntime, now: u64, operations: Vec<SignedOperation>) {
    let bytes = super::proof_fetch::finality(runtime.history().head().unwrap(), now, operations);
    runtime.node.accept_finality(&bytes).unwrap();
    runtime.on_height().unwrap();
}

pub(super) fn prepare(runtime: &mut StateRuntime, now: u64) -> naome_chain::StateRecord {
    let state = runtime.state().unwrap();
    let reports: Vec<_> = (0..3)
        .map(|i| {
            SignedTimeReport::sign(
                state.genesis(),
                state.head(),
                state.height() + 1,
                now,
                &consensus(i),
            )
            .unwrap()
        })
        .collect();
    runtime.time_reports.clear();
    for report in reports {
        runtime.time_reports.insert(report.validator(), report);
    }
    let bytes = runtime.prepare_record().unwrap().unwrap();
    naome_chain::StateRecord::decode(&bytes, runtime.state().unwrap().genesis()).unwrap()
}

#[tokio::test]
async fn registration_is_pending_until_finality_and_ordinary_authority_starts_at_nonce_two() {
    let (_directory, _anchors, mut runtime) = registration_runtime();
    let genesis = runtime.state().unwrap().genesis().clone();
    let key = account(6);
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    let body = OperationBody::decode(operation(&genesis, 1).payload(), &genesis).unwrap();
    assert!(
        runtime
            .submit_operation(body.sign(&genesis, 1, &key).unwrap())
            .is_err()
    );
    assert!(
        runtime
            .submit_operation(OperationBody::Register.sign(&genesis, 2, &key).unwrap())
            .is_err()
    );
    for reused in [account(0), consensus(0), SigningKey::from_bytes(&[201; 32])] {
        assert!(
            runtime
                .submit_operation(OperationBody::Register.sign(&genesis, 1, &reused).unwrap())
                .is_err()
        );
    }
    let registration = OperationBody::Register.sign(&genesis, 1, &key).unwrap();
    let id = runtime.submit_operation(registration.clone()).unwrap();
    assert_eq!(runtime.submit_operation(registration.clone()).unwrap(), id);
    assert_eq!(runtime.pending_operations(), 1);
    assert!(runtime.state().unwrap().account_key(author).is_none());
    finalize(&mut runtime, 101, vec![registration.clone()]);
    assert_eq!(runtime.pending_operations(), 0);
    assert_eq!(runtime.state().unwrap().next_nonce(author), Some(2));
    assert_eq!(runtime.state().unwrap().balances().account(author), Some(0));
    assert_eq!(runtime.submit_operation(registration).unwrap(), id);
    assert!(runtime.state().unwrap().receipt(id).is_some());
    assert!(runtime.operation_rejection(id).is_none());
    assert!(
        runtime
            .submit_operation(body.sign(&genesis, 1, &key).unwrap())
            .is_err()
    );
    let submission = body.sign(&genesis, 2, &key).unwrap();
    runtime.submit_operation(submission.clone()).unwrap();
    finalize(&mut runtime, 102, vec![submission]);
    finalize(&mut runtime, 103, vec![]);
    let active = runtime.state().unwrap().active().unwrap();
    let vote = OperationBody::Vote {
        question: active.question,
        attempt: active.number,
        yes: true,
    };
    assert!(
        runtime
            .submit_operation(vote.sign(&genesis, 3, &key).unwrap())
            .is_err()
    );
    assert_eq!(runtime.state().unwrap().genesis().validators().len(), 4);
}

#[tokio::test]
async fn registrations_cannot_poison_opening_or_active_work_and_survive_unrelated_finality() {
    let (_directory, _anchors, mut runtime) = registration_runtime();
    let genesis = runtime.state().unwrap().genesis().clone();
    finalize(&mut runtime, 101, vec![operation(&genesis, 1)]);
    let registration = OperationBody::Register
        .sign(&genesis, 1, &account(6))
        .unwrap();
    let id = runtime.submit_operation(registration.clone()).unwrap();
    let opening = prepare(&mut runtime, 102);
    assert!(opening.operations().is_empty());
    assert_eq!(runtime.pending_operations(), 1);
    assert!(runtime.operation_rejection(id).is_none());
    finalize(&mut runtime, 102, opening.operations().to_vec());
    assert_eq!(runtime.pending_operations(), 1);
    let active = runtime.state().unwrap().active().unwrap();
    let vote = OperationBody::Vote {
        question: active.question,
        attempt: active.number,
        yes: true,
    }
    .sign(&genesis, 1, &account(0))
    .unwrap();
    runtime.submit_operation(vote.clone()).unwrap();
    let protected = prepare(&mut runtime, 103);
    assert_eq!(protected.operations(), &[vote]);
    assert!(runtime.operation_rejection(id).is_none());
    finalize(&mut runtime, 103, protected.operations().to_vec());
    let ordinary = prepare(&mut runtime, 104);
    assert_eq!(ordinary.operations(), &[registration]);
    let prior = runtime.state().unwrap().reserved_records();
    finalize(&mut runtime, 104, ordinary.operations().to_vec());
    assert_eq!(runtime.state().unwrap().reserved_records(), prior);
    assert!(runtime.state().unwrap().receipt(id).is_some());
}

#[tokio::test]
async fn pending_custody_does_not_expand_to_the_account_registry_limit() {
    let (_directory, _anchors, mut runtime) = registration_runtime();
    let genesis = runtime.state().unwrap().genesis().clone();
    for index in 6..22 {
        runtime
            .submit_operation(
                OperationBody::Register
                    .sign(&genesis, 1, &account(index))
                    .unwrap(),
            )
            .unwrap();
    }
    let extra = OperationBody::Register
        .sign(&genesis, 1, &account(22))
        .unwrap();
    assert!(
        runtime
            .submit_operation(extra)
            .unwrap_err()
            .to_string()
            .contains("pending operation capacity")
    );
    assert_eq!(runtime.pending_operations(), 16);
    assert_eq!(runtime.state().unwrap().accounts().len(), 6);
}
