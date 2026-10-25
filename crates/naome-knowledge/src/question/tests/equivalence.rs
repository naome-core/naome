use super::*;

#[tokio::test]
async fn running_node_rejects_certified_equivalence_before_interest_and_after_registry_recovery() {
    let directory = Directory::new();
    let baseline = question("goal=and(all(x,mem(x,x)),all(y,not(mem(y,y))))");
    let exchanged = question("goal=and(all(y,not(mem(y,y))),all(x,mem(x,x)))");
    for recovery in [false, true] {
        let (handle, admin, inbox) = channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let task = tokio::spawn(network::run_with_questions(
            directory.config(Vec::new()),
            false,
            inbox,
            move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                async { Ok(true) }
            },
        ));
        let _ = context(&handle).await;
        if !recovery {
            admin
                .import_baseline(baseline.clone())
                .await
                .unwrap()
                .unwrap();
        }
        let before = context(&handle).await;
        assert_eq!(before.registered_questions, 1);
        let result = handle.admit_question(exchanged.clone()).await.unwrap();
        assert_eq!(
            result.assessment.prefilter.reason,
            Some(RejectionReason::ProvenEquivalent)
        );
        assert!(result.assessment.prefilter.equivalence.is_some());
        assert_eq!(result.assessment.interest, InterestAssessment::NotRun);
        assert_eq!(result.outcome, AdmissionOutcome::NotInserted);
        assert_eq!(context(&handle).await, before);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        stop(admin, task).await;
    }
}
