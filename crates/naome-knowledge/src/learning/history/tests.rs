use super::*;

fn fixture() -> (Job, Page, Receipt) {
    let mut state = State::fresh();
    let mut example = crate::learning::tests::own_example();
    example.job = 1;
    state.accept(example).unwrap();
    state.replay.clear();
    state.anchors.clear();
    let mut job = state.job();
    job.training = true;
    job.request_history(2);
    let solution = crate::learning::tests::own_solution();
    let page = Page {
        request: job.history_request.clone().unwrap(),
        next: None,
        examined: vec![(solution.proof_id.clone(), 1)],
        sources: vec![Source {
            job: 1,
            origin: Origin::Local,
            question: crate::learning::tests::own_question(),
            solution,
            peer_certificate: None,
        }],
    };
    let receipt = receipt(&page);
    job.history = Some(receipt.clone());
    (job, page, receipt)
}
fn receipt(page: &Page) -> Receipt {
    Receipt {
        request: page.request.clone(),
        blob: Blob::of(&crate::checkpoint::encode(page).unwrap()),
        next: page.next.clone(),
        read_bytes: 0,
        read_operations: 1,
        read_cpu_micros: 0,
    }
}

#[test]
fn an_evicted_owned_proof_returns_without_new_counts_epoch_anchors_or_model_changes() {
    let (job, page, receipt) = fixture();
    let working = Working::prepare(&job, &page, &receipt).unwrap();
    let restored = working.state(&job).unwrap();
    assert_eq!(restored.replay.len(), 1);
    assert_eq!(
        restored.replay[0].proof_id,
        page.sources[0].solution.proof_id
    );
    let mut original = job.base.clone();
    original.replay.clone_from(&restored.replay);
    assert_eq!(digest(&original), digest(&restored));
    let pool = restored.training_pool(&working.evidence).unwrap();
    assert!(
        !pool.is_empty(),
        "the restored trajectory must actually reach the training pool"
    );
    let roundtrip: Job =
        crate::checkpoint::decode(&crate::checkpoint::encode(&job).unwrap()).unwrap();
    assert_eq!(
        digest(&Working::prepare(&roundtrip, &page, &receipt).unwrap()),
        digest(&working)
    );
}

#[test]
fn source_substitution_missing_closure_and_omitted_records_fail_before_training() {
    let (mut job, original, _) = fixture();
    for mutation in 0..3 {
        let mut page = original.clone();
        match mutation {
            0 => page.sources[0].solution.proof_id = "f1".repeat(32),
            1 => {
                page.sources[0].solution.tree = search::Tree::Definitions {
                    entries: Vec::new(),
                    selected: 0,
                    available: 1,
                    proof: Box::new(page.sources[0].solution.tree.clone()),
                }
            }
            _ => page.sources.clear(),
        }
        let receipt = receipt(&page);
        job.history = Some(receipt.clone());
        assert!(
            Working::prepare(&job, &page, &receipt).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn prepared_history_preserves_exact_model_optimizer_and_sampling_after_restart() {
    let (mut job, page, receipt) = fixture();
    job.base.preparation = Preparation::Balanced;
    job.base_hash = digest(&job.base);
    let mut io = crate::learning::tests::MemoryStore::default();
    assert_eq!(
        artifact::save(&mut io, &crate::checkpoint::encode(&page).unwrap()).unwrap(),
        receipt.blob
    );
    let mut engine = Engine::default();
    job.execute(1, None, 2, &mut engine, &mut io).unwrap();
    job.validate().unwrap();
    let parent = job.progress.as_ref().unwrap().candidate.as_ref().unwrap();
    assert_eq!(parent.updates, model::UPDATES_PER_UNIT);
    let mut resumed: Job =
        crate::checkpoint::decode(&crate::checkpoint::encode(&job).unwrap()).unwrap();
    let original_page = job.progress.as_ref().unwrap().prepared.clone().unwrap();
    let batches = model::observation::consumed(
        &engine,
        job.base.draws,
        job.progress.as_ref().unwrap().rng,
        &mut model::observation::Decisions::new(),
        &mut model::observation::Decisions::new(),
    );
    assert_eq!(batches.len(), model::UPDATES_PER_UNIT as usize);
    assert!(batches.iter().all(|batch| batch.len() == 16));
    job.execute(2, None, 2, &mut engine, &mut io).unwrap();
    resumed
        .execute(2, None, 2, &mut Engine::default(), &mut io)
        .unwrap();
    job.validate().unwrap();
    resumed.validate().unwrap();
    let continued = job.progress.as_ref().unwrap();
    let restored = resumed.progress.as_ref().unwrap();
    assert_eq!(
        continued.candidate, restored.candidate,
        "both model and Adam/EMA blobs must match byte for byte"
    );
    assert_eq!(
        continued.candidate.as_ref().unwrap().updates,
        2 * model::UPDATES_PER_UNIT
    );
    assert_eq!(continued.rng, restored.rng);
    assert_eq!(
        continued.last_loss.unwrap().to_bits(),
        restored.last_loss.unwrap().to_bits()
    );
    assert_eq!(continued.prepared.as_ref().unwrap(), &original_page);
    assert_eq!(continued.prepared, restored.prepared);
    assert_eq!(continued.plan, restored.plan);
}
