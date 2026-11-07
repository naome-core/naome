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
        records: Vec::new(),
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
fn journal_views_rotate_with_independent_cursors_and_canonical_keys() {
    let (mut job, page, mut receipt) = fixture();
    let source = page.sources[0].solution.proof_id.clone();
    receipt.next = Some(source.clone());
    job.base.history_cursor.advance(&receipt);
    job.request_history(3);
    let request = job.history_request.as_ref().unwrap();
    assert_eq!(request.lane, Lane::Records);
    assert_eq!(request.after, None);
    receipt.request = request.clone();
    receipt.next = Some("12".into());
    receipt.validate(request).unwrap();
    job.base.history_cursor.advance(&receipt);
    job.request_history(4);
    assert_eq!(job.history_request.as_ref().unwrap().lane, Lane::Sources);
    assert_eq!(job.history_request.as_ref().unwrap().after, Some(source));
    let restored: Cursor =
        crate::checkpoint::decode(&crate::checkpoint::encode(&job.base.history_cursor).unwrap())
            .unwrap();
    assert_eq!(restored, job.base.history_cursor);
    for after in ["0", "01", "-1", "not-a-record"] {
        assert!(
            Request {
                lane: Lane::Records,
                after: Some(after.into()),
                horizon: 4
            }
            .validate()
            .is_err()
        );
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

#[test]
fn meta_update_preserves_the_reloaded_selection_instead_of_recomputing_base_context() {
    let (job, page, receipt) = fixture();
    let restored = Working::prepare(&job, &page, &receipt)
        .unwrap()
        .state(&job)
        .unwrap();
    let mut io = crate::learning::tests::MemoryStore::default();
    let selection = meta::Engine::default().select(&restored, &mut io).unwrap();
    assert_ne!(selection.context, meta::context(&job.base));
    let experience = meta::Experience {
        job: 2,
        context: selection.context,
        plan: selection.plan.clone(),
        source_model: digest(&job.base.model),
        selected_model: digest(&job.base.model),
        candidate_model: None,
        source_epoch: job.base.epoch,
        before: 0,
        after: 0,
        protected_loss: false,
        anchor_loss: false,
        transfer: transfer::Summary::default(),
        lower_cpu_micros: 1,
        lower_wall_micros: 1,
    };
    // A real cost-only meta update isolates this binding without simulating a
    // lower candidate or claiming a training/promotion outcome.
    let update = meta::Engine::default()
        .learn(&job.base, &selection, experience.clone(), &mut io)
        .unwrap();
    let selection: meta::Selection =
        crate::checkpoint::decode(&crate::checkpoint::encode(&selection).unwrap()).unwrap();
    let repeated = meta::Engine::default()
        .learn(&job.base, &selection, experience, &mut io)
        .unwrap();
    assert_eq!(update.experience.context, meta::context(&restored));
    assert_eq!(update.experience.plan, selection.plan);
    assert_eq!(update.model.updates, meta::UPDATES);
    assert_eq!(update.model, repeated.model);
    assert_eq!(update.draw, repeated.draw);
    assert_eq!(update.first_loss.to_bits(), repeated.first_loss.to_bits());
    assert_eq!(update.last_loss.to_bits(), repeated.last_loss.to_bits());
}

#[cfg(feature = "system-tests")]
#[test]
fn final_meta_update_keeps_the_selected_history_context_across_restart() {
    let (mut job, page, receipt) = fixture();
    assert_eq!(job.base.preparation, Preparation::Meta);
    let mut io = crate::learning::tests::MemoryStore::default();
    assert_eq!(
        artifact::save(&mut io, &crate::checkpoint::encode(&page).unwrap()).unwrap(),
        receipt.blob
    );
    let mut engine = Engine::default();
    let last = job.units();
    assert_eq!(last, model::TRAINING_UNITS + EVALUATIONS + 1);
    for unit in 1..last {
        job.execute(unit, None, 2, &mut engine, &mut io).unwrap();
    }
    job.validate().unwrap();
    let progress = job.progress.as_ref().unwrap();
    let prepared = progress.prepared.clone().unwrap();
    let selection = progress.plan.clone().unwrap();
    assert_eq!(selection.context, prepared.context);
    assert_ne!(selection.context, meta::context(&job.base));
    assert_eq!(progress.candidate.as_ref().unwrap().updates, 250);
    let mut resumed: Job =
        crate::checkpoint::decode(&crate::checkpoint::encode(&job).unwrap()).unwrap();
    job.execute(last, None, 2, &mut engine, &mut io).unwrap();
    resumed
        .execute(last, None, 2, &mut Engine::default(), &mut io)
        .unwrap();
    job.validate().unwrap();
    resumed.validate().unwrap();
    let completed = job.progress.as_ref().unwrap();
    let restored = resumed.progress.as_ref().unwrap();
    let update = completed.meta_update.as_ref().unwrap();
    let after_restart = restored.meta_update.as_ref().unwrap();
    assert_eq!(update.experience.context, prepared.context);
    assert_eq!(update.experience.plan, selection.plan);
    assert_eq!(update.model.updates, meta::UPDATES);
    assert_eq!(update.model, after_restart.model);
    assert_eq!(update.draw, after_restart.draw);
    assert_eq!(
        update.first_loss.to_bits(),
        after_restart.first_loss.to_bits()
    );
    assert_eq!(
        update.last_loss.to_bits(),
        after_restart.last_loss.to_bits()
    );
    assert_eq!(completed.model, restored.model);
    assert_eq!(completed.prepared, Some(prepared));
}
