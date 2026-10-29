use super::*;
fn parent(job: u64, promoted: bool) -> Parent {
    Parent {
        state: State::fresh(),
        store: Store::default(),
        job,
        promoted,
        before: State::fresh().feedback.development,
    }
}
#[test]
fn only_the_first_real_promotion_replaces_the_retained_fallback() {
    let rejected = retain_parent(None, parent(10, false));
    let still_rejected = retain_parent(Some(rejected), parent(11, false));
    assert_eq!(still_rejected.job, 10);
    let promoted = retain_parent(Some(still_rejected), parent(12, true));
    assert_eq!(promoted.job, 12);
    let earliest = retain_parent(Some(promoted), parent(13, true));
    assert_eq!(earliest.job, 12);
}
#[test]
fn a_new_source_epoch_preserves_the_actual_retained_model_and_adam_pair() {
    let mut previous = State::fresh();
    previous
        .accept(crate::learning::tests::own_example())
        .unwrap();
    let graphs = previous.training_graphs().unwrap();
    let mut io = MemoryStore::default();
    previous.model = model::test_update(&previous.model, &graphs, &mut 71, &mut io).unwrap();
    assert!(previous.model.model.is_some() && previous.model.optimizer.is_some());
    previous.trained = 19;
    previous.attempted = 19;
    previous.epoch = 19;
    previous.rejections = 3;
    previous.promotions = 1;
    previous.feedback = crate::training::ability::Feedback::fresh(digest(&previous.model));
    let mut source = State::fresh();
    source.epoch = 27;
    let input = acquisition::FrozenRound {
        state: source,
        evidence: Vec::new(),
        rows: Vec::new(),
    };
    let actual = acquisition::bind(&input, &previous);
    assert_eq!(actual.model, previous.model);
    assert_eq!(actual.trained, 19);
    assert_eq!(actual.attempted, 19);
    assert_eq!(actual.epoch, 27);
    assert_eq!(actual.promotions, 1);
    assert_eq!(actual.rejections, 3);
    assert_eq!(digest(&actual.feedback), digest(&previous.feedback));
    let mut job = actual.job();
    job.training = true;
    assert_eq!(job.units(), model::TRAINING_UNITS + EVALUATIONS + 1);
    let restored = model::test_update(&job.base.model, &graphs, &mut 73, &mut io).unwrap();
    let direct = model::test_update(&previous.model, &graphs, &mut 73, &mut io).unwrap();
    assert_eq!(
        restored, direct,
        "binding keeps the exact next real Adam update"
    );
}
