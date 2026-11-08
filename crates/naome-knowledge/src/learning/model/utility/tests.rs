use super::*;
use crate::learning::{
    State,
    pool::Pool,
    tests::{MemoryStore, own_example},
};

#[test]
fn cosine_preserves_sign_and_handles_zero_or_invalid_gradients() {
    assert_eq!(cosine([2., 4., 1.]).unwrap(), Some(1.));
    assert_eq!(cosine([-2., 4., 1.]).unwrap(), Some(-1.));
    assert_eq!(cosine([0., 4., 1.]).unwrap(), Some(0.));
    assert_eq!(cosine([0., 0., 1.]).unwrap(), None);
    assert!(cosine([f64::NAN, 1., 1.]).is_err());
}

#[test]
fn scoring_real_checked_graphs_preserves_model_adam_mask_and_cursor() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let graphs = state
        .training_pool_for(&[], true)
        .unwrap()
        .graphs()
        .to_vec();
    assert!(!graphs.is_empty());
    let mut io = MemoryStore::default();
    let mut engine = Engine::default();
    let mut cursor = 0;
    let pool = Pool::from_graphs(&graphs);
    let mut runtime = Runtime::load(&state.model, &mut io).unwrap();
    runtime
        .train_using(
            &pool,
            &mut cursor,
            1,
            crate::learning::meta::Plan::balanced().phase(0),
            Some((&pool, 0)),
            preservation::Mode::default(),
        )
        .unwrap();
    let model = runtime.checkpoint(&state.model, 1, &mut io).unwrap();
    let saved = cursor;
    let before = engine.snapshot(&model, &mut io).unwrap();
    let score = engine
        .with(&model, &mut io, |runtime| {
            runtime.utility_alignment(&graphs[0], &graphs[..1])
        })
        .unwrap()
        .unwrap();
    assert!((score - 1.).abs() < 1e-4);
    let after = engine.snapshot(&model, &mut io).unwrap();
    assert_eq!(before, after, "scoring is not an optimizer step");
    assert_eq!(cursor, saved);
}
