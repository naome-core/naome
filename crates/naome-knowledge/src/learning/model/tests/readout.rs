use super::*;
use crate::learning::{self as native, artifact, tests::MemoryStore};
use std::collections::BTreeMap;

type Parameters = BTreeMap<String, Vec<u8>>;
fn groups(checkpoint: &Checkpoint, io: &mut MemoryStore) -> (Parameters, Parameters) {
    let bytes = artifact::load(io, checkpoint.model.as_ref().unwrap()).unwrap();
    let reader = burn_pack::Reader::from_bytes(Bytes::from_bytes_vec(bytes)).unwrap();
    let mut encoder = BTreeMap::new();
    let mut readout = BTreeMap::new();
    for tensor in reader.into_tensors().unwrap() {
        let bytes = tensor.to_bytes().unwrap().to_vec();
        let group = if tensor.name.starts_with("readout") || tensor.name.starts_with("output") {
            &mut readout
        } else {
            &mut encoder
        };
        group.insert(tensor.name, bytes);
    }
    assert_eq!(
        readout.values().map(Vec::len).sum::<usize>() / 4,
        READOUT_PARAMETERS
    );
    assert_eq!(
        encoder.values().map(Vec::len).sum::<usize>() / 4,
        PARAMETERS - READOUT_PARAMETERS
    );
    (encoder, readout)
}
fn state() -> native::State {
    let mut state = native::State::fresh();
    state.accept(native::tests::own_example()).unwrap();
    state
}

#[test]
fn freezing_encoder_preserves_exact_predictions_checkpoint_and_parameter_ids() {
    let state = state();
    let pool = state.training_pool_for(&[], true).unwrap();
    let mut io = MemoryStore::default();
    let mut runtime = Runtime::load(&state.model, &mut io).unwrap();
    let before = runtime.checkpoint(&state.model, 0, &mut io).unwrap();
    let scores: Vec<_> = pool
        .graphs()
        .iter()
        .map(|g| {
            runtime
                .scores_graph(g)
                .unwrap()
                .into_iter()
                .map(f32::to_bits)
                .collect::<Vec<_>>()
        })
        .collect();
    runtime.policy = runtime.policy.clone().readout_training();
    let after: Vec<_> = pool
        .graphs()
        .iter()
        .map(|g| {
            runtime
                .scores_graph(g)
                .unwrap()
                .into_iter()
                .map(f32::to_bits)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(scores, after);
    assert_eq!(
        before,
        runtime.checkpoint(&state.model, 0, &mut io).unwrap()
    );
    groups(&before, &mut io);
}

#[test]
fn readout_updates_learn_while_encoder_and_shared_recurrent_weights_stay_exact() {
    let state = state();
    let pool = state.training_pool_for(&[], true).unwrap();
    let mut io = MemoryStore::default();
    let mut readout = Engine::default().with_readout_only(true);
    let initial = readout.snapshot(&state.model, &mut io).unwrap();
    let before = groups(&initial, &mut io);
    let mut cursor = 0;
    let (learned, first, last) = readout
        .train(&initial, &pool, &mut cursor, &mut io)
        .unwrap();
    let after = groups(&learned, &mut io);
    assert_eq!(
        before.0, after.0,
        "every encoder and shared recurrent tensor must stay bit-exact"
    );
    assert_ne!(
        before.1, after.1,
        "freezing the whole model cannot satisfy readout learning"
    );
    assert!(
        last < first,
        "the checked training fixture must actually learn"
    );
    assert_eq!(
        groups(&initial, &mut io),
        before,
        "the incumbent remains immutable"
    );
    let mut full = Engine::default();
    let (control, _, _) = full.train(&initial, &pool, &mut 0, &mut io).unwrap();
    assert_ne!(
        groups(&control, &mut io).0,
        before.0,
        "the full-update comparator must still train its encoder"
    );
}

#[test]
fn readout_scope_survives_real_adam_mask_checkpoint_and_restart() {
    let mut state = state();
    let mut io = MemoryStore::default();
    let mut engine = Engine::default().with_readout_only(true);
    let initial = engine.snapshot(&state.model, &mut io).unwrap();
    let frozen = groups(&initial, &mut io).0;
    let mut cursor = 0;
    let phase = native::meta::Plan::balanced().phase(0);
    let (parent, _, _) = engine
        .train_replay_using(&initial, &state, (&[], &[]), &mut cursor, phase, &mut io)
        .unwrap()
        .unwrap();
    state.model = parent.clone();
    let (middle, _, _) = engine
        .train_replay_using(&parent, &state, (&[], &[]), &mut cursor, phase, &mut io)
        .unwrap()
        .unwrap();
    let saved_cursor = cursor;
    let (continuous, _, _) = engine
        .train_replay_using(&middle, &state, (&[], &[]), &mut cursor, phase, &mut io)
        .unwrap()
        .unwrap();
    let mut recovered = Engine::default().with_readout_only(true);
    let mut restored_cursor = saved_cursor;
    let (restored, _, _) = recovered
        .train_replay_using(
            &middle,
            &state,
            (&[], &[]),
            &mut restored_cursor,
            phase,
            &mut io,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        continuous, restored,
        "full weights, Adam, EMA and draw must continue exactly"
    );
    assert_eq!(cursor, restored_cursor);
    assert_eq!(groups(&restored, &mut io).0, frozen);
    assert!(recovered.cost.measurements.readout_only);
    assert_eq!(
        recovered.cost.measurements.trainable_parameters,
        READOUT_PARAMETERS
    );
    assert!(
        recovered.cost.measurements.reference_slots > 0,
        "warm native units must exercise actual preservation"
    );
}
