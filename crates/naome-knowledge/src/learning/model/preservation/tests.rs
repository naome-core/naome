use super::*;
use crate::learning::{
    self, Origin, State,
    artifact::{self, Blob},
    model::{Checkpoint, Engine, Runtime, UPDATES_PER_UNIT},
    pool::Pool,
    tests::{MemoryStore, own_example},
};
use burn::{
    optim::{AdamConfig, Optimizer},
    tensor::Device,
};

fn values(tensor: Tensor<1>) -> Vec<f32> {
    tensor.into_data().try_to_vec().unwrap()
}

#[test]
fn known_coordinate_masks_are_bias_corrected_and_only_attenuate_proposals() {
    let device = Device::flex();
    let gradient = Tensor::from_floats([1., 1., -1., -1., 0.], &device);
    let delta = Tensor::from_floats([-2., 2., -2., 2., 9.], &device);
    let (ema, coefficient) = attenuation(
        Tensor::zeros([5], &device),
        gradient,
        delta.clone(),
        1,
        Mode::Smoothed,
    );
    assert_eq!(values(coefficient.clone()), [1., 0., 0., 1., 1.]);
    assert_eq!(values(coefficient * delta.clone()), [-2., 0., 0., 2., 9.]);
    let (_, coefficient) = attenuation(
        ema,
        Tensor::from_floats([-1., -1., 1., 1., 0.], &device),
        delta.clone(),
        2,
        Mode::Smoothed,
    );
    let expected = [9. / 19., 10. / 19., 10. / 19., 9. / 19., 1.];
    for (actual, expected) in values(coefficient.clone()).into_iter().zip(expected) {
        assert!((actual - expected).abs() < 2e-6);
        assert!((0.0..=1.0).contains(&actual));
    }
    for (actual, original) in values(coefficient * delta)
        .into_iter()
        .zip([-2.0_f32, 2., -2., 2., 9.])
    {
        assert!(actual.abs() <= original.abs());
        assert!(actual == 0. || actual.signum() == original.signum());
    }
}

#[test]
fn binary_ablation_has_no_temporal_carry_from_the_previous_mask() {
    let device = Device::flex();
    let (_, coefficient) = attenuation(
        Tensor::from_floats([0.9, 0.1], &device),
        Tensor::from_floats([1., 1.], &device),
        Tensor::from_floats([1., -1.], &device),
        73,
        Mode::Binary,
    );
    assert_eq!(values(coefficient), [0., 1.]);
}

#[test]
fn momentum_conflict_is_decided_by_actual_adam_delta_not_new_gradient() {
    let device = Device::flex();
    let adam = AdamConfig::new().build();
    let (first, state) = adam.step(
        0.001,
        Tensor::from_floats([1.], &device),
        Tensor::from_floats([10.], &device),
        None,
    );
    let (proposed, _) = adam.step(
        0.001,
        first.clone(),
        Tensor::from_floats([-0.1], &device),
        state,
    );
    let delta = proposed - first;
    assert!(
        values(delta.clone())[0] < 0.,
        "old momentum still proposes a negative change"
    );
    let (_, coefficient) = attenuation(
        Tensor::zeros([1], &device),
        Tensor::from_floats([-1.], &device),
        delta,
        1,
        Mode::Smoothed,
    );
    assert_eq!(
        values(coefficient),
        [0.],
        "a negative preservation gradient forbids the actual negative proposal"
    );
    let (_, raw_gradient_rule) = attenuation(
        Tensor::zeros([1], &device),
        Tensor::from_floats([-1.], &device),
        Tensor::from_floats([0.1], &device),
        1,
        Mode::Smoothed,
    );
    assert_eq!(
        values(raw_gradient_rule),
        [1.],
        "negating only the current gradient would miss this conflict"
    );
}

#[test]
fn preservation_sources_are_rechecked_local_training_proofs_only() {
    let own = own_example();
    let mut state = State::fresh();
    state.anchors.push(own.clone());
    let accepted = state.preservation_pool(&[], &Pool::default()).unwrap();
    assert!(!accepted.is_empty());
    let mut peer = own.clone();
    peer.origin = Origin::Peer {
        artifact: "not-a-local-input".into(),
        peer: "peer".into(),
    };
    peer.question = "must not be parsed as preservation material".into();
    state.anchors.push(peer);
    assert_eq!(
        state
            .preservation_pool(&[], &Pool::default())
            .unwrap()
            .graphs()
            .len(),
        accepted.graphs().len()
    );
    state.anchors[0].proof_id = "0".repeat(64);
    assert!(
        state.preservation_pool(&[], &Pool::default()).is_err(),
        "stored acceptance flags cannot replace exact native replay"
    );
    let mut reserved = own;
    reserved.question = learning::curriculum::development()[0].source.clone();
    state.anchors = vec![reserved];
    assert!(
        state.preservation_pool(&[], &Pool::default()).is_err(),
        "dedicated held-out material is never a preservation source"
    );
}

#[test]
fn checkpoint_boundary_restores_adam_mask_and_cursor_without_mutating_parent() {
    let own = own_example();
    let mut state = State::fresh();
    state.accept(own).unwrap();
    let pool = state.training_pool_for(&[], true).unwrap();
    let mut io = MemoryStore::default();
    let mut engine = Engine::default();
    let mut cursor = 0;
    let initial = state.model.clone();
    let (parent, _, _) = engine.train(&initial, &pool, &mut cursor, &mut io).unwrap();
    state.model = parent.clone();
    let parent_model = artifact::load(&mut io, parent.model.as_ref().unwrap()).unwrap();
    let parent_optimizer = artifact::load(&mut io, parent.optimizer.as_ref().unwrap()).unwrap();
    let (middle, _, _) = engine
        .train_replay_using(
            &parent,
            &state,
            &[],
            &mut cursor,
            learning::meta::Plan::targeted().phase(0),
            &mut io,
        )
        .unwrap()
        .unwrap();
    let saved_cursor = cursor;
    let (continuous, _, _) = engine
        .train_replay_using(
            &middle,
            &state,
            &[],
            &mut cursor,
            learning::meta::Plan::targeted().phase(1),
            &mut io,
        )
        .unwrap()
        .unwrap();
    let mut recovered = Engine::default();
    let mut resumed_cursor = saved_cursor;
    let (resumed, _, _) = recovered
        .train_replay_using(
            &middle,
            &state,
            &[],
            &mut resumed_cursor,
            learning::meta::Plan::targeted().phase(1),
            &mut io,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        resumed, continuous,
        "weights, Adam moments and smoothed mask must all resume exactly"
    );
    assert_eq!(resumed_cursor, cursor);
    assert_eq!(
        artifact::load(&mut io, parent.model.as_ref().unwrap()).unwrap(),
        parent_model
    );
    assert_eq!(
        artifact::load(&mut io, parent.optimizer.as_ref().unwrap()).unwrap(),
        parent_optimizer
    );
    let runtime = Runtime::load(&resumed, &mut io).unwrap();
    assert_eq!(runtime.preservation.steps, 2 * UPDATES_PER_UNIT);
    assert!(resumed.optimizer.as_ref().unwrap().bytes < learning::model::REQUIREMENTS.blob_bytes);
    let ema = values_by_name(&runtime.preservation);
    assert!(
        ema.iter().any(|v| *v > 0. && *v < 1.),
        "roundtrip must exercise actual nonzero smoothed memory"
    );
}

#[test]
fn unmasked_control_preserves_actual_adam_weights_and_training_cursor() {
    let mut state = State::fresh();
    state.accept(own_example()).unwrap();
    let pool = state.training_pool_for(&[], false).unwrap();
    let mut io = MemoryStore::default();
    let mut raw = Engine::default();
    let mut cursor = 0;
    let (parent, _, _) = raw
        .train(&state.model, &pool, &mut cursor, &mut io)
        .unwrap();
    state.model = parent.clone();
    let mut control = Engine {
        preservation_mode: Mode::Unmasked,
        ..Engine::default()
    };
    let mut comparison_cursor = cursor;
    let (expected, _, _) = raw.train(&parent, &pool, &mut cursor, &mut io).unwrap();
    let (actual, _, _) = control
        .train_replay_using(
            &parent,
            &state,
            &[],
            &mut comparison_cursor,
            learning::meta::Plan::balanced().phase(0),
            &mut io,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        actual, expected,
        "reference-gradient acquisition cannot alter unmasked Adam"
    );
    assert_eq!(comparison_cursor, cursor);
}

fn values_by_name(state: &Preservation) -> Vec<f32> {
    let bytes = state.ema.clone().into_record().into_bytes().unwrap();
    burn_pack::Reader::from_bytes(bytes)
        .unwrap()
        .into_tensors()
        .unwrap()
        .iter()
        .flat_map(|t| {
            t.to_bytes()
                .unwrap()
                .chunks_exact(4)
                .map(|b| f32::from_le_bytes(b.try_into().unwrap()))
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn current_optimizer_memory_rejects_missing_steps_and_nonfinite_ema() {
    let mut io = MemoryStore::default();
    let initial = Checkpoint::fresh();
    let runtime = Runtime::load(&initial, &mut io).unwrap();
    let snapshot = runtime.checkpoint(&initial, 0, &mut io).unwrap();
    let bytes = artifact::load(&mut io, snapshot.optimizer.as_ref().unwrap()).unwrap();
    for corruption in ["missing_steps", "nonfinite", "unknown_parameter"] {
        let reader = burn_pack::Reader::from_bytes(Bytes::from_bytes_vec(bytes.clone())).unwrap();
        let metadata = reader.metadata().clone();
        let scalars = reader.scalars().clone();
        let mut tensors = reader.into_tensors().unwrap();
        if corruption == "nonfinite" {
            let old = tensors.remove(0);
            let mut data = old.to_bytes().unwrap().to_vec();
            data[..4].copy_from_slice(&f32::NAN.to_le_bytes());
            tensors.insert(
                0,
                burn_pack::Tensor::new(
                    old.name,
                    old.dtype,
                    old.shape,
                    old.param_id,
                    Bytes::from_bytes_vec(data),
                ),
            );
        } else if corruption == "unknown_parameter" {
            tensors[0].param_id = Some(99999);
        }
        let mut writer = burn_pack::Writer::new(tensors);
        for (key, value) in metadata {
            writer = writer.with_metadata(&key, &value);
        }
        for (key, value) in scalars {
            if corruption != "missing_steps" || key != "preservation_steps" {
                writer = writer.with_scalar(&key, value);
            }
        }
        let altered = writer.into_bytes().unwrap();
        let mut invalid = snapshot.clone();
        invalid.optimizer = Some(artifact::save(&mut io, &altered[..]).unwrap());
        assert_ne!(invalid.optimizer.as_ref().unwrap(), &Blob::of(&bytes));
        assert!(
            Runtime::load(&invalid, &mut io).is_err(),
            "current optimizer memory corruption: {corruption}"
        );
    }
}
