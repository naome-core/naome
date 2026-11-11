use super::{
    super::{Blob, Engine, Runtime, canonical_checkpoint, record_failure, test_update},
    Span,
};
use crate::learning::{State, tests::MemoryStore};
use burn::module::Module;

#[test]
fn selected_weights_reset_touched_adam_and_resume_exactly() {
    let _reservation = crate::learning::tests::qualification_fixture();
    let mut state = State::fresh();
    state.accept(crate::learning::tests::own_example()).unwrap();
    let graphs = state.training_graphs().unwrap();
    let graph = &graphs[..1];
    let mut store = MemoryStore::default();
    let parent = test_update(&state.model, graph, &mut 10, &mut store).unwrap();
    let candidate = test_update(&parent, graph, &mut 26, &mut store).unwrap();
    let mut engine = Engine::default();
    let weights = engine
        .intervention_weights(&parent, &candidate, &mut store)
        .unwrap();
    let coordinate = (0..weights.parameters)
        .find(|&i| {
            weights.changed(&[Span {
                start: i,
                end: i + 1,
            }]) == 1
        })
        .unwrap();
    let span = [Span {
        start: coordinate,
        end: coordinate + 1,
    }];
    let replacement = engine
        .checkpoint_intervention(&parent, &candidate, &span, &mut store)
        .unwrap();
    assert_ne!(replacement.model, parent.model);
    assert_ne!(replacement.model, candidate.model);
    let exact = engine
        .with_intervention(&parent, &candidate, &span, false, &mut store, |runtime| {
            canonical_checkpoint(
                runtime
                    .policy
                    .clone()
                    .into_record()
                    .into_bytes()
                    .map_err(record_failure)?,
            )
        })
        .unwrap();
    assert_eq!(Blob::of(&exact[..]), replacement.model.clone().unwrap());
    let runtime = Runtime::load(&replacement, &mut store).unwrap();
    assert_eq!(
        runtime.checkpoint(&replacement, 0, &mut store).unwrap(),
        replacement
    );
    let original = Runtime::load(&parent, &mut store).unwrap();
    let touched = weights.touched_ids(&span);
    assert_eq!(touched.len(), 1);
    let checked = |runtime: &Runtime| {
        burn_pack::Reader::from_bytes(runtime.optimizer.into_bytes().unwrap()).unwrap()
    };
    let old = checked(&original);
    let new = checked(&runtime);
    assert!(old.scalars().len() > new.scalars().len());
    for (name, value) in old.scalars() {
        let id = name.split('.').next().unwrap().parse::<u64>().unwrap();
        assert_eq!(
            new.scalars().get(name),
            (!touched.contains(&id)).then_some(value)
        );
    }
    let moments = |reader: burn_pack::Reader| {
        reader
            .into_tensors()
            .unwrap()
            .into_iter()
            .map(|t| {
                (
                    t.name.clone(),
                    (t.param_id.unwrap(), Blob::of(&t.into_bytes().unwrap()[..])),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let old = moments(old);
    let new = moments(new);
    assert!(new.len() < old.len());
    for (name, (id, digest)) in &old {
        if touched.contains(id) {
            assert!(!new.contains_key(name));
        } else {
            assert_eq!(new.get(name), Some(&(*id, digest.clone())));
        }
    }
    let continued = test_update(&replacement, graph, &mut 58, &mut store).unwrap();
    let reloaded = test_update(&replacement, graph, &mut 58, &mut store).unwrap();
    assert_eq!(continued, reloaded);
    assert_ne!(continued.optimizer, replacement.optimizer);
}
