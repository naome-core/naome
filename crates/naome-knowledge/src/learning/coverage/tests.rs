use super::*;
use crate::learning::{Evidence, Origin, State, curriculum, proof, search_question};

struct Symbolic;
impl crate::learning::model::Ranker for Symbolic {
    fn scores(&mut self, decision: &crate::learning::model::Decision) -> Result<Vec<f32>, String> {
        Ok(vec![0.; decision.candidates.len()])
    }
}

fn different(own: &Example) -> Example {
    let original = Profile::of(own).unwrap();
    for case in curriculum::CORPUS
        .cases
        .iter()
        .filter(|c| !c.development)
        .take(24)
    {
        let (solution, _) = search_question(&case.source, &mut Symbolic, 128).unwrap();
        if let Some(solution) = solution {
            let example = Example {
                origin: Origin::Local,
                job: 77,
                question: case.source.clone(),
                proof_id: solution.proof_id,
                refuted: solution.refuted,
                tree: solution.tree,
            };
            if Profile::of(&example).unwrap() != original {
                return example;
            }
        }
    }
    panic!("fixture must supply a different independently checked strategy");
}
fn stored(mut example: Example) -> (Example, Evidence) {
    let q = CompiledQuestion::compile(&example.question).unwrap();
    let steps = super::super::state::proof_steps(q.proved_target(), &example.tree).unwrap();
    let evidence = Evidence {
        job: example.job,
        proof_id: example.proof_id.clone(),
        trace: example.tree.clone(),
    };
    example.tree = search::Tree::Stored {
        coverage: Profile::of(&example).unwrap(),
        steps,
        bytes: serde_json::to_vec(&example.tree).unwrap().len(),
        binding: digest(&example.tree),
    };
    (example, evidence)
}
#[test]
fn unique_old_strategy_survives_pressure_before_an_anchor_duplicate_and_after_restore() {
    let old = crate::learning::tests::own_example();
    let duplicate = different(&old);
    let mut state = State::fresh();
    state.replay = vec![old.clone(), duplicate.clone()];
    state.anchors = vec![duplicate.clone()];
    assert!(
        Profile::losses(
            &[Profile::of(&old).unwrap()],
            &[Profile::of(&duplicate).unwrap()]
        )[0] > 0
    );
    let (stored_old, _) = stored(old.clone());
    state.replay[0] = stored_old;
    let restored: State =
        crate::checkpoint::decode(&crate::checkpoint::encode(&state).unwrap()).unwrap();
    let mut restored = restored;
    state.remove_replay().unwrap();
    restored.remove_replay().unwrap();
    assert_eq!(state.replay.len(), 1);
    assert_eq!(state.replay[0].proof_id, old.proof_id);
    assert_eq!(digest(&state), digest(&restored));
}
#[test]
fn stored_coverage_is_rederived_from_the_checked_source_before_training() {
    let own = crate::learning::tests::own_example();
    let (mut reference, evidence) = stored(own);
    reference
        .trajectory(std::slice::from_ref(&evidence))
        .unwrap();
    let search::Tree::Stored { coverage, .. } = &mut reference.tree else {
        unreachable!()
    };
    coverage.bits[0] ^= 1;
    assert!(
        reference
            .trajectory(std::slice::from_ref(&evidence))
            .unwrap_err()
            .contains("coverage binding")
    );
    let mut state = State::fresh();
    state.replay.push(reference);
    assert!(state.training_pool(&[evidence]).is_err());
}
#[test]
fn renaming_keeps_action_structure_but_changing_variable_sharing_does_not() {
    use crate::learning::model::{Binding, Candidate, Decision, Rule};
    use naome_foundation::{Formula, FreeVariable};
    fn graph(a: u32, b: u32, same: bool) -> Graph {
        let x = FreeVariable::new(a);
        let y = FreeVariable::new(b);
        let p = Formula::member(x, if same { x } else { y });
        Graph::encode(&Decision {
            context: vec![Binding { formula: p.clone() }],
            goal: p.clone(),
            candidates: vec![Candidate {
                rule: Rule::UniversalInstance,
                premises: vec![0],
                consequences: vec![p],
            }],
            expert: 0,
        })
        .unwrap()
    }
    let a = graph(3, 8, false);
    let renamed = graph(91, 70, false);
    let different = graph(3, 8, true);
    assert_eq!(
        structure(&a, &[a.candidates[0]]).unwrap(),
        structure(&renamed, &[renamed.candidates[0]]).unwrap()
    );
    assert_ne!(
        structure(&a, &[a.candidates[0]]).unwrap(),
        structure(&different, &[different.candidates[0]]).unwrap()
    );
}
#[test]
fn native_identity_corruption_cannot_supply_a_coverage_profile() {
    let mut own = crate::learning::tests::own_example();
    Profile::of(&own).unwrap();
    own.proof_id = "f2".repeat(32);
    let before = proof::checking_work().calls;
    assert!(Profile::of(&own).is_err());
    assert!(proof::checking_work().calls > before);
}

#[test]
fn coverage_filter_keeps_exact_bits_and_rejects_an_unbounded_decode() {
    use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
    let profile = Profile::of(&crate::learning::tests::own_example()).unwrap();
    let bytes = serde_json::to_vec(&profile).unwrap();
    assert_eq!(serde_json::from_slice::<Profile>(&bytes).unwrap(), profile);
    let forged = STANDARD_NO_PAD.encode(vec![0; PROFILE_BYTES + 1]);
    assert!(
        serde_json::from_value::<Profile>(serde_json::json!({"features": 1, "bits": forged}))
            .unwrap_err()
            .to_string()
            .contains("capacity")
    );
}
