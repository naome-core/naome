use super::*;
use model::Ranker;
fn decision() -> model::Decision {
    let formula = naome_foundation::Formula::equal(
        naome_foundation::FreeVariable::new(0),
        naome_foundation::FreeVariable::new(0),
    );
    model::Decision {
        goal: formula.clone(),
        context: vec![model::Binding { formula }],
        candidates: (0..3)
            .map(|_| model::Candidate {
                rule: model::Rule::DoubleNegation,
                premises: vec![0],
                consequences: vec![],
            })
            .collect(),
        expert: 0,
    }
}
fn original(
    runtime: &mut model::Runtime,
    d: &model::Decision,
    seed: &mut u64,
    explore: bool,
) -> Result<Vec<f32>, String> {
    let mut scores = runtime.scores(d)?;
    if explore && model::random(seed).is_multiple_of(5) {
        for s in &mut scores {
            *s = (model::random(seed) >> 11) as f32 / 9007199254740992.;
        }
    }
    Ok(scores)
}
#[test]
fn deferred_neural_inference_preserves_scores_draws_and_invalid_input_errors() {
    let c = model::Checkpoint::fresh();
    let mut io = tests::MemoryStore::default();
    Engine::default()
        .with(&c, &mut io, |runtime| {
            let d = decision();
            for explore in [false, true] {
                for seed in 1..33 {
                    let mut expected_seed = seed;
                    let expected = original(runtime, &d, &mut expected_seed, explore)?;
                    let mut actual = Exploring {
                        model: runtime,
                        seed,
                        explore,
                    };
                    let result = actual.scores(&d)?;
                    assert_eq!(
                        result.iter().map(|v| v.to_bits()).collect::<Vec<_>>(),
                        expected.iter().map(|v| v.to_bits()).collect::<Vec<_>>()
                    );
                    assert_eq!(actual.seed, expected_seed);
                }
            }
            let mut bad_expert = decision();
            bad_expert.expert = bad_expert.candidates.len();
            let mut bad_premise = decision();
            bad_premise.candidates[0].premises = vec![99];
            let mut too_many = decision();
            too_many.candidates = (0..17)
                .map(|_| model::Candidate {
                    rule: model::Rule::DoubleNegation,
                    premises: vec![0],
                    consequences: vec![],
                })
                .collect();
            for invalid in [&bad_expert, &bad_premise, &too_many] {
                for seed in 1..33 {
                    let mut expected_seed = seed;
                    let expected =
                        original(runtime, invalid, &mut expected_seed, true).unwrap_err();
                    let mut actual = Exploring {
                        model: runtime,
                        seed,
                        explore: true,
                    };
                    assert_eq!(actual.scores(invalid).unwrap_err(), expected);
                    assert_eq!(actual.seed, expected_seed);
                }
            }
            Ok(())
        })
        .unwrap();
}
