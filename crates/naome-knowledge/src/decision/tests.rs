use super::*;

fn request() -> Request {
    Request {
        state: "local state".into(),
        instruction: "Choose a category.".into(),
        alternatives: ["one", "two"]
            .into_iter()
            .map(|id| Alternative {
                id: id.into(),
                description: id.into(),
            })
            .collect(),
    }
}

#[test]
fn responses_require_the_exact_request_model_options_and_a_real_distribution() {
    let request = request();
    let mut result = Distribution {
        request: request.identity(),
        model: "model".into(),
        probabilities: vec![
            Probability {
                option: "one".into(),
                probability: 0.9,
            },
            Probability {
                option: "two".into(),
                probability: 0.1,
            },
        ],
        input_tokens: 10,
        elapsed_ms: 2,
        peak_rss_bytes: 100,
        accelerator_bytes: 0,
        truncated: false,
    };
    result.validate(&request, "model").unwrap();
    let mut changed = request.clone();
    changed.state.push('x');
    assert!(result.validate(&changed, "model").is_err());
    assert!(result.validate(&request, "another model").is_err());
    for probability in [f64::NAN, f64::INFINITY, -0.1, 1.1, 0.4] {
        result.probabilities[0].probability = probability;
        assert!(result.validate(&request, "model").is_err());
    }
    result.probabilities[0].probability = 0.9;
    result.probabilities.swap(0, 1);
    assert!(result.validate(&request, "model").is_err());
    result.probabilities.pop();
    assert!(result.validate(&request, "model").is_err());
}

#[test]
fn duplicate_options_and_unbounded_input_never_reach_an_adapter() {
    let mut request = request();
    request.alternatives[1].id = "one".into();
    assert!(request.validate().is_err());
    request.alternatives[1].id = "two".into();
    request.state = "λ".repeat(MAX_STATE_BYTES);
    assert!(request.validate().is_err());
}
