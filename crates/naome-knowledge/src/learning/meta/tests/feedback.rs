//! Physical-work feedback must not change the learned quality representation.
use super::*;

#[test]
fn cpu_feedback_changes_cost_without_changing_value_or_risk_learning() {
    let mut cheap = experience(700, Plan::mixture(), 24, 60);
    cheap.context[CONTEXT - 1] = 100;
    cheap.lower_cpu_micros = 9_000_000;
    let mut costly = cheap.clone();
    costly.context[CONTEXT - 1] = 900;
    costly.lower_cpu_micros = 162_000_000;
    assert_eq!(&cheap.targets()[..2], &costly.targets()[..2]);
    let mut a = model::Network::fresh(181);
    let mut b = a.clone();
    for _ in 0..64 {
        a.update(&[&cheap]).unwrap();
        b.update(&[&costly]).unwrap();
        assert_eq!(&a.weights[..model::COST], &b.weights[..model::COST]);
        assert_eq!(&a.first[..model::COST], &b.first[..model::COST]);
        assert_eq!(&a.second[..model::COST], &b.second[..model::COST]);
        let qa = a.forward(&cheap.features()).1;
        let qb = b.forward(&costly.features()).1;
        assert_eq!(qa[..2], qb[..2]);
    }
    let a = a.forward(&cheap.features()).1;
    let b = b.forward(&costly.features()).1;
    assert!(b[2] > a[2] + 0.2, "measured cost remains a learned target");
    const {
        assert!(
            PARAMETERS <= 759,
            "preserve the original parameter envelope"
        );
    }
}

#[test]
fn a_cost_only_observation_has_no_quality_gradient() {
    let mut e = experience(400, Plan::targeted(), 30, 30);
    e.candidate_model = None;
    e.transfer = super::super::super::transfer::Summary {
        before: 0,
        after: 0,
        observed: 0,
    };
    e.validate().unwrap();
    let network = model::Network::fresh(191);
    let (_, gradient) = network.gradient(&e);
    assert!(gradient[..model::COST].iter().all(|g| *g == 0.));
    assert!(gradient[model::COST..].iter().any(|g| *g != 0.));
    let changed = Experience {
        lower_cpu_micros: 150_000_000,
        ..e
    };
    let (_, other) = network.gradient(&changed);
    assert_eq!(&gradient[..model::COST], &other[..model::COST]);
    assert_ne!(&gradient[model::COST..], &other[model::COST..]);
}
