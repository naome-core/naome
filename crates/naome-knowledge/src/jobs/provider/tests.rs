use super::*;
struct OtherProvider {
    uncertain: bool,
}
impl Provider for OtherProvider {
    fn next(&self, checkpoint: u32) -> Result<Option<u32>, Failure> {
        Ok((checkpoint < 2).then_some(checkpoint + 1))
    }
    fn execute(&mut self, _: u32, _: &mut dyn Supervisor) -> Result<(), Failure> {
        if self.uncertain {
            Err(Failure::Uncertain)
        } else {
            Ok(())
        }
    }
    fn result(&mut self, _: &mut dyn Supervisor) -> Result<Output, Failure> {
        Ok(Output::NoCandidate)
    }
}
#[derive(Default)]
struct Grants(Vec<(bool, u32)>, Vec<(Phase, Sample)>);
impl Supervisor for Grants {
    fn blocked_nanos(&self) -> u64 {
        0
    }
    fn observe(
        &mut self,
        phase: Phase,
        sample: Sample,
    ) -> Result<(), crate::outcome::WorkerFailure> {
        self.1.push((phase, sample));
        Ok(())
    }
    fn reserve(&mut self, unit: u32) -> Result<(), crate::outcome::WorkerFailure> {
        self.0.push((false, unit));
        Ok(())
    }
    fn checkpoint(&mut self, unit: u32) -> Result<(), crate::outcome::WorkerFailure> {
        self.0.push((true, unit));
        Ok(())
    }
    fn probe(&mut self, _: Probe) -> Result<(), crate::outcome::WorkerFailure> {
        Ok(())
    }
}

#[test]
fn structural_finding_finalizes_the_exact_selected_source_under_one_owned_quantum() {
    let question = "04040301010000000101000000000101000000000100000001".to_owned();
    let mut grants = Grants::default();
    let result = drive(
        &mut Finding {
            question: question.clone(),
        },
        &mut grants,
        0,
    )
    .unwrap();
    assert!(matches!(result, Output::Question(source) if source == question));
    assert_eq!(grants.0, [(false, 1), (true, 1)]);
    let invalid = "invalid";
    let expected = crate::Error::from(
        naome_checker::question::ResearchQuestion::source_requires_definitions(invalid)
            .unwrap_err(),
    );
    let failure = drive(
        &mut Finding {
            question: invalid.into(),
        },
        &mut Grants::default(),
        0,
    )
    .unwrap_err();
    assert!(matches!(failure, Failure::Coded(code) if u32::from(code) == expected.code()));
}
#[test]
fn mock_question_failures_preserve_their_code_for_each_role() {
    let invalid = "invalid";
    let expected = crate::Error::from(
        naome_checker::question::ResearchQuestion::source_requires_definitions(invalid)
            .unwrap_err(),
    );
    for input in [
        Input::Solve {
            question: invalid.into(),
        },
        Input::Select {
            question: invalid.into(),
            purpose: Purpose::Initial,
            root: None,
        },
    ] {
        let mut provider = Mock {
            input,
            work: MockWork::default(),
        };
        let failure = provider.result(&mut Grants::default()).unwrap_err();
        assert!(matches!(failure, Failure::Coded(code) if u32::from(code) == expected.code()));
    }
}

#[test]
fn structural_finding_preserves_a_definition_aware_source() {
    use naome_foundation::{Formula, FreeVariable};
    use naome_proof::{DefinedFormula, DefinitionCertificate};
    let x = FreeVariable::new(0);
    let definition = DefinitionCertificate::relation(
        1,
        DefinedFormula::from_primitive(&Formula::member(x, x)).unwrap(),
    )
    .unwrap();
    let question = DefinedFormula::for_all(
        x,
        DefinedFormula::defined_relation(definition.definition_id(), [x]),
    );
    let source = crate::hex(&question.encode_canonical_with_limits(1023, 31).unwrap().0);
    assert!(naome_checker::question::ResearchQuestion::from_hex(&source).is_err());
    let result = drive(
        &mut Finding {
            question: source.clone(),
        },
        &mut Grants::default(),
        0,
    )
    .unwrap();
    assert!(matches!(result, Output::Question(returned) if returned == source));
}

#[test]
fn another_provider_resumes_through_the_same_reservations_and_preserves_uncertainty() {
    let mut grants = Grants::default();
    assert!(matches!(
        drive(&mut OtherProvider { uncertain: false }, &mut grants, 1),
        Ok(Output::NoCandidate)
    ));
    assert_eq!(grants.0, [(false, 2), (true, 2)]);
    assert_eq!(
        grants
            .1
            .iter()
            .map(|(phase, sample)| (*phase, sample.succeeded))
            .collect::<Vec<_>>(),
        [
            (Phase::Setup, true),
            (Phase::Unit { unit: 2 }, true),
            (Phase::Finalization, true)
        ]
    );
    assert!(grants.1.iter().all(|(_, sample)| sample.blocked_nanos == 0));
    grants.0.clear();
    grants.1.clear();
    assert!(matches!(
        drive(&mut OtherProvider { uncertain: true }, &mut grants, 0),
        Err(Failure::Uncertain)
    ));
    assert_eq!(grants.0, [(false, 1)]);
    assert_eq!(
        grants
            .1
            .iter()
            .map(|(phase, sample)| (*phase, sample.succeeded))
            .collect::<Vec<_>>(),
        [(Phase::Setup, true), (Phase::Unit { unit: 1 }, false)]
    );
}

#[test]
fn supervisor_failure_survives_provider_drive() {
    struct FailedGrant;
    impl Supervisor for FailedGrant {
        fn reserve(&mut self, _: u32) -> Result<(), crate::outcome::WorkerFailure> {
            Err(crate::outcome::WorkerFailure::GrantIdentity)
        }
        fn checkpoint(&mut self, _: u32) -> Result<(), crate::outcome::WorkerFailure> {
            unreachable!()
        }
        fn probe(&mut self, _: Probe) -> Result<(), crate::outcome::WorkerFailure> {
            unreachable!()
        }
        fn blocked_nanos(&self) -> u64 {
            0
        }
        fn observe(&mut self, _: Phase, _: Sample) -> Result<(), crate::outcome::WorkerFailure> {
            Ok(())
        }
    }
    let result = drive(&mut OtherProvider { uncertain: false }, &mut FailedGrant, 0);
    assert!(
        matches!(result, Err(Failure::Coded(code)) if u32::from(code) == u32::from(crate::outcome::WorkerFailure::GrantIdentity))
    );
}

#[test]
fn mock_provider_rejects_native_jobs_with_a_registered_code() {
    let mut provider = Mock {
        input: Input::Train {
            epoch: 1,
            requalify: None,
        },
        work: MockWork::default(),
    };
    let failure = provider.result(&mut Grants::default()).unwrap_err();
    assert!(
        matches!(failure, Failure::Coded(code) if u32::from(code) == u32::from(crate::WorkerFailure::NativeProviderRequired))
    );
}
