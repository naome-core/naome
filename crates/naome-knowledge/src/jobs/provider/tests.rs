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
    fn observe(&mut self, phase: Phase, sample: Sample) -> Result<(), String> {
        self.1.push((phase, sample));
        Ok(())
    }
    fn reserve(&mut self, unit: u32) -> Result<(), String> {
        self.0.push((false, unit));
        Ok(())
    }
    fn checkpoint(&mut self, unit: u32) -> Result<(), String> {
        self.0.push((true, unit));
        Ok(())
    }
    fn probe(&mut self, _: Probe) -> Result<(), String> {
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
    assert!(
        drive(
            &mut Finding {
                question: "invalid".into()
            },
            &mut Grants::default(),
            0
        )
        .is_err()
    );
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
