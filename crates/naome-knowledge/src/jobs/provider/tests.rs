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
            Err(Failure::Uncertain("effect requires reconciliation".into()))
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
        Err(Failure::Uncertain(_))
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
