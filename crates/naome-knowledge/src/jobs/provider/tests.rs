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
struct Grants(Vec<(bool, u32)>);
impl Supervisor for Grants {
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
    grants.0.clear();
    assert!(matches!(
        drive(&mut OtherProvider { uncertain: true }, &mut grants, 0),
        Err(Failure::Uncertain(_))
    ));
    assert_eq!(grants.0, [(false, 1)]);
}
