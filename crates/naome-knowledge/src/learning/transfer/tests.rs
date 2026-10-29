use super::*;
fn summary(pairs: &[(bool, bool)]) -> Summary {
    let mut s = Summary::default();
    for index in 0..CASES {
        let (before, after) = pairs.get(index).copied().unwrap_or((false, false));
        s.record(index, before, after).unwrap();
    }
    s
}
#[test]
fn aggregate_gain_cannot_hide_a_lost_whole_family() {
    let s = summary(&[(true, false), (false, false), (false, true), (false, true)]);
    assert!(s.gain() > 0.);
    assert_eq!(s.families()[0], [1, 0]);
    assert_eq!(s.families()[1], [0, 2]);
    assert!(!s.accepts());
    let retained = summary(&[(true, true), (false, false), (false, true), (false, false)]);
    assert!(retained.accepts());
    assert!(!summary(&[(true, true)]).accepts());
}
#[test]
fn incomplete_or_duplicate_observations_cannot_qualify() {
    let mut s = Summary::default();
    s.record(0, false, true).unwrap();
    assert!(!s.accepts());
    assert!(s.record(0, false, true).is_err());
    assert!(s.record(2, false, true).is_err());
    s.observed |= 1 << CASES;
    assert!(s.validate().is_err());
    assert!(
        Summary {
            before: 1,
            ..Summary::default()
        }
        .validate()
        .is_err()
    );
}
