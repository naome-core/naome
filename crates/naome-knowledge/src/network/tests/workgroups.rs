use super::*;

#[test]
fn reordered_membership_does_not_resurrect_finished_work() {
    let peer = PeerId::random();
    let first = (peer, [1; 32], [2; 32]);
    let other = (peer, [1; 32], [3; 32]);
    let expires = Instant::now() + Duration::from_secs(10);
    let mut versions = BTreeMap::new();
    let mut members = BTreeMap::new();
    assert!(update_work_status(
        &mut versions,
        &mut members,
        first,
        2,
        false,
        expires
    ));
    assert!(!update_work_status(
        &mut versions,
        &mut members,
        first,
        1,
        true,
        expires
    ));
    assert!(!members.contains_key(&first));
    assert!(update_work_status(
        &mut versions,
        &mut members,
        other,
        1,
        true,
        expires
    ));
    assert_eq!(members.get(&other), Some(&expires));
    assert!(!update_work_status(
        &mut versions,
        &mut members,
        other,
        0,
        false,
        expires
    ));
    assert_eq!(members.get(&other), Some(&expires));
}
