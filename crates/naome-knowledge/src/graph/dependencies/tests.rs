use super::*;
fn id(value: u8) -> ArtifactId {
    ArtifactId::from_bytes([value; 32])
}

#[test]
fn reverse_arrival_and_shared_dependencies_wake_each_edge_once() {
    let mut plan = Dependencies::default();
    for index in (1..=127).rev() {
        plan.add(id(index), &BTreeSet::from([id(index - 1)]))
            .unwrap();
    }
    assert_eq!(plan.next(None), None);
    plan.add(id(0), &BTreeSet::new()).unwrap();
    for index in 0..=127 {
        assert_eq!(plan.next(None), Some(id(index)));
        plan.finish(id(index));
        plan.finish(id(index));
    }
    assert!(plan.complete());
    assert_eq!(plan.visits(), 254);
}

#[test]
fn unknown_syntax_and_cycles_never_become_ready() {
    let mut plan = Dependencies::default();
    plan.declare(id(1));
    assert!(!plan.defined());
    plan.add(id(0), &BTreeSet::from([id(1)])).unwrap();
    assert_eq!(plan.next(None), None);
    plan.add(id(1), &BTreeSet::from([id(0)])).unwrap();
    assert!(plan.defined());
    assert_eq!(plan.next(None), None);
    assert!(!plan.complete());
}
