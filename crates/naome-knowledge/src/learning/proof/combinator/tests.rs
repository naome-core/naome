use super::*;
use std::collections::HashMap;
fn atom() -> Formula {
    Formula::equal(FreeVariable::new(0), FreeVariable::new(0))
}
#[test]
fn independently_built_equal_dags_keep_one_emitted_identity() {
    let shared = Combinator::new(Kind::Variable(7, atom()));
    let left = Combinator::new(Kind::Apply(shared.clone(), shared, atom()));
    let right = Combinator::new(Kind::Apply(
        Combinator::new(Kind::Variable(7, atom())),
        Combinator::new(Kind::Variable(7, atom())),
        atom(),
    ));
    assert!(!Arc::ptr_eq(&left, &right));
    assert_eq!(left, right);
    let mut emitted = HashMap::new();
    emitted.insert(left, 11);
    assert_eq!(emitted.insert(right, 12), Some(11));
    assert_eq!(emitted.len(), 1);
}
#[test]
fn a_fingerprint_collision_never_merges_different_assumptions() {
    let left = Combinator::new(Kind::Variable(1, atom()));
    let mut right = Combinator::new(Kind::Variable(65, atom()));
    Arc::get_mut(&mut right).unwrap().fingerprint = left.fingerprint;
    assert_ne!(left, right);
    assert!(left.contains(1));
    assert!(!left.contains(65));
    assert!(right.contains(65));
    assert!(!right.contains(1));
    let mut emitted = HashMap::new();
    emitted.insert(left, 1);
    emitted.insert(right, 2);
    assert_eq!(emitted.len(), 2);
}
#[test]
fn hashing_a_shared_dag_does_constant_work_at_lookup() {
    #[derive(Default)]
    struct Count(usize);
    impl Hasher for Count {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, bytes: &[u8]) {
            self.0 += bytes.len();
        }
    }
    let mut root = Combinator::new(Kind::Variable(1, atom()));
    for _ in 0..100 {
        root = Combinator::new(Kind::Apply(root.clone(), root, atom()));
    }
    let mut count = Count::default();
    root.hash(&mut count);
    assert!(
        count.0 <= 16,
        "lookup hashing must not expand the shared compiler DAG"
    );
    assert!(
        !root.contains(2),
        "an absent assumption must not traverse the shared DAG"
    );
}
