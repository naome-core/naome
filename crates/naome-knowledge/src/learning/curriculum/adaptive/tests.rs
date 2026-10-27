use super::*;
#[test]
fn whole_construction_families_are_frozen_disjoint_and_new_before_any_search() {
    assert_eq!(
        (
            BANK.learning.len(),
            BANK.development.len(),
            BANK.confirmation.len()
        ),
        (96, 24, 48)
    );
    assert_eq!(BANK.transfer.len(), super::super::super::transfer::CASES);
    assert_eq!(BANK.prior_confirmation.len(), 96);
    assert!(
        BANK.transfer
            .chunks_exact(2)
            .all(|q| q[0].dependency == q[1].dependency)
    );
    let parts = [
        &BANK.learning,
        &BANK.development,
        &BANK.transfer,
        &BANK.confirmation,
    ];
    for (i, a) in parts.iter().enumerate() {
        let families = a.iter().map(|q| &q.dependency).collect::<BTreeSet<_>>();
        assert_eq!(families.len() * 2, a.len());
        for b in parts.iter().skip(i + 1) {
            assert!(b.iter().all(|q| !families.contains(&q.dependency)));
        }
    }
    for q in &BANK.learning {
        assert!(super::super::owned::case(&q.source).is_some());
    }
    for q in BANK
        .development
        .iter()
        .chain(&BANK.transfer)
        .chain(&BANK.confirmation)
    {
        assert!(super::super::owned::case(&q.source).is_none());
    }
    assert!(BANK.confirmation_roots.is_disjoint(&BANK.excluded_roots));
    let previous = BANK
        .learning
        .iter()
        .chain(&BANK.development)
        .chain(&BANK.transfer)
        .chain(&BANK.prior_confirmation)
        .map(|q| &q.dependency)
        .collect::<BTreeSet<_>>();
    assert!(
        BANK.confirmation
            .iter()
            .all(|q| !previous.contains(&q.dependency))
    );
    assert!(
        BANK.prior_confirmation
            .iter()
            .all(|q| super::super::owned::case(&q.source).is_none())
    );
}
