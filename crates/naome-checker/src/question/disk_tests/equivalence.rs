use super::*;

#[test]
fn elementary_equivalence_index_matches_ram_survives_copy_and_never_hides_read_failure() {
    let files = Files::new();
    let target_storage = Files::new();
    let state = ArtifactState::new();
    let a = unresolved();
    let x = FreeVariable::new(0);
    let b = Formula::for_all(x, Formula::negate(Formula::member(x, x)));
    let query = Formula::implies(a.clone(), Formula::negate(b.clone()));
    let related = Formula::for_all(var(17), Formula::implies(b, Formula::negate(a)));
    let mut memory = QuestionRegistry::new();
    let mut disk = QuestionRegistry::with_storage(files.clone());
    for registry in [&mut memory, &mut disk] {
        registry
            .insert(RegisteredQuestion::new([1; 32], &related).unwrap())
            .unwrap();
    }
    let request =
        AssessmentQuestion::new(FOUNDATION_ID, &query, b"cold equivalence", &[], None).unwrap();
    let assess = |registry| {
        assess_question(
            &request,
            &KnowledgeSnapshot::new([7; 32], &state, registry),
            &PrefilterPolicy::default(),
        )
    };
    let expected = assess(&memory);
    assert_eq!(expected.reason, Some(RejectionReason::ProvenEquivalent));
    assert_eq!(assess(&disk), expected);
    let mut copy = disk.begin_copy(target_storage.clone()).unwrap();
    loop {
        if copy
            .advance(crate::DiskCopyBudget {
                records: 3,
                bytes: 4096,
            })
            .unwrap()
            .complete
        {
            break;
        }
    }
    let copied = copy.finish(&disk).unwrap();
    assert_eq!(assess(&copied), expected);
    *target_storage.remaining.lock().unwrap() = Some(0);
    let failed = assess(&copied);
    assert!(failed.inconclusive());
    assert!(failed.novelty().is_none());
    assert!(failed.equivalence.is_none());
    assert!(!target_storage.failures.lock().unwrap().is_empty());
}
