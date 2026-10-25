use super::*;

fn input(index: usize) -> CompiledQuestion {
    CompiledQuestion::compile(&format!(
        "goal=all(x,{}mem(x,x){})",
        "not(".repeat(index),
        ")".repeat(index)
    ))
    .unwrap()
}

#[test]
fn alternating_questions_reuse_complete_decisions_and_fresh_admission_recomputes() {
    let graph = Graph::default();
    let mut local = LocalQuestions::new(Some(|_| async { Ok(true) }));
    for _ in 0..3 {
        for index in 0..8 {
            assert!(local.assess(&graph, &input(index)).passed());
        }
    }
    assert_eq!(local.computation_count(), 8);
    let selected = input(0);
    assert!(local.evaluate(&graph, &selected, false).passed());
    assert_eq!(local.computation_count(), 9);
    assert!(local.assess(&graph, &selected).passed());
    assert_eq!(local.computation_count(), 9);
}

#[test]
fn byte_limit_evicts_least_recent_use_and_live_reduction_releases_entries() {
    let graph = Graph::default();
    let mut local = LocalQuestions::new(Some(|_| async { Ok(true) }));
    let decisions: Vec<_> = (0..3)
        .map(|index| local.assess(&graph, &input(index)))
        .collect();
    let mut cache = DecisionCache::default();
    cache.insert(&decisions[0], usize::MAX);
    let per_entry = cache.bytes;
    let maximum = 2 * per_entry;
    cache.insert(&decisions[1], maximum);
    let first = input(0);
    let request = AssessmentQuestion::new(
        FOUNDATION_ID,
        first.core(),
        first.source().as_bytes(),
        &[],
        None,
    )
    .unwrap();
    assert!(
        cache
            .get(&request, &local.snapshot(&graph), &local.policy)
            .is_some()
    );
    cache.insert(&decisions[2], maximum);
    assert_eq!(cache.entries.len(), 2);
    assert_eq!(cache.entries.front().unwrap().decision, decisions[0]);
    assert_eq!(cache.entries.back().unwrap().decision, decisions[2]);
    assert!(cache.bytes <= maximum);
    cache.trim(per_entry);
    assert_eq!(cache.entries.len(), 1);
    assert_eq!(cache.entries.front().unwrap().decision, decisions[2]);
    cache.trim(0);
    assert_eq!(cache.bytes, 0);
    assert_eq!(cache.entries.capacity(), 0);
    cache.insert(&decisions[0], per_entry - 1);
    assert!(cache.entries.is_empty());
}

#[test]
fn certificate_payloads_are_charged_before_the_cache_clones_them() {
    let graph = Graph::default();
    let mut local = LocalQuestions::new(Some(|_| async { Ok(true) }));
    let existing =
        CompiledQuestion::compile("goal=and(all(x,mem(x,x)),all(y,not(mem(y,y))))").unwrap();
    local
        .registry
        .insert(RegisteredQuestion::new([1; 32], existing.core()).unwrap())
        .unwrap();
    let exchanged =
        CompiledQuestion::compile("goal=and(all(y,not(mem(y,y))),all(x,mem(x,x)))").unwrap();
    let result = local.assess(&graph, &exchanged);
    assert_eq!(result.reason, Some(RejectionReason::ProvenEquivalent));
    let certificates = result.equivalence.as_ref().unwrap();
    let payload = certificates
        .iter()
        .map(retained_witness_bytes)
        .sum::<usize>();
    let mut cache = DecisionCache::default();
    cache.insert(&result, usize::MAX);
    assert!(cache.bytes >= payload + std::mem::size_of::<Entry>());
    let required = cache.bytes;
    cache.clear();
    cache.insert(&result, required - 1);
    assert!(cache.entries.is_empty());
    assert_eq!(cache.bytes, 0);
    cache.insert(&result, required);
    assert_eq!(cache.bytes, required);
    assert_eq!(cache.entries.len(), 1);
}
