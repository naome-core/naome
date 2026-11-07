use super::*;
fn q(source: &str) -> ResearchQuestion {
    ResearchQuestion::from_hex(source).unwrap()
}

#[test]
fn cached_facts_match_fresh_analysis_and_do_not_cache_learned_scores() {
    let a = q("0404040301010000000201000000010301010000000101000000000101000000020100000000");
    let b = q("020404040301010000000201000000010301010000000101000000000101000000020100000000");
    let mut cache = Cache::default();
    let facts = cache.get(&a).unwrap();
    assert_eq!(facts.descriptor.features, Features::of(&a));
    assert_eq!(facts.descriptor.bindings, bindings(&a));
    assert_eq!(facts.meaningful(), super::super::semantics::meaningful(&a));
    let opposite = cache.get(&b).unwrap();
    assert!(!Arc::ptr_eq(&facts, &opposite));
    assert_eq!(
        facts.relevance(&opposite),
        super::super::semantics::relevance(&a, &b)
    );
    let mut model = super::super::Model::fresh();
    let before = model.predictions_from(&facts.descriptor);
    model.observe(&a, true, 1).unwrap();
    let after = model.predictions_from(&facts.descriptor);
    assert_ne!(before, after);
    assert_eq!(after, model.predictions(&a));
    let budget = crate::resources::adaptive::cache(
        crate::resources::active_limits().question_cache_bytes / 2,
    );
    assert!(cache.bytes <= budget);
}

#[test]
fn variable_roles_preserve_shadowing_and_independent_quantifier_scopes() {
    let a = q("040203040101000000000100000000020101000000000100000000");
    let renamed = q("040203040101000000000100000000020101000000000100000000");
    let crossed = q("040203040101000000010100000001020101000000000100000000");
    assert_eq!(bindings(&a), bindings(&renamed));
    assert_ne!(bindings(&a), bindings(&crossed));
}

#[test]
fn oversized_analysis_is_transient_under_a_small_cache_budget() {
    const TEST: &str = "frontier::finder::analysis::tests::oversized_analysis_is_transient_under_a_small_cache_budget";
    if std::env::var_os("NAOME_FINDER_ANALYSIS_CACHE_TEST").is_none() {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env("NAOME_FINDER_ANALYSIS_CACHE_TEST", "1")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let mut profile = crate::resources::ResourceProfile::default();
    profile.tuning.question_cache_bytes = Some(4096);
    crate::resources::configure(profile).unwrap();
    let question = q("04040301010000000101000000000101000000000100000001");
    let mut cache = Cache::default();
    let first = cache.get(&question).unwrap();
    let second = cache.get(&question).unwrap();
    assert!(cache.entries.is_empty());
    assert_eq!(cache.bytes, 0);
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(first.descriptor.bindings, second.descriptor.bindings);
}
