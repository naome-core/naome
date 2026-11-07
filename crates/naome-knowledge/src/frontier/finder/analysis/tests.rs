use super::*;
fn q(source: &str) -> CompiledQuestion {
    CompiledQuestion::compile(source).unwrap()
}

#[test]
fn cached_facts_match_fresh_analysis_and_do_not_cache_learned_scores() {
    let a = q("goal=all(a,all(b,all(c,imp(mem(a,b),imp(mem(b,c),mem(a,c))))))");
    let b = q("goal=not(all(a,all(b,all(c,imp(mem(a,b),imp(mem(b,c),mem(a,c)))))))");
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
    let a = q("goal=all(a,and(all(a,mem(a,a)),mem(a,a)))");
    let renamed = q("goal=all(x,and(all(y,mem(y,y)),mem(x,x)))");
    let crossed = q("goal=all(x,and(all(y,mem(x,x)),mem(x,x)))");
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
    let question = q("goal=all(a,all(b,imp(mem(a,b),mem(b,a))))");
    let mut cache = Cache::default();
    let first = cache.get(&question).unwrap();
    let second = cache.get(&question).unwrap();
    assert!(cache.entries.is_empty());
    assert_eq!(cache.bytes, 0);
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(first.descriptor.bindings, second.descriptor.bindings);
}
