//! Sealed question-only subset of the original TRAIN corpus.
//! Dependency SHA-256 buckets 0/1 are development/reserved; 2..4 learn.
use serde::{Deserialize, Serialize};
pub mod composition;
pub mod frontier;
pub mod owned;
use std::sync::LazyLock;
#[derive(Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub source: String,
    pub family: String,
    pub dependency: String,
    pub development: bool,
}
#[derive(Deserialize)]
pub struct Corpus {
    pub manifest_sha256: String,
    pub questions_sha256: String,
    pub cases: Vec<Case>,
    pub reserved_ids: Vec<String>,
}
pub static CORPUS: LazyLock<Corpus> = LazyLock::new(|| {
    let corpus: Corpus = serde_json::from_str(include_str!("curriculum.json"))
        .expect("sealed native question corpus");
    assert_eq!(
        corpus.manifest_sha256,
        "61622bc8abdc409c8cafeb8f26b9091188676d41229f55683e2a554858e314fa"
    );
    assert_eq!(
        corpus.questions_sha256,
        "ce97460843891e8b28b2fb514e322b824f161906dde2cc41df646c22c9566832"
    );
    corpus
});
pub fn learning(id: &str) -> Option<&'static Case> {
    learning_cases().find(|q| q.id == id)
}
pub fn learning_cases() -> impl Iterator<Item = &'static Case> {
    CORPUS
        .cases
        .iter()
        .filter(|q| !q.development)
        .chain(frontier::BANK.learning.iter())
        .chain(composition::BANK.learning.iter())
}
pub fn statistics_key(case: &Case) -> &str {
    if case.family.starts_with("frontier-") || case.family.starts_with("composition-") {
        &case.family
    } else {
        &case.dependency
    }
}
pub fn reserved(id: &str) -> bool {
    CORPUS
        .reserved_ids
        .binary_search_by(|s| s.as_str().cmp(id))
        .is_ok()
        || CORPUS.cases.iter().any(|q| q.id == id && q.development)
        || frontier::BANK.reserved.contains(id)
        || composition::BANK.reserved.contains(id)
        || owned::retired(id)
}
/// Extend the original eight sentinels across every development dependency.
/// Selection uses only sealed identities, never solver outcomes or labels.
pub const CORPUS_DEVELOPMENT: usize = 32;
pub const DEVELOPMENT: usize = CORPUS_DEVELOPMENT + 32 + 32;
pub fn development() -> Vec<&'static Case> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut families = BTreeSet::new();
    let mut selected: Vec<_> = CORPUS
        .cases
        .iter()
        .filter(|q| q.development && families.insert(q.dependency.clone()))
        .take(8)
        .collect();
    let mut groups: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for q in CORPUS.cases.iter().filter(|q| q.development) {
        groups.entry(&q.dependency).or_default().push(q);
    }
    for cases in groups.values_mut() {
        cases.sort_by_key(|q| &q.id);
    }
    for index in 0..groups.values().map(Vec::len).max().unwrap_or(0) {
        for cases in groups.values() {
            if let Some(q) = cases.get(index)
                && selected.len() < CORPUS_DEVELOPMENT
                && !selected.iter().any(|s| s.id == q.id)
            {
                selected.push(*q);
            }
        }
    }
    selected.extend(&frontier::BANK.development);
    selected.extend(&composition::BANK.development);
    selected
}
