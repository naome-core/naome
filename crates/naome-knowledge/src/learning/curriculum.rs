//! Sealed question-only subset of the original TRAIN corpus.
//! Dependency SHA-256 buckets 0/1 are development/reserved; 2..4 learn.
use serde::Deserialize;
use std::sync::LazyLock;
#[derive(Deserialize)]
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
    CORPUS.cases.iter().find(|q| q.id == id && !q.development)
}
pub fn reserved(id: &str) -> bool {
    CORPUS
        .reserved_ids
        .binary_search_by(|s| s.as_str().cmp(id))
        .is_ok()
        || CORPUS.cases.iter().any(|q| q.id == id && q.development)
}
pub fn development() -> Vec<&'static Case> {
    let mut families = std::collections::BTreeSet::new();
    CORPUS
        .cases
        .iter()
        .filter(|q| q.development && families.insert(q.dependency.clone()))
        .take(8)
        .collect()
}
