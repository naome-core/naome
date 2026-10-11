//! Accounting controls only; artificial vectors are not relevance evidence.
use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "naome-index-work-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn interrupted_work_consumes_original_reservation_and_cannot_be_reset() {
    let directory = Directory::new();
    let key = "ab".repeat(32);
    let cache = Cache::open(&directory.0).unwrap();
    let mut account = Account::load(&cache, &key).unwrap();
    assert_eq!(account.reserve(&cache).unwrap(), LIMIT_MS);
    drop(cache);
    let cache = Cache::open(&directory.0).unwrap();
    let mut account = Account::load(&cache, &key).unwrap();
    assert_eq!(
        (
            account.spent_ms,
            account.reserved_ms,
            account.stage.as_str()
        ),
        (LIMIT_MS, 0, "failed")
    );
    assert!(account.reserve(&cache).is_err());
    cache.collect(&Default::default()).unwrap();
    fs::remove_file(cache.accounts.join("work").join(format!("{key}.json"))).unwrap();
    assert!(
        Account::load(&cache, &key)
            .err()
            .unwrap()
            .contains("refusing allowance reset")
    );
}

#[test]
fn successful_cleanup_refunds_only_unused_original_time_and_repair_keeps_limits() {
    let directory = Directory::new();
    let key = "ac".repeat(32);
    let cache = Cache::open(&directory.0).unwrap();
    let mut account = Account::load(&cache, &key).unwrap();
    account.reserve(&cache).unwrap();
    account.unit(&cache).unwrap();
    account
        .complete(&cache, Duration::from_nanos(1_000_001), &Ok(()))
        .unwrap();
    let mut recovered = Account::load(&cache, &key).unwrap();
    assert_eq!((recovered.spent_ms, recovered.spent_units), (2, 2));
    assert_eq!(recovered.reserve(&cache).unwrap(), LIMIT_MS - 2);
    recovered
        .complete(&cache, Duration::ZERO, &Err("cleanup uncertain".into()))
        .unwrap();
    assert_eq!(Account::load(&cache, &key).unwrap().spent_ms, LIMIT_MS);
}

#[test]
fn incompatible_or_nonfinite_query_vectors_are_rejected() {
    let directory = Directory::new();
    let cache = Cache::open(&directory.0).unwrap();
    let mut vector = vec![0.; 384];
    vector[0] = 1.;
    cache.save_query("complete query", vector.clone()).unwrap();
    assert_eq!(cache.query("complete query").unwrap().unwrap(), vector);
    assert!(cache.query("different query").unwrap().is_none());
    vector[0] = f32::NAN;
    assert!(cache.save_query("complete query", vector).is_err());
}

#[test]
fn disposable_vector_loss_preserves_accounts_but_account_directory_loss_fails_closed() {
    let directory = Directory::new();
    let key = "ad".repeat(32);
    let cache = Cache::open(&directory.0).unwrap();
    let mut account = Account::load(&cache, &key).unwrap();
    account.reserve(&cache).unwrap();
    fs::remove_dir_all(&cache.root).unwrap();
    drop(cache);
    let cache = Cache::open(&directory.0).unwrap();
    assert_eq!(Account::load(&cache, &key).unwrap().spent_ms, LIMIT_MS);
    fs::remove_dir_all(&cache.accounts).unwrap();
    drop(cache);
    assert!(
        Cache::open(&directory.0)
            .err()
            .unwrap()
            .contains("refusing reset")
    );
}

#[test]
fn question_provenance_changes_cannot_renew_original_content_allowance() {
    use crate::{
        Graph,
        question::{StoredQuestion, StoredQuestionKind},
    };
    use std::collections::BTreeMap;
    let directory = Directory::new();
    let cache = Cache::open(&directory.0).unwrap();
    let graph = Graph::default();
    let question = naome_authoring::CompiledQuestion::compile("goal=all(x,eq(x,x))").unwrap();
    let make = |kind| {
        Arc::new(
            Frozen::capture(
                &graph,
                Some(BTreeMap::from([(
                    crate::hex(question.source_hash()),
                    StoredQuestion {
                        source: question.source().into(),
                        kind,
                        first: None,
                    },
                )])),
                &"00".repeat(32),
            )
            .unwrap(),
        )
    };
    let mut owner = Owner::new(Arc::new(AtomicBool::new(false)));
    owner
        .reconcile(make(StoredQuestionKind::Baseline), &cache)
        .unwrap();
    let key = owner.work.front().unwrap().key().to_owned();
    let mut account = Account::load(&cache, &key).unwrap();
    account.reserve(&cache).unwrap();
    owner
        .reconcile(make(StoredQuestionKind::Exchange), &cache)
        .unwrap();
    assert!(
        owner.work.is_empty(),
        "exhausted content must remain failed across provenance changes"
    );
    assert_eq!(Account::load(&cache, &key).unwrap().spent_ms, LIMIT_MS);
}

#[test]
fn joint_account_and_marker_loss_cannot_recreate_original_allowance() {
    let directory = Directory::new();
    let key = "ae".repeat(32);
    let cache = Cache::open(&directory.0).unwrap();
    let mut account = Account::load(&cache, &key).unwrap();
    account.reserve(&cache).unwrap();
    for bucket in ["work", "work-markers"] {
        fs::remove_file(cache.accounts.join(bucket).join(format!("{key}.json"))).unwrap();
    }
    drop(cache);
    let cache = Cache::open(&directory.0).unwrap();
    assert!(
        Account::load(&cache, &key)
            .err()
            .unwrap()
            .contains("refusing allowance reset")
    );
}
