use super::*;
use crate::context::cache::ReadContext;
use naome_foundation::FreeVariable;
use naome_proof::{DefinedFormula, DefinitionKind};

fn fixture() -> (Arc<MemoryStorage>, DiskArtifactState, DefinitionCertificate) {
    let storage = Arc::new(MemoryStorage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let x = FreeVariable::new(0);
    let certificate = DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap();
    state
        .register_definition(
            crate::check_definition_with_state(certificate.clone(), &state).unwrap(),
        )
        .unwrap();
    storage.reads.lock().unwrap().clear();
    (storage, state, certificate)
}

#[test]
fn definition_kind_and_expansion_share_one_authenticated_read_per_operation() {
    let (storage, state, certificate) = fixture();
    let address = definition_address(certificate.canonical_bytes());
    let context = ReadContext::new(&state);
    for _ in 0..8 {
        assert_eq!(
            context
                .definition_kind(certificate.definition_id())
                .unwrap(),
            Some(DefinitionKind::Relation { arity: 1 })
        );
        assert_eq!(
            context
                .resolve_definition(certificate.definition_id())
                .unwrap()
                .unwrap()
                .body(),
            certificate.body()
        );
    }
    assert_eq!(storage.reads.lock().unwrap().get(&address), Some(&1));
    drop(context);
    let mut records = storage.bytes.lock().unwrap();
    let bytes = records.get_mut(&address).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    drop(records);
    let context = ReadContext::new(&state);
    assert!(matches!(
        context.definition_kind(certificate.definition_id()),
        Err(ContextError::Corrupt)
    ));
    assert!(
        storage
            .failures
            .lock()
            .unwrap()
            .contains(&ContextError::Corrupt)
    );
}

#[test]
fn a_zero_read_cache_preserves_definition_results_without_retaining_reads() {
    let (storage, state, certificate) = fixture();
    let state = state
        .with_read_cache_limits(crate::ReadCacheLimits::new(0, 0).unwrap())
        .unwrap();
    let context = ReadContext::new(&state);
    for _ in 0..3 {
        assert_eq!(
            context
                .resolve_definition(certificate.definition_id())
                .unwrap()
                .unwrap()
                .body(),
            certificate.body()
        );
    }
    assert_eq!(
        storage
            .reads
            .lock()
            .unwrap()
            .get(&definition_address(certificate.canonical_bytes())),
        Some(&3)
    );
}
