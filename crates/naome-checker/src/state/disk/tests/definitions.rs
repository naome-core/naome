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

#[test]
fn definition_cache_respects_the_exact_byte_budget() {
    for fits in [false, true] {
        let (storage, state, certificate) = fixture();
        let required = 512 + 512 + certificate.canonical_bytes().len() * 64;
        let budget = if fits { required } else { required - 1 };
        let state = state
            .with_read_cache_limits(crate::ReadCacheLimits::new(1, budget).unwrap())
            .unwrap();
        let context = ReadContext::new(&state);
        for _ in 0..2 {
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
            Some(if fits { &1 } else { &2 })
        );
    }
}

#[test]
fn mixed_cached_formulas_and_definitions_keep_their_limits_and_identity() {
    let (storage, mut state, certificate) = fixture();
    let (first_id, _, _) = register_axiom(&mut state, ZfcAxiom::Pairing);
    let (second_id, _, _) = register_axiom(&mut state, ZfcAxiom::Union);
    let context = ReadContext::new(&state);
    let first_header = context.proof_header(first_id).unwrap().unwrap();
    let second_header = context.proof_header(second_id).unwrap().unwrap();
    let first = context
        .proof_formula(first_header, first_header.length)
        .unwrap()
        .unwrap();
    assert_eq!(
        context
            .resolve_definition(certificate.definition_id())
            .unwrap()
            .unwrap()
            .body(),
        certificate.body()
    );
    let second = context
        .proof_formula(second_header, second_header.length)
        .unwrap()
        .unwrap();
    let reads = storage.reads.lock().unwrap().values().sum::<usize>();
    for (header, expected) in [(first_header, &first), (second_header, &second)] {
        let cached = context
            .proof_formula(header, header.length)
            .unwrap()
            .unwrap();
        assert!(std::ptr::eq(expected.as_ref(), cached.as_ref()));
        assert!(matches!(
            context.proof_formula(header, header.length - 1),
            Err(ContextError::Limit)
        ));
    }
    assert_eq!(storage.reads.lock().unwrap().values().sum::<usize>(), reads);
}
