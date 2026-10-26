use super::*;
use crate::{ContextError, ContextStorage, DiskArtifactState};
use naome_proof::program::Command;
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Default)]
struct Storage {
    bytes: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
    corrupt: AtomicBool,
}
impl ContextStorage for Storage {
    fn read(&self, key: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        if self.corrupt.load(Ordering::Relaxed) {
            return Err(ContextError::Corrupt);
        }
        let bytes = self
            .bytes
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or(ContextError::Corrupt)?;
        if bytes.len() > maximum {
            return Err(ContextError::Limit);
        }
        Ok(bytes)
    }
    fn write(&self, key: [u8; 32], value: &[u8]) -> Result<(), ContextError> {
        let mut bytes = self.bytes.lock().unwrap();
        if bytes.get(&key).is_some_and(|old| old != value) {
            return Err(ContextError::Corrupt);
        }
        bytes.insert(key, value.to_vec());
        Ok(())
    }
}

fn finish(mut engine: Engine, context: &dyn ContextView) -> CheckedProgram {
    while engine.advance(97, 32768, context).unwrap() {}
    loop {
        match engine.prepare_export(97) {
            Ok(true) => break,
            Ok(false) => {}
            Err(error) => {
                let integrity = |schema: &str| {
                    engine.connection.query_row(
                        &format!("PRAGMA {schema}.quick_check"),
                        [],
                        |row| row.get::<_, String>(0),
                    )
                };
                panic!(
                    "export failed: {error:?}; sqlite={}; status={:?}; main={:?}; temp={:?}",
                    rusqlite::version(),
                    engine.status(),
                    integrity("main"),
                    integrity("temp")
                );
            }
        }
    }
    engine.checked().unwrap()
}

fn register(state: &mut DiskArtifactState, proof: &CheckedProgram) {
    let mut registration = state.begin_program_registration(proof).unwrap();
    while !registration.complete() {
        registration.advance(proof, 31).unwrap();
    }
    *state = registration.finish().unwrap();
}

fn large_proof(implication: bool) -> CheckedProgram {
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append(&Command::Reflexivity { variable: 0 })
        .unwrap();
    engine
        .append(&Command::Generalization {
            premise: 0,
            variable: 0,
        })
        .unwrap();
    let mut root = 1;
    for _ in 0..520 {
        root = engine
            .append(&Command::Generalization {
                premise: root,
                variable: 1,
            })
            .unwrap();
    }
    if implication {
        let axiom = engine
            .append(&Command::Simplification {
                antecedent: 1,
                consequent: root,
            })
            .unwrap();
        root = engine
            .append(&Command::ModusPonens {
                premise: 1,
                implication: axiom,
            })
            .unwrap();
    }
    engine.append(&Command::Seal { proof: root }).unwrap();
    finish(engine, &ArtifactState::new())
}

#[test]
fn programs_compose_large_checked_lemmas_into_a_small_conclusion_in_bounded_quanta() {
    compose(false);
}

#[test]
fn cache_reductions_and_growth_preserve_live_citations_and_export() {
    compose(true);
}

fn compose(changing_budget: bool) {
    let mut state = DiskArtifactState::new(Arc::new(Storage::default()));
    let premise = large_proof(false);
    let implication = large_proof(true);
    assert!(premise.conclusion().is_none() && implication.conclusion().is_none());
    register(&mut state, &premise);
    register(&mut state, &implication);
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::ProofReference {
                proof_id: *premise.manifest().proof_id().as_bytes(),
            },
            Command::ProofReference {
                proof_id: *implication.manifest().proof_id().as_bytes(),
            },
            Command::ModusPonens {
                premise: 0,
                implication: 1,
            },
            Command::Seal { proof: 2 },
        ])
        .unwrap();
    let mut steps = 0;
    loop {
        let before = engine.status().unwrap().formula_nodes;
        let cache = if changing_budget && steps % 16 >= 8 {
            32768
        } else {
            4096
        };
        let progressed = engine.advance(1, cache, &state).unwrap();
        assert!(
            engine.status().unwrap().formula_nodes - before <= 1,
            "one quantum cannot materialize the whole cited DAG"
        );
        steps += 1;
        assert!(
            steps < 5000,
            "shared imported nodes must not be walked exponentially"
        );
        if !progressed {
            break;
        }
    }
    assert!(steps > 520);
    let proof = finish(engine, &state);
    assert_eq!(proof.manifest().commands, 4);
    let expected = naome_foundation::Formula::for_all(
        naome_foundation::FreeVariable::new(0),
        naome_foundation::Formula::equal(
            naome_foundation::FreeVariable::new(0),
            naome_foundation::FreeVariable::new(0),
        ),
    );
    assert_eq!(proof.conclusion(), Some(&expected));
    let first = proof.dependencies_after(None, 1).unwrap();
    let second = proof
        .dependencies_after(Some(first[0].proof_id()), 1)
        .unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert!(
        proof
            .dependencies_after(Some(second[0].proof_id()), 1)
            .unwrap()
            .is_empty()
    );
    let empty = DiskArtifactState::new(Arc::new(Storage::default()));
    let mut rejected = empty.begin_program_registration(&proof).unwrap();
    assert!(matches!(
        rejected.advance(&proof, 1),
        Err(crate::ArtifactStateError::MissingProofDependency { .. })
    ));
    register(&mut state, &proof);
    assert_eq!(
        state
            .proof_dependency_depth(proof.manifest().proof_id())
            .unwrap(),
        Some(2)
    );
}

#[test]
fn program_citations_resolve_checker_validated_certificate_proofs() {
    let normal = naome_proof::ProofCertificate::new(vec![
        naome_proof::ProofStep::EqualityReflexivity {
            variable: naome_foundation::FreeVariable::new(0),
        },
        naome_proof::ProofStep::Generalization {
            premise: 0,
            variable: naome_foundation::FreeVariable::new(0),
        },
    ])
    .unwrap()
    .into_unchecked_normal_form();
    let checked = crate::check_normal_form_with_state(normal, &ArtifactState::new()).unwrap();
    let id = checked.proof_id();
    let expected = checked.conclusion().clone();
    let mut state = ArtifactState::new();
    let _ = state.register_proof_for_replication(checked).unwrap();
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::ProofReference {
                proof_id: *id.as_bytes(),
            },
            Command::Seal { proof: 0 },
        ])
        .unwrap();
    let proof = finish(engine, &state);
    assert_eq!(proof.conclusion(), Some(&expected));
    assert!(proof.references_proof(id).unwrap());
}

#[test]
fn saved_proved_results_cannot_restore_citation_authority_after_reopen() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "naome-program-reference-{}-{}.sqlite3",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut state = DiskArtifactState::new(Arc::new(Storage::default()));
    let parent = large_proof(false);
    register(&mut state, &parent);
    let mut engine = Engine::open(Connection::open(&path).unwrap()).unwrap();
    engine
        .append_group(&[
            Command::ProofReference {
                proof_id: *parent.manifest().proof_id().as_bytes(),
            },
            Command::Seal { proof: 0 },
        ])
        .unwrap();
    while engine.advance(97, 32768, &state).unwrap() {}
    assert!(engine.status().unwrap().fully_checked);
    drop(engine);
    let mut reopened = Engine::open(Connection::open(&path).unwrap()).unwrap();
    assert!(!reopened.status().unwrap().fully_checked);
    assert!(
        matches!(reopened.advance(97, 32768, &ArtifactState::new()), Err(Error::Check(diagnostic)) if matches!(diagnostic.failure, crate::diagnostics::Failure::MissingProof { proof_id } if proof_id.0 == *parent.manifest().proof_id().as_bytes()))
    );
    assert!(!reopened.status().unwrap().fully_checked);
    let replayed = finish(reopened, &state);
    assert!(replayed.conclusion().is_none());
    drop(replayed);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn corrupt_cited_context_never_yields_a_proved_program_result() {
    let storage = Arc::new(Storage::default());
    let mut state = DiskArtifactState::new(storage.clone());
    let parent = large_proof(false);
    register(&mut state, &parent);
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::ProofReference {
                proof_id: *parent.manifest().proof_id().as_bytes(),
            },
            Command::Seal { proof: 0 },
        ])
        .unwrap();
    storage.corrupt.store(true, Ordering::Relaxed);
    assert!(matches!(
        engine.advance(1, 4096, &state),
        Err(Error::Context(ContextError::Corrupt))
    ));
    assert!(!engine.status().unwrap().fully_checked);
}

#[test]
fn definition_expansion_cannot_mint_proof_authority_or_hide_missing_selected_state() {
    use naome_proof::{DefinedFormula, DefinitionCertificate};
    let storage = Arc::new(Storage::default());
    let mut context = DiskArtifactState::new(storage.clone());
    let x = naome_foundation::FreeVariable::new(0);
    let certificate = DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap();
    let id = certificate.definition_id();
    context
        .register_definition(crate::check_definition_with_state(certificate, &context).unwrap())
        .unwrap();
    let command = Command::DefinedRelation {
        definition_id: *id.as_bytes(),
        arguments: vec![0],
    };
    let mut unproved = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    unproved
        .append_group(&[command.clone(), Command::Seal { proof: 0 }])
        .unwrap();
    assert!(
        matches!(unproved.advance(97,32768,&context),Err(Error::Check(error))
        if matches!(error.failure,crate::diagnostics::Failure::InputNotProved { .. }))
    );
    let mut missing = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    missing.append(&command).unwrap();
    assert!(
        matches!(missing.advance(97,32768,&ArtifactState::new()),Err(Error::Check(error))
        if matches!(error.failure,crate::diagnostics::Failure::Expansion { reason: crate::diagnostics::ExpansionFailure::UnknownDefinition { .. } }))
    );
    storage.corrupt.store(true, Ordering::Relaxed);
    assert!(matches!(
        context.definition_kind(id),
        Err(ContextError::Corrupt)
    ));
    assert!(matches!(
        missing.advance(97, 32768, &context),
        Err(Error::Context(ContextError::Corrupt))
    ));
}

#[test]
fn checked_program_definition_dependencies_are_revalidated_at_registration() {
    use naome_proof::{DefinedFormula, DefinitionCertificate};
    let storage = Arc::new(Storage::default());
    let mut context = DiskArtifactState::new(storage);
    let x = naome_foundation::FreeVariable::new(0);
    let certificate = DefinitionCertificate::relation(1, DefinedFormula::equal(x, x)).unwrap();
    let id = certificate.definition_id();
    context
        .register_definition(crate::check_definition_with_state(certificate, &context).unwrap())
        .unwrap();
    let mut engine = Engine::open(Connection::open_in_memory().unwrap()).unwrap();
    engine
        .append_group(&[
            Command::DefinedRelation {
                definition_id: *id.as_bytes(),
                arguments: vec![0],
            },
            Command::Separation {
                predicate: 0,
                element: 0,
                source: 1,
                result: 2,
            },
            Command::Seal { proof: 1 },
        ])
        .unwrap();
    let checked = finish(engine, &context);
    assert_eq!(
        checked.definition_dependencies_after(None, 1).unwrap(),
        [id]
    );
    let empty = DiskArtifactState::new(Arc::new(Storage::default()));
    let mut registration = empty.begin_program_registration(&checked).unwrap();
    assert!(
        matches!(registration.advance(&checked,31),Err(crate::ArtifactStateError::MissingDefinitionDependency { definition_id }) if definition_id==id)
    );
    register(&mut context, &checked);
    assert!(
        context
            .contains_proof(checked.manifest().proof_id())
            .unwrap()
    );
}
