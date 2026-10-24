use super::*;
use naome_foundation::Formula;
use std::sync::atomic::{AtomicU64, Ordering};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "naome-proof-work-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("proof.sqlite3")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn budget() -> Budget {
    Budget {
        memory_bytes: 8 * 1024 * 1024,
        concurrency: 1,
        cache_bytes: 4096,
        batch_steps: 37,
        network_requests: 1,
        yield_ms: 0,
        paused: None,
    }
}
fn finish(work: &mut Work) -> Status {
    let budget = budget();
    for _ in 0..100_000 {
        if !work.advance(&budget).unwrap() {
            return work.status().unwrap();
        }
    }
    panic!("proof processing did not terminate");
}
fn identity(work: &mut Work) {
    work.append(&Command::Reflexivity { variable: 0 }).unwrap();
    work.append(&Command::Generalization {
        premise: 0,
        variable: 0,
    })
    .unwrap();
    work.append(&Command::Seal { proof: 1 }).unwrap();
}

#[test]
fn closed_generalization_does_not_repeat_the_whole_growing_transformation() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::Reflexivity { variable: 0 }).unwrap();
    work.append(&Command::Generalization {
        premise: 0,
        variable: 0,
    })
    .unwrap();
    for position in 2..2048 {
        work.append(&Command::Generalization {
            premise: position - 1,
            variable: 1,
        })
        .unwrap();
    }
    work.append(&Command::Seal { proof: 1 }).unwrap();
    let status = finish(&mut work);
    assert!(status.fully_checked && status.formula_nodes >= 2048);
    assert!(
        status.transformation_equations <= 2 * status.commands,
        "closed input must not create quadratic transformation history"
    );
    drop(work);
    let mut work = Work::open(&directory.path()).unwrap();
    assert!(!work.status().unwrap().fully_checked);
    assert!(finish(&mut work).fully_checked);
}

#[test]
fn native_disk_pressure_preserves_the_retryable_outcome_and_committed_prefix() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::Reflexivity { variable: 0 }).unwrap();
    crate::resources::with_disk_available(0, || {
        assert!(matches!(
            work.append(&Command::Generalization {
                premise: 0,
                variable: 0
            }),
            Err(crate::Error::DiskOverload { .. })
        ));
        assert!(matches!(
            work.advance(&budget()),
            Err(crate::Error::DiskOverload { .. })
        ));
        assert_eq!(work.status().unwrap().commands, 1);
        assert_eq!(work.status().unwrap().committed_commands, 0);
    });
    work.append(&Command::Generalization {
        premise: 0,
        variable: 0,
    })
    .unwrap();
    work.append(&Command::Seal { proof: 1 }).unwrap();
    assert!(finish(&mut work).fully_checked);
}

#[test]
fn committed_prefix_is_rechecked_after_reopen_without_trusting_proved_flags() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    identity(&mut work);
    let first = finish(&mut work);
    assert!(first.fully_checked);
    assert_eq!(first.checked_commands, 3);
    assert!(work.append(&Command::Reflexivity { variable: 1 }).is_err());
    drop(work);
    let mut work = Work::open(&directory.path()).unwrap();
    let before = work.status().unwrap();
    assert_eq!(before.committed_commands, 3);
    assert_eq!(before.checked_commands, 0);
    assert!(!before.fully_checked);
    let again = finish(&mut work);
    assert!(again.fully_checked);
    assert_eq!(again.conclusion, first.conclusion);
}

#[test]
fn repeated_generalization_of_closed_subgraphs_adds_only_linear_work_and_replays() {
    for binders in [32_u64, 64, 128, 256] {
        let directory = Directory::new();
        let mut work = Work::open(&directory.path()).unwrap();
        let mut commands = vec![Command::Reflexivity { variable: 0 }];
        for premise in 0..binders {
            commands.push(Command::Generalization {
                premise,
                variable: 0,
            });
        }
        commands.push(Command::Seal { proof: binders });
        work.append_group(&commands).unwrap();
        let status = finish(&mut work);
        assert!(status.fully_checked);
        println!(
            "generalizations={binders} nodes={} equations={}",
            status.formula_nodes, status.transformation_equations
        );
        assert!(
            status.transformation_equations <= 2 * binders,
            "{binders} generalizations require only linear transformation evidence, got {}",
            status.transformation_equations,
        );
        // The first binder captures the free variable. All later binders are
        // vacuous and must preserve the exact existing bound-variable graph.
        let variable = naome_foundation::FreeVariable::new(0);
        let mut expected = Formula::equal(variable, variable);
        for _ in 0..binders {
            expected = Formula::for_all(variable, expected);
        }
        assert_eq!(
            status.conclusion,
            Some(crate::hex(&naome_proof::program::formula_hash(&expected)))
        );
        drop(work);
        let mut work = Work::open(&directory.path()).unwrap();
        assert!(!work.status().unwrap().fully_checked);
        let replay = finish(&mut work);
        assert!(replay.fully_checked);
        assert_eq!(replay.conclusion, status.conclusion);
        assert_eq!(
            replay.transformation_equations,
            status.transformation_equations
        );
    }
}

#[test]
fn pressure_pauses_mid_transformation_and_resumes_every_mathematical_step() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    identity(&mut work);
    let mut quantum = budget();
    quantum.batch_steps = 1;
    for _ in 0..4 {
        assert!(work.advance(&quantum).unwrap());
    }
    let before = work.status().unwrap();
    assert!(!before.fully_checked);
    let mut paused = quantum.clone();
    paused.paused = Some("memory pressure".into());
    paused.batch_steps = 0;
    assert!(!work.advance(&paused).unwrap());
    let after = work.status().unwrap();
    assert_eq!(after.checked_commands, before.checked_commands);
    assert_eq!(
        after.transformation_equations,
        before.transformation_equations
    );
    drop(work);
    let mut work = Work::open(&directory.path()).unwrap();
    assert!(finish(&mut work).fully_checked);
}

#[test]
fn formula_tree_depth_and_program_work_can_exceed_certificate_limits() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    let mut root = work.append(&Command::Equal { left: 0, right: 0 }).unwrap();
    // Sharing doubles the expanded tree at every command. No expanded tree,
    // total formula-node count or cumulative checker-work cap is allocated.
    for _ in 0..300 {
        root = work
            .append(&Command::Implies {
                antecedent: root,
                consequent: root,
            })
            .unwrap();
    }
    let theorem = work
        .append(&Command::Simplification {
            antecedent: root,
            consequent: root,
        })
        .unwrap();
    let closed = work
        .append(&Command::Generalization {
            premise: theorem,
            variable: 0,
        })
        .unwrap();
    work.append(&Command::Seal { proof: closed }).unwrap();
    let status = finish(&mut work);
    assert!(status.fully_checked);
    assert!(status.formula_nodes > u64::from(naome_foundation::FORMULA_MAX_DEPTH));
    assert!(status.database_bytes > budget().cache_bytes * 8);
    assert!(status.transformation_equations > 300);
}

#[test]
fn formulas_cannot_be_promoted_to_proofs_or_invalid_mp_hidden_by_sealing() {
    for commands in [
        vec![
            Command::Equal { left: 0, right: 0 },
            Command::Seal { proof: 0 },
        ],
        vec![
            Command::Reflexivity { variable: 0 },
            Command::ModusPonens {
                premise: 0,
                implication: 0,
            },
            Command::Seal { proof: 0 },
        ],
        vec![
            Command::Reflexivity { variable: 0 },
            Command::Seal { proof: 0 },
        ],
        vec![Command::Generalization {
            premise: 0,
            variable: 0,
        }],
    ] {
        let directory = Directory::new();
        let mut work = Work::open(&directory.path()).unwrap();
        for command in commands {
            work.append(&command).unwrap();
        }
        assert!(work.advance(&budget()).is_err());
        assert!(!work.status().unwrap().fully_checked);
    }
}

#[test]
fn malformed_custom_boundaries_and_false_saved_equations_fail_closed() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    identity(&mut work);
    finish(&mut work);
    drop(work);
    let connection = Connection::open(directory.path()).unwrap();
    connection.execute("UPDATE equation SET result=(SELECT node FROM result WHERE position=1) WHERE sequence=(SELECT min(sequence) FROM equation)",[]).unwrap();
    drop(connection);
    let mut work = Work::open(&directory.path()).unwrap();
    assert!(work.advance(&budget()).is_err());
    assert!(!work.status().unwrap().fully_checked);
}

#[test]
fn schema_freshness_is_checked_across_disk_traversals() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::Equal { left: 2, right: 2 }).unwrap();
    work.append(&Command::Separation {
        predicate: 0,
        element: 0,
        source: 1,
        result: 2,
    })
    .unwrap();
    let mut rejected = false;
    for _ in 0..100 {
        match work.advance(&budget()) {
            Err(e) => {
                assert!(e.contains("freshness"));
                rejected = true;
                break;
            }
            Ok(false) => break,
            _ => {}
        }
    }
    assert!(rejected);
    assert!(!work.status().unwrap().fully_checked);
}

#[test]
fn owner_and_immutable_nodes_reject_concurrent_writers_and_corruption() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    identity(&mut work);
    assert!(Work::open(&directory.path()).is_err());
    finish(&mut work);
    let connection = Connection::open(directory.path()).unwrap();
    connection
        .execute("UPDATE node SET free=0 WHERE id=1", [])
        .unwrap();
    drop(connection);
    assert!(work.status().is_err());
    drop(work);
    let mut work = Work::open(&directory.path()).unwrap();
    assert!(work.advance(&budget()).is_err());
}

#[test]
fn modus_ponens_crosses_committed_module_boundaries_and_checks_exact_antecedents() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::Reflexivity { variable: 0 }).unwrap();
    work.append(&Command::Generalization {
        premise: 0,
        variable: 0,
    })
    .unwrap();
    work.append(&Command::Simplification {
        antecedent: 1,
        consequent: 1,
    })
    .unwrap();
    assert_eq!(finish(&mut work).checked_commands, 3);
    drop(work);
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::ModusPonens {
        premise: 1,
        implication: 2,
    })
    .unwrap();
    work.append(&Command::ModusPonens {
        premise: 1,
        implication: 3,
    })
    .unwrap();
    work.append(&Command::Seal { proof: 4 }).unwrap();
    let status = finish(&mut work);
    assert!(status.fully_checked);
    let expected = Formula::for_all(
        naome_foundation::FreeVariable::new(0),
        Formula::equal(
            naome_foundation::FreeVariable::new(0),
            naome_foundation::FreeVariable::new(0),
        ),
    );
    let expected = naome_proof::program::formula_hash(&expected);
    assert_eq!(status.conclusion, Some(crate::hex(&expected)));
}

#[test]
fn a_forged_persisted_proved_bit_never_authorizes_a_seal() {
    let directory = Directory::new();
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::Equal { left: 0, right: 0 }).unwrap();
    work.append(&Command::ForAll {
        variable: 0,
        body: 0,
    })
    .unwrap();
    finish(&mut work);
    drop(work);
    let connection = Connection::open(directory.path()).unwrap();
    connection
        .execute("UPDATE result SET proved=1", [])
        .unwrap();
    drop(connection);
    let mut work = Work::open(&directory.path()).unwrap();
    work.append(&Command::Seal { proof: 1 }).unwrap();
    assert!(
        work.advance(&budget())
            .unwrap_err()
            .contains("saved proof result differs")
    );
    assert!(!work.status().unwrap().fully_checked);
}

#[test]
fn every_logical_recipe_and_both_schemas_match_foundation_tree_semantics() {
    use naome_foundation::{FreeVariable as V, Logic, Replacement, Separation};
    let v = V::new;
    let a = Formula::equal(v(0), v(1));
    let b = Formula::member(v(0), v(1));
    let c = Formula::equal(v(1), v(0));
    let cases = [
        (
            Command::Simplification {
                antecedent: 0,
                consequent: 1,
            },
            Logic::simplification(a.clone(), b.clone()),
        ),
        (
            Command::Frege {
                first: 0,
                second: 1,
                third: 2,
            },
            Logic::frege(a.clone(), b.clone(), c.clone()),
        ),
        (
            Command::Contraposition {
                antecedent: 0,
                consequent: 1,
            },
            Logic::classical_contraposition(a.clone(), b.clone()),
        ),
        (
            Command::Distribution {
                variable: 0,
                antecedent: 0,
                consequent: 1,
            },
            Logic::universal_distribution(v(0), a.clone(), b.clone()),
        ),
        (
            Command::Vacuous { formula: 0 },
            Logic::vacuous_universal(a.clone()),
        ),
        (
            Command::Instantiation {
                variable: 0,
                replacement: 1,
                body: 0,
            },
            Logic::universal_instantiation(v(0), v(1), a.clone()),
        ),
        (
            Command::Substitution {
                from: 0,
                to: 1,
                body: 0,
            },
            Logic::equality_substitution(v(0), v(1), a.clone()),
        ),
        (
            Command::Separation {
                predicate: 0,
                element: 0,
                source: 1,
                result: 2,
            },
            Separation {
                predicate: a.clone(),
                element: v(0),
                source: v(1),
                result: v(2),
                parameters: vec![],
            }
            .formula()
            .unwrap(),
        ),
        (
            Command::Replacement {
                predicate: 0,
                input: 0,
                output: 1,
                witness: 2,
                source: 3,
                result: 4,
            },
            Replacement {
                predicate: a.clone(),
                input: v(0),
                output: v(1),
                uniqueness_witness: v(2),
                source: v(3),
                result: v(4),
                parameters: vec![],
            }
            .formula()
            .unwrap(),
        ),
    ];
    for (command, expected) in cases {
        let directory = Directory::new();
        let mut work = Work::open(&directory.path()).unwrap();
        work.append(&Command::Equal { left: 0, right: 1 }).unwrap();
        work.append(&Command::Member { element: 0, set: 1 })
            .unwrap();
        work.append(&Command::Equal { left: 1, right: 0 }).unwrap();
        work.append(&command).unwrap();
        finish(&mut work);
        let expected = naome_proof::program::formula_hash(&expected);
        assert_eq!(
            work.engine.result_digest(3).unwrap(),
            (expected, true),
            "{command:?}"
        );
    }
}
