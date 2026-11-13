use naome_proof_loop::{
    APPLY, Action, AdaptiveSolver, Archive, Artifact, CATALOG_SLOTS, CONSTRUCTOR, EXACT, EntryId,
    INTRO, KernelBundle, RFL, Reference, Task,
};
use std::path::{Path, PathBuf};

fn step(id: u8) -> Action {
    Action { id, argument: None }
}

fn reference(id: u8, argument: Reference) -> Action {
    Action {
        id,
        argument: Some(argument),
    }
}

fn decl(id: u8, name: &str) -> Action {
    reference(id, Reference::Declaration(name.into()))
}

fn proof(target: &str, steps: Vec<Action>) -> Artifact {
    Artifact::Proof {
        target: target.into(),
        steps,
        dependencies: vec![],
    }
}

fn task(target: &str) -> Task {
    Task {
        target: target.into(),
        hints: vec![],
        dependencies: vec![],
        activate: vec![],
        seed: None,
    }
}

struct Temp(PathBuf);

impl Temp {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("naome-lean-{name}-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("archive.sqlite")
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn lean_checks_all_five_actions_and_standard_axiom_arguments() {
    let mut archive = Archive::open(Path::new(":memory:")).unwrap();
    let conjunction = proof(
        "∀ (n : Nat) (P : Prop), P → (n = n ∧ P)",
        vec![
            step(INTRO),
            step(INTRO),
            step(INTRO),
            step(CONSTRUCTOR),
            step(RFL),
            reference(EXACT, Reference::Local(2)),
        ],
    );
    assert!(archive.compile(conjunction).unwrap().axioms.is_empty());

    let propext = proof(
        "∀ (P Q : Prop), (P ↔ Q) → P = Q",
        vec![step(INTRO), step(INTRO), decl(APPLY, "propext")],
    );
    assert_eq!(archive.compile(propext).unwrap().axioms, ["propext"]);

    let quotient = proof(
        "∀ (r : Nat → Nat → Prop) (a b : Nat), r a b → Quot.mk r a = Quot.mk r b",
        vec![
            step(INTRO),
            step(INTRO),
            step(INTRO),
            decl(APPLY, "Quot.sound"),
        ],
    );
    assert_eq!(archive.compile(quotient).unwrap().axioms, ["Quot.sound"]);

    let choice = proof(
        "∀ (α : Type), Nonempty α → ∃ _ : α, True",
        vec![
            step(INTRO),
            step(INTRO),
            step(CONSTRUCTOR),
            step(CONSTRUCTOR),
            decl(APPLY, "Classical.choice"),
            reference(EXACT, Reference::Local(1)),
        ],
    );
    assert_eq!(
        archive.compile(choice).unwrap().axioms,
        ["Classical.choice"]
    );

    let set_foundation = proof("∀ x : ZFSet, x ∉ x", vec![decl(EXACT, "ZFSet.mem_irrefl")]);
    assert_eq!(
        archive.compile(set_foundation).unwrap().axioms,
        ["propext", "Quot.sound"]
    );

    assert!(archive.compile(proof("False", vec![step(RFL)])).is_err());
    assert!(
        archive
            .compile(proof("True ∧ True", vec![step(CONSTRUCTOR)]))
            .is_err()
    );
    assert!(archive.compile(proof("True", vec![step(5)])).is_err());
    let invalid = Artifact::Definition {
        target: "False".into(),
        value: "by sorry".into(),
        dependencies: vec![],
    };
    assert!(
        archive
            .compile(invalid)
            .unwrap_err()
            .to_string()
            .contains("sorryAx")
    );
}

#[test]
fn search_learns_closed_fragments_from_lean_feedback() {
    let archive = Archive::open(Path::new(":memory:")).unwrap();
    let mut solver = AdaptiveSolver::new(archive);
    let first = solver.prove(task("(∀ n : Nat, n = n) ∧ True"), 11).unwrap();
    assert!(first.solved);
    assert_eq!(first.model_before, first.model_after);
    let second = solver.prove(task("True ∧ (∀ n : Nat, n = n)"), 13).unwrap();
    assert!(second.solved);
    assert_eq!(second.admitted.len(), 1);
    let learned = second.admitted[0].1;
    let cited = solver.prove(task("∀ n : Nat, n = n"), 17).unwrap();
    assert!(cited.solved);
    assert_eq!(
        cited.steps,
        vec![reference(EXACT, Reference::Archived(learned))]
    );
    assert_eq!(cited.checker_calls, 2);
    let unsolved = solver.prove(task("False"), 19).unwrap();
    assert!(!unsolved.solved);
    assert_eq!(unsolved.model_before, unsolved.model_after);
}

#[test]
fn restart_resolves_a_proof_and_definition_after_active_slot_eviction() {
    let temp = Temp::new("archive");
    let path = temp.db();
    let mut archive = Archive::open(&path).unwrap();
    let first = archive
        .compile(proof("True", vec![step(CONSTRUCTOR)]))
        .unwrap()
        .id;
    let mut replacements = Vec::new();
    for number in 0..CATALOG_SLOTS {
        let entry = Artifact::Definition {
            target: "Nat".into(),
            value: number.to_string(),
            dependencies: vec![],
        };
        replacements.push(archive.compile(entry).unwrap().id);
    }
    let definition = replacements[0];

    let mut solver = AdaptiveSolver::new(archive);
    let mut first_task = task("True");
    first_task.activate = vec![first];
    let first_use = solver.prove(first_task, 11).unwrap();
    let receipt = first_use.proof.unwrap().id;
    assert_eq!(
        first_use.steps,
        vec![reference(EXACT, Reference::Archived(first))]
    );

    drop(solver);
    let archive = Archive::open(&path).unwrap();
    let mut solver = AdaptiveSolver::new(archive);
    let mut first_task = task("False");
    first_task.activate = vec![first];
    assert!(!solver.prove(first_task, 11).unwrap().solved);
    let mut fill = task("True");
    fill.activate = replacements;
    let full = solver.prove(fill, 13).unwrap();
    assert_eq!(full.active_entries, CATALOG_SLOTS);
    assert!(full.solved);
    assert!(
        full.steps
            .iter()
            .all(|action| action.argument != Some(Reference::Archived(first)))
    );
    drop(solver);

    let mut archive = Archive::open_for_replay(&path).unwrap();
    assert_eq!(archive.read(receipt).unwrap().dependencies(), &[first]);
    assert_eq!(archive.replay(receipt).unwrap().checker_calls, 4);
    drop(archive);

    let mut archive = Archive::open(&path).unwrap();
    let name = definition.lean_name();
    let mut dependent = proof(&format!("{name} = 0"), vec![step(RFL)]);
    let Artifact::Proof { dependencies, .. } = &mut dependent else {
        unreachable!()
    };
    dependencies.push(definition);
    let checked = archive.compile(dependent).unwrap().id;
    let undeclared = proof(&format!("{name} = 0"), vec![step(RFL)]);
    assert!(
        archive
            .compile(undeclared)
            .unwrap_err()
            .to_string()
            .contains("undeclared archive dependency")
    );
    drop(archive);
    let mut archive = Archive::open_for_replay(&path).unwrap();
    assert_eq!(archive.read(checked).unwrap().dependencies(), &[definition]);
    assert_eq!(archive.replay(checked).unwrap().checker_calls, 3);
    assert!(
        archive
            .read(EntryId::try_from("0".repeat(64)).unwrap())
            .is_err()
    );
    drop(archive);

    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.execute(
            "DELETE FROM declaration WHERE lower(hex(id)) = ?1",
            [first.to_string()]
        )
        .unwrap(),
        1
    );
    assert!(
        Archive::open_for_replay(&path)
            .unwrap()
            .replay(receipt)
            .is_err()
    );
}

#[test]
fn search_and_archive_count_all_checker_calls() {
    let temp = Temp::new("checker-calls");
    let path = temp.db();

    // Every candidate fails, so the solver must search the complete candidate list.
    let mut impossible = task("False");
    impossible.hints = (0..300)
        .map(|index| format!("MissingHint.h{index}"))
        .collect();
    let mut solver = AdaptiveSolver::new(Archive::open(&path).unwrap());
    let search = solver.prove(impossible, 11).unwrap();
    assert!(!search.solved);
    assert_eq!(search.checker_calls, 603);
    drop(solver);

    let binders = (0..300)
        .map(|index| format!("x{index}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut steps = vec![step(INTRO); 300];
    steps.push(step(CONSTRUCTOR));
    let artifact = proof(&format!("∀ ({binders} : Nat), True"), steps);
    let mut archive = Archive::open(&path).unwrap();
    let compiled = archive.compile(artifact).unwrap();
    assert_eq!(compiled.checker_calls, 302);
    drop(archive);

    let mut archive = Archive::open_for_replay(&path).unwrap();
    let replayed = archive.replay(compiled.id).unwrap();
    assert_eq!(replayed.id, compiled.id);
    assert_eq!(replayed.checker_calls, compiled.checker_calls);
    assert_eq!(replayed.axioms, compiled.axioms);
}

#[test]
fn default_search_resumes_a_deep_branch_and_replays_its_proof() {
    fn conjunction(terms: &[String]) -> String {
        if let [term] = terms {
            return term.clone();
        }
        let (left, right) = terms.split_at(terms.len() / 2);
        format!("({} ∧ {})", conjunction(left), conjunction(right))
    }

    let temp = Temp::new("resumed-proof");
    let path = temp.db();
    let names: Vec<_> = (0..60).map(|index| format!("x{index}")).collect();
    let equalities: Vec<_> = names
        .iter()
        .map(|name| format!("{name} = {name}"))
        .collect();
    let target = format!(
        "∀ ({} : Nat), {}",
        names.join(" "),
        conjunction(&equalities)
    );
    let mut solver = AdaptiveSolver::new(Archive::open(&path).unwrap());
    let outcome = solver.prove(task(&target), 11).unwrap();
    assert!(outcome.solved);
    assert_eq!(outcome.steps.len(), 179);
    let proof = outcome.proof.unwrap();
    drop(solver);

    let mut archive = Archive::open_for_replay(&path).unwrap();
    let Artifact::Proof {
        target: archived,
        steps,
        ..
    } = archive.read(proof.id).unwrap()
    else {
        panic!("expected a proof artifact")
    };
    assert_eq!(archived, target);
    assert_eq!(steps, outcome.steps);
    let replayed = archive.replay(proof.id).unwrap();
    assert_eq!(replayed.axioms, proof.axioms);
    assert_eq!(replayed.checker_calls, steps.len() + 1);
}

#[test]
fn search_recalls_checked_theorems_from_a_cold_archive() {
    let temp = Temp::new("recall");
    let path = temp.db();
    let mut archive = Archive::open(&path).unwrap();
    let theorem = archive
        .compile(proof(
            "∀ a b : Nat, a + b = b + a",
            vec![step(INTRO), step(INTRO), decl(APPLY, "Nat.add_comm")],
        ))
        .unwrap()
        .id;
    let definition = archive
        .compile(Artifact::Definition {
            target: "Nat → Nat → Nat".into(),
            value: "(fun a b => a + b)".into(),
            dependencies: vec![],
        })
        .unwrap()
        .id;
    drop(archive);

    let mut solver = AdaptiveSolver::new(Archive::open(&path).unwrap());
    let output = solver
        .prove(task("∀ a b : Nat, b + a = a + b"), 37)
        .unwrap();
    assert!(output.recalled.iter().any(|&(_, id)| id == theorem));
    assert!(output.recalled.iter().any(|&(_, id)| id == definition));
    let receipt = output.proof.unwrap();
    assert!(
        output
            .steps
            .iter()
            .any(|action| action.argument == Some(Reference::Archived(theorem)))
    );
    drop(solver);

    let mut reopened = Archive::open_for_replay(&path).unwrap();
    assert_eq!(
        reopened.read(receipt.id).unwrap().dependencies(),
        &[theorem]
    );
    assert_eq!(reopened.replay(receipt.id).unwrap().axioms, receipt.axioms);
}

#[test]
fn search_restores_a_relevant_proof_across_a_deep_definition_chain() {
    let temp = Temp::new("question-retrieval");
    let path = temp.db();
    let mut archive = Archive::open(&path).unwrap();

    let mut top = archive
        .compile(Artifact::Definition {
            target: "Nat → Nat → Nat".into(),
            value: "fun a b : Nat => a + b".into(),
            dependencies: vec![],
        })
        .unwrap()
        .id;
    for level in 0..70 {
        top = archive
            .compile(Artifact::Definition {
                target: "Nat → Nat → Nat".into(),
                value: format!(
                    "fun a b : Nat => let x{level} := {}; x{level} a b",
                    top.lean_name()
                ),
                dependencies: vec![top],
            })
            .unwrap()
            .id;
    }
    let name = top.lean_name();
    let donor_target = format!("∀ a b : Nat, {name} a b = {name} b a");
    let supplier = archive
        .compile(Artifact::Definition {
            target: donor_target.clone(),
            value: "fun a b => show a + b = b + a from Nat.add_comm a b".into(),
            dependencies: vec![top],
        })
        .unwrap()
        .id;
    let mut donor = proof(
        &donor_target,
        vec![reference(EXACT, Reference::Archived(supplier))],
    );
    let Artifact::Proof { dependencies, .. } = &mut donor else {
        unreachable!()
    };
    dependencies.push(top);
    let donor = archive.compile(donor).unwrap().id;
    let unrelated = archive
        .compile(Artifact::Definition {
            target: "List Nat".into(),
            value: "[17, 31]".into(),
            dependencies: vec![],
        })
        .unwrap()
        .id;
    drop(archive);

    let mut solver = AdaptiveSolver::new(Archive::open(&path).unwrap());
    let mut follow_up = task(&format!("∀ a b : Nat, True → {name} b a = {name} a b"));
    follow_up.dependencies.push(top);
    let result = solver.prove(follow_up, 11).unwrap();
    assert!(result.solved);
    assert!(result.recalled.iter().any(|&(_, id)| id == donor));
    assert!(result.recalled.iter().all(|&(_, id)| id != unrelated));
    assert!(result.active_entries < 16);
    assert!(result.steps.iter().any(|step| {
        matches!(step.argument, Some(Reference::Archived(id)) if id == donor || id == supplier)
    }));
    drop(solver);

    let checked = result.proof.unwrap();
    let mut fresh = Archive::open_for_replay(&path).unwrap();
    let replayed = fresh.replay(checked.id).unwrap();
    assert_eq!(replayed.axioms, checked.axioms);
    assert!(replayed.checker_calls > 70);
}

#[test]
fn kernel_bundle_transfers_a_proof_and_its_definition_atomically() {
    let temp = Temp::new("kernel-transfer");
    let source = temp.0.join("source.sqlite");
    let destination = temp.0.join("destination.sqlite");
    let mut producer = Archive::open(&source).unwrap();
    let increment = producer
        .compile(Artifact::Definition {
            target: "Nat → Nat".into(),
            value: "fun n => n.succ".into(),
            dependencies: vec![],
        })
        .unwrap()
        .id;
    let target = format!("∀ n : Nat, {} n = n.succ", increment.lean_name());
    let original = producer
        .compile(Artifact::Proof {
            target,
            steps: vec![step(INTRO), step(RFL)],
            dependencies: vec![increment],
        })
        .unwrap()
        .id;
    let bundle = producer.export_kernel(original).unwrap();
    let root = bundle.root;
    let bytes = bundle.to_bytes().unwrap();
    drop(producer);
    let mut producer = Archive::open_for_replay(&source).unwrap();
    assert_eq!(
        producer
            .export_kernel(original)
            .unwrap()
            .to_bytes()
            .unwrap(),
        bytes
    );

    let mut receiver = Archive::open(&destination).unwrap();
    let mut modified: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let declarations = modified["declarations"].as_array_mut().unwrap();
    assert_eq!(declarations.len(), 2);
    let definition_bytes = serde_json::to_vec(&declarations[0]).unwrap();
    let definition: naome_proof_loop::KernelArtifact =
        serde_json::from_slice(&definition_bytes).unwrap();
    let definition_id = definition.id().unwrap();
    declarations[1]["terms"]["type"] =
        serde_json::json!({"constant":{"name":{"parts":[{"text":{"value":"False"}}]},"levels":[]}});
    let wrong: naome_proof_loop::KernelArtifact =
        serde_json::from_value(declarations[1].clone()).unwrap();
    modified["root"] = serde_json::to_value(wrong.id().unwrap()).unwrap();
    let modified: KernelBundle = serde_json::from_value(modified).unwrap();
    let invalid = KernelBundle::from_bytes(&modified.to_bytes().unwrap()).unwrap();
    let error = receiver.import_kernel(invalid).unwrap_err();
    assert!(error.to_string().contains("type mismatch"), "{error}");
    assert!(receiver.read(definition_id).is_err());
    assert!(receiver.read(root).is_err());

    let receipt = receiver
        .import_kernel(KernelBundle::from_bytes(&bytes).unwrap())
        .unwrap();
    assert_eq!(receipt.root, root);
    assert_eq!(receipt.checked, [definition_id, root]);
    assert!(receipt.axioms.is_empty());
    drop(receiver);

    let mut receiver = Archive::open(&destination).unwrap();
    assert_eq!(receiver.replay(root).unwrap().checker_calls, 2);
    assert_eq!(
        receiver.export_kernel(root).unwrap().to_bytes().unwrap(),
        bytes
    );
    let mut solver = AdaptiveSolver::new(receiver);
    let mut follow_up = task(&format!(
        "True ∧ (∀ n : Nat, {} n = n.succ)",
        definition_id.lean_name()
    ));
    follow_up.dependencies.push(definition_id);
    follow_up.activate.push(root);
    let result = solver.prove(follow_up, 11).unwrap();
    assert!(result.solved);
    assert!(
        result
            .steps
            .iter()
            .any(|step| step.argument == Some(Reference::Archived(root)))
    );
}
