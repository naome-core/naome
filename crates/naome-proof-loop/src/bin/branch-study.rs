use naome_proof_loop::{
    ActionValues, AdaptiveSolver, Archive, EntryId, Experience, LearningSignal, Result, Task,
    Verification,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct Case {
    id: String,
    family: String,
    profile: String,
    task: Task,
}

fn seed_for(seed: u64, index: usize, holdout: bool) -> u64 {
    seed ^ (index as u64).wrapping_mul(0x9e3779b97f4a7c15) ^ (u64::from(holdout) << 48)
}

fn write(output: &mut impl Write, record: Value) -> Result<()> {
    serde_json::to_writer(&mut *output, &record)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

fn replay(db: &Path, records: &[Verification]) -> Result<usize> {
    let mut replay = Archive::open_for_replay(db)?;
    let mut checked = HashSet::<EntryId>::new();
    for record in records {
        if checked.insert(record.id) {
            let proof = replay.replay(record.id)?;
            if proof.axioms != record.axioms {
                return Err(format!("independent axiom mismatch for {}", record.id).into());
            }
        }
    }
    Ok(checked.len())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [training, holdout, destination, seed] = args.as_slice() else {
        return Err(
            "branch-study <training.json> <holdout.json> <new-result-directory> <seed>".into(),
        );
    };
    let seed = seed.parse::<u64>()?;
    let training: Vec<Case> = serde_json::from_reader(File::open(training)?)?;
    let holdout: Vec<Case> = serde_json::from_reader(File::open(holdout)?)?;
    let destination = PathBuf::from(destination);
    fs::create_dir(&destination)?;
    let mut output = BufWriter::new(File::create(destination.join("results.jsonl"))?);
    let training_db = destination.join("exploration.sqlite");
    let mut experience = Experience::default();
    let mut training_proofs = Vec::new();
    {
        let mut explorer = AdaptiveSolver::new(Archive::open(&training_db)?);
        for rollout in 0..3 {
            for (index, case) in training.iter().enumerate() {
                let search_seed = seed_for(seed, index + rollout * training.len(), false);
                let result =
                    explorer.collect_experience(case.task.clone(), search_seed, &mut experience)?;
                if let Some(proof) = &result.proof {
                    training_proofs.push(proof.clone());
                }
                write(
                    &mut output,
                    json!({"kind":"experience","case":case.id,"family":case.family,
                           "profile":case.profile,"rollout":rollout,"outcome":result}),
                )?;
            }
        }
    }
    let replayed = replay(&training_db, &training_proofs)?;
    assert!(replayed > 0 && experience.evidence.compared_siblings > 0);
    let distinct_training_proofs = training_proofs
        .iter()
        .map(|proof| proof.id)
        .collect::<HashSet<_>>()
        .len();
    assert_eq!(replayed, distinct_training_proofs);
    write(
        &mut output,
        json!({"kind":"training_evidence","experience":experience.evidence,
                             "independently_replayed":replayed}),
    )?;

    let acceptance = ActionValues::fit(&experience, LearningSignal::StepAcceptance, seed);
    let paired = acceptance.fit_sibling_preferences(&experience, seed);
    let arms = [
        ("untrained", ActionValues::default()),
        ("acceptance", acceptance),
        (
            "continuation",
            ActionValues::fit(&experience, LearningSignal::CheckedContinuation, seed),
        ),
        ("paired", paired),
    ];
    for (arm, values) in arms {
        serde_json::to_writer(
            File::create(destination.join(format!("{arm}.model.json")))?,
            &values,
        )?;
        let db = destination.join(format!("{arm}.sqlite"));
        let mut solver = AdaptiveSolver::new(Archive::open(&db)?);
        let mut proofs = Vec::new();
        for (index, case) in holdout.iter().enumerate() {
            let result = solver.evaluate_action_values(
                case.task.clone(),
                seed_for(seed, index, true),
                &values,
            )?;
            if let Some(proof) = &result.proof {
                proofs.push(proof.clone());
            }
            write(
                &mut output,
                json!({"kind":"holdout","arm":arm,"case":case.id,"family":case.family,
                                     "profile":case.profile,"outcome":result}),
            )?;
        }
        drop(solver);
        write(
            &mut output,
            json!({"kind":"replay","arm":arm,"checked":replay(&db, &proofs)?}),
        )?;
    }
    Ok(())
}
