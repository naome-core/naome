use crate::{ActionValues, AdaptiveSolver, Archive, Artifact, EntryId, KernelBundle, Result, Task};
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

const HELP: &str = "naome proof prove <Lean proposition> <seed> [Lean declaration names ...]
naome proof prove-with-values <model.json> <Lean proposition> <seed> [Lean declaration names ...]
naome proof prove-sequence <goals-file> <seed> --archive <archive.sqlite>
naome proof compile-archived <archive.sqlite> <artifact.json>
naome proof define-archived <archive.sqlite> <Lean type> <Lean term> [archive IDs ...]
naome proof replay-archived <archive.sqlite> <archive-id>
naome proof export-kernel <archive.sqlite> <archive-id>
naome proof import-kernel <archive.sqlite> <bundle.json>

Sequence input accepts one Lean proposition per line, optionally preceded by a
decimal search seed and tab. A JSON line can specify target, hints, dependencies,
activate, and seed. Dependencies are available when elaborating the target.
Activate makes specified archive entries available in the 64-slot search catalog.
The solver also recalls up to eight related checked entries by Lean symbols.
The default search ranks concrete actions with a bundled Lean-acceptance
checkpoint and backtracks on repeated obligations. It resumes deep branches
in turns alongside shallower alternatives. Its weights stay fixed during proof
search. The sequence command learns and reuses checked fragments.
Use prove-with-values for a saved checkpoint from branch-study.
Export writes a checked kernel bundle to stdout. Import checks the full
bundle in a fresh Lean session and prints the resulting archive ID.

Lean uses the pinned project files and Mathlib revisions shipped with NAOME.
Set NAOME_LEAN_PROJECT to select an alternate copy of the pinned project.
Run lake exe cache get in the project to prepare the imported Mathlib modules.
NAOME_LEAN_LAKE optionally selects a Lake executable. The default is lake on PATH.

A proof artifact has kind=proof, target, and steps. The fixed action IDs are
0 intro, 1 exact, 2 apply, 3 constructor, and 4 rfl. Actions 1 and 2 take an
argument, for example {\"declaration\":\"propext\"}, {\"local\":0}, or
{\"archived\":\"<id>\"}. An archived declaration can also be named in a term
as NaomeArchive.e_<id> after listing its ID in dependencies.
";

fn parse_task(line: &str) -> Result<Task> {
    if line.starts_with("{\"") || line.starts_with("{ ") {
        return Ok(serde_json::from_str(line)?);
    }
    let (seed, target) = line
        .split_once('\t')
        .and_then(|(seed, target)| Some((Some(seed.parse().ok()?), target)))
        .unwrap_or((None, line));
    Ok(Task {
        target: target.to_owned(),
        hints: Vec::new(),
        dependencies: Vec::new(),
        activate: Vec::new(),
        seed,
    })
}

fn output(value: &impl serde::Serialize) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

/// Execute a local Lean proof or archive command.
pub fn execute(args: &[String]) -> Result<()> {
    match args {
        [] => print!("{HELP}"),
        [help] if help == "--help" || help == "-h" => print!("{HELP}"),
        [mode, goal, seed, hints @ ..] if mode == "prove" => {
            let seed = seed.parse()?;
            let mut solver = AdaptiveSolver::new(Archive::open(Path::new(":memory:"))?);
            let task = Task {
                target: goal.clone(),
                hints: hints.to_vec(),
                dependencies: Vec::new(),
                activate: Vec::new(),
                seed: None,
            };
            output(&solver.prove(task, seed)?)?;
        }
        [mode, checkpoint, goal, seed, hints @ ..] if mode == "prove-with-values" => {
            let seed = seed.parse()?;
            let values: ActionValues = serde_json::from_reader(File::open(checkpoint)?)?;
            let mut solver = AdaptiveSolver::new(Archive::open(Path::new(":memory:"))?);
            let task = Task {
                target: goal.clone(),
                hints: hints.to_vec(),
                dependencies: Vec::new(),
                activate: Vec::new(),
                seed: None,
            };
            output(&solver.prove_with_values(task, seed, &values)?)?;
        }
        [mode, goals, seed, flag, archive] if mode == "prove-sequence" && flag == "--archive" => {
            let seed = seed.parse::<u64>()?;
            let mut solver = AdaptiveSolver::new(Archive::open(Path::new(archive))?);
            for (index, line) in BufReader::new(File::open(goals)?).lines().enumerate() {
                let line = line?;
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let result = parse_task(line)
                    .and_then(|task| solver.prove(task, seed ^ index as u64))
                    .map_err(|error| format!("line {}: {error}", index + 1))?;
                output(&result)?;
            }
        }
        [mode, archive, artifact] if mode == "compile-archived" => {
            let artifact: Artifact = serde_json::from_reader(File::open(artifact)?)?;
            output(&Archive::open(Path::new(archive))?.compile(artifact)?)?;
        }
        [mode, archive, target, value, dependencies @ ..] if mode == "define-archived" => {
            let dependencies = dependencies
                .iter()
                .map(|id| id.parse::<EntryId>())
                .collect::<Result<Vec<_>>>()?;
            let artifact = Artifact::Definition {
                target: target.clone(),
                value: value.clone(),
                dependencies,
            };
            output(&Archive::open(Path::new(archive))?.compile(artifact)?)?;
        }
        [mode, archive, id] if mode == "replay-archived" => {
            output(&Archive::open_for_replay(Path::new(archive))?.replay(id.parse()?)?)?;
        }
        [mode, archive, id] if mode == "export-kernel" => {
            let bundle =
                Archive::open_for_replay(Path::new(archive))?.export_kernel(id.parse()?)?;
            io::stdout().lock().write_all(&bundle.to_bytes()?)?;
        }
        [mode, archive, bundle] if mode == "import-kernel" => {
            let mut bytes = Vec::new();
            File::open(bundle)?
                .take(KernelBundle::MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            let bundle = KernelBundle::from_bytes(&bytes)?;
            output(&Archive::open(Path::new(archive))?.import_kernel(bundle)?)?;
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}
