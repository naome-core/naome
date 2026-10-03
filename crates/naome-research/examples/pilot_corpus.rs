//! Offline pilot oracle. Never opens a provider, node, key store, or network.

use std::env;
use std::fs;
use std::io::Read;
use std::process::ExitCode;

use naome_checker::ArtifactState;
use naome_foundation::ZfcAxiom;
use naome_research::formal::{AnswerFile, FormulaInput, Outcome, check_answer};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    formula: FormulaInput,
    outcome: Outcome,
    answer: AnswerFile,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| error.to_string())?
        .take(262_145)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 262_144 {
        return Err("input exceeds pilot file limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [command, path] = args.as_slice() else {
        return Err("usage: pilot_corpus answer|question|proof-id <file> OR axiom <name>".into());
    };
    match command.as_str() {
        "answer" => {
            let request: Request = read_json(path)?;
            let result = request.formula.to_formula().and_then(|formula| {
                check_answer(&request.answer, &formula, request.outcome, &ArtifactState::new())
                    .map(|checked| {
                        json!({
                            "accepted": true,
                            "question_canonical_hex": hex(&formula.encode_canonical().unwrap()),
                            "conclusion_canonical_hex": hex(&checked.conclusion.encode_canonical().unwrap()),
                            "canonical_proof_hex": hex(&checked.canonical_bytes),
                            "proof_id": hex(naome_authoring::compile_against_proof_context(
                                &request.answer.source, &checked.resulting_state,
                            ).expect("accepted source rechecks in its resulting context").proof_id().as_bytes()),
                            "artifact_ids": checked.artifact_ids,
                            "error": null,
                        })
                    })
            });
            let value = result.unwrap_or_else(|error| json!({"accepted": false, "error": error}));
            println!("{value}");
        }
        "question" => {
            let input: serde_json::Value = read_json(path)?;
            let result = serde_json::from_value::<FormulaInput>(input)
                .map_err(|error| error.to_string())
                .and_then(|formula| formula.to_formula()).map(|checked| {
                json!({"valid": true, "canonical_hex": hex(&checked.encode_canonical().unwrap()), "source": checked.to_source(), "error": null})
            });
            println!(
                "{}",
                result.unwrap_or_else(|error| json!({"valid": false, "error": error}))
            );
        }
        "proof-id" => {
            let source = fs::read_to_string(path).map_err(|error| error.to_string())?;
            let proof = naome_authoring::compile(&source).map_err(|error| error.to_string())?;
            println!("{}", hex(proof.proof_id().as_bytes()));
        }
        "axiom" => {
            let axiom = match path.as_str() {
                "extensionality" => ZfcAxiom::Extensionality,
                "infinity" => ZfcAxiom::Infinity,
                _ => return Err("pilot exporter supports extensionality and infinity".into()),
            };
            println!("{}", axiom.formula().to_source());
        }
        _ => return Err("unknown pilot command".into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pilot_corpus: {error}");
            ExitCode::from(2)
        }
    }
}
