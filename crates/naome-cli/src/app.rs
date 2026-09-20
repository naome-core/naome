use std::error::Error;

mod actions;
mod agent;
mod control;
mod export;
mod files;
mod inspect;
mod node;
mod package;
mod setup;

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub async fn run(args: Vec<String>) -> Result<()> {
    match args.first().map(String::as_str) {
        None | Some("--help" | "help") => {
            println!(
                "Trusted research MVP commands:\n  setup DIRECTORY lab|research|short-test RUN_RECORDS BASE_PORT [standard|compact [ENDPOINTS_JSON]]\n  profile-info GENESIS\n  start|status|shutdown CONFIG\n  profile CONFIG TEXT_FILE\n  compile-question GENESIS SOURCE\n  submit CONFIG KEY SOURCE PURPOSE ACTION\n  vote CONFIG KEY YES|NO ACTION\n  agent-vote CONFIG KEY ACTION REPORT PROVIDER\n  package GENESIS KEY OUTPUT ROOT_SOURCE [--reference PROOF|--helper SOURCE]...\n  commit CONFIG KEY PACKAGE SECRET ACTION\n  reveal CONFIG KEY SECRET ACTION\n  send CONFIG ACTION\n  receipt|question CONFIG ID\n  fetch-proof CONFIG PROOF_ID OUTPUT\n  fetch-proof-from CONFIG VALIDATOR_INDEX PROOF_ID OUTPUT\n  check-proof GENESIS ROOT_PROOF [DEPENDENCY_PROOF...]\n  export CONFIG DIRECTORY\n  verify GENESIS DIRECTORY\n  inspect GENESIS DIRECTORY SUBMISSION_ID OUTPUT_DIRECTORY\n  peer CONFIG VALIDATOR_INDEX on|off"
            );
            Ok(())
        }
        Some("setup") => setup::run(&args[1..]),
        Some("profile-info") if args.len() == 2 => {
            setup::profile_info(std::path::Path::new(&args[1]))
        }
        Some("compile-question") if args.len() == 3 => {
            let genesis = naome_ledger::profile::Genesis::decode(&files::read(
                std::path::Path::new(&args[1]),
                16384,
                false,
            )?)?;
            let source = String::from_utf8(files::read(
                std::path::Path::new(&args[2]),
                genesis.profile().limits().question_source_bytes as usize,
                false,
            )?)?;
            let question =
                naome_ledger::question::CompiledQuestion::compile(&source, genesis.profile())?;
            println!("{}", inspect::compiled_question(&question));
            Ok(())
        }
        Some("package") => package::run(&args[1..]),
        Some("check-proof") => package::check(&args[1..]),
        Some("agent-vote") => agent::run(&args[1..]).await,
        Some("profile") if args.len() == 3 => {
            let config = setup::NodeConfig::read(std::path::Path::new(&args[1]))?;
            let text =
                String::from_utf8(files::read(std::path::Path::new(&args[2]), 16384, false)?)?;
            if text.trim().is_empty() {
                return Err("research profile must not be empty".into());
            }
            files::replace_private(&config.agenda_profile, text.as_bytes())?;
            println!(
                "{}",
                serde_json::json!({"status":"local_agenda_profile_updated","path":config.agenda_profile})
            );
            Ok(())
        }
        Some("start") if args.len() == 2 => node::run(std::path::Path::new(&args[1])).await,
        Some(
            "export" | "verify" | "inspect" | "fetch-proof" | "fetch-proof-from" | "receipt"
            | "question" | "peer",
        ) => export::run(&args).await,
        Some("submit" | "vote" | "commit" | "reveal" | "send") => actions::run(&args).await,
        Some("status" | "shutdown") if args.len() == 2 => {
            let config = setup::NodeConfig::read(std::path::Path::new(&args[1]))?;
            let request = if args[0] == "status" {
                control::Request::Status {}
            } else {
                control::Request::Shutdown {}
            };
            println!("{}", control::call(&config, request).await?);
            Ok(())
        }
        _ => {
            Err("usage: naome setup DIRECTORY lab|research|short-test RUN_RECORDS BASE_PORT".into())
        }
    }
}
