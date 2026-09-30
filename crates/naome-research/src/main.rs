use std::path::Path;

use naome_research::{journal::Journal, provider::AppServer, run, scenario, state::hex};
use serde_json::json;

fn main() {
    match execute() {
        Ok(value) => println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("report serializes")
        ),
        Err(reason) => {
            eprintln!("naome-research: {reason}");
            std::process::exit(1);
        }
    }
}

fn execute() -> Result<serde_json::Value, String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("demo") if args.len()==2 => scenario::run_fixture(Path::new(&args[1])),
        Some("prepare") if args.len()==4 || args.len()==5 && args[4]=="--shared-plan-sample" => {
            let file=run::prepare(Path::new(&args[1]),Path::new(&args[2]),&args[3],args.len()==5)?;
            Ok(json!({"config":file,"call_cap":6,"note":"Sign into each participant Codex home through codex login. Shared plan mode is only a consenting user's local sample."}))
        }
        Some("run") if args.len()==2 => run::live(&run::read_config(Path::new(&args[1]))?),
        Some("provider-info") if args.len()==2 => {
            let config=run::read_config(Path::new(&args[1]))?;
            let first=config.participants.first().ok_or("no participant configured")?;
            let server=AppServer::start(&first.provider).map_err(|e|e.to_string())?;
            Ok(json!({"info":server.info(),"rate_limits":server.limits(),"provider_turns":0}))
        }
        Some("replay") if args.len()==2 || args.len()==4 => {
            let (_,state)=if args.len()==4 {
                Journal::open_at(Path::new(&args[1]),run::parse_id(&args[2])?,args[3].parse().map_err(|_|"event count must be an integer")?)?
            } else {Journal::open(Path::new(&args[1]))?};
            Ok(json!({"events":state.events().len(),"result_blocks":state.results(),"head":hex(&state.head()),"active":state.active().iter().map(|id|hex(id)).collect::<Vec<_>>(),"target":state.target(),"logical_tick":state.tick(),"independent_checkpoint_verified":args.len()==4,"prefix_only":args.len()==2}))
        }
        _ => Err("usage: naome-research demo DIRECTORY | prepare DIRECTORY CODEX_HOME MODEL [--shared-plan-sample] | run CONFIG | provider-info CONFIG | replay HISTORY_DIRECTORY [EXPECTED_HEAD EXPECTED_COUNT]".into()),
    }
}
