use std::path::Path;

use naome_research::{
    chatgpt,
    journal::{Journal, read_bounded},
    node::{self, Control, Node, SignedAction},
    provider::AppServer,
    run, scenario,
    state::hex,
};
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
        Some("chatgpt-sign-in") | Some("chatgpt-enable-plan") if args.len()<=3 => {
            let directory=credential_directory(args.get(1))?;
            with_signals(|control|chatgpt::sign_in(&directory,args.get(2).map(String::as_str),args[0]=="chatgpt-enable-plan",control.cancellation()))
        }
        Some("chatgpt-accounts") if args.len()<=2 => chatgpt::accounts(&credential_directory(args.get(1))?),
        Some("chatgpt-models") if args.len()==2 || args.len()==3 => {
            let account=account_config(&args[1],args.get(2))?;
            with_signals(|control|chatgpt::models(&account,control.cancellation()))
        }
        Some("chatgpt-model-diagnostics") if args.len()==3 || args.len()==4 => {
            let account=account_config(&args[1],args.get(3))?;
            with_signals(|control|chatgpt::diagnose_model(&account,&args[2],control.cancellation()))
        }
        Some("chatgpt-sign-out") if args.len()==2 || args.len()==3 => {
            let account=account_config(&args[1],args.get(2))?;
            with_signals(|control|chatgpt::sign_out(&account,control.cancellation()))
        }
        Some("node-preflight") if args.len()==2 => {
            let config=node::read_config(Path::new(&args[1]))?;
            let account=config.provider.responses.as_ref().ok_or("This profile uses the explicit legacy native route")?;
            with_signals(|control|chatgpt::preflight(account,&config.provider.model,control.cancellation()))
        }
        Some("prepare-node") if args.len()==4 || args.len()==5 => {
            let account=account_config(&args[2],args.get(4))?;
            with_signals(|control|chatgpt::preflight(&account,&args[3],control.cancellation()))?;
            let path=node::prepare_direct(Path::new(&args[1]),account,&args[3])?;
            Ok(json!({"config":path,"model_requests":0,"note":"Set interests, local credit and three explicit allowances before init-node. Prepared allocations are zero. The selected ChatGPT registration and model become immutable at genesis.","manage_usage":chatgpt::USAGE_SETTINGS}))
        }
        Some("prepare-native-node") if args.len()==5 => {
            let path=node::prepare(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),&args[4])?;
            Ok(json!({"config":path,"note":"Set interests, local credit and three explicit allowances before init-node. Prepared allocations are zero. Use an existing participant-owned authenticated home and source-pinned native Codex 0.159.2."}))
        }
        Some("init-node") if args.len()==2 => Node::initialize(node::read_config(Path::new(&args[1]))?, wall_time()?)?.status("initialized"),
        Some("node-run") if args.len()==2 => run_node(node::read_config(Path::new(&args[1]))?),
        Some("prepare-node-sample") if args.len()==3 => Node::inspect(node::read_config(Path::new(&args[1]))?)?.prepare_sample(Path::new(&args[2])),
        Some("node-sample") if args.len()==3 => {
            let mut node=Node::open(node::read_config(Path::new(&args[1]))?)?;
            with_signals(|control|node.run_sample(Path::new(&args[2]),control))
        }
        Some("node-status") if args.len()==2 => Node::inspect(node::read_config(Path::new(&args[1]))?)?.status("selected_snapshot"),
        Some("node-submit") if args.len()==3 => {
            let mut node=Node::open(node::read_config(Path::new(&args[1]))?)?;
            let action:SignedAction=read_bounded(Path::new(&args[2]),256*1024)?;
            serde_json::to_value(node.submit(action)?).map_err(|e|e.to_string())
        }
        Some("node-questions") if args.len()==3 => {
            let node=Node::inspect(node::read_config(Path::new(&args[1]))?)?;
            let cursor=args[2].parse().map_err(|_|"question cursor must be an integer")?;
            serde_json::to_value(node.questions(cursor,16)?).map_err(|e|e.to_string())
        }
        Some("node-artifact") if args.len()==3 => {
            let node=Node::inspect(node::read_config(Path::new(&args[1]))?)?;
            Ok(json!({"source":node.artifact_source(run::parse_id(&args[2])?)?}))
        }
        Some("node-replay") if args.len()==3 || args.len()==5 => {
            let expected=if args.len()==5 {Some((run::parse_id(&args[3])?,args[4].parse().map_err(|_|"record count must be an integer")?))} else {None};
            Node::replay(node::read_config(Path::new(&args[1]))?,Path::new(&args[2]),expected)
        }
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
        _ => Err("usage: naome-research chatgpt-sign-in [CREDENTIAL_DIRECTORY [ACCOUNT_ID]] | chatgpt-enable-plan [CREDENTIAL_DIRECTORY [ACCOUNT_ID]] | chatgpt-accounts [CREDENTIAL_DIRECTORY] | chatgpt-models ACCOUNT_ID [CREDENTIAL_DIRECTORY] | chatgpt-model-diagnostics ACCOUNT_ID MODEL [CREDENTIAL_DIRECTORY] | chatgpt-sign-out ACCOUNT_ID [CREDENTIAL_DIRECTORY] | prepare-node DIRECTORY ACCOUNT_ID MODEL [CREDENTIAL_DIRECTORY] | prepare-native-node DIRECTORY NATIVE_CODEX CODEX_HOME MODEL | node-preflight CONFIG | prepare-node-sample CONFIG NEW_GRANT | node-sample CONFIG GRANT | init-node CONFIG | node-run CONFIG | node-status CONFIG | node-submit CONFIG SIGNED_ACTION | node-questions CONFIG CURSOR | node-artifact CONFIG ARTIFACT_ID | node-replay CONFIG NEW_DIRECTORY [EXPECTED_HEAD EXPECTED_COUNT] | demo DIRECTORY | prepare DIRECTORY CODEX_HOME MODEL [--shared-plan-sample] | run CONFIG | provider-info CONFIG | replay HISTORY_DIRECTORY [EXPECTED_HEAD EXPECTED_COUNT]".into()),
    }
}

fn wall_time() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        .try_into()
        .map_err(|_| "wall clock exhausted".into())
}

fn run_node(config: node::Config) -> Result<serde_json::Value, String> {
    // Opening an existing node is deliberately separate from initialization.
    let mut node = Node::open(config)?;
    with_signals(|control| node.run(control))
}

fn credential_directory(value: Option<&String>) -> Result<std::path::PathBuf, String> {
    value.map_or_else(chatgpt::default_directory, |s| Ok(s.into()))
}
fn account_config(
    account: &str,
    directory: Option<&String>,
) -> Result<chatgpt::ResponsesConfig, String> {
    let config = chatgpt::ResponsesConfig {
        version: 1,
        credential_directory: credential_directory(directory)?,
        account_id: account.into(),
    };
    config.validate()?;
    Ok(config)
}
fn with_signals<T>(work: impl FnOnce(&Control) -> Result<T, String>) -> Result<T, String> {
    let control = Control::default();
    let signals = control.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let listener = std::thread::spawn(move || {
        runtime.block_on(async move {
        #[cfg(unix)]
        let mut terminate=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e|{signals.stop();e.to_string()})?;
        let interrupt=tokio::signal::ctrl_c();
        tokio::pin!(interrupt);
        loop {
            if signals.stopped() {return Ok::<(),String>(());}
            #[cfg(unix)]
            tokio::select! {
                result=&mut interrupt=>{signals.stop();result.map_err(|e|e.to_string())?;return Ok(());}
                _=terminate.recv()=>{signals.stop(); return Ok(());}
                _=tokio::time::sleep(std::time::Duration::from_millis(100))=>{}
            }
            #[cfg(not(unix))]
            tokio::select! {
                result=&mut interrupt=>{signals.stop();result.map_err(|e|e.to_string())?;return Ok(());}
                _=tokio::time::sleep(std::time::Duration::from_millis(100))=>{}
            }
        }
    })
    });
    let result = work(&control);
    control.stop();
    listener
        .join()
        .map_err(|_| "node signal listener failed")??;
    result
}
