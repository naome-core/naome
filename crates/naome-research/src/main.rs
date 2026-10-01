use std::path::Path;

use naome_research::{
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
        Some("prepare-node") if args.len()==5 => {
            let path=node::prepare(Path::new(&args[1]),Path::new(&args[2]),Path::new(&args[3]),&args[4])?;
            Ok(json!({"config":path,"note":"Set interests, local credit and three explicit allowances before init-node. Prepared allocations are zero. Use an existing participant-owned authenticated home and source-pinned native Codex 0.159.2."}))
        }
        Some("init-node") if args.len()==2 => Node::initialize(node::read_config(Path::new(&args[1]))?, wall_time()?)?.status("initialized"),
        Some("node-run") if args.len()==2 => run_node(node::read_config(Path::new(&args[1]))?),
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
        _ => Err("usage: naome-research prepare-node DIRECTORY NATIVE_CODEX CODEX_HOME MODEL | init-node CONFIG | node-run CONFIG | node-status CONFIG | node-submit CONFIG SIGNED_ACTION | node-questions CONFIG CURSOR | node-artifact CONFIG ARTIFACT_ID | node-replay CONFIG NEW_DIRECTORY [EXPECTED_HEAD EXPECTED_COUNT] | demo DIRECTORY | prepare DIRECTORY CODEX_HOME MODEL [--shared-plan-sample] | run CONFIG | provider-info CONFIG | replay HISTORY_DIRECTORY [EXPECTED_HEAD EXPECTED_COUNT]".into()),
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
    let result = node.run(&control);
    control.stop();
    listener
        .join()
        .map_err(|_| "node signal listener failed")??;
    result
}
