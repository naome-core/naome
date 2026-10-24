use libp2p::identity;
use naome_knowledge::{CHECKER_ID, CODEC_ID, GRAPH_POLICY_ID, compatibility, hex, network};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = naome_knowledge::resources::initialize_from_environment() {
        eprintln!("{error}");
        std::process::exit(1);
    }
    if let Err(error) = execute().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn execute() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| {
        matches!(
            arg.as_str(),
            "--decision-supervisor-v1" | "--decision-worker-v1"
        )
    }) {
        return naome_knowledge::runtime::execute().await;
    }
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["decision-screen", directory, cases, output] => naome_knowledge::decision::screen::run(Path::new(directory), Path::new(cases), Path::new(output)).await,
        ["decision-probe", directory, python] => {
            tokio::time::timeout(std::time::Duration::from_secs(40), naome_knowledge::decision::probe::run(Path::new(directory),Path::new(python))).await.map_err(|_|"decision protocol probe deadline")?
        },
        ["interest-screen", directory, cases, output] => naome_knowledge::interest::screen::run(Path::new(directory), Path::new(cases), Path::new(output)).await,
        ["init", directory] => {
            let directory = Path::new(directory);
            fs::create_dir_all(directory).map_err(|error|error.to_string())?;
            let key = identity::Keypair::generate_ed25519();
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
            let mut file = options.open(directory.join("identity.key")).map_err(|error|error.to_string())?;
            file.write_all(&key.to_protobuf_encoding().map_err(|error|error.to_string())?)
                .and_then(|_|file.sync_all()).map_err(|error|error.to_string())?;
            println!("{}",json!({"peer_id":key.public().to_peer_id().to_string(),
                "config":{"directory":fs::canonicalize(directory).map_err(|error|error.to_string())?, "listen":"/ip4/0.0.0.0/tcp/0", "peers":[],
                "discovery":{"mdns":true,"dht":false,"bootstrap":[],"relays":[],"hole_punch":true,"relay_only":false,"external_addresses":[]},"producer_sources":[]}}));
            Ok(())
        },
        ["relay", config] => naome_knowledge::relay::run(Path::new(config)).await,
        ["run", config, options @ ..] => {
            let (test_controls, selection) = interest_options(options)?;
            network::run_with_interest(network::read_config(Path::new(config))?,test_controls,selection).await
        },
        ["contract"] => {
            println!("{}",json!({"foundation":naome_foundation::FOUNDATION_ID, "codec":CODEC_ID, "checker":CHECKER_ID,
                "policy":GRAPH_POLICY_ID,"compatibility":hex(&compatibility()),"routing":network::routing_contract(),"limits":{
                    "proof_bytes":naome_knowledge::resources::limits().proof_bytes,"dependencies":naome_knowledge::resources::limits().proof_dependencies,"dependency_depth":"derived; no configured ceiling",
                    "pending":naome_knowledge::resources::limits().pending_page,"dependency_timeout_seconds":naome_knowledge::resources::limits().pending_retry.as_secs(),
                    "checked_cache_bytes":naome_knowledge::resources::limits().checked_cache_bytes,
                    "inventory_page_ids":naome_knowledge::resources::limits().inventory_page,
                    "status_page_ids":naome_knowledge::resources::limits().status_page,
                    "config_bytes":naome_knowledge::resources::limits().network_config_bytes,
                    "command_bytes":naome_knowledge::resources::limits().command_bytes,
                    "peers":naome_knowledge::resources::limits().configured_peers,"fetches":naome_knowledge::resources::limits().fetches,"inflight_requests":naome_knowledge::resources::limits().flights,
                    "inflight_requests_per_peer":naome_knowledge::resources::limits().flights_per_peer,
                    "request_timeout_seconds":naome_knowledge::resources::limits().request_timeout.as_secs(),"reconcile_seconds":naome_knowledge::resources::limits().reconcile_interval.as_secs()}}));
            Ok(())
        },
        _ => Err("usage: naome-knowledge init <directory> | run <config.json> [--test-controls] [--question-interest all | --question-interest-file <questions.json>] | relay <config.json> | contract\nrun consumes bounded newline-delimited JSON commands: status (optional after ProofId; ids, next_after, accepted_proofs), produce, ingest, object, describe, links, announce, offer, stop\npeer proof exchange requires an explicit positive question interest selector".into()),
    }
}

fn interest_options(
    mut options: &[&str],
) -> Result<(bool, Option<network::InterestSelection>), String> {
    let mut test_controls = false;
    let mut selection = None;
    while !options.is_empty() {
        match options {
            ["--test-controls", rest @ ..] if !test_controls => {
                test_controls = true;
                options = rest;
            }
            ["--question-interest", "all", rest @ ..] if selection.is_none() => {
                selection = Some(network::InterestSelection::AllSupported);
                options = rest;
            }
            ["--question-interest-file", file, rest @ ..] if selection.is_none() => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Selected {
                    questions: Vec<String>,
                }
                let selected: Selected = serde_json::from_slice(&read_interest(Path::new(file))?)
                    .map_err(|error| error.to_string())?;
                if selected.questions.len()
                    > naome_knowledge::resources::limits().developer_questions
                {
                    return Err("question interest count limit".into());
                }
                let questions = selected
                    .questions
                    .into_iter()
                    .map(|source| {
                        naome_authoring::CompiledQuestion::compile(&source)
                            .map_err(|error| error.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                selection = Some(network::InterestSelection::Questions(questions));
                options = rest;
            }
            _ => {
                return Err(
                    "invalid or duplicate run option; use one explicit question interest selector"
                        .into(),
                );
            }
        }
    }
    Ok((test_controls, selection))
}

fn read_interest(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("expected regular question interest file".into());
    }
    file.take(naome_knowledge::resources::limits().producer_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > naome_knowledge::resources::limits().producer_bytes {
        return Err("question interest file byte limit".into());
    }
    Ok(bytes)
}
