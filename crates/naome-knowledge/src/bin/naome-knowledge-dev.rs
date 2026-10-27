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
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
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
                "discovery":network::DiscoveryConfig::default(),"producer_sources":[]}}));
            Ok(())
        },
        ["relay", config] => naome_knowledge::relay::run(Path::new(config)).await,
        ["run", config, options @ ..] => {
            let test_controls = match options {
                [] => false,
                [option] if *option == "--test-controls" => true,
                _ => return Err("invalid run option; use --test-controls".into()),
            };
            network::run(network::read_config(Path::new(config))?, test_controls).await
        },
        ["training", "--help"] => { println!("{}", naome_knowledge::training::HELP); Ok(()) },
        ["training", directory, request] => naome_knowledge::training::run(Path::new(directory), Path::new(request)),
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
        _ => Err("usage: naome-knowledge init <directory> | run <config.json> [--test-controls] | relay <config.json> | contract | training <node-directory> <request.json> | training --help\nrun consumes bounded newline-delimited JSON commands: status (optional after ArtifactId; ids, next_after, status_page_ids, accepted_artifacts), produce, ingest, object, describe, links, announce, offer, stop".into()),
    }
}
