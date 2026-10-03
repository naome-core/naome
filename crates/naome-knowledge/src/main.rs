use libp2p::identity;
use naome_knowledge::{
    CHECKER_ID, CODEC_ID, GRAPH_POLICY_ID, MAX_ACCEPTED_BYTES, MAX_CONTEXT_BYTES, MAX_DEPENDENCIES,
    MAX_DEPTH, MAX_OBJECTS, MAX_PENDING, MAX_PROOF_BYTES, PENDING_TTL, compatibility, hex, network,
};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
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
            println!("{}",json!({"peer_id":key.public().to_peer_id().to_string()}));
            Ok(())
        },
        ["run", config] => network::run(network::read_config(Path::new(config))?,false).await,
        ["run", config, "--test-controls"] => network::run(network::read_config(Path::new(config))?,true).await,
        ["contract"] => {
            println!("{}",json!({"foundation":naome_foundation::FOUNDATION_ID, "codec":CODEC_ID, "checker":CHECKER_ID,
                "policy":GRAPH_POLICY_ID,"compatibility":hex(&compatibility()),"limits":{
                    "proof_bytes":MAX_PROOF_BYTES,"dependencies":MAX_DEPENDENCIES,"depth":MAX_DEPTH,"objects":MAX_OBJECTS,
                    "accepted_bytes":MAX_ACCEPTED_BYTES,"pending":MAX_PENDING,"dependency_timeout_seconds":PENDING_TTL.as_secs(),
                    "checked_context_bytes":MAX_CONTEXT_BYTES,
                    "peers":network::MAX_PEERS,"fetches":network::MAX_FETCHES,"inflight_requests":network::MAX_FLIGHTS,
                    "inflight_requests_per_peer":network::MAX_FLIGHTS_PER_PEER,
                    "request_timeout_seconds":network::REQUEST_TIMEOUT.as_secs(),"reconcile_seconds":network::RECONCILE_INTERVAL.as_secs()}}));
            Ok(())
        },
        _ => Err("usage: naome-knowledge init <directory> | run <config.json> [--test-controls] | contract\nrun consumes bounded newline-delimited JSON commands: status, produce, ingest, object, links, announce, offer, stop".into()),
    }
}
