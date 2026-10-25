//! Local wallet presentation; verification never needs a node or private key.
use crate::wallet as store;
use naome_wallet::{Address, OwnershipChallenge, OwnershipProof};
use serde::Serialize;
use std::{ffi::OsString, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

const INPUT_MAX_BYTES: u64 = 4096;
const USAGE: &str = "usage: naome [--json] wallet address | wallet challenge <audience> | wallet prove <challenge.json> | wallet verify <address> <challenge.json> <proof.json>";

fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|error| error.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("wallet input must be a regular JSON file".into());
    }
    let mut bytes = Vec::new();
    file.take(INPUT_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > INPUT_MAX_BYTES {
        return Err("wallet JSON input exceeds 4096 bytes".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn print(value: &impl Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(value).map_err(|e| e.to_string())?
    );
    Ok(())
}

pub(super) fn execute(arguments: &[OsString], json: bool) -> Result<(), String> {
    match arguments {
        [command] if command == "address" => {
            let identity = store::identity(&super::directory()?)?
                .ok_or("wallet is not initialized; start the node first")?;
            if json {
                print(&identity)
            } else {
                println!("{}", identity.address);
                Ok(())
            }
        }
        [command, audience] if command == "challenge" => {
            let audience = audience.to_str().ok_or("wallet audience must be UTF-8")?;
            print(&OwnershipChallenge::new(audience.into())?)
        }
        [command, challenge] if command == "prove" => {
            let challenge: OwnershipChallenge = read(Path::new(challenge))?;
            print(&store::prove(&super::directory()?, challenge)?)
        }
        [command, address, challenge, proof] if command == "verify" => {
            let address: Address = address
                .to_str()
                .ok_or("wallet address must be UTF-8")?
                .parse()?;
            let challenge: OwnershipChallenge = read(Path::new(challenge))?;
            let proof: OwnershipProof = read(Path::new(proof))?;
            proof.verify(address, &challenge)?;
            print(&serde_json::json!({
                "address": address,
                "verified": true,
                "scope": "wallet_key_control"
            }))
        }
        _ => Err(USAGE.into()),
    }
}
