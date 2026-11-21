mod node;
mod quota;
mod wire;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use libp2p::identity;
use naome_protocol::{store::Archive, wire::Id};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(about = "Replicate released Research Evidence Protocol inventories")]
struct Cli {
    #[arg(long)]
    directory: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or read a persistent Ed25519 transport identity.
    Init,
    /// Release a complete readable inventory to all configured replicas.
    Publish { head: Id },
    /// Print the locally published and completely mirrored inventory identifiers.
    Heads,
    /// Listen and reconcile with the configured peers.
    Run { config: PathBuf },
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "file exceeds limit");
    Ok(bytes)
}

fn identity(directory: &Path, create: bool) -> Result<identity::Keypair> {
    let path = directory.join("identity.key");
    if create && !path.exists() {
        let key = identity::Keypair::generate_ed25519();
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        file.write_all(&key.to_protobuf_encoding()?)?;
        file.as_file().sync_all()?;
        if let Err(e) = file.persist_noclobber(&path)
            && e.error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(e.into());
        }
    }
    Ok(identity::Keypair::from_protobuf_encoding(&read_bounded(
        &path, 1024,
    )?)?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let dir = &cli.directory;
    if matches!(cli.command, Command::Init) {
        std::fs::create_dir_all(dir)?;
        let key = identity(dir, true)?;
        Archive::open(dir.join("archive.sqlite"))?;
        println!("{}", key.public().to_peer_id());
        return Ok(());
    }
    ensure!(
        dir.join("archive.sqlite").is_file(),
        "initialize the node directory first"
    );
    let archive = Archive::open(dir.join("archive.sqlite"))?;
    match cli.command {
        Command::Init => unreachable!(),
        Command::Publish { head } => {
            archive.release(head)?;
            println!("{head}");
        }
        Command::Heads => println!("{}", serde_json::to_string(&archive.releases()?)?),
        Command::Run { config } => {
            let config = serde_json::from_slice(&read_bounded(&config, 16_384)?)
                .context("invalid peer configuration")?;
            node::run(
                archive,
                dir.join("archive.sqlite"),
                identity(dir, false)?,
                config,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_configuration_rejects_before_decoding_and_identity_survives_restart() -> Result<()>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("oversized.json");
        std::fs::write(&path, vec![b' '; 16_385])?;
        assert!(read_bounded(&path, 16_384).is_err());
        let peer = identity(dir.path(), true)?.public().to_peer_id();
        assert_eq!(identity(dir.path(), false)?.public().to_peer_id(), peer);
        assert_eq!(identity(dir.path(), true)?.public().to_peer_id(), peer);
        Ok(())
    }
}
