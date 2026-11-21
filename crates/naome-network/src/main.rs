mod lifecycle;
mod node;
mod quota;
mod wire;

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use libp2p::identity;
use naome_protocol::{
    cli::{self, ArchiveCommand},
    store::Archive,
    wire::Format,
};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Operate a Research Evidence Protocol node and its archive"
)]
struct Cli {
    /// Node directory (also NAOME_NODE_DIR).
    #[arg(long, global = true)]
    directory: Option<PathBuf>,
    /// Emit machine-readable lifecycle results. Archive results already use JSON.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the node in the background and wait for its network listener.
    Start,
    /// Wait for the node to finish local work and shut down.
    Stop,
    /// Read live connection and replication state.
    Status,
    /// Store, inspect, evaluate and publish research evidence.
    Archive {
        #[arg(long, global = true, value_enum, default_value = "a")]
        format: Format,
        #[command(subcommand)]
        command: ArchiveCommand,
    },
    #[command(hide = true)]
    Serve,
}

fn directory(explicit: Option<PathBuf>) -> Result<PathBuf> {
    explicit
        .or_else(|| std::env::var_os("NAOME_NODE_DIR").map(PathBuf::from))
        .or_else(|| std::env::var_os("XDG_DATA_HOME").map(|p| PathBuf::from(p).join("naome-rep")))
        .or_else(|| {
            std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share/naome-rep"))
        })
        .context("select a node directory with --directory or NAOME_NODE_DIR")
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

fn initialize(dir: &Path) -> Result<identity::Keypair> {
    std::fs::create_dir_all(dir)?;
    let previously_running =
        dir.join("events.jsonl").try_exists()? || dir.join("node.log").try_exists()?;
    let key = identity(dir, !previously_running).context("open node identity")?;
    Archive::open(dir.join("archive.sqlite"))?;
    let path = dir.join("node.json");
    if !path.exists() {
        let mut file = tempfile::NamedTempFile::new_in(dir)?;
        writeln!(file, r#"{{"listen":"/ip4/127.0.0.1/tcp/0","peers":[]}}"#)?;
        file.as_file().sync_all()?;
        if let Err(e) = file.persist_noclobber(path)
            && e.error.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(e.into());
        }
    }
    Ok(key)
}

fn execute(args: Cli) -> Result<()> {
    let dir = directory(args.directory)?;
    let status = match args.command {
        Command::Archive {
            command: ArchiveCommand::Init,
            ..
        } => {
            let peer = initialize(&dir)?.public().to_peer_id();
            println!(
                "{}",
                serde_json::json!({"peer_id":peer.to_string(),"directory":dir})
            );
            return Ok(());
        }
        Command::Archive { format, command } => {
            std::fs::create_dir_all(&dir)?;
            return cli::run(command, dir.join("archive.sqlite"), format);
        }
        Command::Serve => return lifecycle::serve(&dir),
        Command::Start => lifecycle::start(&dir)?,
        Command::Stop => lifecycle::stop(&dir)?,
        Command::Status => lifecycle::status(&dir)?,
    };
    status.print(args.json)
}

fn main() -> std::process::ExitCode {
    let args = Cli::parse();
    let json = args.json;
    match execute(args) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            if json {
                eprintln!("{}", serde_json::json!({"error":format!("{e:#}")}));
            } else {
                eprintln!("Error: {e:#}");
            }
            std::process::ExitCode::FAILURE
        }
    }
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
