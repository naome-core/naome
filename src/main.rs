use anyhow::Result;
use clap::Parser;
use naome_protocol::{
    cli::{self, ArchiveCommand},
    wire::Format,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    version,
    about = "Store, exchange and evaluate immutable research evidence"
)]
struct Cli {
    /// Local custody database. The operator controls this file and its disclosure policy.
    #[arg(long, global = true, default_value = "evidence.sqlite")]
    db: PathBuf,
    #[arg(long, global = true, value_enum, default_value = "a")]
    format: Format,
    #[command(subcommand)]
    command: ArchiveCommand,
}
fn main() -> Result<()> {
    let args = Cli::parse();
    cli::run(args.command, args.db, args.format)
}
