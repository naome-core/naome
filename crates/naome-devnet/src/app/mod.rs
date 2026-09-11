use serde_json::Value;
use std::{env, path::Path};

mod config;
mod files;
mod verify;
mod workload;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) const MAX_HEIGHTS: usize = 128;

pub(super) fn run() -> Result<Value> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, plan, output] if command == "init" => {
            config::init(Path::new(plan), Path::new(output))
        }
        [command, role, height] if command == "publish" => {
            workload::publish(Path::new(role), height.parse()?)
        }
        [command, role, height] if command == "verify" => {
            verify::verify(Path::new(role), height.parse()?)
        }
        _ => Err("usage: naome-devnet init PLAN.json NEW_DIRECTORY | publish PUBLISHER_DIRECTORY HEIGHT | verify STOPPED_VALIDATOR_DIRECTORY HEIGHT".into()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected canonical 32-byte hexadecimal value".into());
    }
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
