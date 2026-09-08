use std::{
    io::{self, BufRead},
    path::PathBuf,
};

use serde::Deserialize;
use tokio::sync::mpsc;

use super::Result;

pub(super) const COMMAND_MAX_BYTES: usize = 65_536;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Import {
        id: u64,
        envelope_file: PathBuf,
        payload_file: PathBuf,
    },
    Status {
        id: u64,
    },
    Record {
        id: u64,
        height: u64,
    },
    Sync {
        id: u64,
        peer_id: String,
        count: u64,
    },
    FollowFinality {
        id: u64,
        peer_id: String,
        count: u64,
        interval_millis: String,
    },
    CancelSync {
        id: u64,
    },
    Shutdown {
        id: u64,
    },
}

impl Command {
    pub fn parse(bytes: &[u8]) -> serde_json::Result<Self> {
        // Preserve duplicate fields and require an object. Derived Serde
        // structures also accept positional sequences unless constrained.
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = Command;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a command object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                map: M,
            ) -> std::result::Result<Command, M::Error> {
                Command::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let command = serde::Deserializer::deserialize_map(&mut deserializer, Object)?;
        deserializer.end()?;
        Ok(command)
    }

    pub fn id(&self) -> u64 {
        match self {
            Self::Import { id, .. }
            | Self::Status { id }
            | Self::Record { id, .. }
            | Self::Sync { id, .. }
            | Self::FollowFinality { id, .. }
            | Self::CancelSync { id }
            | Self::Shutdown { id } => *id,
        }
    }
}

pub(super) enum Input {
    Line(Vec<u8>),
    End(&'static str),
}

pub(super) fn start() -> Result<mpsc::Receiver<Input>> {
    let (sender, receiver) = mpsc::channel(1);
    // This bounded reader owns no journal. A partial line cannot prevent the
    // executor from handling termination and dropping the journal owner.
    std::thread::Builder::new()
        .name("verifier-input".into())
        .spawn(move || {
            let stdin = io::stdin();
            let mut reader = stdin.lock();
            loop {
                let input = frame(&mut reader);
                let ended = matches!(input, Input::End(_));
                if sender.blocking_send(input).is_err() || ended {
                    break;
                }
            }
        })
        .map_err(|_| "input_thread")?;
    Ok(receiver)
}

fn frame(reader: &mut impl BufRead) -> Input {
    let mut line = Vec::new();
    loop {
        let available = match reader.fill_buf() {
            Ok(bytes) => bytes,
            Err(_) => return Input::End("input_read"),
        };
        if available.is_empty() {
            return Input::End(if line.is_empty() {
                "eof"
            } else {
                "input_truncated"
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.unwrap_or(available.len());
        if count > COMMAND_MAX_BYTES - line.len() {
            return Input::End("input_too_large");
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count + usize::from(newline.is_some()));
        if newline.is_some() {
            return Input::Line(line);
        }
    }
}
