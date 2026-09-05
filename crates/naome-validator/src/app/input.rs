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
    Status {
        id: u64,
    },
    Shutdown {
        id: u64,
    },
    AuthorFresh {
        id: u64,
        block_file: PathBuf,
        payload_file: PathBuf,
    },
    AuthorRetained {
        id: u64,
        payload_file: PathBuf,
    },
    SubmitVote {
        id: u64,
        vote_file: PathBuf,
    },
    SubmitProposal {
        id: u64,
        control_file: PathBuf,
        payload_file: PathBuf,
    },
}

impl Command {
    pub fn id(&self) -> u64 {
        match self {
            Self::Status { id }
            | Self::Shutdown { id }
            | Self::AuthorFresh { id, .. }
            | Self::AuthorRetained { id, .. }
            | Self::SubmitVote { id, .. }
            | Self::SubmitProposal { id, .. } => *id,
        }
    }
}

pub(super) enum Input {
    Line(Vec<u8>),
    End(&'static str),
}

pub(super) fn start() -> Result<mpsc::Receiver<Input>> {
    let (sender, receiver) = mpsc::channel(1);
    // This dedicated thread owns no signer, runtime, or journal. It is not a
    // Tokio blocking task: process exit must not wait for an open stdin pipe.
    std::thread::Builder::new()
        .name("validator-input".into())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Cursor};

    #[test]
    fn bounded_framing_preserves_split_lines_and_refuses_unterminated_suffixes() {
        let mut reader = BufReader::with_capacity(2, Cursor::new(b"abc\ndef\n"));
        assert!(matches!(frame(&mut reader), Input::Line(bytes) if bytes == b"abc"));
        assert!(matches!(frame(&mut reader), Input::Line(bytes) if bytes == b"def"));
        assert!(matches!(frame(&mut reader), Input::End("eof")));
        assert!(matches!(
            frame(&mut Cursor::new(b"abc")),
            Input::End("input_truncated")
        ));
        let oversized = vec![b'x'; COMMAND_MAX_BYTES + 1];
        assert!(matches!(
            frame(&mut Cursor::new(oversized)),
            Input::End("input_too_large")
        ));
    }
}
