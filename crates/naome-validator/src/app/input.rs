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
    DiscardInbox {
        id: u64,
        inbox: InboxClass,
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
    AdvanceHigherQuorum {
        id: u64,
        certificate_file: PathBuf,
    },
    AdvanceHigherVotes {
        id: u64,
        evidence_round: u64,
        role: VoteRole,
        target: VoteTarget,
        vote_files: Vec<PathBuf>,
    },
    FinalizeCurrentQuorum {
        id: u64,
        control_file: PathBuf,
        payload_file: PathBuf,
        certificate_file: PathBuf,
    },
    FinalizeCurrentVotes {
        id: u64,
        #[serde(deserialize_with = "object")]
        proof: ProposalVoteFiles,
    },
    FinalizeLowerQuorum {
        id: u64,
        control_file: PathBuf,
        payload_file: PathBuf,
        certificate_file: PathBuf,
    },
    FinalizeLowerVotes {
        id: u64,
        evidence_round: u64,
        #[serde(deserialize_with = "object")]
        proof: ProposalVoteFiles,
    },
    HaltLowerConflict {
        id: u64,
        evidence_round: u64,
        #[serde(deserialize_with = "object")]
        first: ProposalVoteFiles,
        #[serde(deserialize_with = "object")]
        second: ProposalVoteFiles,
    },
    HaltHistoricalEnvelope {
        id: u64,
        envelope_file: PathBuf,
        payload_file: PathBuf,
    },
    HaltHistoricalVotes {
        id: u64,
        evidence_round: u64,
        #[serde(deserialize_with = "object")]
        proof: ProposalVoteFiles,
    },
    HaltCurrentConflict {
        id: u64,
        #[serde(deserialize_with = "object")]
        first: ProposalVoteFiles,
        #[serde(deserialize_with = "object")]
        second: ProposalVoteFiles,
    },
}

#[derive(Clone, Copy, Deserialize, serde::Serialize)]
#[serde(try_from = "String", rename_all = "snake_case")]
pub(super) enum InboxClass {
    Higher,
    Current,
    Finality,
    NilPrecommit,
}

impl TryFrom<String> for InboxClass {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self> {
        match value.as_str() {
            "higher" => Ok(Self::Higher),
            "current" => Ok(Self::Current),
            "finality" => Ok(Self::Finality),
            "nil_precommit" => Ok(Self::NilPrecommit),
            _ => Err("inbox_class"),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProposalVoteFiles {
    pub control_file: PathBuf,
    pub payload_file: PathBuf,
    pub vote_files: Vec<PathBuf>,
}

#[derive(Deserialize)]
#[serde(try_from = "String")]
pub(super) enum VoteRole {
    Prevote,
    Precommit,
}

impl TryFrom<String> for VoteRole {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self> {
        match value.as_str() {
            "prevote" => Ok(Self::Prevote),
            "precommit" => Ok(Self::Precommit),
            _ => Err("proof_role"),
        }
    }
}

pub(super) enum VoteTarget {
    Nil {},
    Proposal { root: String },
}

impl<'de> Deserialize<'de> for VoteTarget {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Target;
        impl<'de> serde::de::Visitor<'de> for Target {
            type Value = VoteTarget;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a vote target object")
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> std::result::Result<VoteTarget, M::Error> {
                let mut kind = None;
                let mut root = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "kind" if kind.is_none() => kind = Some(map.next_value::<String>()?),
                        "kind" => return Err(serde::de::Error::duplicate_field("kind")),
                        "root" if root.is_none() => root = Some(map.next_value::<String>()?),
                        "root" => return Err(serde::de::Error::duplicate_field("root")),
                        _ => return Err(serde::de::Error::custom("unexpected vote target field")),
                    }
                }
                // Decode the discriminator as a String, not a buffered enum
                // identifier, which would also accept numeric variant indexes.
                match (kind.as_deref(), root) {
                    (Some("nil"), None) => Ok(VoteTarget::Nil {}),
                    (Some("proposal"), Some(root)) => Ok(VoteTarget::Proposal { root }),
                    _ => Err(serde::de::Error::custom("invalid vote target")),
                }
            }
        }
        deserializer.deserialize_map(Target)
    }
}

impl Command {
    pub fn parse(bytes: &[u8]) -> serde_json::Result<Self> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let command = object(&mut deserializer)?;
        deserializer.end()?;
        Ok(command)
    }

    pub fn id(&self) -> u64 {
        match self {
            Self::Status { id }
            | Self::Shutdown { id }
            | Self::DiscardInbox { id, .. }
            | Self::AuthorFresh { id, .. }
            | Self::AuthorRetained { id, .. }
            | Self::SubmitVote { id, .. }
            | Self::SubmitProposal { id, .. }
            | Self::AdvanceHigherQuorum { id, .. }
            | Self::AdvanceHigherVotes { id, .. }
            | Self::FinalizeCurrentQuorum { id, .. }
            | Self::FinalizeCurrentVotes { id, .. }
            | Self::FinalizeLowerQuorum { id, .. }
            | Self::FinalizeLowerVotes { id, .. }
            | Self::HaltLowerConflict { id, .. }
            | Self::HaltHistoricalEnvelope { id, .. }
            | Self::HaltHistoricalVotes { id, .. }
            | Self::HaltCurrentConflict { id, .. } => *id,
        }
    }
}

/// Serde's derived enums/structs also accept sequences. Require an object at
/// each JSON object boundary, forwarding the original map entries so duplicate
/// fields still fail rather than being collapsed by a Value intermediate.
fn object<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Object<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Object<T> {
        type Value = T;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an object")
        }

        fn visit_map<M>(self, map: M) -> std::result::Result<T, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
        }
    }
    deserializer.deserialize_map(Object(std::marker::PhantomData))
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
