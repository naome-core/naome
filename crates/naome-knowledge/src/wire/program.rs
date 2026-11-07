//! Program packages carry the same canonical manifest and records as storage.
use super::{Body, Message};
use crate::object::ProgramMetadata;
use naome_proof::program::{Chunk, Manifest};

pub(super) fn binary(body: &Body) -> bool {
    matches!(
        body,
        Body::ProgramData { .. } | Body::ProgramDescription { .. } | Body::ProgramOffer { .. }
    )
}

pub(super) fn encode(message: &Message) -> Result<Vec<u8>, String> {
    let mut bytes = message.compatibility.to_vec();
    match &message.body {
        Body::ProgramData { root, id, chunk } => {
            bytes.push(0);
            bytes.extend_from_slice(root);
            bytes.extend_from_slice(id);
            bytes.extend(chunk.canonical_bytes()?);
        }
        Body::ProgramDescription { root, metadata } => {
            bytes.push(1);
            bytes.push(u8::from(root.is_some()));
            if let Some(root) = root {
                bytes.extend_from_slice(root);
            }
            write_metadata(metadata, &mut bytes)?;
        }
        Body::ProgramOffer { metadata } => {
            bytes.push(2);
            write_metadata(metadata, &mut bytes)?;
        }
        _ => return Err("expected a binary program frame".into()),
    }
    Ok(bytes)
}

fn write_metadata(metadata: &ProgramMetadata, bytes: &mut Vec<u8>) -> Result<(), String> {
    let manifest = metadata.manifest.canonical_bytes()?;
    bytes.push(manifest.len() as u8);
    bytes.extend(manifest);
    bytes.push(u8::from(metadata.question.is_some()));
    if let Some(question) = &metadata.question {
        if question.len() > naome_authoring::QUESTION_SOURCE_MAX_BYTES {
            return Err("program question byte capacity".into());
        }
        bytes.extend_from_slice(question.as_bytes());
    }
    Ok(())
}

pub(super) fn decode(mut bytes: &[u8]) -> Result<Message, String> {
    let compatibility = take::<32>(&mut bytes)?;
    let body = match take::<1>(&mut bytes)?[0] {
        0 => Body::ProgramData {
            root: take::<32>(&mut bytes)?,
            id: take::<32>(&mut bytes)?,
            chunk: Chunk::from_canonical_bytes(bytes)?,
        },
        1 => {
            let root = if flag(&mut bytes)? {
                Some(take::<32>(&mut bytes)?)
            } else {
                None
            };
            Body::ProgramDescription {
                root,
                metadata: read_metadata(bytes)?,
            }
        }
        2 => Body::ProgramOffer {
            metadata: read_metadata(bytes)?,
        },
        _ => return Err("unknown binary program frame kind".into()),
    };
    Ok(Message {
        compatibility,
        body,
    })
}

fn read_metadata(mut bytes: &[u8]) -> Result<ProgramMetadata, String> {
    let [size] = take(&mut bytes)?;
    let (manifest, mut remainder) = bytes
        .split_at_checked(usize::from(size))
        .ok_or("truncated program manifest")?;
    let manifest = Manifest::from_canonical_bytes(manifest)?;
    let question = if flag(&mut remainder)? {
        if remainder.len() > naome_authoring::QUESTION_SOURCE_MAX_BYTES {
            return Err("program question byte capacity".into());
        }
        Some(
            std::str::from_utf8(remainder)
                .map_err(|e| e.to_string())?
                .to_owned(),
        )
    } else if remainder.is_empty() {
        None
    } else {
        return Err("trailing program metadata".into());
    };
    Ok(ProgramMetadata { manifest, question })
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], String> {
    let (field, rest) = bytes.split_at_checked(N).ok_or("truncated program frame")?;
    *bytes = rest;
    Ok(field.try_into().expect("fixed program field width"))
}

fn flag(bytes: &mut &[u8]) -> Result<bool, String> {
    match take::<1>(bytes)?[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err("invalid program frame flag".into()),
    }
}
