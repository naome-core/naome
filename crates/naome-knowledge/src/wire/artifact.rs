//! Artifact frames transport bounded canonical payloads as binary blocks.
use super::{Body, Message};
use crate::{
    Envelope,
    object::{ProgramMetadata, id_bytes},
};
use lz4_flex::block;
use naome_proof::program::{Chunk, Manifest};
use std::sync::Arc;

const PACKED: u32 = 1 << 31;
type Leases = Vec<Arc<crate::resources::MemoryLease>>;

pub(super) fn binary(body: &Body) -> bool {
    matches!(
        body,
        Body::ProgramData { .. }
            | Body::ProgramDescription { .. }
            | Body::ProgramOffer { .. }
            | Body::Object { .. }
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
        Body::Object {
            root,
            object,
            question,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(root);
            write_object(object, question.as_deref(), &mut bytes)?;
        }
        _ => return Err("expected a binary artifact frame".into()),
    }
    Ok(bytes)
}

fn write_object(
    object: &Envelope,
    question: Option<&str>,
    bytes: &mut Vec<u8>,
) -> Result<(), String> {
    let id = |value| id_bytes(value).map_err(|error| error.to_string());
    bytes.extend_from_slice(&id(&object.compatibility)?);
    bytes.extend_from_slice(&id(&object.artifact_id)?);
    for value in [
        object.statement_id.as_deref(),
        object.obligation_proof.as_deref(),
    ] {
        bytes.push(u8::from(value.is_some()));
        if let Some(value) = value {
            bytes.extend_from_slice(&id(value)?);
        }
    }
    write_blob(
        &object.payload,
        crate::resources::limits().proof_bytes,
        bytes,
    )?;
    write_question(question, bytes)
}

fn read_object(
    mut bytes: &[u8],
    leases: &mut Leases,
) -> Result<(Envelope, Option<String>), String> {
    let compatibility = crate::hex(&take::<32>(&mut bytes)?);
    let artifact_id = crate::hex(&take::<32>(&mut bytes)?);
    let mut optional_id = || -> Result<Option<String>, String> {
        if flag(&mut bytes)? {
            Ok(Some(crate::hex(&take::<32>(&mut bytes)?)))
        } else {
            Ok(None)
        }
    };
    let statement_id = optional_id()?;
    let obligation_proof = optional_id()?;
    let payload = read_blob(&mut bytes, crate::resources::limits().proof_bytes, leases)?;
    let question = read_question(bytes, leases)?;
    Ok((
        Envelope {
            compatibility,
            artifact_id,
            statement_id,
            obligation_proof,
            payload,
        },
        question,
    ))
}

fn write_blob(source: &str, maximum: usize, bytes: &mut Vec<u8>) -> Result<(), String> {
    if source.is_empty() || source.len() > 2 * maximum {
        return Err("artifact frame payload capacity".into());
    }
    let length = source.len() / 2;
    let _work =
        crate::resources::MemoryLease::acquire(length + block::get_maximum_output_size(length))
            .map_err(|error| error.to_string())?;
    let raw = crate::unhex(source).map_err(|error| error.to_string())?;
    let packed = block::compress(&raw);
    if packed.len() + 4 < raw.len() {
        bytes.extend_from_slice(&(packed.len() as u32 | PACKED).to_be_bytes());
        bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        bytes.extend(packed);
    } else {
        bytes.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        bytes.extend(raw);
    }
    Ok(())
}

fn read_blob(bytes: &mut &[u8], maximum: usize, leases: &mut Leases) -> Result<String, String> {
    let header = u32::from_be_bytes(take(bytes)?);
    let encoded = (header & !PACKED) as usize;
    let packed = header & PACKED != 0;
    let length = if packed {
        u32::from_be_bytes(take(bytes)?) as usize
    } else {
        encoded
    };
    if encoded == 0 || length > maximum || (packed && encoded + 4 >= length) {
        return Err("artifact frame payload capacity".into());
    }
    let (data, remainder) = bytes
        .split_at_checked(encoded)
        .ok_or("truncated artifact frame payload")?;
    *bytes = remainder;
    if !packed {
        return Ok(crate::hex(data));
    }
    let lease =
        crate::resources::MemoryLease::acquire(3 * length).map_err(|error| error.to_string())?;
    let mut raw = vec![0; length];
    let written = block::decompress_into(data, &mut raw).map_err(|error| error.to_string())?;
    if written != length {
        return Err("artifact frame expanded length differs".into());
    }
    leases.push(lease);
    Ok(crate::hex(&raw))
}

fn write_question(question: Option<&str>, bytes: &mut Vec<u8>) -> Result<(), String> {
    bytes.push(u8::from(question.is_some()));
    if let Some(question) = question {
        write_blob(question, naome_checker::question::QUESTION_BYTES, bytes)?;
    }
    Ok(())
}

fn read_question(mut bytes: &[u8], leases: &mut Leases) -> Result<Option<String>, String> {
    let question = if flag(&mut bytes)? {
        Some(read_blob(
            &mut bytes,
            naome_checker::question::QUESTION_BYTES,
            leases,
        )?)
    } else {
        None
    };
    if !bytes.is_empty() {
        return Err("trailing artifact frame bytes".into());
    }
    Ok(question)
}

fn write_metadata(metadata: &ProgramMetadata, bytes: &mut Vec<u8>) -> Result<(), String> {
    let manifest = metadata.manifest.canonical_bytes()?;
    bytes.push(manifest.len() as u8);
    bytes.extend(manifest);
    write_question(metadata.question.as_deref(), bytes)
}

pub(super) fn decode(mut bytes: &[u8]) -> Result<(Message, Leases), String> {
    let mut leases = Leases::new();
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
                metadata: read_metadata(bytes, &mut leases)?,
            }
        }
        2 => Body::ProgramOffer {
            metadata: read_metadata(bytes, &mut leases)?,
        },
        3 => {
            let root = take::<32>(&mut bytes)?;
            let (object, question) = read_object(bytes, &mut leases)?;
            Body::Object {
                root,
                object,
                question,
            }
        }
        _ => return Err("unknown binary artifact frame kind".into()),
    };
    Ok((
        Message {
            compatibility,
            body,
        },
        leases,
    ))
}

fn read_metadata(mut bytes: &[u8], leases: &mut Leases) -> Result<ProgramMetadata, String> {
    let [size] = take(&mut bytes)?;
    let (manifest, remainder) = bytes
        .split_at_checked(usize::from(size))
        .ok_or("truncated program manifest")?;
    let manifest = Manifest::from_canonical_bytes(manifest)?;
    let question = read_question(remainder, leases)?;
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
