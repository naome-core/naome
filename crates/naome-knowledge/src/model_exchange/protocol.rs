use super::{Blob, Comparison, Profile, Registration};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "model_message", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Packet {
    Inspect {
        profile: Profile,
    },
    Manifest {
        registration: Registration,
        chunk_limit: usize,
    },
    Chunk {
        model: String,
        blob: Blob,
        offset: usize,
        length: usize,
    },
    ChunkData {
        model: String,
        blob: Blob,
        offset: usize,
        data: String,
    },
    Offer {
        comparison: Box<Comparison>,
    },
    Acknowledged,
}

impl Packet {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Inspect { .. } => "model_inspect",
            Self::Manifest { .. } => "model_manifest",
            Self::Chunk { .. } => "model_chunk",
            Self::ChunkData { .. } => "model_chunk_data",
            Self::Offer { .. } => "model_offer",
            Self::Acknowledged => "model_acknowledged",
        }
    }
}
pub(crate) fn chunk_limit() -> usize {
    // Leave headroom for base64, model/blob IDs and the existing frame header.
    (crate::resources::limits().proof_bytes / 2).min(64 * 1024)
}

pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn decode(data: &str, expected: usize) -> Result<Vec<u8>, String> {
    if expected == 0 || expected > chunk_limit() || data.len() != (expected * 4).div_ceil(3) {
        return Err("model wire chunk length differs".into());
    }
    let bytes = URL_SAFE_NO_PAD.decode(data).map_err(|e| e.to_string())?;
    if bytes.len() != expected {
        return Err("model wire chunk length differs".into());
    }
    Ok(bytes)
}
