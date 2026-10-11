//! Offline CPU BGE retrieval; model assets are explicitly provisioned separately.
//! Neither this adapter nor its vectors establish mathematical validity.

use super::semantic::{EncoderIdentity, SEMANTIC_REPRESENTATION_VERSION, SemanticEncoder};
use candle_core::{DType, Device, IndexOp, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokenizers::Tokenizer;

pub const MODEL_ID: &str = "BAAI/bge-small-en-v1.5";
pub const MODEL_REVISION: &str = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a";
pub const QUERY_PREFIX: &str = "Represent this sentence for searching relevant passages: ";
pub const DIMENSIONS: usize = 384;
pub const WINDOW_TOKENS: usize = 512;
pub const CONTENT_TOKENS: usize = WINDOW_TOKENS - 2;
pub const PREFIX_TOKENS: usize = 8;
pub const MAX_CHUNKS: usize = 256;
pub const MAX_INPUT_BYTES: usize = 256 * 1024;

/// Primary source and exact bytes of each required, separately installed asset.
#[derive(Clone, Debug, Serialize)]
pub struct ModelAsset {
    pub local_name: &'static str,
    pub upstream_path: &'static str,
    pub bytes: usize,
    pub sha256: &'static str,
}

pub const MODEL_ASSETS: [ModelAsset; 5] = [
    ModelAsset {
        local_name: "model.safetensors",
        upstream_path: "model.safetensors",
        bytes: 133_466_304,
        sha256: "3c9f31665447c8911517620762200d2245a2518d6e7208acc78cd9db317e21ad",
    },
    ModelAsset {
        local_name: "config.json",
        upstream_path: "config.json",
        bytes: 743,
        sha256: "094f8e891b932f2000c92cfc663bac4c62069f5d8af5b5278c4306aef3084750",
    },
    ModelAsset {
        local_name: "tokenizer.json",
        upstream_path: "tokenizer.json",
        bytes: 711_396,
        sha256: "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66",
    },
    ModelAsset {
        local_name: "pooling.json",
        upstream_path: "1_Pooling/config.json",
        bytes: 190,
        sha256: "d1caf60c96f5fba2157c0c26b76d80818fad6cf0b8eb5e73ec372ff9818eba5c",
    },
    ModelAsset {
        local_name: "model-card.md",
        upstream_path: "README.md",
        bytes: 94_783,
        sha256: "ddb964361a55c6e5dfca6361615854b260c9c960205d04c7520151aaa1d75837",
    },
];

/// Tokens are partitioned once without truncation or padding. Byte intervals
/// partition the original input, including tokenizer-normalized whitespace.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EmbeddedChunk {
    pub token_start: usize,
    pub token_end: usize,
    pub total_tokens: usize,
    pub byte_start: usize,
    pub byte_end: usize,
    pub vector: Vec<f32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChunkCoverage {
    pub token_start: usize,
    pub token_end: usize,
    pub total_tokens: usize,
    pub byte_start: usize,
    pub byte_end: usize,
}

pub(crate) struct PreparedDocument {
    ids: Vec<u32>,
    pub coverage: Vec<ChunkCoverage>,
}

/// One CPU-only model. Its owner must supervise execution and bound its lifetime.
/// Loading never downloads files, calls an API or allocates a GPU backend.
pub struct LocalEncoder {
    model: BertModel,
    tokenizer: Tokenizer,
    identity: EncoderIdentity,
}

impl LocalEncoder {
    pub fn specification() -> serde_json::Value {
        serde_json::json!({
            "model": MODEL_ID, "revision": MODEL_REVISION, "license": "MIT",
            "license_source": "model-card.md front matter; upstream model card declares MIT",
            "assets": MODEL_ASSETS, "runtime": "candle-0.11.0-cpu-f32",
            "tokenizer_runtime": "tokenizers-0.22.2", "dimensions": DIMENSIONS,
            "query_prefix": QUERY_PREFIX, "document_prefix": "",
            "query_prefix_tokens": PREFIX_TOKENS, "maximum_query_content_tokens": CONTENT_TOKENS - PREFIX_TOKENS,
            "pooling": "last-hidden-state-first-CLS-token-then-L2",
            "chunking": "complete-token-order; 510-content-tokens-plus-CLS-SEP; no-overlap; batch-one; no-padding; no-truncation",
            "ranking": "maximum-normalized-chunk-cosine; ascending-ProofId-tie-break",
            "compatibility_encode": "content-token-weighted-mean-of-normalized-chunks-then-L2",
            "maximum_chunks": MAX_CHUNKS, "maximum_input_bytes": MAX_INPUT_BYTES,
        })
    }

    pub fn identity_specification() -> EncoderIdentity {
        EncoderIdentity {
            name: MODEL_ID.into(),
            revision: crate::hex(&Sha256::digest(
                serde_json::to_vec(&Self::specification()).expect("fixed encoder specification"),
            )),
            representation_version: SEMANTIC_REPRESENTATION_VERSION,
            dimensions: DIMENSIONS as u16,
            maximum_input_bytes: MAX_INPUT_BYTES,
        }
    }

    pub fn validate_assets(directory: &Path) -> Result<(), String> {
        for asset in &MODEL_ASSETS {
            let _ = read_asset(directory, asset)?;
        }
        Ok(())
    }

    pub fn load(directory: &Path) -> Result<Self, String> {
        Self::validate_assets(directory)?;
        let config: Config = serde_json::from_slice(&read_asset(directory, &MODEL_ASSETS[1])?)
            .map_err(|e| e.to_string())?;
        if config.hidden_size != DIMENSIONS || config.max_position_embeddings != WINDOW_TOKENS {
            return Err("retrieval model architecture differs".into());
        }
        let data = read_asset(directory, &MODEL_ASSETS[0])?;
        let device = Device::Cpu;
        // Safe buffered loading preserves workspace's unsafe-code prohibition.
        // The model owns copied CPU tensors; no mutable weights mapping survives.
        let vb = VarBuilder::from_buffered_safetensors(data, DType::F32, &device)
            .map_err(|e| e.to_string())?;
        let model = BertModel::load(vb, &config).map_err(|e| e.to_string())?;
        let mut tokenizer = Tokenizer::from_bytes(read_asset(directory, &MODEL_ASSETS[2])?)
            .map_err(|e| e.to_string())?;
        tokenizer.with_truncation(None).map_err(|e| e.to_string())?;
        tokenizer.with_padding(None);
        if tokenizer.token_to_id("[CLS]") != Some(101)
            || tokenizer.token_to_id("[SEP]") != Some(102)
            || tokenizer
                .encode(QUERY_PREFIX, false)
                .map_err(|e| e.to_string())?
                .get_ids()
                .len()
                != PREFIX_TOKENS
        {
            return Err("retrieval tokenizer special tokens differ".into());
        }
        Ok(Self {
            model,
            tokenizer,
            identity: Self::identity_specification(),
        })
    }

    fn chunk(&self, content: &[u32]) -> Result<Vec<f32>, String> {
        if content.is_empty() || content.len() > CONTENT_TOKENS {
            return Err("retrieval chunk capacity differs".into());
        }
        let mut ids = Vec::with_capacity(content.len() + 2);
        ids.push(101);
        ids.extend_from_slice(content);
        ids.push(102);
        let tokens = Tensor::new(ids.as_slice(), &Device::Cpu)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| e.to_string())?;
        let types = tokens.zeros_like().map_err(|e| e.to_string())?;
        let output = self
            .model
            .forward(&tokens, &types, None)
            .and_then(|t| t.i((0, 0, ..)))
            .and_then(|t| t.to_vec1::<f32>())
            .map_err(|e| e.to_string())?;
        normalize(output)
    }

    pub(crate) fn prepare_document(&self, input: &str) -> Result<PreparedDocument, String> {
        if input.trim().is_empty() || input.len() > MAX_INPUT_BYTES {
            return Err("retrieval complete document input byte limit".into());
        }
        let encoding = self
            .tokenizer
            .encode(input, false)
            .map_err(|e| e.to_string())?;
        let ids = encoding.get_ids();
        if ids.is_empty() || ids.len().div_ceil(CONTENT_TOKENS) > MAX_CHUNKS {
            return Err("retrieval complete document token/chunk limit".into());
        }
        let offsets = encoding.get_offsets();
        let mut coverage = Vec::new();
        let mut previous_byte = 0;
        for token_start in (0..ids.len()).step_by(CONTENT_TOKENS) {
            let token_end = (token_start + CONTENT_TOKENS).min(ids.len());
            let byte_end = if token_end == ids.len() {
                input.len()
            } else {
                offsets[token_end].0
            };
            if byte_end < previous_byte
                || byte_end > input.len()
                || !input.is_char_boundary(byte_end)
            {
                return Err("retrieval tokenizer coverage differs".into());
            }
            coverage.push(ChunkCoverage {
                token_start,
                token_end,
                total_tokens: ids.len(),
                byte_start: previous_byte,
                byte_end,
            });
            previous_byte = byte_end;
        }
        if previous_byte != input.len() {
            return Err("retrieval complete byte coverage differs".into());
        }
        Ok(PreparedDocument {
            ids: ids.to_vec(),
            coverage,
        })
    }

    pub(crate) fn encode_prepared(
        &self,
        prepared: &PreparedDocument,
        position: usize,
    ) -> Result<EmbeddedChunk, String> {
        let span = prepared
            .coverage
            .get(position)
            .ok_or("retrieval prepared chunk is absent")?;
        Ok(EmbeddedChunk {
            token_start: span.token_start,
            token_end: span.token_end,
            total_tokens: span.total_tokens,
            byte_start: span.byte_start,
            byte_end: span.byte_end,
            vector: self.chunk(&prepared.ids[span.token_start..span.token_end])?,
        })
    }

    pub fn encode_chunks(&mut self, input: &str) -> Result<Vec<EmbeddedChunk>, String> {
        let prepared = self.prepare_document(input)?;
        (0..prepared.coverage.len())
            .map(|position| self.encode_prepared(&prepared, position))
            .collect()
    }

    pub fn query(&mut self, query: &str) -> Result<Vec<f32>, String> {
        if query.trim().is_empty() || query.len() > 1024 {
            return Err("retrieval query must contain 1..=1024 UTF-8 bytes".into());
        }
        let content = self
            .tokenizer
            .encode(query, false)
            .map_err(|e| e.to_string())?;
        if content.get_ids().is_empty() || content.get_ids().len() > CONTENT_TOKENS - PREFIX_TOKENS
        {
            return Err(
                "retrieval query has no normalized content or exceeds prefixed token capacity"
                    .into(),
            );
        }
        let input = format!("{QUERY_PREFIX}{query}");
        let encoding = self
            .tokenizer
            .encode(input, false)
            .map_err(|e| e.to_string())?;
        self.chunk(encoding.get_ids())
    }
}

impl SemanticEncoder for LocalEncoder {
    fn identity(&self) -> EncoderIdentity {
        self.identity.clone()
    }
    fn encode(&mut self, input: &str) -> Result<Vec<f32>, String> {
        let chunks = self.encode_chunks(input)?;
        let mut mean = vec![0f64; DIMENSIONS];
        for chunk in chunks {
            let weight = (chunk.token_end - chunk.token_start) as f64;
            for (sum, value) in mean.iter_mut().zip(chunk.vector) {
                *sum += f64::from(value) * weight;
            }
        }
        normalize(mean.into_iter().map(|v| v as f32).collect())
    }
    fn encode_query(&mut self, input: &str) -> Result<Vec<f32>, String> {
        self.query(input)
    }
    fn encode_document(&mut self, input: &str) -> Result<Vec<Vec<f32>>, String> {
        Ok(self
            .encode_chunks(input)?
            .into_iter()
            .map(|c| c.vector)
            .collect())
    }
}

fn normalize(mut vector: Vec<f32>) -> Result<Vec<f32>, String> {
    let magnitude = vector
        .iter()
        .map(|v| f64::from(*v).powi(2))
        .sum::<f64>()
        .sqrt();
    if vector.len() != DIMENSIONS
        || !magnitude.is_finite()
        || magnitude == 0.0
        || vector.iter().any(|v| !v.is_finite())
    {
        return Err("retrieval encoder output dimension or magnitude differs".into());
    }
    for value in &mut vector {
        *value = (f64::from(*value) / magnitude) as f32;
    }
    Ok(vector)
}

fn read_asset(directory: &Path, asset: &ModelAsset) -> Result<Vec<u8>, String> {
    let data = super::snapshot::read_regular(&directory.join(asset.local_name), asset.bytes)?;
    if data.len() != asset.bytes || crate::hex(&Sha256::digest(&data)) != asset.sha256 {
        return Err(format!("retrieval asset differs: {}", asset.local_name));
    }
    Ok(data)
}
