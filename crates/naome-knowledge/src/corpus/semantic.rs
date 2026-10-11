//! Provider-neutral ranking of the complete accepted node-local proof corpus.
//!
//! An encoder for retrieval is a separate choice from a proof-generation model.
//! This module chooses neither. Encodings and rankings are untrusted hints;
//! only the native checker establishes validity and target admission. An index
//! is a derived cache, never another owner of accepted mathematical state.

use super::{MAX_SNAPSHOT_BYTES, ProofCorpus as CheckedContext, Reference};
const MAX_REQUEST_BYTES: usize = 256 * 1024;

fn digest_value(value: &impl Serialize) -> String {
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite corpus value"),
    ))
}
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Version of the complete mathematical projection supplied to encoders.
/// Canonical records and provenance stay separately bound in the source.
pub const SEMANTIC_REPRESENTATION_VERSION: u8 = 6;
const MAX_DIMENSIONS: u16 = 1024;
const MAX_VECTOR_ELEMENTS: usize = 8_388_608;
pub(crate) const MAX_DOCUMENT_CHUNKS: usize = 256;
const MAX_QUERY_BYTES: usize = 1024;
const MAX_TOP_K: u16 = 1024;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_ERROR_BYTES: usize = 1024;
// A million bounded f32 values plus complete identities fit this export cap.
const MAX_CACHE_BYTES: usize = 256 * 1024 * 1024;

/// Immutable declared identity and capacity of a retrieval encoder.
/// An adapter must change revision whenever its encoding behavior changes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncoderIdentity {
    pub name: String,
    pub revision: String,
    pub representation_version: u8,
    pub dimensions: u16,
    pub maximum_input_bytes: usize,
}

impl EncoderIdentity {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty()
            || self.name.len() > MAX_IDENTITY_BYTES
            || self.revision.trim().is_empty()
            || self.revision.len() > MAX_IDENTITY_BYTES
            || self.representation_version != SEMANTIC_REPRESENTATION_VERSION
            || !(1..=MAX_DIMENSIONS).contains(&self.dimensions)
            || !(1..=MAX_REQUEST_BYTES).contains(&self.maximum_input_bytes)
        {
            return Err(
                "semantic encoder identity, representation or capacity is unsupported".into(),
            );
        }
        Ok(())
    }
}

/// Supplies genuine encodings for both complete stored proof content and text
/// queries in the same vector space. No default, fake production encoder,
/// provider credentials, model weights, or inference is installed here.
///
/// `encode` must honor the declared input capacity and immutable identity.
/// Its output must have exactly the declared dimensions and finite nonzero
/// magnitude. An encoder failure aborts construction rather than omitting a
/// proof. Local and hosted adapters can implement this same narrow interface.
pub trait SemanticEncoder {
    fn identity(&self) -> EncoderIdentity;
    fn encode(&mut self, input: &str) -> Result<Vec<f32>, String>;
    /// Separately encodes retrieval queries, including the encoder's query-only prefix.
    fn encode_query(&mut self, input: &str) -> Result<Vec<f32>, String> {
        self.encode(input)
    }
    /// Complete document chunks; existing single-vector encoders remain supported.
    fn encode_document(&mut self, input: &str) -> Result<Vec<Vec<f32>>, String> {
        self.encode(input).map(|vector| vec![vector])
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IndexedProof {
    #[serde(deserialize_with = "deserialize_id")]
    proof_id: String,
    #[serde(deserialize_with = "deserialize_id")]
    statement_id: String,
    #[serde(deserialize_with = "deserialize_id")]
    content_digest: String,
    #[serde(deserialize_with = "deserialize_chunks")]
    chunks: Vec<ChunkVector>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChunkVector {
    #[serde(deserialize_with = "deserialize_vector")]
    vector: Vec<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coverage: Option<super::local::ChunkCoverage>,
}

/// Complete derived row. The proof store never reads this as authority.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceVectorRow {
    pub encoder: EncoderIdentity,
    pub proof_id: String,
    pub statement_id: String,
    pub content_digest: String,
    pub chunks: Vec<super::local::EmbeddedChunk>,
}

impl SourceVectorRow {
    pub fn bound_key(&self) -> String {
        digest_value(&(
            "naome:source-vector-row:v3",
            &self.encoder,
            &self.proof_id,
            &self.content_digest,
        ))
    }
    pub fn key(encoder: &EncoderIdentity, proof_id: &str, content: &str) -> String {
        digest_value(&(
            "naome:source-vector-row:v3",
            encoder,
            proof_id,
            digest_value(&content),
        ))
    }
    pub fn validate(
        &self,
        source: &super::snapshot::Frozen,
        expected: &EncoderIdentity,
    ) -> Result<(), String> {
        let reference = source
            .reference(&self.proof_id)
            .ok_or("derived vector proof is absent")?;
        let content = source.semantic_content(&self.proof_id)?;
        self.validate_content(reference, &content, expected)
    }
    pub fn validate_content(
        &self,
        reference: &Reference,
        content: &str,
        expected: &EncoderIdentity,
    ) -> Result<(), String> {
        self.encoder.validate()?;
        if self.encoder != *expected
            || self.proof_id != reference.proof.proof_id
            || self.statement_id != reference.proof.statement_id
            || self.content_digest != digest_value(&content)
            || self.chunks.is_empty()
            || self.chunks.len() > MAX_DOCUMENT_CHUNKS
        {
            return Err("derived vector row content, encoder or completeness differs".into());
        }
        let mut token_end = 0;
        let mut byte_end = 0;
        let total = self.chunks[0].total_tokens;
        if total == 0 || total > super::local::CONTENT_TOKENS * MAX_DOCUMENT_CHUNKS {
            return Err("derived vector token coverage capacity differs".into());
        }
        for chunk in &self.chunks {
            if chunk.token_start != token_end
                || chunk.byte_start != byte_end
                || chunk.token_end <= token_end
                || chunk.token_end - token_end > super::local::CONTENT_TOKENS
                || chunk.total_tokens != total
                || chunk.token_end > total
                || chunk.byte_end < byte_end
                || chunk.byte_end > content.len()
                || !content.is_char_boundary(chunk.byte_end)
            {
                return Err("derived vector complete chunk coverage differs".into());
            }
            vector_shape(&chunk.vector, expected.dimensions)?;
            if (magnitude(&chunk.vector) - 1.0).abs() > 0.000_002 {
                return Err("derived vector chunk normalization differs".into());
            }
            token_end = chunk.token_end;
            byte_end = chunk.byte_end;
        }
        if token_end != total
            || byte_end != content.len()
            || self.chunks.len() != total.div_ceil(super::local::CONTENT_TOKENS)
        {
            return Err("derived vector row does not cover every input token and byte".into());
        }
        Ok(())
    }
    pub fn new(
        encoder: EncoderIdentity,
        reference: &Reference,
        content: &str,
        chunks: Vec<super::local::EmbeddedChunk>,
    ) -> Result<Self, String> {
        let row = Self {
            encoder: encoder.clone(),
            proof_id: reference.proof.proof_id.clone(),
            statement_id: reference.proof.statement_id.clone(),
            content_digest: digest_value(&content),
            chunks,
        };
        row.validate_content(reference, content, &encoder)?;
        Ok(row)
    }
}

/// Complete bounded vector cache tied to one exact corpus and encoder.
///
/// Serialized caches are untrusted. Every search rechecks native source closure,
/// all content bindings, vector bounds and the cache checksum before ranking.
/// The checksum detects corruption; it does not authenticate encoder relevance
/// or make a deserialized cache authoritative mathematical state.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIndex {
    version: u8,
    encoder: EncoderIdentity,
    artifact_snapshot: String,
    graph_root: String,
    corpus_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_identity: Option<String>,
    #[serde(deserialize_with = "deserialize_proofs")]
    proofs: Vec<IndexedProof>,
    index_identity: String,
}

/// One ranked hint addressing an exact accepted proof for subsequent full fetch.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticHit {
    pub proof_id: String,
    pub statement_id: String,
    pub content_digest: String,
    pub score: f64,
    pub matched_chunk: usize,
    pub document_chunks: usize,
}

/// Top-K ranking after scanning the complete bound local corpus.
/// `complete_corpus_scan` concerns ranking scope, never absence of other
/// mathematics, natural-language understanding quality, or question novelty.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticPage {
    pub artifact_snapshot: String,
    pub graph_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot: Option<String>,
    pub corpus_digest: String,
    pub index_identity: String,
    pub encoder: EncoderIdentity,
    pub query_digest: String,
    pub top_k: u16,
    pub corpus_proofs: usize,
    pub complete_corpus_scan: bool,
    pub original_source_available: bool,
    pub results: Vec<SemanticHit>,
}

impl SemanticPage {
    pub(crate) fn validate_window(
        &self,
        source: &super::snapshot::Frozen,
        query: &str,
        top_k: u16,
    ) -> Result<(), String> {
        self.encoder.validate()?;
        crate::object::id_bytes(&self.index_identity)?;
        let source_owned = self.source_snapshot.is_some();
        if !self.complete_corpus_scan
            || self.original_source_available
            || self.artifact_snapshot != source.handle().artifact_snapshot
            || self.graph_root != source.handle().graph_root
            || self
                .source_snapshot
                .as_ref()
                .is_some_and(|id| id != &source.handle().snapshot_id)
            || self.corpus_digest
                != if source_owned {
                    digest_value(source.handle())
                } else {
                    digest_value(source.corpus())
                }
            || self.query_digest != digest_value(&query)
            || self.top_k != top_k
            || !(1..=MAX_TOP_K).contains(&top_k)
            || self.corpus_proofs != source.corpus().references.len()
            || self.results.len() != usize::from(top_k).min(self.corpus_proofs)
        {
            return Err("semantic saved window complete source or query binding differs".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut previous: Option<&SemanticHit> = None;
        for hit in &self.results {
            let reference = source
                .reference(&hit.proof_id)
                .ok_or("semantic saved window proof is absent")?;
            let content = if source_owned {
                source.semantic_content(&hit.proof_id)?
            } else {
                source.base_semantic_content(&hit.proof_id)?
            };
            if !ids.insert(&hit.proof_id)
                || hit.statement_id != reference.proof.statement_id
                || hit.content_digest != digest_value(&content)
                || !hit.score.is_finite()
                || !(-1.0..=1.0).contains(&hit.score)
                || !(1..=MAX_DOCUMENT_CHUNKS).contains(&hit.document_chunks)
                || hit.matched_chunk >= hit.document_chunks
                || previous.is_some_and(|old| {
                    old.score.total_cmp(&hit.score).is_lt()
                        || (old.score.total_cmp(&hit.score).is_eq() && old.proof_id >= hit.proof_id)
                })
            {
                return Err(
                    "semantic saved window identity, order, score or chunk binding differs".into(),
                );
            }
            previous = Some(hit);
        }
        Ok(())
    }
}

impl SemanticIndex {
    /// The Frozen constructor already crossed the mathematical trust boundary.
    /// Row import checks complete content once; hot ranking checks only custody.
    pub(crate) fn build_source(
        source: &super::snapshot::Frozen,
        identity: EncoderIdentity,
        rows: Vec<SourceVectorRow>,
    ) -> Result<Self, String> {
        identity.validate()?;
        if rows.len() != source.corpus().references.len() {
            return Err("derived source index is incomplete".into());
        }
        let mut proofs = Vec::with_capacity(rows.len());
        for (row, reference) in rows.into_iter().zip(&source.corpus().references) {
            if row.proof_id != reference.proof.proof_id {
                return Err("derived source index order differs".into());
            }
            row.validate(source, &identity)?;
            proofs.push(IndexedProof {
                proof_id: row.proof_id,
                statement_id: row.statement_id,
                content_digest: row.content_digest,
                chunks: row
                    .chunks
                    .into_iter()
                    .map(|chunk| ChunkVector {
                        coverage: Some(super::local::ChunkCoverage {
                            token_start: chunk.token_start,
                            token_end: chunk.token_end,
                            total_tokens: chunk.total_tokens,
                            byte_start: chunk.byte_start,
                            byte_end: chunk.byte_end,
                        }),
                        vector: chunk.vector,
                    })
                    .collect(),
            });
        }
        let mut index = Self {
            version: 3,
            encoder: identity,
            artifact_snapshot: source.corpus().artifact_snapshot.clone(),
            graph_root: source.corpus().graph_root.clone(),
            corpus_digest: digest_value(source.handle()),
            source_identity: Some(source.handle().snapshot_id.clone()),
            proofs,
            index_identity: String::new(),
        };
        index.index_identity = index.checksum();
        index.validate_source(source)?;
        Ok(index)
    }

    pub(crate) fn from_json_source(
        source: &super::snapshot::Frozen,
        bytes: &[u8],
    ) -> Result<Self, String> {
        if bytes.len() > MAX_CACHE_BYTES {
            return Err("semantic serialized cache byte limit".into());
        }
        let index: Self = serde_json::from_slice(bytes)
            .map_err(|e| format!("semantic source cache decoding: {e}"))?;
        index.validate_source(source)?;
        Ok(index)
    }

    fn validate_source(&self, source: &super::snapshot::Frozen) -> Result<(), String> {
        self.encoder.validate()?;
        if self.version != 3
            || self.source_identity.as_deref() != Some(&source.handle().snapshot_id)
            || self.corpus_digest != digest_value(source.handle())
            || self.artifact_snapshot != source.handle().artifact_snapshot
            || self.graph_root != source.handle().graph_root
            || self.proofs.len() != source.corpus().references.len()
        {
            return Err("semantic frozen source binding is stale or incomplete".into());
        }
        let mut elements = 0usize;
        for (proof, reference) in self.proofs.iter().zip(&source.corpus().references) {
            if proof.proof_id != reference.proof.proof_id
                || proof.statement_id != reference.proof.statement_id
                || proof.chunks.is_empty()
                || proof.chunks.len() > MAX_DOCUMENT_CHUNKS
            {
                return Err("semantic frozen source proof ordering or chunk count differs".into());
            }
            let chunks = proof
                .chunks
                .iter()
                .map(|chunk| {
                    let coverage = chunk
                        .coverage
                        .as_ref()
                        .ok_or("semantic source chunk coverage is missing")?;
                    Ok(super::local::EmbeddedChunk {
                        token_start: coverage.token_start,
                        token_end: coverage.token_end,
                        total_tokens: coverage.total_tokens,
                        byte_start: coverage.byte_start,
                        byte_end: coverage.byte_end,
                        vector: chunk.vector.clone(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            SourceVectorRow {
                encoder: self.encoder.clone(),
                proof_id: proof.proof_id.clone(),
                statement_id: proof.statement_id.clone(),
                content_digest: proof.content_digest.clone(),
                chunks,
            }
            .validate_content(
                reference,
                &source.semantic_content(&proof.proof_id)?,
                &self.encoder,
            )?;
            for chunk in &proof.chunks {
                vector_shape(&chunk.vector, self.encoder.dimensions)?;
                if (magnitude(&chunk.vector) - 1.0).abs() > 0.000_002 {
                    return Err("semantic source vector normalization differs".into());
                }
                elements = elements
                    .checked_add(chunk.vector.len())
                    .ok_or("semantic source vector budget overflow")?;
                if elements > MAX_VECTOR_ELEMENTS {
                    return Err("semantic source complete chunk vector budget exceeded".into());
                }
            }
        }
        if self.index_identity != self.checksum() {
            return Err("semantic source index checksum differs".into());
        }
        Ok(())
    }

    pub(crate) fn validate_ranking(
        &self,
        source: &super::snapshot::Frozen,
        query: &str,
        top_k: u16,
        page: &SemanticPage,
    ) -> Result<(), String> {
        page.validate_window(source, query, top_k)?;
        if page.index_identity != self.index_identity
            || page.encoder != self.encoder
            || page.source_snapshot != self.source_identity
            || page.corpus_digest != self.corpus_digest
        {
            return Err("semantic saved ranking complete index identity differs".into());
        }
        for hit in &page.results {
            let position = self
                .proofs
                .binary_search_by(|proof| proof.proof_id.cmp(&hit.proof_id))
                .map_err(|_| "semantic saved ranking proof is absent from complete index")?;
            let proof = &self.proofs[position];
            if hit.statement_id != proof.statement_id
                || hit.content_digest != proof.content_digest
                || hit.document_chunks != proof.chunks.len()
                || hit.matched_chunk >= proof.chunks.len()
            {
                return Err("semantic saved ranking complete indexed proof differs".into());
            }
        }
        Ok(())
    }

    pub(crate) fn search_vector(
        &self,
        source: &super::snapshot::Frozen,
        query: &str,
        top_k: u16,
        query_vector: &[f32],
    ) -> Result<SemanticPage, String> {
        if query.trim().is_empty()
            || query.len() > MAX_QUERY_BYTES
            || !(1..=MAX_TOP_K).contains(&top_k)
        {
            return Err("semantic query or ranked window capacity differs".into());
        }
        // In-memory instances are immutable after a checked import/build. Avoid
        // rehashing the whole cache or reconstructing the graph for every page.
        if self.source_identity.as_deref() != Some(&source.handle().snapshot_id)
            || self.proofs.len() != source.corpus().references.len()
        {
            return Err("semantic query frozen source identity differs".into());
        }
        vector_shape(query_vector, self.encoder.dimensions)?;
        let norm = magnitude(query_vector);
        let vector: Vec<_> = query_vector
            .iter()
            .map(|v| (f64::from(*v) / norm) as f32)
            .collect();
        Ok(self.rank(query, top_k, &vector))
    }
    /// Encodes every accepted proof exactly once. No truncated or partial index
    /// is returned if any proof, representation or encoder output is unavailable.
    pub fn build<E: SemanticEncoder + ?Sized>(
        corpus: &CheckedContext,
        encoder: &mut E,
    ) -> Result<Self, String> {
        let checked = corpus.checked_graph()?;
        corpus_bounds(corpus)?;
        let identity = encoder.identity();
        identity.validate()?;
        vector_budget(corpus.references.len(), identity.dimensions)?;
        let mut index = Self {
            version: 3,
            encoder: identity.clone(),
            artifact_snapshot: corpus.artifact_snapshot.clone(),
            graph_root: corpus.graph_root.clone(),
            corpus_digest: digest_value(corpus),
            source_identity: None,
            proofs: Vec::with_capacity(corpus.references.len()),
            index_identity: String::new(),
        };
        let mut elements = 0usize;
        for (reference, row) in corpus.references.iter().zip(checked.corpus_references()) {
            let content = proof_content(reference, &row.controlled_conclusion)?;
            let chunks = encode_document(encoder, &identity, &content)?;
            elements = elements
                .checked_add(chunks.len() * usize::from(identity.dimensions))
                .ok_or("semantic complete chunk vector budget overflow")?;
            if elements > MAX_VECTOR_ELEMENTS {
                return Err("semantic complete chunk vector budget exceeded".into());
            }
            index.proofs.push(IndexedProof {
                proof_id: reference.proof.proof_id.clone(),
                statement_id: reference.proof.statement_id.clone(),
                content_digest: digest_value(&content),
                chunks,
            });
        }
        if encoder.identity() != identity {
            return Err("semantic encoder identity changed while indexing".into());
        }
        index.index_identity = index.checksum();
        Ok(index)
    }

    /// Encodes the exact bounded user text and ranks every corpus proof by
    /// normalized cosine similarity. Scores descend, with ascending ProofId as
    /// a deterministic tie break. Top-K limits results, not the scanned corpus;
    /// there is no incomplete candidate page or undisclosed lexical fallback.
    pub fn search<E: SemanticEncoder + ?Sized>(
        &self,
        corpus: &CheckedContext,
        query: &str,
        top_k: u16,
        encoder: &mut E,
    ) -> Result<SemanticPage, String> {
        if query.trim().is_empty() || query.len() > MAX_QUERY_BYTES {
            return Err("semantic text query must contain 1..=1024 UTF-8 bytes".into());
        }
        if !(1..=MAX_TOP_K).contains(&top_k) {
            return Err("semantic top_k must be in 1..=1024".into());
        }
        self.validate(corpus)?;
        if encoder.identity() != self.encoder {
            return Err("semantic query encoder identity differs from the complete index".into());
        }
        let query_vector = encode_query(encoder, &self.encoder, query)?;
        Ok(self.rank(query, top_k, &query_vector))
    }

    fn rank(&self, query: &str, top_k: u16, query_vector: &[f32]) -> SemanticPage {
        let mut ranked: Vec<_> = self
            .proofs
            .iter()
            .map(|proof| {
                let (matched_chunk, score) = proof
                    .chunks
                    .iter()
                    .enumerate()
                    .map(|(position, chunk)| {
                        (
                            position,
                            chunk
                                .vector
                                .iter()
                                .zip(query_vector)
                                .map(|(a, b)| f64::from(*a) * f64::from(*b))
                                .sum::<f64>()
                                .clamp(-1.0, 1.0),
                        )
                    })
                    .fold((0, f64::NEG_INFINITY), |best, value| {
                        if value.1 > best.1 { value } else { best }
                    });
                SemanticHit {
                    proof_id: proof.proof_id.clone(),
                    statement_id: proof.statement_id.clone(),
                    content_digest: proof.content_digest.clone(),
                    score,
                    matched_chunk,
                    document_chunks: proof.chunks.len(),
                }
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.proof_id.cmp(&b.proof_id))
        });
        ranked.truncate(usize::from(top_k));
        SemanticPage {
            artifact_snapshot: self.artifact_snapshot.clone(),
            graph_root: self.graph_root.clone(),
            source_snapshot: self.source_identity.clone(),
            corpus_digest: self.corpus_digest.clone(),
            index_identity: self.index_identity.clone(),
            encoder: self.encoder.clone(),
            query_digest: digest_value(&query),
            top_k,
            corpus_proofs: self.proofs.len(),
            complete_corpus_scan: true,
            original_source_available: false,
            results: ranked,
        }
    }

    pub fn identity(&self) -> &str {
        &self.index_identity
    }
    pub fn encoder_identity(&self) -> &EncoderIdentity {
        &self.encoder
    }
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Imports a bounded JSON cache and rechecks its entire native source and
    /// vector bindings before returning it. Use this entry point for persisted
    /// bytes; direct serde decoding also bounds proof/vector arrays, but its
    /// caller must bound the complete input and metadata strings itself.
    pub fn from_json(corpus: &CheckedContext, bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CACHE_BYTES {
            return Err("semantic serialized cache byte limit".into());
        }
        let index: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("semantic cache decoding: {error}"))?;
        index.validate(corpus)?;
        Ok(index)
    }

    fn validate(&self, corpus: &CheckedContext) -> Result<(), String> {
        let checked = corpus.checked_graph()?;
        corpus_bounds(corpus)?;
        self.encoder.validate()?;
        vector_budget(self.proofs.len(), self.encoder.dimensions)?;
        if self.version != 3
            || self.source_identity.is_some()
            || self.artifact_snapshot != corpus.artifact_snapshot
            || self.graph_root != corpus.graph_root
            || self.corpus_digest != digest_value(corpus)
            || self.proofs.len() != corpus.references.len()
        {
            return Err("semantic index corpus binding is stale, incomplete or differs".into());
        }
        let mut elements = 0usize;
        for ((proof, reference), row) in self
            .proofs
            .iter()
            .zip(&corpus.references)
            .zip(checked.corpus_references())
        {
            let content = proof_content(reference, &row.controlled_conclusion)?;
            if content.len() > self.encoder.maximum_input_bytes
                || proof.proof_id != reference.proof.proof_id
                || proof.statement_id != reference.proof.statement_id
                || proof.content_digest != digest_value(&content)
            {
                return Err("semantic index proof content or ordering differs".into());
            }
            if proof.chunks.is_empty() || proof.chunks.len() > MAX_DOCUMENT_CHUNKS {
                return Err("semantic complete document chunks differ".into());
            }
            for chunk in &proof.chunks {
                if chunk.coverage.is_some() {
                    return Err(
                        "external adapter index unexpectedly declares token coverage".into(),
                    );
                }
                vector_shape(&chunk.vector, self.encoder.dimensions)?;
                let norm = magnitude(&chunk.vector);
                if (norm - 1.0).abs() > 0.000_002 {
                    return Err("semantic cache vector is not normalized".into());
                }
                elements = elements
                    .checked_add(chunk.vector.len())
                    .ok_or("semantic chunk vector budget overflow")?;
                if elements > MAX_VECTOR_ELEMENTS {
                    return Err("semantic complete chunk vector budget exceeded".into());
                }
            }
        }
        if self.index_identity != self.checksum() {
            return Err("semantic index cache checksum differs".into());
        }
        Ok(())
    }

    fn checksum(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"naome:semantic-index:v3\0");
        hash.update([self.version]);
        framed(&mut hash, digest_value(&self.encoder).as_bytes());
        framed(&mut hash, digest_value(&self.source_identity).as_bytes());
        for value in [
            &self.artifact_snapshot,
            &self.graph_root,
            &self.corpus_digest,
        ] {
            framed(&mut hash, value.as_bytes());
        }
        hash.update((self.proofs.len() as u64).to_be_bytes());
        for proof in &self.proofs {
            for value in [&proof.proof_id, &proof.statement_id, &proof.content_digest] {
                framed(&mut hash, value.as_bytes());
            }
            hash.update((proof.chunks.len() as u64).to_be_bytes());
            for chunk in &proof.chunks {
                framed(&mut hash, digest_value(&chunk.coverage).as_bytes());
                hash.update((chunk.vector.len() as u64).to_be_bytes());
                for value in &chunk.vector {
                    hash.update(value.to_bits().to_be_bytes());
                }
            }
        }
        crate::hex(&hash.finalize())
    }
}

fn framed(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn corpus_bounds(corpus: &CheckedContext) -> Result<(), String> {
    if corpus.references.len() > crate::MAX_OBJECTS
        || serde_json::to_vec(corpus).map_err(|e| e.to_string())?.len() > MAX_SNAPSHOT_BYTES
    {
        return Err("semantic complete corpus count or byte limit".into());
    }
    Ok(())
}

fn vector_budget(proofs: usize, dimensions: u16) -> Result<(), String> {
    if proofs > crate::MAX_OBJECTS
        || proofs
            .checked_mul(usize::from(dimensions))
            .is_none_or(|elements| elements > MAX_VECTOR_ELEMENTS)
    {
        return Err("semantic complete corpus vector budget exceeded".into());
    }
    Ok(())
}

pub(crate) fn proof_content(
    reference: &Reference,
    controlled_conclusion: &str,
) -> Result<String, String> {
    let candidate = reference.proof.clone().prepare()?;
    if controlled_conclusion.is_empty() {
        return Err("semantic checker-owned controlled conclusion is unavailable".into());
    }
    let mut mathematics = format!(
        "naome:semantic-proof-content:v6\nChecked primitive conclusion: ({controlled_conclusion}).\nActual normalized certificate constructors and operands:\n"
    );
    for (position, step) in candidate.normal.certificate().steps().iter().enumerate() {
        use std::fmt::Write;
        writeln!(
            mathematics,
            "Step {position}: {}",
            step.to_controlled_english()?
        )
        .map_err(|e| e.to_string())?;
        if mathematics.len() > MAX_REQUEST_BYTES {
            return Err("semantic complete controlled mathematics byte limit".into());
        }
    }
    // Every mathematical constructor and operand is rendered once. Canonical
    // identity, native/debug serialization and provenance are already bound by
    // the source and index; duplicating them here adds no mathematical content.
    if mathematics.len() > MAX_REQUEST_BYTES {
        return Err("semantic complete proof representation byte limit".into());
    }
    Ok(mathematics)
}

fn encode_query<E: SemanticEncoder + ?Sized>(
    encoder: &mut E,
    identity: &EncoderIdentity,
    input: &str,
) -> Result<Vec<f32>, String> {
    if input.len() > identity.maximum_input_bytes || input.len() > MAX_REQUEST_BYTES {
        return Err("semantic encoder input capacity cannot hold the complete content".into());
    }
    if encoder.identity() != *identity {
        return Err("semantic encoder identity changed before encoding".into());
    }
    let output = encoder.encode_query(input);
    if encoder.identity() != *identity {
        return Err("semantic encoder identity changed during encoding".into());
    }
    let mut vector = output.map_err(|error| {
        if error.len() > MAX_ERROR_BYTES {
            "semantic encoder diagnostic byte limit".into()
        } else {
            format!("semantic encoder failed: {error}")
        }
    })?;
    vector_shape(&vector, identity.dimensions)?;
    let norm = magnitude(&vector);
    for value in &mut vector {
        *value = (f64::from(*value) / norm) as f32;
    }
    Ok(vector)
}

fn encode_document<E: SemanticEncoder + ?Sized>(
    encoder: &mut E,
    identity: &EncoderIdentity,
    input: &str,
) -> Result<Vec<ChunkVector>, String> {
    if input.len() > identity.maximum_input_bytes || input.len() > MAX_REQUEST_BYTES {
        return Err("semantic encoder input capacity cannot hold the complete content".into());
    }
    if encoder.identity() != *identity {
        return Err("semantic encoder identity changed before encoding".into());
    }
    let output = encoder.encode_document(input);
    if encoder.identity() != *identity {
        return Err("semantic encoder identity changed during encoding".into());
    }
    let vectors = output.map_err(|error| {
        if error.len() > MAX_ERROR_BYTES {
            "semantic encoder diagnostic byte limit".into()
        } else {
            format!("semantic encoder failed: {error}")
        }
    })?;
    if vectors.is_empty() || vectors.len() > MAX_DOCUMENT_CHUNKS {
        return Err("semantic complete document chunk capacity differs".into());
    }
    vectors
        .into_iter()
        .map(|mut vector| {
            vector_shape(&vector, identity.dimensions)?;
            let norm = magnitude(&vector);
            for value in &mut vector {
                *value = (f64::from(*value) / norm) as f32;
            }
            Ok(ChunkVector {
                vector,
                coverage: None,
            })
        })
        .collect()
}

fn magnitude(vector: &[f32]) -> f64 {
    vector
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt()
}

pub(crate) fn vector_shape(vector: &[f32], dimensions: u16) -> Result<(), String> {
    if vector.len() != usize::from(dimensions) || vector.iter().any(|value| !value.is_finite()) {
        return Err("semantic encoder vector dimension or finite-value contract differs".into());
    }
    let norm = magnitude(vector);
    if norm == 0.0 || !norm.is_finite() {
        return Err("semantic encoder vector has zero or invalid magnitude".into());
    }
    Ok(())
}

fn deserialize_id<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let id = String::deserialize(deserializer)?;
    crate::object::id_bytes(&id).map_err(D::Error::custom)?;
    Ok(id)
}

fn deserialize_vector<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<f32>, D::Error> {
    struct VectorVisitor;
    impl<'de> Visitor<'de> for VectorVisitor {
        type Value = Vec<f32>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 1024 finite vector elements")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut vector = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(usize::from(MAX_DIMENSIONS)),
            );
            while let Some(value) = sequence.next_element::<f32>()? {
                if vector.len() == usize::from(MAX_DIMENSIONS) || !value.is_finite() {
                    return Err(A::Error::custom(
                        "semantic decoded vector dimension or finite-value limit",
                    ));
                }
                vector.push(value);
            }
            Ok(vector)
        }
    }
    deserializer.deserialize_seq(VectorVisitor)
}

fn deserialize_proofs<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<IndexedProof>, D::Error> {
    struct ProofsVisitor;
    impl<'de> Visitor<'de> for ProofsVisitor {
        type Value = Vec<IndexedProof>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a complete bounded proof vector cache")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut proofs =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(crate::MAX_OBJECTS));
            let mut elements = 0usize;
            while let Some(proof) = sequence.next_element::<IndexedProof>()? {
                elements = elements
                    .checked_add(proof.chunks.iter().map(|c| c.vector.len()).sum::<usize>())
                    .ok_or_else(|| A::Error::custom("semantic decoded vector budget overflow"))?;
                if proofs.len() == crate::MAX_OBJECTS || elements > MAX_VECTOR_ELEMENTS {
                    return Err(A::Error::custom(
                        "semantic decoded complete corpus vector budget",
                    ));
                }
                proofs.push(proof);
            }
            Ok(proofs)
        }
    }
    deserializer.deserialize_seq(ProofsVisitor)
}

fn deserialize_chunks<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ChunkVector>, D::Error> {
    struct ChunksVisitor;
    impl<'de> Visitor<'de> for ChunksVisitor {
        type Value = Vec<ChunkVector>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most 256 complete document chunks")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut chunks = Vec::new();
            while let Some(chunk) = sequence.next_element::<ChunkVector>()? {
                if chunks.len() == MAX_DOCUMENT_CHUNKS {
                    return Err(A::Error::custom("semantic decoded document chunk limit"));
                }
                chunks.push(chunk);
            }
            Ok(chunks)
        }
    }
    deserializer.deserialize_seq(ChunksVisitor)
}

#[cfg(test)]
mod tests;
