//! Provider-neutral ranking of the complete accepted node-local proof corpus.
//!
//! An encoder for retrieval is a separate choice from a proof-generation model.
//! This module chooses neither. Encodings and rankings are untrusted hints;
//! only the native checker establishes validity and target admission. An index
//! is a derived cache, never another owner of accepted mathematical state.

use super::{MAX_SNAPSHOT_BYTES as MAX_REQUEST_BYTES, ProofCorpus as CheckedContext, Reference};

fn digest_value(value: &impl Serialize) -> String {
    crate::hex(&Sha256::digest(
        serde_json::to_vec(value).expect("finite corpus value"),
    ))
}
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Version of the complete per-proof representation supplied to encoders.
pub const SEMANTIC_REPRESENTATION_VERSION: u8 = 1;
const MAX_DIMENSIONS: u16 = 1024;
const MAX_VECTOR_ELEMENTS: usize = 1_048_576;
const MAX_QUERY_BYTES: usize = 1024;
const MAX_TOP_K: u16 = 16;
const MAX_IDENTITY_BYTES: usize = 256;
const MAX_ERROR_BYTES: usize = 1024;
// A million bounded f32 values plus complete identities fit this export cap.
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;

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
    fn validate(&self) -> Result<(), String> {
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
    #[serde(deserialize_with = "deserialize_vector")]
    vector: Vec<f32>,
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
}

/// Top-K ranking after scanning the complete bound local corpus.
/// `complete_corpus_scan` concerns ranking scope, never absence of other
/// mathematics, natural-language understanding quality, or question novelty.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SemanticPage {
    pub artifact_snapshot: String,
    pub graph_root: String,
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

impl SemanticIndex {
    /// Encodes every accepted proof exactly once. No truncated or partial index
    /// is returned if any proof, representation or encoder output is unavailable.
    pub fn build<E: SemanticEncoder + ?Sized>(
        corpus: &CheckedContext,
        encoder: &mut E,
    ) -> Result<Self, String> {
        corpus.recheck()?;
        corpus_bounds(corpus)?;
        let identity = encoder.identity();
        identity.validate()?;
        vector_budget(corpus.references.len(), identity.dimensions)?;
        let mut index = Self {
            version: 1,
            encoder: identity.clone(),
            artifact_snapshot: corpus.artifact_snapshot.clone(),
            graph_root: corpus.graph_root.clone(),
            corpus_digest: digest_value(corpus),
            proofs: Vec::with_capacity(corpus.references.len()),
            index_identity: String::new(),
        };
        for reference in &corpus.references {
            let content = proof_content(reference)?;
            let vector = encode(encoder, &identity, &content)?;
            index.proofs.push(IndexedProof {
                proof_id: reference.proof.proof_id.clone(),
                statement_id: reference.proof.statement_id.clone(),
                content_digest: digest_value(&content),
                vector,
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
            return Err("semantic top_k must be in 1..=16".into());
        }
        self.validate(corpus)?;
        if encoder.identity() != self.encoder {
            return Err("semantic query encoder identity differs from the complete index".into());
        }
        let query_vector = encode(encoder, &self.encoder, query)?;
        let mut ranked: Vec<_> = self
            .proofs
            .iter()
            .map(|proof| {
                let score = proof
                    .vector
                    .iter()
                    .zip(&query_vector)
                    .map(|(a, b)| f64::from(*a) * f64::from(*b))
                    .sum::<f64>()
                    .clamp(-1.0, 1.0);
                SemanticHit {
                    proof_id: proof.proof_id.clone(),
                    statement_id: proof.statement_id.clone(),
                    content_digest: proof.content_digest.clone(),
                    score,
                }
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.proof_id.cmp(&b.proof_id))
        });
        ranked.truncate(usize::from(top_k));
        Ok(SemanticPage {
            artifact_snapshot: self.artifact_snapshot.clone(),
            graph_root: self.graph_root.clone(),
            corpus_digest: self.corpus_digest.clone(),
            index_identity: self.index_identity.clone(),
            encoder: self.encoder.clone(),
            query_digest: digest_value(&query),
            top_k,
            corpus_proofs: self.proofs.len(),
            complete_corpus_scan: true,
            original_source_available: false,
            results: ranked,
        })
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
        corpus.recheck()?;
        corpus_bounds(corpus)?;
        self.encoder.validate()?;
        vector_budget(self.proofs.len(), self.encoder.dimensions)?;
        if self.version != 1
            || self.artifact_snapshot != corpus.artifact_snapshot
            || self.graph_root != corpus.graph_root
            || self.corpus_digest != digest_value(corpus)
            || self.proofs.len() != corpus.references.len()
        {
            return Err("semantic index corpus binding is stale, incomplete or differs".into());
        }
        for (proof, reference) in self.proofs.iter().zip(&corpus.references) {
            let content = proof_content(reference)?;
            if content.len() > self.encoder.maximum_input_bytes
                || proof.proof_id != reference.proof.proof_id
                || proof.statement_id != reference.proof.statement_id
                || proof.content_digest != digest_value(&content)
            {
                return Err("semantic index proof content or ordering differs".into());
            }
            vector_shape(&proof.vector, self.encoder.dimensions)?;
            let norm = magnitude(&proof.vector);
            if (norm - 1.0).abs() > 0.000_002 {
                return Err("semantic cache vector is not normalized".into());
            }
        }
        if self.index_identity != self.checksum() {
            return Err("semantic index cache checksum differs".into());
        }
        Ok(())
    }

    fn checksum(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(b"naome:semantic-index:v1\0");
        hash.update([self.version]);
        framed(&mut hash, digest_value(&self.encoder).as_bytes());
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
            hash.update((proof.vector.len() as u64).to_be_bytes());
            for value in &proof.vector {
                hash.update(value.to_bits().to_be_bytes());
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
        || serde_json::to_vec(corpus).map_err(|e| e.to_string())?.len() > MAX_REQUEST_BYTES
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

fn proof_content(reference: &Reference) -> Result<String, String> {
    let candidate = reference.proof.clone().prepare()?;
    let content = format!(
        "naome:semantic-proof-content:v1\nrepresentation: derived checked conclusion and complete canonical normalized proof certificate; original .nao source is not stored\ncompatibility: {}\nproof_id: {}\nstatement_id: {}\nnative_checked_conclusion:\n{}\ndirect_dependencies: {}\nnormalized_certificate:\n{:?}\n",
        reference.proof.compatibility,
        reference.proof.proof_id,
        reference.proof.statement_id,
        reference.native_conclusion,
        serde_json::to_string(&reference.dependencies).map_err(|e| e.to_string())?,
        candidate.normal.certificate(),
    );
    if content.len() > MAX_REQUEST_BYTES {
        return Err("semantic complete proof representation byte limit".into());
    }
    Ok(content)
}

fn encode<E: SemanticEncoder + ?Sized>(
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
    let output = encoder.encode(input);
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

fn magnitude(vector: &[f32]) -> f64 {
    vector
        .iter()
        .map(|value| f64::from(*value).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn vector_shape(vector: &[f32], dimensions: u16) -> Result<(), String> {
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
                    .checked_add(proof.vector.len())
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

#[cfg(test)]
mod tests;
