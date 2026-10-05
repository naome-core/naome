//! Offline advisory cache. Every row stays addressable, including exact repeats.
use crate::{
    dataset::{Corpus, Record, digest},
    model::{EMBEDDING, Model},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub proof_id: String,
    pub statement_id: String,
    pub derivation_id: String,
    pub dependencies: Vec<String>,
    pub cost: usize,
    pub vector: Vec<f64>,
}
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct Index {
    pub schema: u32,
    pub foundation: String,
    pub policy: String,
    pub model_digest: String,
    pub corpus_digest: String,
    pub entries: Vec<Entry>,
    pub rows: Vec<usize>,
    pub proofs: BTreeMap<String, usize>,
    pub statements: BTreeMap<String, Vec<usize>>,
    pub derivations: BTreeMap<String, Vec<usize>>,
}
impl Index {
    pub fn new(m: &Model, c: &Corpus) -> Self {
        Self {
            schema: 1,
            foundation: naome_foundation::FOUNDATION_ID.into(),
            policy: c.policy.clone(),
            model_digest: digest(&serde_json::to_vec(m).unwrap()),
            corpus_digest: c.digest(),
            entries: Vec::new(),
            rows: Vec::new(),
            proofs: BTreeMap::new(),
            statements: BTreeMap::new(),
            derivations: BTreeMap::new(),
        }
    }
    pub fn append(&mut self, m: &Model, r: &Record) {
        let entry = if let Some(i) = self.proofs.get(&r.proof_id) {
            *i
        } else {
            let i = self.entries.len();
            self.entries.push(Entry {
                proof_id: r.proof_id.clone(),
                statement_id: r.statement_id.clone(),
                derivation_id: r.derivation_id.clone(),
                dependencies: r.dependencies.clone(),
                cost: r.graph.cost,
                vector: m.embedding(&r.graph),
            });
            self.proofs.insert(r.proof_id.clone(), i);
            i
        };
        let row = self.rows.len();
        self.rows.push(entry);
        self.statements
            .entry(r.statement_id.clone())
            .or_default()
            .push(row);
        self.derivations
            .entry(r.derivation_id.clone())
            .or_default()
            .push(row);
    }
    pub fn exact_matches(&self, r: &Record) -> &[usize] {
        self.derivations
            .get(&r.derivation_id)
            .map_or(&[], Vec::as_slice)
    }
    pub fn statement_matches(&self, r: &Record) -> &[usize] {
        self.statements
            .get(&r.statement_id)
            .map_or(&[], Vec::as_slice)
    }
    pub fn validate(&self, m: &Model, c: &Corpus) -> Result<(), String> {
        if self.schema != 1
            || self.foundation != naome_foundation::FOUNDATION_ID
            || self.policy != c.policy
            || self.model_digest != digest(&serde_json::to_vec(m).unwrap())
            || self.corpus_digest != c.digest()
            || self.rows.len() > 65536
            || self
                .entries
                .iter()
                .any(|e| e.vector.len() != EMBEDDING || e.vector.iter().any(|v| !v.is_finite()))
            || self.rows.iter().any(|i| *i >= self.entries.len())
        {
            return Err("incompatible or malformed index".into());
        }
        // Reconstruct the cached vectors and all deterministic addresses, not just metadata.
        let mut expected = Self::new(m, c);
        for i in 0..self.rows.len() {
            expected.append(m, &c.records[i % c.records.len()]);
        }
        if *self != expected {
            return Err("index content differs from checked corpus/model".into());
        }
        Ok(())
    }
}
