//! Bounded inverted index over checker-owned, reusable lemma statements.
use super::*;
use naome_proof::ProofId;
use std::collections::{BTreeMap, BTreeSet};

type Key = [u8; 32];
const KEYS: usize = 32;
const ENTRIES: usize = 64;

#[derive(Default)]
pub(super) struct Index {
    entries: VecDeque<(ProofId, usize, Vec<Key>)>,
    postings: BTreeMap<Key, BTreeSet<(usize, ProofId)>>,
}

impl Index {
    // Charges owned keys, postings and bounded tree allocation overhead.
    pub(super) const RESERVATION: usize = ENTRIES * (256 + KEYS * 160);

    pub(super) fn keys(formula: &Formula) -> Vec<Key> {
        crate::learning::knowledge::lemma_keys(formula, KEYS)
    }

    pub(super) fn insert(&mut self, proof: ProofId, bytes: usize, formula: &Formula) {
        if self.entries.iter().any(|(id, _, _)| *id == proof) {
            return;
        }
        let keys = Self::keys(formula);
        if keys.is_empty() {
            return;
        }
        if self.entries.len() == ENTRIES {
            let (old, bytes, keys) = self.entries.pop_front().expect("full lemma index");
            for key in keys {
                if let std::collections::btree_map::Entry::Occupied(mut entry) =
                    self.postings.entry(key)
                {
                    entry.get_mut().remove(&(bytes, old));
                    if entry.get().is_empty() {
                        entry.remove();
                    }
                }
            }
        }
        for key in &keys {
            self.postings
                .entry(*key)
                .or_default()
                .insert((bytes, proof));
        }
        self.entries.push_back((proof, bytes, keys));
    }

    pub(super) fn query(question: &ResearchQuestion) -> Vec<Key> {
        crate::learning::knowledge::lookup_keys(question.proved_target(), KEYS)
    }

    pub(super) fn has_support(&self, keys: &[Key]) -> bool {
        keys.iter().any(|key| self.postings.contains_key(key))
    }

    pub(super) fn offers(&self, keys: &[Key]) -> Vec<ProofId> {
        let mut hits = BTreeMap::new();
        for key in keys {
            if let Some(postings) = self.postings.get(key) {
                for &(bytes, id) in postings {
                    *hits.entry((bytes, id)).or_insert(0usize) += 1;
                }
            }
        }
        let mut ranked = hits.into_iter().collect::<Vec<_>>();
        ranked.sort_by_key(|(id, count)| (std::cmp::Reverse(*count), *id));
        ranked.into_iter().map(|((_, id), _)| id).take(4).collect()
    }
}
