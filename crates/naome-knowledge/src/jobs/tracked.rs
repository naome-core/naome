//! A bounded active map whose mutation sites identify the durable delta.
use crate::checkpoint::Update;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet, btree_map},
    ops::Deref,
};

#[derive(Clone, Debug)]
pub(super) struct TrackedMap<K, V> {
    entries: BTreeMap<K, V>,
    dirty: BTreeSet<K>,
    removed: BTreeSet<K>,
    lengths: BTreeMap<K, usize>,
}
impl<K: Ord + Clone, V> TrackedMap<K, V> {
    pub(super) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            dirty: BTreeSet::new(),
            removed: BTreeSet::new(),
            lengths: BTreeMap::new(),
        }
    }
    pub(super) fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.dirty.insert(key.clone());
        self.removed.remove(&key);
        self.entries.insert(key, value)
    }
    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        if self.entries.contains_key(key) {
            self.dirty.insert(key.clone());
        }
        self.entries.get_mut(key)
    }
    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        let result = self.entries.remove(key);
        if result.is_some() {
            self.dirty.remove(key);
            self.lengths.remove(key);
            self.removed.insert(key.clone());
        }
        result
    }
    pub(super) fn values_mut(&mut self) -> btree_map::ValuesMut<'_, K, V> {
        self.dirty.extend(self.entries.keys().cloned());
        self.entries.values_mut()
    }
    pub(super) fn changed(&self, key: &K) -> bool {
        self.dirty.contains(key)
    }
    pub(super) fn clean(&mut self) {
        self.dirty.clear();
        self.removed.clear();
    }
    /// Eviction is not durable deletion: account history remains queryable.
    pub(super) fn evict_except(&mut self, retained: &BTreeSet<K>) {
        debug_assert!(self.dirty.is_empty() && self.removed.is_empty());
        self.entries.retain(|key, _| retained.contains(key));
        self.lengths.retain(|key, _| retained.contains(key));
    }
}
impl<K: Ord + Clone + ToString, V: Serialize> TrackedMap<K, V> {
    pub(super) fn updates(&self, kind: &'static str) -> Result<Vec<Update>, String> {
        let mut updates = Vec::with_capacity(self.dirty.len() + self.removed.len());
        for key in &self.dirty {
            updates.push(Update::put(kind, key.to_string(), &self.entries[key])?);
        }
        for key in &self.removed {
            updates.push(Update::Remove {
                kind,
                key: key.to_string(),
            });
        }
        Ok(updates)
    }
    pub(super) fn encoded_len(&mut self) -> Result<usize, String> {
        for key in &self.dirty {
            self.lengths.insert(
                key.clone(),
                crate::checkpoint::encode(&self.entries[key])?.len() + key.to_string().len() + 4,
            );
        }
        // Deserialized/new entries are dirty until their first successful save.
        self.lengths.values().try_fold(0usize, |sum, length| {
            sum.checked_add(*length)
                .ok_or("active journal byte overflow".into())
        })
    }
}
impl<K: Ord + Clone, V> Default for TrackedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
impl<K, V> Deref for TrackedMap<K, V> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}
impl<'a, K, V> IntoIterator for &'a TrackedMap<K, V> {
    type Item = (&'a K, &'a V);
    type IntoIter = btree_map::Iter<'a, K, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
impl<K: Serialize, V: Serialize> Serialize for TrackedMap<K, V> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.entries.serialize(serializer)
    }
}
impl<'de, K: Ord + Clone + Deserialize<'de>, V: Deserialize<'de>> Deserialize<'de>
    for TrackedMap<K, V>
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries = BTreeMap::<K, V>::deserialize(deserializer)?;
        Ok(Self {
            dirty: entries.keys().cloned().collect(),
            entries,
            removed: BTreeSet::new(),
            lengths: BTreeMap::new(),
        })
    }
}
