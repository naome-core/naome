use crate::context::{ContextError, ContextStorage};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(super) const MAX_NODE_BYTES: usize = 4096;
const MAX_VALUE_BYTES: usize = 2048;
const VERSION: u8 = 1;
const LEAF: u8 = 0;
const BRANCH: u8 = 1;
const CHILD_BYTES: usize = 128;

/// Only an authenticated enclosing context may restore a root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Root {
    pub(crate) address: [u8; 32],
    pub(crate) fingerprint: [u8; 32],
}

/// Immutable fixed-byte Patricia nodes owned and authenticated by the checker.
/// The logical fingerprint retains PersistentMap's key-only contract. Storage
/// addresses independently bind every encoded byte, including values.
#[derive(Clone)]
pub(crate) struct DiskMap {
    storage: Arc<dyn ContextStorage>,
    root: Option<Root>,
}

impl DiskMap {
    pub(crate) fn new(storage: Arc<dyn ContextStorage>) -> Self {
        Self::from_root(storage, None)
    }

    pub(crate) fn from_root(storage: Arc<dyn ContextStorage>, root: Option<Root>) -> Self {
        Self { storage, root }
    }

    pub(crate) const fn root(&self) -> Option<Root> {
        self.root
    }

    pub(crate) fn storage(&self) -> Arc<dyn ContextStorage> {
        self.storage.clone()
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.root.map_or([0; 32], |root| root.fingerprint)
    }

    pub(crate) fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, ContextError> {
        let Some(root) = self.root else {
            return Ok(None);
        };
        let mut pending = Pending::root(root);
        loop {
            match load_node(self.storage.as_ref(), pending)? {
                Node::Leaf { key: stored, value } => return Ok((stored == *key).then_some(value)),
                Node::Branch { bit, left, right } => {
                    let child = if key_bit(key, bit) { right } else { left };
                    pending = pending.child(child, bit)?;
                }
            }
        }
    }

    pub(crate) fn contains_key(&self, key: &[u8; 32]) -> Result<bool, ContextError> {
        self.get(key).map(|value| value.is_some())
    }

    /// An existing key keeps both its value and the complete root unchanged.
    pub(crate) fn insert(&mut self, key: [u8; 32], value: &[u8]) -> Result<bool, ContextError> {
        self.write_value(key, value, false)
    }

    pub(crate) fn set(&mut self, key: [u8; 32], value: &[u8]) -> Result<(), ContextError> {
        self.write_value(key, value, true).map(|_| ())
    }

    pub(crate) fn entries(&self) -> Entries {
        self.entries_after(None)
    }
    pub(crate) fn entries_after(&self, after: Option<[u8; 32]>) -> Entries {
        Entries {
            storage: self.storage(),
            pending: self.root.into_iter().map(Pending::root).collect(),
            previous_key: after,
            after,
        }
    }

    /// Copy only nodes reachable from this live authenticated root. The
    /// traversal stack is bounded independently of the number of entries.
    pub(crate) fn copy_to(&self, storage: Arc<dyn ContextStorage>) -> Result<Self, ContextError> {
        let mut walk = self.walk();
        while let Some(visit) = walk.step()? {
            storage.write(visit.address, &visit.bytes)?;
        }
        Ok(Self::from_root(storage, self.root))
    }

    pub(super) fn walk(&self) -> Walk {
        Walk {
            storage: self.storage(),
            pending: self.root.into_iter().map(Pending::root).collect(),
            previous_key: None,
            failed: false,
        }
    }

    fn write_value(
        &mut self,
        key: [u8; 32],
        value: &[u8],
        replace: bool,
    ) -> Result<bool, ContextError> {
        if value.len() > MAX_VALUE_BYTES {
            return Err(ContextError::Limit);
        }
        let Some(root) = self.root else {
            let leaf = self.save_node(Node::Leaf {
                key,
                value: value.to_vec(),
            })?;
            self.root = Some(leaf.root);
            return Ok(true);
        };

        // At most 256 branch frames are retained, independent of corpus size.
        let mut path = Vec::new();
        let mut pending = Pending::root(root);
        let (terminal, old_key, old_value) = loop {
            let node = load_node(self.storage.as_ref(), pending)?;
            let source = Child {
                root: pending.root,
                range: node.range(),
            };
            match node {
                Node::Leaf { key, value } => break (source, key, value),
                Node::Branch { bit, left, right } => {
                    let right_side = key_bit(&key, bit);
                    path.push(Frame {
                        source,
                        bit,
                        left,
                        right,
                        right_side,
                    });
                    pending = pending.child(if right_side { right } else { left }, bit)?;
                }
            }
        };

        if old_key == key && (!replace || old_value == value) {
            return Ok(false);
        }
        let mut changed = self.save_node(Node::Leaf {
            key,
            value: value.to_vec(),
        })?;
        let prefix_length = if old_key == key {
            path.len()
        } else {
            let bit = first_differing_bit(&old_key, &key).ok_or(ContextError::Corrupt)?;
            let index = path
                .iter()
                .position(|frame| frame.bit >= bit)
                .unwrap_or(path.len());
            let existing = path.get(index).map_or(terminal, |frame| frame.source);
            let (left, right) = if key_bit(&key, bit) {
                (existing, changed)
            } else {
                (changed, existing)
            };
            changed = self.save_node(Node::Branch { bit, left, right })?;
            index
        };

        for frame in path[..prefix_length].iter().rev() {
            let (left, right) = if frame.right_side {
                (frame.left, changed)
            } else {
                (changed, frame.right)
            };
            changed = self.save_node(Node::Branch {
                bit: frame.bit,
                left,
                right,
            })?;
        }
        // A failed write can leave unreachable immutable nodes, never a
        // partially updated published root or a mutation of an old handle.
        self.root = Some(changed.root);
        Ok(old_key != key)
    }

    fn save_node(&self, node: Node) -> Result<Child, ContextError> {
        node.validate()?;
        let bytes = node.encode();
        if bytes.len() > MAX_NODE_BYTES {
            return Err(ContextError::Limit);
        }
        let root = Root {
            address: storage_address(&bytes),
            fingerprint: node.fingerprint(),
        };
        self.storage.write(root.address, &bytes)?;
        Ok(Child {
            root,
            range: node.range(),
        })
    }
}

/// One authenticated node per step, including branches that yield no entry.
/// Nested bucket traversal needs at most one additional bounded DFS stack.
pub(super) struct Walk {
    storage: Arc<dyn ContextStorage>,
    pending: Vec<Pending>,
    previous_key: Option<[u8; 32]>,
    failed: bool,
}

pub(super) struct Visit {
    pub(super) address: [u8; 32],
    pub(super) bytes: Vec<u8>,
    pub(super) entry: Option<([u8; 32], Vec<u8>)>,
}

impl Walk {
    pub(super) fn complete(&self) -> bool {
        !self.failed && self.pending.is_empty()
    }

    pub(super) fn step(&mut self) -> Result<Option<Visit>, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        let Some(pending) = self.pending.pop() else {
            return Ok(None);
        };
        let result = (|| {
            let node = load_node_inner(self.storage.as_ref(), pending)?;
            let bytes = node.encode();
            let entry = match node {
                Node::Leaf { key, value } => {
                    if self.previous_key.is_some_and(|previous| previous >= key) {
                        return Err(ContextError::Corrupt);
                    }
                    self.previous_key = Some(key);
                    Some((key, value))
                }
                Node::Branch { bit, left, right } => {
                    self.pending.push(pending.child(right, bit)?);
                    self.pending.push(pending.child(left, bit)?);
                    None
                }
            };
            Ok(Some(Visit {
                address: pending.root.address,
                bytes,
                entry,
            }))
        })();
        if let Err(error) = &result {
            self.failed = true;
            self.pending.clear();
            self.storage.record_failure(error);
        }
        result
    }
}

/// Completion is decided only by the checker's exhausted traversal stack.
/// A failed read yields one error and terminates this failed traversal.
pub(crate) struct Entries {
    storage: Arc<dyn ContextStorage>,
    pending: Vec<Pending>,
    previous_key: Option<[u8; 32]>,
    after: Option<[u8; 32]>,
}

impl Iterator for Entries {
    type Item = Result<([u8; 32], Vec<u8>), ContextError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(pending) = self.pending.pop() {
            if self
                .after
                .zip(pending.range)
                .is_some_and(|(after, range)| range.maximum <= after)
            {
                continue;
            }
            let result = (|| match load_node(self.storage.as_ref(), pending)? {
                Node::Leaf { key, value } => {
                    if self.after.is_some_and(|after| key <= after) {
                        return Ok(None);
                    }
                    if self.previous_key.is_some_and(|previous| previous >= key) {
                        return Err(ContextError::Corrupt);
                    }
                    self.previous_key = Some(key);
                    Ok(Some((key, value)))
                }
                Node::Branch { bit, left, right } => {
                    self.pending.push(pending.child(right, bit)?);
                    self.pending.push(pending.child(left, bit)?);
                    Ok(None)
                }
            })();
            match result {
                Ok(Some(entry)) => return Some(Ok(entry)),
                Ok(None) => {}
                Err(error) => {
                    self.storage.record_failure(&error);
                    self.pending.clear();
                    return Some(Err(error));
                }
            }
        }
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct KeyRange {
    minimum: [u8; 32],
    maximum: [u8; 32],
}

#[derive(Clone, Copy)]
struct Child {
    root: Root,
    range: KeyRange,
}

#[derive(Clone, Copy)]
struct Pending {
    root: Root,
    range: Option<KeyRange>,
    previous_bit: Option<u8>,
    depth: u16,
}

impl Pending {
    fn root(root: Root) -> Self {
        Self {
            root,
            range: None,
            previous_bit: None,
            depth: 0,
        }
    }

    fn child(self, child: Child, bit: u8) -> Result<Self, ContextError> {
        let depth = self.depth.checked_add(1).ok_or(ContextError::Corrupt)?;
        if depth > 256 {
            return Err(ContextError::Corrupt);
        }
        Ok(Self {
            root: child.root,
            range: Some(child.range),
            previous_bit: Some(bit),
            depth,
        })
    }
}

struct Frame {
    source: Child,
    bit: u8,
    left: Child,
    right: Child,
    right_side: bool,
}

// Nodes are short-lived; each traversal path is bounded to 256 branches. Inline
// children avoid an extra heap allocation for each authenticated branch read.
#[allow(clippy::large_enum_variant)]
enum Node {
    Leaf { key: [u8; 32], value: Vec<u8> },
    Branch { bit: u8, left: Child, right: Child },
}

impl Node {
    fn range(&self) -> KeyRange {
        match self {
            Self::Leaf { key, .. } => KeyRange {
                minimum: *key,
                maximum: *key,
            },
            Self::Branch { left, right, .. } => KeyRange {
                minimum: left.range.minimum,
                maximum: right.range.maximum,
            },
        }
    }

    fn fingerprint(&self) -> [u8; 32] {
        match self {
            Self::Leaf { key, .. } => crate::context::fingerprint::leaf(key),
            Self::Branch { bit, left, right } => crate::context::fingerprint::branch(
                *bit,
                left.root.fingerprint,
                right.root.fingerprint,
            ),
        }
    }

    fn validate(&self) -> Result<(), ContextError> {
        match self {
            Self::Leaf { value, .. } if value.len() > MAX_VALUE_BYTES => Err(ContextError::Corrupt),
            Self::Leaf { .. } => Ok(()),
            Self::Branch { bit, left, right } => {
                let left_range = left.range;
                let right_range = right.range;
                if left_range.minimum > left_range.maximum
                    || right_range.minimum > right_range.maximum
                    || left_range.maximum >= right_range.minimum
                    || left.root.address == right.root.address
                    || first_differing_bit(&left_range.minimum, &right_range.maximum) != Some(*bit)
                    || !same_prefix(&left_range.minimum, &left_range.maximum, *bit)
                    || !same_prefix(&left_range.minimum, &right_range.minimum, *bit)
                    || !same_prefix(&right_range.minimum, &right_range.maximum, *bit)
                    || key_bit(&left_range.minimum, *bit)
                    || key_bit(&left_range.maximum, *bit)
                    || !key_bit(&right_range.minimum, *bit)
                    || !key_bit(&right_range.maximum, *bit)
                {
                    return Err(ContextError::Corrupt);
                }
                Ok(())
            }
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(match self {
            Self::Leaf { value, .. } => 36 + value.len(),
            Self::Branch { .. } => 3 + 2 * CHILD_BYTES,
        });
        bytes.push(VERSION);
        match self {
            Self::Leaf { key, value } => {
                bytes.push(LEAF);
                bytes.extend_from_slice(key);
                bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
                bytes.extend_from_slice(value);
            }
            Self::Branch { bit, left, right } => {
                bytes.push(BRANCH);
                bytes.push(*bit);
                encode_child(&mut bytes, *left);
                encode_child(&mut bytes, *right);
            }
        }
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ContextError> {
        if bytes.first() != Some(&VERSION) {
            return Err(ContextError::Corrupt);
        }
        let node = match bytes.get(1) {
            Some(&LEAF) if bytes.len() >= 36 => {
                let length = u16::from_be_bytes([bytes[34], bytes[35]]) as usize;
                if length > MAX_VALUE_BYTES || bytes.len() != 36 + length {
                    return Err(ContextError::Corrupt);
                }
                Self::Leaf {
                    key: fixed_key(&bytes[2..34])?,
                    value: bytes[36..].to_vec(),
                }
            }
            Some(&BRANCH) if bytes.len() == 3 + 2 * CHILD_BYTES => Self::Branch {
                bit: bytes[2],
                left: decode_child(&bytes[3..3 + CHILD_BYTES])?,
                right: decode_child(&bytes[3 + CHILD_BYTES..])?,
            },
            _ => return Err(ContextError::Corrupt),
        };
        node.validate()?;
        Ok(node)
    }
}

fn load_node(storage: &dyn ContextStorage, pending: Pending) -> Result<Node, ContextError> {
    let result = load_node_inner(storage, pending);
    if let Err(error) = &result {
        storage.record_failure(error);
    }
    result
}

fn load_node_inner(storage: &dyn ContextStorage, pending: Pending) -> Result<Node, ContextError> {
    if pending.depth > 256 {
        return Err(ContextError::Corrupt);
    }
    let bytes = storage.read(pending.root.address, MAX_NODE_BYTES)?;
    if bytes.len() > MAX_NODE_BYTES {
        return Err(ContextError::Limit);
    }
    if storage_address(&bytes) != pending.root.address {
        return Err(ContextError::Corrupt);
    }
    let node = Node::decode(&bytes)?;
    if node.fingerprint() != pending.root.fingerprint
        || pending.range.is_some_and(|range| range != node.range())
    {
        return Err(ContextError::Corrupt);
    }
    if let Node::Branch { bit, .. } = &node
        && (pending.depth == 256
            || pending
                .previous_bit
                .is_some_and(|previous| *bit <= previous))
    {
        return Err(ContextError::Corrupt);
    }
    Ok(node)
}

fn storage_address(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-map:storage:v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

fn encode_child(bytes: &mut Vec<u8>, child: Child) {
    bytes.extend_from_slice(&child.root.address);
    bytes.extend_from_slice(&child.root.fingerprint);
    bytes.extend_from_slice(&child.range.minimum);
    bytes.extend_from_slice(&child.range.maximum);
}

fn decode_child(bytes: &[u8]) -> Result<Child, ContextError> {
    if bytes.len() != CHILD_BYTES {
        return Err(ContextError::Corrupt);
    }
    Ok(Child {
        root: Root {
            address: fixed_key(&bytes[..32])?,
            fingerprint: fixed_key(&bytes[32..64])?,
        },
        range: KeyRange {
            minimum: fixed_key(&bytes[64..96])?,
            maximum: fixed_key(&bytes[96..])?,
        },
    })
}

fn fixed_key(bytes: &[u8]) -> Result<[u8; 32], ContextError> {
    bytes.try_into().map_err(|_| ContextError::Corrupt)
}

fn first_differing_bit(left: &[u8; 32], right: &[u8; 32]) -> Option<u8> {
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        let differing = left ^ right;
        if differing != 0 {
            return Some((index * 8 + differing.leading_zeros() as usize) as u8);
        }
    }
    None
}

fn same_prefix(left: &[u8; 32], right: &[u8; 32], bit: u8) -> bool {
    first_differing_bit(left, right).is_none_or(|differing| differing >= bit)
}

fn key_bit(key: &[u8; 32], bit: u8) -> bool {
    let bit = usize::from(bit);
    key[bit / 8] & (1 << (7 - bit % 8)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::persistent_map::{Key256, PersistentMap};
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemoryStorage {
        bytes: Mutex<BTreeMap<[u8; 32], Vec<u8>>>,
        writes_until_failure: Mutex<Option<usize>>,
        failures: Mutex<Vec<ContextError>>,
    }

    impl ContextStorage for MemoryStorage {
        fn record_failure(&self, error: &ContextError) {
            self.failures.lock().unwrap().push(error.clone());
        }
        fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
            let value = self
                .bytes
                .lock()
                .unwrap()
                .get(&address)
                .cloned()
                .ok_or_else(|| ContextError::Storage("missing node".into()))?;
            if value.len() > maximum {
                return Err(ContextError::Limit);
            }
            Ok(value)
        }

        fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
            let mut budget = self.writes_until_failure.lock().unwrap();
            if let Some(remaining) = budget.as_mut() {
                if *remaining == 0 {
                    return Err(ContextError::Storage("injected write failure".into()));
                }
                *remaining -= 1;
            }
            let mut stored = self.bytes.lock().unwrap();
            if let Some(existing) = stored.get(&address) {
                if existing != bytes {
                    return Err(ContextError::Corrupt);
                }
            } else {
                stored.insert(address, bytes.to_vec());
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct TestKey([u8; 32]);

    impl Key256 for TestKey {
        fn as_key_bytes(&self) -> &[u8; 32] {
            &self.0
        }
    }

    fn bit_key(bit: usize) -> [u8; 32] {
        let mut key = [0; 32];
        key[bit / 8] = 1 << (7 - bit % 8);
        key
    }

    fn restored_node(storage: Arc<MemoryStorage>, node: Node) -> DiskMap {
        let bytes = node.encode();
        let root = Root {
            address: storage_address(&bytes),
            fingerprint: node.fingerprint(),
        };
        storage.bytes.lock().unwrap().insert(root.address, bytes);
        DiskMap::from_root(storage, Some(root))
    }

    #[test]
    fn insertion_orders_match_memory_fingerprints_and_sorted_entries() {
        let keys = [[0; 32], bit_key(0), bit_key(1), bit_key(132), bit_key(255)];
        let mut expected_fingerprint = None;
        for order in [
            [0, 1, 2, 3, 4],
            [4, 3, 2, 1, 0],
            [2, 4, 0, 3, 1],
            [1, 3, 0, 4, 2],
        ] {
            let storage = Arc::new(MemoryStorage::default());
            let mut disk = DiskMap::new(storage);
            let mut memory = PersistentMap::new();
            for index in order {
                let value = [index as u8];
                assert!(disk.insert(keys[index], &value).unwrap());
                assert!(memory.insert(TestKey(keys[index]), value.to_vec()));
                assert_eq!(disk.fingerprint(), memory.fingerprint());
            }
            let before = disk.root();
            assert!(!disk.insert(keys[2], &[255]).unwrap());
            assert_eq!(disk.root(), before);
            for (index, key) in keys.iter().enumerate() {
                assert_eq!(disk.get(key).unwrap(), Some(vec![index as u8]));
                assert!(disk.contains_key(key).unwrap());
            }
            let entries: Vec<_> = disk.entries().collect::<Result<_, _>>().unwrap();
            let mut expected: Vec<_> = keys
                .into_iter()
                .enumerate()
                .map(|(index, key)| (key, vec![index as u8]))
                .collect();
            expected.sort();
            assert_eq!(entries, expected);
            if let Some(fingerprint) = expected_fingerprint {
                assert_eq!(disk.fingerprint(), fingerprint);
            } else {
                expected_fingerprint = Some(disk.fingerprint());
            }
        }
    }

    #[test]
    fn value_replacement_changes_storage_address_not_key_fingerprint_or_old_handles() {
        let storage = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(storage);
        map.insert([0; 32], b"old").unwrap();
        map.insert(bit_key(0), b"other").unwrap();
        let old = map.clone();
        map.set([0; 32], b"new").unwrap();
        assert_eq!(old.fingerprint(), map.fingerprint());
        assert_ne!(old.root(), map.root());
        assert_eq!(old.get(&[0; 32]).unwrap(), Some(b"old".to_vec()));
        assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"new".to_vec()));
        let reopened = DiskMap::from_root(map.storage(), map.root());
        assert_eq!(
            reopened.entries().collect::<Result<Vec<_>, _>>().unwrap(),
            map.entries().collect::<Result<Vec<_>, _>>().unwrap()
        );
        let same = map.root();
        map.set([0; 32], b"new").unwrap();
        assert_eq!(map.root(), same);
    }

    #[test]
    fn full_256_branch_path_is_bounded_and_retains_clone_isolation() {
        let storage = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(storage);
        let mut memory = PersistentMap::new();
        map.insert([0; 32], b"zero").unwrap();
        memory.insert(TestKey([0; 32]), ());
        for bit in 0..256 {
            map.insert(bit_key(bit), &[bit as u8]).unwrap();
            memory.insert(TestKey(bit_key(bit)), ());
        }
        assert_eq!(map.fingerprint(), memory.fingerprint());
        assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"zero".to_vec()));
        assert_eq!(
            map.entries().collect::<Result<Vec<_>, _>>().unwrap().len(),
            257
        );
        let target = Arc::new(MemoryStorage::default());
        let mut walk = map.walk();
        let mut visited = 0;
        let mut leaves = 0;
        while let Some(visit) = walk.step().unwrap() {
            visited += 1;
            leaves += if visit.entry.is_some() { 1 } else { 0 };
            assert!(visit.bytes.len() <= MAX_NODE_BYTES);
            assert!(
                walk.pending.len() <= 257,
                "DFS memory follows depth, not corpus size"
            );
            target.write(visit.address, &visit.bytes).unwrap();
        }
        assert!(walk.complete());
        assert_eq!(
            (visited, leaves),
            (513, 257),
            "branches consume separate steps"
        );
        assert_eq!(target.bytes.lock().unwrap().len(), 513);
        assert_eq!(
            DiskMap::from_root(target, map.root())
                .get(&[0; 32])
                .unwrap(),
            Some(b"zero".to_vec())
        );
        let old = map.clone();
        let mut new_key = [0; 32];
        new_key[31] = 3;
        map.set(new_key, b"extra").unwrap();
        assert_eq!(old.get(&new_key).unwrap(), None);
        assert_eq!(map.get(&new_key).unwrap(), Some(b"extra".to_vec()));
    }

    #[test]
    fn failed_path_write_does_not_publish_partial_root() {
        let storage = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(storage.clone());
        map.insert([0; 32], b"zero").unwrap();
        map.insert(bit_key(0), b"one").unwrap();
        let before = map.root();
        *storage.writes_until_failure.lock().unwrap() = Some(1);
        assert!(matches!(
            map.set([0; 32], b"changed"),
            Err(ContextError::Storage(_))
        ));
        assert_eq!(map.root(), before);
        assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"zero".to_vec()));
        *storage.writes_until_failure.lock().unwrap() = None;
        map.set([0; 32], b"changed").unwrap();
        assert_eq!(map.get(&[0; 32]).unwrap(), Some(b"changed".to_vec()));
    }

    #[test]
    fn cold_tamper_and_missing_nodes_are_errors_even_for_absent_queries() {
        let storage = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(storage.clone());
        map.insert([0; 32], b"value").unwrap();
        let leaf = map.root().unwrap();
        let original = storage
            .bytes
            .lock()
            .unwrap()
            .get(&leaf.address)
            .unwrap()
            .clone();
        storage
            .bytes
            .lock()
            .unwrap()
            .get_mut(&leaf.address)
            .unwrap()[36] ^= 1;
        assert_eq!(map.get(&[0; 32]), Err(ContextError::Corrupt));
        assert_eq!(
            storage.failures.lock().unwrap().last(),
            Some(&ContextError::Corrupt)
        );
        assert_eq!(map.get(&bit_key(0)), Err(ContextError::Corrupt));
        storage.bytes.lock().unwrap().insert(leaf.address, original);
        map.insert(bit_key(0), b"right").unwrap();
        storage.bytes.lock().unwrap().remove(&leaf.address);
        assert!(matches!(
            map.get(&bit_key(1)),
            Err(ContextError::Storage(_))
        ));
        assert!(matches!(
            map.entries().next(),
            Some(Err(ContextError::Storage(_)))
        ));
    }

    #[test]
    fn iterator_cannot_hide_a_failed_cold_sibling_as_completion() {
        let storage = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(storage.clone());
        map.insert(bit_key(0), b"right").unwrap();
        let right_leaf = map.root().unwrap();
        map.insert([0; 32], b"left").unwrap();
        storage.bytes.lock().unwrap().remove(&right_leaf.address);
        let mut entries = map.entries();
        assert_eq!(entries.next(), Some(Ok(([0; 32], b"left".to_vec()))));
        assert!(matches!(
            entries.next(),
            Some(Err(ContextError::Storage(_)))
        ));
        assert_eq!(entries.next(), None);
        let mut walk = map.walk();
        assert!(walk.step().is_ok()); // root branch
        assert!(walk.step().is_ok()); // left leaf
        assert!(walk.step().is_err());
        assert!(!walk.complete(), "a failed cursor cannot look exhausted");
        assert!(walk.step().is_err());
    }

    #[test]
    fn authenticated_malformed_metadata_and_branch_order_are_rejected() {
        let storage = Arc::new(MemoryStorage::default());
        let map = DiskMap::new(storage.clone());
        let left = map
            .save_node(Node::Leaf {
                key: [0; 32],
                value: vec![],
            })
            .unwrap();
        let right = map
            .save_node(Node::Leaf {
                key: bit_key(0),
                value: vec![],
            })
            .unwrap();
        let invalid_split = restored_node(
            storage.clone(),
            Node::Branch {
                bit: 1,
                left,
                right,
            },
        );
        assert_eq!(invalid_split.get(&[0; 32]), Err(ContextError::Corrupt));
        let mut invalid_fingerprint = left;
        invalid_fingerprint.root.fingerprint[0] ^= 1;
        let bad_child = restored_node(
            storage.clone(),
            Node::Branch {
                bit: 0,
                left: invalid_fingerprint,
                right,
            },
        );
        assert_eq!(bad_child.get(&[0; 32]), Err(ContextError::Corrupt));
        let mut invalid_range = left;
        invalid_range.range.maximum = bit_key(1);
        let bad_range = restored_node(
            storage.clone(),
            Node::Branch {
                bit: 0,
                left: invalid_range,
                right,
            },
        );
        assert_eq!(bad_range.get(&[0; 32]), Err(ContextError::Corrupt));
        let reversed = restored_node(
            storage,
            Node::Branch {
                bit: 0,
                left: right,
                right: left,
            },
        );
        assert_eq!(reversed.entries().next(), Some(Err(ContextError::Corrupt)));
    }

    #[test]
    fn strict_node_codec_and_value_limit_preserve_existing_root() {
        let storage = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(storage.clone());
        assert_eq!(map.fingerprint(), [0; 32]);
        assert_eq!(map.entries().next(), None);
        map.insert([0; 32], &vec![7; MAX_VALUE_BYTES]).unwrap();
        let before = map.root();
        assert_eq!(
            map.set([0; 32], &vec![8; MAX_VALUE_BYTES + 1]),
            Err(ContextError::Limit)
        );
        assert_eq!(map.root(), before);
        let original = Node::Leaf {
            key: [0; 32],
            value: vec![1],
        }
        .encode();
        let mut bad_version = original.clone();
        bad_version[0] = 2;
        let mut bad_type = original.clone();
        bad_type[1] = 2;
        let mut trailing = original.clone();
        trailing.push(0);
        let truncated = original[..original.len() - 1].to_vec();
        for bytes in [bad_version, bad_type, trailing, truncated] {
            let root = Root {
                address: storage_address(&bytes),
                fingerprint: before.unwrap().fingerprint,
            };
            storage.bytes.lock().unwrap().insert(root.address, bytes);
            assert_eq!(
                DiskMap::from_root(storage.clone(), Some(root)).get(&[0; 32]),
                Err(ContextError::Corrupt)
            );
        }
    }
    #[test]
    fn cursor_seeks_authenticated_ranges_and_copy_retains_every_reachable_node() {
        let source = Arc::new(MemoryStorage::default());
        let mut map = DiskMap::new(source.clone());
        let first = [1; 32];
        let middle = [64; 32];
        let last = [192; 32];
        map.insert(first, b"first").unwrap();
        let first_address = map.root().unwrap().address;
        map.insert(middle, b"middle").unwrap();
        map.insert(last, b"last").unwrap();
        let target = Arc::new(MemoryStorage::default());
        let copied = map.copy_to(target).unwrap();
        assert_eq!(copied.root(), map.root());
        assert_eq!(
            copied.entries().collect::<Result<Vec<_>, _>>().unwrap(),
            map.entries().collect::<Result<Vec<_>, _>>().unwrap()
        );
        source.bytes.lock().unwrap().remove(&first_address);
        assert_eq!(
            map.entries_after(Some(middle))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec![(last, b"last".to_vec())]
        );
        assert!(map.get(&first).is_err());
        assert!(map.copy_to(Arc::new(MemoryStorage::default())).is_err());
        assert_eq!(copied.get(&first).unwrap(), Some(b"first".to_vec()));
    }
}
