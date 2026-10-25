use crate::context::{ContextError, ContextStorage};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const MAX_NODE_BYTES: usize = 4096;
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
        let mut lookup = self.lookup(*key);
        while self.advance_lookup(&mut lookup)?.is_some() {}
        lookup.into_value()
    }

    pub(crate) fn lookup(&self, key: [u8; 32]) -> Lookup {
        Lookup {
            pending: self.root.map(Pending::root),
            key,
            value: None,
            failed: false,
        }
    }

    pub(crate) fn advance_lookup(
        &self,
        lookup: &mut Lookup,
    ) -> Result<Option<usize>, ContextError> {
        lookup.step(self.storage.as_ref())
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

    pub(crate) fn walk(&self) -> Walk {
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

/// An authenticated point lookup with one bounded node read per step. The
/// key and live root are captured before a caller starts charging its work.
pub(crate) struct Lookup {
    pending: Option<Pending>,
    key: [u8; 32],
    value: Option<Vec<u8>>,
    failed: bool,
}
impl Lookup {
    pub(crate) fn complete(&self) -> bool {
        !self.failed && self.pending.is_none()
    }
    pub(crate) fn value(&self) -> Result<Option<&[u8]>, ContextError> {
        if !self.complete() {
            return Err(ContextError::Corrupt);
        }
        Ok(self.value.as_deref())
    }
    fn into_value(self) -> Result<Option<Vec<u8>>, ContextError> {
        self.value()?;
        Ok(self.value)
    }
    fn step(&mut self, storage: &dyn ContextStorage) -> Result<Option<usize>, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        let Some(pending) = self.pending.take() else {
            return Ok(None);
        };
        let result = (|| {
            let (node, bytes) = load_node_sized(storage, pending)?;
            match node {
                Node::Leaf { key, value } => self.value = (key == self.key).then_some(value),
                Node::Branch { bit, left, right } => {
                    let child = if key_bit(&self.key, bit) { right } else { left };
                    self.pending = Some(pending.child(child, bit)?);
                }
            }
            Ok(Some(bytes))
        })();
        if let Err(error) = &result {
            self.failed = true;
            self.pending = None;
            storage.record_failure(error);
        }
        result
    }
}

/// One authenticated node per step, including branches that yield no entry.
/// Nested bucket traversal needs at most one additional bounded DFS stack.
pub(crate) struct Walk {
    storage: Arc<dyn ContextStorage>,
    pending: Vec<Pending>,
    previous_key: Option<[u8; 32]>,
    failed: bool,
}

pub(crate) struct Visit {
    pub(crate) address: [u8; 32],
    pub(crate) bytes: Vec<u8>,
    pub(crate) entry: Option<([u8; 32], Vec<u8>)>,
}

impl Walk {
    pub(crate) fn complete(&self) -> bool {
        !self.failed && self.pending.is_empty()
    }

    pub(crate) fn step(&mut self) -> Result<Option<Visit>, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        self.step_selected(&mut |_| Ok(true))
    }

    /// A storage frontier may prune an already materialized immutable subtree.
    /// This only enumerates records of existing live roots; it creates no roots.
    pub(crate) fn step_selected(
        &mut self,
        select: &mut impl FnMut([u8; 32]) -> Result<bool, ContextError>,
    ) -> Result<Option<Visit>, ContextError> {
        if self.failed {
            return Err(ContextError::Corrupt);
        }
        let result = (|| {
            let pending = loop {
                let Some(pending) = self.pending.pop() else {
                    return Ok(None);
                };
                if select(pending.root.address)? {
                    break pending;
                }
            };
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
    load_node_sized(storage, pending).map(|(node, _)| node)
}

fn load_node_sized(
    storage: &dyn ContextStorage,
    pending: Pending,
) -> Result<(Node, usize), ContextError> {
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
    Ok((node, bytes.len()))
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
mod tests;
