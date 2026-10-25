use std::sync::Arc;

pub(crate) trait Key256: Copy + Eq {
    fn as_key_bytes(&self) -> &[u8; 32];
}

/// An immutable-node Patricia map whose mutable handle replaces only the path
/// to a newly inserted leaf.
///
/// Cloning a handle clones one optional [`Arc`]. Values never need to implement
/// [`Clone`], and every untouched subtree remains shared after insertion.
pub(crate) struct PersistentMap<K, V> {
    root: Option<Arc<Node<K, V>>>,
}

impl<K, V> PersistentMap<K, V> {
    pub(crate) const fn new() -> Self {
        Self { root: None }
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        self.root.as_deref().map_or([0; 32], Node::fingerprint)
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut pending: Vec<_> = self.root.as_deref().into_iter().collect();
        std::iter::from_fn(move || {
            while let Some(node) = pending.pop() {
                match node {
                    Node::Leaf { key, value, .. } => return Some((key, value)),
                    Node::Branch { left, right, .. } => {
                        pending.push(right.as_ref());
                        pending.push(left.as_ref());
                    }
                }
            }
            None
        })
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.root.as_deref().map_or(0, leaf_count)
    }
}

impl<K, V> Clone for PersistentMap<K, V> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}

impl<K, V> Default for PersistentMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Key256, V> PersistentMap<K, V> {
    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        let mut node = self.root.as_deref()?;
        loop {
            match node {
                Node::Leaf {
                    key: stored_key,
                    value,
                    ..
                } => return (stored_key == key).then_some(value),
                Node::Branch {
                    bit, left, right, ..
                } => {
                    node = if key_bit(key.as_key_bytes(), *bit) {
                        right.as_ref()
                    } else {
                        left.as_ref()
                    };
                }
            }
        }
    }

    /// Inserts one absent key without replacing an existing value.
    ///
    /// Returns whether a new leaf was inserted. An existing key leaves the
    /// complete root unchanged.
    pub(crate) fn insert(&mut self, key: K, value: V) -> bool {
        let Some(root) = &self.root else {
            self.root = Some(Arc::new(Node::leaf(key, value)));
            return true;
        };

        let terminal_key = *terminal_key(root, &key);
        if terminal_key == key {
            return false;
        }

        let differing_bit = first_differing_bit(terminal_key.as_key_bytes(), key.as_key_bytes());
        self.root = Some(insert_at(root, differing_bit, key, value));
        true
    }

    /// Replaces only the path to this key, retaining immutable old handles.
    /// Fingerprints bind keys only; callers must bind derived values through
    /// their authoritative content-addressed input set.
    pub(crate) fn set(&mut self, key: K, value: V) {
        if self.contains_key(&key) {
            self.root = Some(replace_at(
                self.root.as_ref().expect("present key"),
                key,
                value,
            ));
        } else {
            self.insert(key, value);
        }
    }

    #[cfg(test)]
    pub(crate) fn shares_root_with(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn shares_terminal_for_key_with(&self, other: &Self, key: &K) -> bool {
        match (&self.root, &other.root) {
            (Some(left), Some(right)) => {
                Arc::ptr_eq(terminal_node(left, key), terminal_node(right, key))
            }
            _ => false,
        }
    }
}

enum Node<K, V> {
    Leaf {
        key: K,
        value: V,
        fingerprint: [u8; 32],
    },
    Branch {
        bit: u8,
        left: Arc<Self>,
        right: Arc<Self>,
        fingerprint: [u8; 32],
    },
}

impl<K, V> Node<K, V> {
    fn fingerprint(&self) -> [u8; 32] {
        match self {
            Self::Leaf { fingerprint, .. } | Self::Branch { fingerprint, .. } => *fingerprint,
        }
    }

    fn branch(bit: u8, left: Arc<Self>, right: Arc<Self>) -> Self {
        let fingerprint =
            crate::context::fingerprint::branch(bit, left.fingerprint(), right.fingerprint());
        Self::Branch {
            bit,
            left,
            right,
            fingerprint,
        }
    }
}

impl<K: Key256, V> Node<K, V> {
    fn leaf(key: K, value: V) -> Self {
        let fingerprint = crate::context::fingerprint::leaf(key.as_key_bytes());
        Self::Leaf {
            key,
            value,
            fingerprint,
        }
    }
}

fn terminal_key<'a, K: Key256, V>(mut node: &'a Arc<Node<K, V>>, key: &K) -> &'a K {
    node = terminal_node(node, key);
    match node.as_ref() {
        Node::Leaf { key, .. } => key,
        Node::Branch { .. } => unreachable!("terminal traversal ends at one leaf"),
    }
}

fn terminal_node<'a, K: Key256, V>(mut node: &'a Arc<Node<K, V>>, key: &K) -> &'a Arc<Node<K, V>> {
    loop {
        match node.as_ref() {
            Node::Leaf { .. } => return node,
            Node::Branch {
                bit, left, right, ..
            } => {
                node = if key_bit(key.as_key_bytes(), *bit) {
                    right
                } else {
                    left
                };
            }
        }
    }
}

fn replace_at<K: Key256, V>(node: &Arc<Node<K, V>>, key: K, value: V) -> Arc<Node<K, V>> {
    match node.as_ref() {
        Node::Leaf { .. } => Arc::new(Node::leaf(key, value)),
        Node::Branch {
            bit, left, right, ..
        } => {
            if key_bit(key.as_key_bytes(), *bit) {
                Arc::new(Node::branch(
                    *bit,
                    left.clone(),
                    replace_at(right, key, value),
                ))
            } else {
                Arc::new(Node::branch(
                    *bit,
                    replace_at(left, key, value),
                    right.clone(),
                ))
            }
        }
    }
}

fn insert_at<K: Key256, V>(
    node: &Arc<Node<K, V>>,
    differing_bit: u8,
    key: K,
    value: V,
) -> Arc<Node<K, V>> {
    if let Node::Branch {
        bit, left, right, ..
    } = node.as_ref()
        && *bit < differing_bit
    {
        return if key_bit(key.as_key_bytes(), *bit) {
            Arc::new(Node::branch(
                *bit,
                left.clone(),
                insert_at(right, differing_bit, key, value),
            ))
        } else {
            Arc::new(Node::branch(
                *bit,
                insert_at(left, differing_bit, key, value),
                right.clone(),
            ))
        };
    }

    let leaf = Arc::new(Node::leaf(key, value));
    let (left, right) = if key_bit(key.as_key_bytes(), differing_bit) {
        (node.clone(), leaf)
    } else {
        (leaf, node.clone())
    };
    Arc::new(Node::branch(differing_bit, left, right))
}

fn first_differing_bit(left: &[u8; 32], right: &[u8; 32]) -> u8 {
    for (byte_index, (left, right)) in left.iter().zip(right).enumerate() {
        let differing = left ^ right;
        if differing != 0 {
            let bit = byte_index * 8 + differing.leading_zeros() as usize;
            return u8::try_from(bit).expect("a 256-bit key index fits in u8");
        }
    }
    unreachable!("distinct keys have one differing bit")
}

fn key_bit(key: &[u8; 32], bit: u8) -> bool {
    let bit = usize::from(bit);
    key[bit / 8] & (1 << (7 - bit % 8)) != 0
}

#[cfg(test)]
fn leaf_count<K, V>(node: &Node<K, V>) -> usize {
    match node {
        Node::Leaf { .. } => 1,
        Node::Branch { left, right, .. } => leaf_count(left) + leaf_count(right),
    }
}

#[cfg(test)]
mod tests;
