use std::sync::Arc;

pub(super) trait Key256: Copy + Eq {
    fn as_key_bytes(&self) -> &[u8; 32];
}

/// An immutable-node Patricia map whose mutable handle replaces only the path
/// to a newly inserted leaf.
///
/// Cloning a handle clones one optional [`Arc`]. Values never need to implement
/// [`Clone`], and every untouched subtree remains shared after insertion.
pub(super) struct PersistentMap<K, V> {
    root: Option<Arc<Node<K, V>>>,
}

impl<K, V> PersistentMap<K, V> {
    pub(super) const fn new() -> Self {
        Self { root: None }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
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
    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        let mut node = self.root.as_deref()?;
        loop {
            match node {
                Node::Leaf {
                    key: stored_key,
                    value,
                } => return (stored_key == key).then_some(value),
                Node::Branch { bit, left, right } => {
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
    pub(super) fn insert(&mut self, key: K, value: V) -> bool {
        let Some(root) = &self.root else {
            self.root = Some(Arc::new(Node::Leaf { key, value }));
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

    #[cfg(test)]
    pub(super) fn shares_root_with(&self, other: &Self) -> bool {
        match (&self.root, &other.root) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        }
    }

    #[cfg(test)]
    pub(super) fn shares_terminal_for_key_with(&self, other: &Self, key: &K) -> bool {
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
    },
    Branch {
        bit: u8,
        left: Arc<Self>,
        right: Arc<Self>,
    },
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
            Node::Branch { bit, left, right } => {
                node = if key_bit(key.as_key_bytes(), *bit) {
                    right
                } else {
                    left
                };
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
    if let Node::Branch { bit, left, right } = node.as_ref()
        && *bit < differing_bit
    {
        return if key_bit(key.as_key_bytes(), *bit) {
            Arc::new(Node::Branch {
                bit: *bit,
                left: left.clone(),
                right: insert_at(right, differing_bit, key, value),
            })
        } else {
            Arc::new(Node::Branch {
                bit: *bit,
                left: insert_at(left, differing_bit, key, value),
                right: right.clone(),
            })
        };
    }

    let leaf = Arc::new(Node::Leaf { key, value });
    let (left, right) = if key_bit(key.as_key_bytes(), differing_bit) {
        (node.clone(), leaf)
    } else {
        (leaf, node.clone())
    };
    Arc::new(Node::Branch {
        bit: differing_bit,
        left,
        right,
    })
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
mod tests {
    use super::{Key256, PersistentMap};

    #[derive(Clone, Copy, PartialEq, Eq)]
    struct TestKey([u8; 32]);

    impl Key256 for TestKey {
        fn as_key_bytes(&self) -> &[u8; 32] {
            &self.0
        }
    }

    #[test]
    fn insertion_permutations_cover_boundary_bits_without_replacement() {
        let mut final_bit = [0; 32];
        final_bit[31] = 0x01;
        let mut middle_bit = [0; 32];
        middle_bit[16] = 0x08;
        let keys = [
            TestKey([0; 32]),
            TestKey([0x80; 32]),
            TestKey({
                let mut bytes = [0; 32];
                bytes[0] = 0x40;
                bytes
            }),
            TestKey(middle_bit),
            TestKey(final_bit),
        ];
        let permutations = [
            [0, 1, 2, 3, 4],
            [4, 3, 2, 1, 0],
            [2, 4, 0, 3, 1],
            [1, 3, 0, 4, 2],
        ];

        for permutation in permutations {
            let mut map = PersistentMap::new();
            for index in permutation {
                assert!(map.insert(keys[index], index));
            }
            for (index, key) in keys.iter().enumerate() {
                assert_eq!(map.get(key), Some(&index));
            }

            let before_duplicate = map.clone();
            assert!(!map.insert(keys[2], usize::MAX));
            assert!(map.shares_root_with(&before_duplicate));
            assert_eq!(map.get(&keys[2]), Some(&2));
        }
    }

    #[test]
    fn cloned_map_path_copies_only_the_changed_search_path() {
        let mut selected = PersistentMap::new();
        assert!(selected.insert(TestKey([0; 32]), 0));
        assert!(selected.insert(TestKey([0x80; 32]), 1));
        let mut branch = selected.clone();
        assert!(selected.shares_root_with(&branch));

        let mut branch_key = [0; 32];
        branch_key[0] = 0x40;
        assert!(branch.insert(TestKey(branch_key), 2));

        assert!(!selected.shares_root_with(&branch));
        assert!(selected.shares_terminal_for_key_with(&branch, &TestKey([0x80; 32])));
        assert_eq!(selected.get(&TestKey(branch_key)), None);
        assert_eq!(branch.get(&TestKey(branch_key)), Some(&2));
    }

    #[test]
    fn maximum_key_path_round_trips_and_remains_clone_isolated() {
        let zero = TestKey([0; 32]);
        let mut selected = PersistentMap::new();
        assert!(selected.insert(zero, 0));

        for bit in 0..256 {
            let mut bytes = [0; 32];
            bytes[bit / 8] = 1 << (7 - bit % 8);
            assert!(selected.insert(TestKey(bytes), bit + 1));
        }
        assert_eq!(selected.get(&zero), Some(&0));
        for bit in 0..256 {
            let mut bytes = [0; 32];
            bytes[bit / 8] = 1 << (7 - bit % 8);
            assert_eq!(selected.get(&TestKey(bytes)), Some(&(bit + 1)));
        }

        let mut branch = selected.clone();
        let mut branch_key = [0; 32];
        branch_key[31] = 0x03;
        assert!(branch.insert(TestKey(branch_key), usize::MAX));
        assert_eq!(selected.get(&TestKey(branch_key)), None);
        assert_eq!(branch.get(&TestKey(branch_key)), Some(&usize::MAX));
        assert_eq!(selected.get(&zero), Some(&0));
        assert_eq!(branch.get(&zero), Some(&0));
    }
}
