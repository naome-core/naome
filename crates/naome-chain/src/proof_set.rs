use std::error::Error;
use std::fmt;

use naome_ledger::AcceptedProofRecord;
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

const PROOF_SET_DOMAIN: &[u8] = b"naome:proof-set\0";
const LEAF_TAG: u8 = 0x01;
const BRANCH_TAG: u8 = 0x02;
const KEY_BITS: usize = 256;
const EMPTY_DIGEST: [u8; 32] = [
    0xe9, 0xa9, 0x80, 0x28, 0x7e, 0x77, 0x0a, 0xc3, 0x89, 0xd3, 0x73, 0x5f, 0xf0, 0x64, 0xe7, 0x44,
    0x7f, 0x11, 0xc9, 0x64, 0x0e, 0xfd, 0xb9, 0x0b, 0x91, 0x78, 0x17, 0x66, 0x49, 0x7f, 0x16, 0xca,
];

/// The SHA-256 commitment to one selected set of exact proof artifacts.
///
/// This value authenticates only set membership. [`Self::from_bytes`] creates
/// an address and does not establish mathematical validity, consensus
/// selection, or finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ProofSetRoot([u8; 32]);

impl ProofSetRoot {
    /// Constructs a root address from raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The authenticated result of querying one [`ProofId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ProofSetMembership {
    /// The exact proof artifact belongs to the committed set.
    Present,
    /// The exact proof artifact does not belong to the committed set.
    Absent,
}

/// A compact membership or non-membership proof for one [`ProofId`].
///
/// The proof has no public constructor or wire codec. It is derived from one
/// selected [`crate::ProofDag`] and must be verified against a trusted expected
/// root before its membership result is used.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ProofSetProof {
    terminal: ProofTerminal,
    path: Box<[ProofPathStep]>,
}

impl ProofSetProof {
    /// Returns the number of authenticated branch siblings in this proof.
    pub const fn sibling_count(&self) -> usize {
        self.path.len()
    }

    /// Verifies this proof for `proof_id` against `expected_root`.
    ///
    /// The returned status is available only after the complete proof shape
    /// and reconstructed root have both been validated.
    pub fn verify(
        &self,
        expected_root: ProofSetRoot,
        proof_id: ProofId,
    ) -> Result<ProofSetMembership, ProofSetProofError> {
        if self.path.len() > KEY_BITS {
            return Err(ProofSetProofError::PathTooLong);
        }

        let empty = empty_digest();
        let mut previous_bit = None;
        for step in &self.path {
            if let Some(previous) = previous_bit
                && step.bit <= previous
            {
                return Err(ProofSetProofError::NonIncreasingBits {
                    previous,
                    actual: step.bit,
                });
            }
            if step.sibling == empty {
                return Err(ProofSetProofError::EmptySibling { bit: step.bit });
            }
            previous_bit = Some(step.bit);
        }

        let (membership, mut digest) = match self.terminal {
            ProofTerminal::Empty => {
                if !self.path.is_empty() {
                    return Err(ProofSetProofError::EmptyTerminalHasPath);
                }
                (ProofSetMembership::Absent, empty)
            }
            ProofTerminal::Member => (ProofSetMembership::Present, leaf_digest(proof_id)),
            ProofTerminal::NonMember(terminal) => {
                if terminal == proof_id {
                    return Err(ProofSetProofError::NonMemberMatchesQuery);
                }
                for step in &self.path {
                    if key_bit(terminal, step.bit) != key_bit(proof_id, step.bit) {
                        return Err(ProofSetProofError::TerminalPathMismatch { bit: step.bit });
                    }
                }
                (ProofSetMembership::Absent, leaf_digest(terminal))
            }
        };

        for step in self.path.iter().rev() {
            digest = if key_bit(proof_id, step.bit) {
                branch_digest(step.bit, step.sibling, digest)
            } else {
                branch_digest(step.bit, digest, step.sibling)
            };
        }

        let actual_root = ProofSetRoot(digest);
        if actual_root != expected_root {
            return Err(ProofSetProofError::RootMismatch {
                expected: expected_root,
                actual: actual_root,
            });
        }

        Ok(membership)
    }
}

/// A malformed proof-set witness or reconstructed-root mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofSetProofError {
    /// More branch steps were supplied than a 256-bit key can traverse.
    PathTooLong,
    /// Branch bit positions were duplicated or did not increase root-to-leaf.
    NonIncreasingBits { previous: u8, actual: u8 },
    /// A compressed Patricia branch cannot have an empty sibling.
    EmptySibling { bit: u8 },
    /// Only the empty tree may use an empty terminal.
    EmptyTerminalHasPath,
    /// A non-membership terminal must differ from the queried key.
    NonMemberMatchesQuery,
    /// The queried key would not reach the supplied non-membership terminal.
    TerminalPathMismatch { bit: u8 },
    /// The reconstructed root did not equal the trusted expected root.
    RootMismatch {
        expected: ProofSetRoot,
        actual: ProofSetRoot,
    },
}

impl fmt::Display for ProofSetProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathTooLong => formatter.write_str("proof-set path exceeds 256 branches"),
            Self::NonIncreasingBits { previous, actual } => write!(
                formatter,
                "proof-set branch bit {actual} does not follow bit {previous}"
            ),
            Self::EmptySibling { bit } => {
                write!(formatter, "proof-set branch bit {bit} has an empty sibling")
            }
            Self::EmptyTerminalHasPath => {
                formatter.write_str("empty proof-set terminal has a branch path")
            }
            Self::NonMemberMatchesQuery => {
                formatter.write_str("non-member terminal equals the queried proof id")
            }
            Self::TerminalPathMismatch { bit } => write!(
                formatter,
                "queried proof id diverges from its terminal at branch bit {bit}"
            ),
            Self::RootMismatch { expected, actual } => write!(
                formatter,
                "proof-set root mismatch: expected {expected:?}, reconstructed {actual:?}"
            ),
        }
    }
}

impl Error for ProofSetProofError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProofTerminal {
    Empty,
    Member,
    NonMember(ProofId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProofPathStep {
    sibling: [u8; 32],
    bit: u8,
}

pub(super) trait ProofSetValue {
    fn proof_id(&self) -> ProofId;
}

impl ProofSetValue for AcceptedProofRecord {
    fn proof_id(&self) -> ProofId {
        self.proof_id()
    }
}

pub(super) struct AuthenticatedProofSet<V> {
    root: Option<NodeRef>,
    leaves: Vec<V>,
    branches: Vec<Branch>,
    search_path: Vec<usize>,
}

impl<V> Default for AuthenticatedProofSet<V> {
    fn default() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
            branches: Vec::new(),
            search_path: Vec::new(),
        }
    }
}

impl<V: ProofSetValue> AuthenticatedProofSet<V> {
    pub(crate) const fn new() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
            branches: Vec::new(),
            search_path: Vec::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.leaves.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    pub(crate) fn root(&self) -> ProofSetRoot {
        ProofSetRoot(
            self.root
                .map_or_else(empty_digest, |root| self.node_digest(root)),
        )
    }

    pub(crate) fn get(&self, proof_id: ProofId) -> Option<&V> {
        let mut node = self.root?;
        loop {
            if node.is_branch() {
                let branch = &self.branches[node.index()];
                node = if key_bit(proof_id, branch.bit) {
                    branch.right
                } else {
                    branch.left
                };
            } else {
                let value = &self.leaves[node.index()];
                return (value.proof_id() == proof_id).then_some(value);
            }
        }
    }

    pub(crate) fn proof(&self, proof_id: ProofId) -> ProofSetProof {
        let Some(mut node) = self.root else {
            return ProofSetProof {
                terminal: ProofTerminal::Empty,
                path: Box::new([]),
            };
        };

        let mut path = Vec::with_capacity(16);
        while node.is_branch() {
            let branch = &self.branches[node.index()];
            let goes_right = key_bit(proof_id, branch.bit);
            let sibling = if goes_right {
                branch.left
            } else {
                branch.right
            };
            path.push(ProofPathStep {
                sibling: self.node_digest(sibling),
                bit: branch.bit,
            });
            node = if goes_right {
                branch.right
            } else {
                branch.left
            };
        }

        let terminal = self.leaves[node.index()].proof_id();
        ProofSetProof {
            terminal: if terminal == proof_id {
                ProofTerminal::Member
            } else {
                ProofTerminal::NonMember(terminal)
            },
            path: path.into_boxed_slice(),
        }
    }

    pub(crate) fn insert(&mut self, value: V) -> Option<&V> {
        let proof_id = value.proof_id();
        let Some(mut node) = self.root else {
            self.leaves.push(value);
            self.root = Some(NodeRef::leaf(0));
            return self.leaves.first();
        };

        self.search_path.clear();
        while node.is_branch() {
            let branch_index = node.index();
            let branch = &self.branches[branch_index];
            let goes_right = key_bit(proof_id, branch.bit);
            self.search_path.push(branch_index);
            node = if goes_right {
                branch.right
            } else {
                branch.left
            };
        }

        let terminal_id = self.leaves[node.index()].proof_id();
        if terminal_id == proof_id {
            return None;
        }
        let differing_bit = first_differing_bit(proof_id, terminal_id);
        let insertion_position = self
            .search_path
            .partition_point(|branch| self.branches[*branch].bit < differing_bit);
        debug_assert!(
            insertion_position == self.search_path.len()
                || self.branches[self.search_path[insertion_position]].bit > differing_bit
        );

        let old_subtree = if insertion_position == self.search_path.len() {
            node
        } else {
            NodeRef::branch(self.search_path[insertion_position])
        };
        let leaf_index = self.leaves.len();
        self.leaves.push(value);
        let new_leaf = NodeRef::leaf(leaf_index);
        let (left, right) = if key_bit(proof_id, differing_bit) {
            (old_subtree, new_leaf)
        } else {
            (new_leaf, old_subtree)
        };
        let branch_index = self.branches.len();
        self.branches.push(Branch {
            bit: differing_bit,
            left,
            right,
            digest: branch_digest(
                differing_bit,
                self.node_digest(left),
                self.node_digest(right),
            ),
        });
        let new_branch = NodeRef::branch(branch_index);

        if insertion_position == 0 {
            self.root = Some(new_branch);
        } else {
            let parent_index = self.search_path[insertion_position - 1];
            let goes_right = key_bit(proof_id, self.branches[parent_index].bit);
            let parent = &mut self.branches[parent_index];
            if goes_right {
                parent.right = new_branch;
            } else {
                parent.left = new_branch;
            }
        }

        for position in (0..insertion_position).rev() {
            let branch_index = self.search_path[position];
            let (bit, left, right) = {
                let branch = &self.branches[branch_index];
                (branch.bit, branch.left, branch.right)
            };
            let digest = branch_digest(bit, self.node_digest(left), self.node_digest(right));
            self.branches[branch_index].digest = digest;
        }

        Some(&self.leaves[leaf_index])
    }

    fn node_digest(&self, node: NodeRef) -> [u8; 32] {
        if node.is_branch() {
            self.branches[node.index()].digest
        } else {
            leaf_digest(self.leaves[node.index()].proof_id())
        }
    }
}

#[derive(Clone, Copy)]
struct NodeRef(usize);

impl NodeRef {
    const BRANCH_BIT: usize = 1;

    fn leaf(index: usize) -> Self {
        Self(
            index
                .checked_mul(2)
                .expect("proof-set leaf arena cannot exhaust usize"),
        )
    }

    fn branch(index: usize) -> Self {
        Self(
            index
                .checked_mul(2)
                .and_then(|value| value.checked_add(Self::BRANCH_BIT))
                .expect("proof-set branch arena cannot exhaust usize"),
        )
    }

    const fn is_branch(self) -> bool {
        self.0 & Self::BRANCH_BIT != 0
    }

    const fn index(self) -> usize {
        self.0 >> 1
    }
}

struct Branch {
    bit: u8,
    left: NodeRef,
    right: NodeRef,
    digest: [u8; 32],
}

fn key_bit(proof_id: ProofId, bit: u8) -> bool {
    let bit = bit as usize;
    let byte = proof_id.as_bytes()[bit / 8];
    byte & (1 << (7 - bit % 8)) != 0
}

fn first_differing_bit(left: ProofId, right: ProofId) -> u8 {
    for (byte_index, (left, right)) in left.as_bytes().iter().zip(right.as_bytes()).enumerate() {
        let difference = left ^ right;
        if difference != 0 {
            return u8::try_from(byte_index * 8 + difference.leading_zeros() as usize)
                .expect("ProofId bit positions fit u8");
        }
    }
    unreachable!("callers compare ProofIds before finding their differing bit")
}

fn empty_digest() -> [u8; 32] {
    EMPTY_DIGEST
}

fn leaf_digest(proof_id: ProofId) -> [u8; 32] {
    tagged_digest(LEAF_TAG, &[proof_id.as_bytes()])
}

fn branch_digest(bit: u8, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    tagged_digest(BRANCH_TAG, &[&[bit], &left, &right])
}

fn tagged_digest(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROOF_SET_DOMAIN);
    hasher.update([tag]);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use super::{
        AuthenticatedProofSet, ProofPathStep, ProofSetMembership, ProofSetProofError, ProofSetRoot,
        ProofSetValue, empty_digest, first_differing_bit, key_bit,
    };
    use naome_proof::ProofId;

    impl ProofSetValue for ProofId {
        fn proof_id(&self) -> ProofId {
            *self
        }
    }

    fn id(bytes: [u8; 32]) -> ProofId {
        ProofId::from_bytes(bytes)
    }

    fn hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").unwrap();
        }
        encoded
    }

    fn root_for(order: &[ProofId]) -> ProofSetRoot {
        let mut set = AuthenticatedProofSet::new();
        for proof_id in order {
            assert!(set.insert(*proof_id).is_some());
        }
        set.root()
    }

    fn reference_root(keys: &[ProofId]) -> ProofSetRoot {
        let mut keys = keys.to_vec();
        keys.sort_unstable();
        keys.dedup();
        reference_subtree(&keys)
    }

    fn reference_subtree(keys: &[ProofId]) -> ProofSetRoot {
        match keys {
            [] => ProofSetRoot(empty_digest()),
            [key] => ProofSetRoot(super::leaf_digest(*key)),
            _ => {
                let bit = first_differing_bit(keys[0], keys[keys.len() - 1]);
                let split = keys.partition_point(|key| !key_bit(*key, bit));
                ProofSetRoot(super::branch_digest(
                    bit,
                    reference_subtree(&keys[..split]).0,
                    reference_subtree(&keys[split..]).0,
                ))
            }
        }
    }

    fn permutations(values: &mut [ProofId], start: usize, roots: &mut Vec<ProofSetRoot>) {
        if start == values.len() {
            roots.push(root_for(values));
            return;
        }
        for index in start..values.len() {
            values.swap(start, index);
            permutations(values, start + 1, roots);
            values.swap(start, index);
        }
    }

    #[test]
    fn empty_leaf_and_branch_roots_have_stable_goldens() {
        let zero = id([0; 32]);
        let mut high = [0; 32];
        high[0] = 0x80;
        let mut low = [0; 32];
        low[31] = 0x01;

        assert_eq!(
            hex(root_for(&[]).as_bytes()),
            "e9a980287e770ac389d3735ff064e7447f11c9640efdb90b91781766497f16ca"
        );
        assert_eq!(empty_digest(), super::tagged_digest(0x00, &[]));
        assert_eq!(
            hex(root_for(&[zero]).as_bytes()),
            "6035299a52844d846d83ca0395e1a7df37e62b7de9adc638ea2cbaf97d799a04"
        );
        assert_eq!(
            hex(root_for(&[zero, id(high)]).as_bytes()),
            "4c77fb731087d077c434cc706d41eea1fc9aa9b324638f709747b492cbb52687"
        );
        assert_eq!(
            hex(root_for(&[zero, id(high), id(low)]).as_bytes()),
            "00d65391369a613d7a56aca448277a0da7cc44e57a12a8b2159f0b1c5712c396"
        );
    }

    #[test]
    fn every_insertion_order_matches_an_independent_canonical_root() {
        let mut values = [id([0; 32]), id([0x55; 32]), id([0xaa; 32]), id([0xff; 32])];
        let expected = reference_root(&values);
        let mut roots = Vec::new();
        permutations(&mut values, 0, &mut roots);

        assert_eq!(roots.len(), 24);
        assert!(roots.into_iter().all(|root| root == expected));
    }

    #[test]
    fn long_shared_prefixes_store_only_one_branch() {
        let zero = id([0; 32]);
        let mut last_bit = [0; 32];
        last_bit[31] = 1;
        let mut set = AuthenticatedProofSet::new();

        let _ = set.insert(zero).unwrap();
        let _ = set.insert(id(last_bit)).unwrap();

        assert_eq!(set.leaves.len(), 2);
        assert_eq!(set.branches.len(), 1);
        assert_eq!(set.branches[0].bit, 255);
        assert_eq!(set.root(), reference_root(&[zero, id(last_bit)]));
    }

    #[test]
    fn membership_and_nonmembership_proofs_verify_exclusively() {
        let members = [id([0x11; 32]), id([0x77; 32]), id([0xee; 32])];
        let absent = id([0x55; 32]);
        let mut set = AuthenticatedProofSet::new();
        for member in members {
            let _ = set.insert(member).unwrap();
        }
        let root = set.root();

        for member in members {
            assert_eq!(
                set.proof(member).verify(root, member),
                Ok(ProofSetMembership::Present)
            );
        }
        assert_eq!(
            set.proof(absent).verify(root, absent),
            Ok(ProofSetMembership::Absent)
        );
        assert_eq!(
            AuthenticatedProofSet::<ProofId>::new()
                .proof(absent)
                .verify(ProofSetRoot(empty_digest()), absent),
            Ok(ProofSetMembership::Absent)
        );
    }

    #[test]
    fn duplicate_insertions_do_not_change_structure_or_root() {
        let proof_id = id([0x44; 32]);
        let mut set = AuthenticatedProofSet::new();
        let _ = set.insert(proof_id).unwrap();
        let root = set.root();

        assert!(set.insert(proof_id).is_none());
        assert_eq!(set.len(), 1);
        assert_eq!(set.branches.len(), 0);
        assert_eq!(set.root(), root);
    }

    #[test]
    fn malformed_or_mutated_proofs_fail_closed() {
        let members = [id([0x10; 32]), id([0x40; 32]), id([0xf0; 32])];
        let query = id([0x20; 32]);
        let mut set = AuthenticatedProofSet::new();
        for member in members {
            let _ = set.insert(member).unwrap();
        }
        let root = set.root();
        let proof = set.proof(query);

        let mut changed_sibling = proof.clone();
        changed_sibling.path[0].sibling[0] ^= 1;
        assert!(matches!(
            changed_sibling.verify(root, query),
            Err(ProofSetProofError::RootMismatch { .. })
        ));

        let mut changed_bit = proof.clone();
        changed_bit.path[0].bit = changed_bit.path[1].bit;
        assert!(matches!(
            changed_bit.verify(root, query),
            Err(ProofSetProofError::NonIncreasingBits { .. })
        ));

        let mut empty_sibling = proof.clone();
        empty_sibling.path[0].sibling = empty_digest();
        assert!(matches!(
            empty_sibling.verify(root, query),
            Err(ProofSetProofError::EmptySibling { .. })
        ));

        let mut wrong_terminal = proof.clone();
        wrong_terminal.terminal = super::ProofTerminal::NonMember(id([0xa0; 32]));
        assert!(matches!(
            wrong_terminal.verify(root, query),
            Err(ProofSetProofError::TerminalPathMismatch { .. })
        ));

        let mut too_long = proof;
        too_long.path = vec![
            ProofPathStep {
                sibling: [0x55; 32],
                bit: 0,
            };
            257
        ]
        .into_boxed_slice();
        assert_eq!(
            too_long.verify(root, query),
            Err(ProofSetProofError::PathTooLong)
        );

        let mut wrong_root = *root.as_bytes();
        wrong_root[0] ^= 1;
        assert!(matches!(
            set.proof(query)
                .verify(ProofSetRoot::from_bytes(wrong_root), query),
            Err(ProofSetProofError::RootMismatch { .. })
        ));
    }

    #[test]
    fn maximum_depth_is_bounded_by_the_proof_id_width() {
        let zero = id([0; 32]);
        let mut set = AuthenticatedProofSet::new();
        let _ = set.insert(zero).unwrap();

        for bit in 0..256 {
            let mut bytes = [0; 32];
            bytes[bit / 8] = 1 << (7 - bit % 8);
            let _ = set.insert(id(bytes)).unwrap();
        }

        assert_eq!(set.len(), 257);
        assert_eq!(set.branches.len(), 256);
        assert_eq!(set.proof(zero).sibling_count(), 256);
        assert_eq!(
            set.proof(zero).verify(set.root(), zero),
            Ok(ProofSetMembership::Present)
        );
    }
}
