use std::error::Error;
use std::fmt;

use naome_ledger::{AcceptedProofRecord, PROOF_BATCH_MAX_CANDIDATES};
use naome_proof::ProofId;
use sha2::{Digest, Sha256};

mod codec;

pub use codec::PROOF_SET_PROOF_MAX_BYTES;

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
    /// Exact width of one authenticated proof-set root.
    pub const BYTE_LENGTH: usize = 32;

    /// Constructs a root address from raw digest bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the raw digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn empty() -> Self {
        Self(EMPTY_DIGEST)
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
/// The proof has no public constructor. It is derived from one selected
/// [`crate::ProofDag`] or decoded from its strict canonical wire format and
/// must be verified against a trusted expected root before its membership
/// result is used.
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
        self.validate_shape()?;
        let empty = *ProofSetRoot::empty().as_bytes();
        let (membership, mut digest) = match self.terminal {
            ProofTerminal::Empty => (ProofSetMembership::Absent, empty),
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

    fn validate_shape(&self) -> Result<(), ProofSetProofError> {
        if self.path.len() > KEY_BITS
            || matches!(self.terminal, ProofTerminal::NonMember(_)) && self.path.len() == KEY_BITS
        {
            return Err(ProofSetProofError::PathTooLong);
        }

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
            if step.sibling == EMPTY_DIGEST {
                return Err(ProofSetProofError::EmptySibling { bit: step.bit });
            }
            previous_bit = Some(step.bit);
        }

        if matches!(self.terminal, ProofTerminal::Empty) && !self.path.is_empty() {
            return Err(ProofSetProofError::EmptyTerminalHasPath);
        }

        Ok(())
    }
}

/// A malformed proof-set witness, canonical encoding, or root mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProofSetProofError {
    /// The encoded proof exceeds the deterministic byte limit.
    InputTooLong { actual: usize, maximum: usize },
    /// The encoded proof ended before its terminal or path step was complete.
    UnexpectedEnd,
    /// The encoded proof uses an unknown terminal tag.
    UnknownTerminalTag(u8),
    /// An empty-tree proof is followed by additional bytes.
    TrailingBytes { remaining: usize },
    /// More branch steps were supplied than the selected terminal can admit.
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
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "canonical proof-set proof has {actual} bytes; the limit is {maximum}"
            ),
            Self::UnexpectedEnd => {
                formatter.write_str("canonical proof-set proof ended unexpectedly")
            }
            Self::UnknownTerminalTag(tag) => {
                write!(formatter, "unknown proof-set terminal tag 0x{tag:02x}")
            }
            Self::TrailingBytes { remaining } => write!(
                formatter,
                "empty proof-set proof has {remaining} trailing bytes"
            ),
            Self::PathTooLong => formatter.write_str("proof-set path exceeds its terminal limit"),
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
        self.root.map_or_else(ProofSetRoot::empty, |root| {
            ProofSetRoot(self.node_digest(root))
        })
    }

    pub(crate) fn projected_root(
        &self,
        proof_ids: &[ProofId],
    ) -> (ProofSetRoot, Option<(usize, ProofId)>) {
        assert!(
            proof_ids.len() <= PROOF_BATCH_MAX_CANDIDATES,
            "proof-set projection exceeds the rooted proof-batch limit"
        );
        if self.root.is_none() && proof_ids.len() == 1 {
            return (ProofSetRoot(leaf_digest(proof_ids[0])), None);
        }

        let mut projection = ProofSetProjection {
            base: self,
            proof_ids,
            root: self.root.map(ProjectedNodeRef::Base),
            branches: Vec::new(),
            path: Vec::with_capacity(16),
        };
        let mut first_existing = None;
        for (index, proof_id) in proof_ids.iter().copied().enumerate() {
            if !projection.insert(index, proof_id) && first_existing.is_none() {
                first_existing = Some((index, proof_id));
            }
        }
        let root = projection.root.map_or_else(ProofSetRoot::empty, |root| {
            ProofSetRoot(projection.node_digest(root))
        });
        (root, first_existing)
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

struct ProofSetProjection<'a, V> {
    base: &'a AuthenticatedProofSet<V>,
    proof_ids: &'a [ProofId],
    root: Option<ProjectedNodeRef>,
    branches: Vec<ProjectedBranch>,
    path: Vec<ProjectedNodeRef>,
}

impl<V: ProofSetValue> ProofSetProjection<'_, V> {
    fn insert(&mut self, index: usize, proof_id: ProofId) -> bool {
        let added_leaf = ProjectedNodeRef::AddedLeaf(
            u8::try_from(index).expect("bounded proof-set projection indices fit u8"),
        );
        let Some(mut node) = self.root else {
            self.root = Some(added_leaf);
            return true;
        };

        self.path.clear();
        while let Some((bit, left, right)) = self.branch(node) {
            self.path.push(node);
            node = if key_bit(proof_id, bit) { right } else { left };
        }

        let terminal_id = self.node_proof_id(node);
        if terminal_id == proof_id {
            return false;
        }
        let differing_bit = first_differing_bit(proof_id, terminal_id);
        let insertion_position = self.path.partition_point(|node| {
            self.branch(*node)
                .expect("the projection path contains only branches")
                .0
                < differing_bit
        });
        debug_assert!(
            insertion_position == self.path.len()
                || self
                    .branch(self.path[insertion_position])
                    .expect("the projection path contains only branches")
                    .0
                    > differing_bit
        );

        let old_subtree = if insertion_position == self.path.len() {
            node
        } else {
            self.path[insertion_position]
        };
        let (left, right) = if key_bit(proof_id, differing_bit) {
            (old_subtree, added_leaf)
        } else {
            (added_leaf, old_subtree)
        };
        let mut subtree = self.push_branch(differing_bit, left, right);

        for position in (0..insertion_position).rev() {
            let ancestor = self.path[position];
            let (bit, left, right) = self
                .branch(ancestor)
                .expect("the projection path contains only branches");
            let (left, right) = if key_bit(proof_id, bit) {
                (left, subtree)
            } else {
                (subtree, right)
            };
            subtree = self.push_branch(bit, left, right);
        }
        self.root = Some(subtree);
        true
    }

    fn branch(&self, node: ProjectedNodeRef) -> Option<(u8, ProjectedNodeRef, ProjectedNodeRef)> {
        match node {
            ProjectedNodeRef::Base(node) if node.is_branch() => {
                let branch = &self.base.branches[node.index()];
                Some((
                    branch.bit,
                    ProjectedNodeRef::Base(branch.left),
                    ProjectedNodeRef::Base(branch.right),
                ))
            }
            ProjectedNodeRef::AddedBranch(index) => {
                let branch = &self.branches[index];
                Some((branch.bit, branch.left, branch.right))
            }
            ProjectedNodeRef::Base(_) | ProjectedNodeRef::AddedLeaf(_) => None,
        }
    }

    fn node_proof_id(&self, node: ProjectedNodeRef) -> ProofId {
        match node {
            ProjectedNodeRef::Base(node) if !node.is_branch() => {
                self.base.leaves[node.index()].proof_id()
            }
            ProjectedNodeRef::AddedLeaf(index) => self.proof_ids[index as usize],
            ProjectedNodeRef::Base(_) | ProjectedNodeRef::AddedBranch(_) => {
                unreachable!("only projection leaves have proof identities")
            }
        }
    }

    fn node_digest(&self, node: ProjectedNodeRef) -> [u8; 32] {
        match node {
            ProjectedNodeRef::Base(node) => self.base.node_digest(node),
            ProjectedNodeRef::AddedLeaf(index) => leaf_digest(self.proof_ids[index as usize]),
            ProjectedNodeRef::AddedBranch(index) => self.branches[index].digest,
        }
    }

    fn push_branch(
        &mut self,
        bit: u8,
        left: ProjectedNodeRef,
        right: ProjectedNodeRef,
    ) -> ProjectedNodeRef {
        let digest = branch_digest(bit, self.node_digest(left), self.node_digest(right));
        let index = self.branches.len();
        self.branches.push(ProjectedBranch {
            bit,
            left,
            right,
            digest,
        });
        ProjectedNodeRef::AddedBranch(index)
    }
}

#[derive(Clone, Copy)]
enum ProjectedNodeRef {
    Base(NodeRef),
    AddedLeaf(u8),
    AddedBranch(usize),
}

struct ProjectedBranch {
    bit: u8,
    left: ProjectedNodeRef,
    right: ProjectedNodeRef,
    digest: [u8; 32],
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
mod tests;
