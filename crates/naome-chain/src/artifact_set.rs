use std::error::Error;
use std::fmt;

use naome_ledger::AcceptedArtifactRecord;
use naome_proof::ArtifactId;
use sha2::{Digest, Sha256};

mod codec;

pub use codec::ARTIFACT_SET_PROOF_MAX_BYTES;

const ARTIFACT_SET_DOMAIN: &[u8] = b"naome:artifact-set:v0\0";
const LEAF_TAG: u8 = 0x01;
const BRANCH_TAG: u8 = 0x02;
const KEY_BITS: usize = 256;
const EMPTY_DIGEST: [u8; 32] = [
    0x97, 0x6e, 0x57, 0x6e, 0xc6, 0x14, 0x5d, 0x57, 0xb5, 0xe1, 0x92, 0xd1, 0xc3, 0x7a, 0x09, 0x38,
    0xbb, 0x5c, 0x76, 0x66, 0x35, 0x32, 0xd0, 0x35, 0x4f, 0xcd, 0x98, 0xba, 0x3f, 0xbf, 0x59, 0x7a,
];

/// The SHA-256 commitment to one selected set of exact artifacts.
///
/// This value authenticates only set membership. [`Self::from_bytes`] creates
/// an address and does not establish mathematical validity, consensus
/// selection, or finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct ArtifactSetRoot([u8; 32]);

impl ArtifactSetRoot {
    /// Exact width of one authenticated artifact-set root.
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

/// The authenticated result of querying one [`ArtifactId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ArtifactSetMembership {
    /// The exact artifact belongs to the committed set.
    Present,
    /// The exact artifact does not belong to the committed set.
    Absent,
}

/// A compact membership or non-membership proof for one [`ArtifactId`].
///
/// The proof has no public constructor. It is derived from one selected
/// [`crate::ArtifactDag`] or decoded from its strict canonical wire format and
/// must be verified against a trusted expected root before its membership
/// result is used.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct ArtifactSetProof {
    terminal: ArtifactTerminal,
    path: Box<[ArtifactPathStep]>,
}

impl ArtifactSetProof {
    /// Returns the number of authenticated branch siblings in this proof.
    pub const fn sibling_count(&self) -> usize {
        self.path.len()
    }

    /// Verifies this proof for `artifact_id` against `expected_root`.
    ///
    /// The returned status is available only after the complete proof shape
    /// and reconstructed root have both been validated.
    pub fn verify(
        &self,
        expected_root: ArtifactSetRoot,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactSetMembership, ArtifactSetProofError> {
        self.validate_shape()?;
        let empty = *ArtifactSetRoot::empty().as_bytes();
        let (membership, mut digest) = match self.terminal {
            ArtifactTerminal::Empty => (ArtifactSetMembership::Absent, empty),
            ArtifactTerminal::Member => (ArtifactSetMembership::Present, leaf_digest(artifact_id)),
            ArtifactTerminal::NonMember(terminal) => {
                if terminal == artifact_id {
                    return Err(ArtifactSetProofError::NonMemberMatchesQuery);
                }
                for step in &self.path {
                    if key_bit(terminal, step.bit) != key_bit(artifact_id, step.bit) {
                        return Err(ArtifactSetProofError::TerminalPathMismatch { bit: step.bit });
                    }
                }
                (ArtifactSetMembership::Absent, leaf_digest(terminal))
            }
        };

        for step in self.path.iter().rev() {
            digest = if key_bit(artifact_id, step.bit) {
                branch_digest(step.bit, step.sibling, digest)
            } else {
                branch_digest(step.bit, digest, step.sibling)
            };
        }

        let actual_root = ArtifactSetRoot(digest);
        if actual_root != expected_root {
            return Err(ArtifactSetProofError::RootMismatch {
                expected: expected_root,
                actual: actual_root,
            });
        }

        Ok(membership)
    }

    fn validate_shape(&self) -> Result<(), ArtifactSetProofError> {
        if self.path.len() > KEY_BITS
            || matches!(self.terminal, ArtifactTerminal::NonMember(_))
                && self.path.len() == KEY_BITS
        {
            return Err(ArtifactSetProofError::PathTooLong);
        }

        let mut previous_bit = None;
        for step in &self.path {
            if let Some(previous) = previous_bit
                && step.bit <= previous
            {
                return Err(ArtifactSetProofError::NonIncreasingBits {
                    previous,
                    actual: step.bit,
                });
            }
            if step.sibling == EMPTY_DIGEST {
                return Err(ArtifactSetProofError::EmptySibling { bit: step.bit });
            }
            previous_bit = Some(step.bit);
        }

        if matches!(self.terminal, ArtifactTerminal::Empty) && !self.path.is_empty() {
            return Err(ArtifactSetProofError::EmptyTerminalHasPath);
        }

        Ok(())
    }
}

/// A malformed artifact-set witness, canonical encoding, or root mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArtifactSetProofError {
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
        expected: ArtifactSetRoot,
        actual: ArtifactSetRoot,
    },
}

impl fmt::Display for ArtifactSetProofError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLong { actual, maximum } => write!(
                formatter,
                "canonical artifact-set proof has {actual} bytes; the limit is {maximum}"
            ),
            Self::UnexpectedEnd => {
                formatter.write_str("canonical artifact-set proof ended unexpectedly")
            }
            Self::UnknownTerminalTag(tag) => {
                write!(formatter, "unknown artifact-set terminal tag 0x{tag:02x}")
            }
            Self::TrailingBytes { remaining } => write!(
                formatter,
                "empty artifact-set proof has {remaining} trailing bytes"
            ),
            Self::PathTooLong => {
                formatter.write_str("artifact-set path exceeds its terminal limit")
            }
            Self::NonIncreasingBits { previous, actual } => write!(
                formatter,
                "artifact-set branch bit {actual} does not follow bit {previous}"
            ),
            Self::EmptySibling { bit } => {
                write!(
                    formatter,
                    "artifact-set branch bit {bit} has an empty sibling"
                )
            }
            Self::EmptyTerminalHasPath => {
                formatter.write_str("empty artifact-set terminal has a branch path")
            }
            Self::NonMemberMatchesQuery => {
                formatter.write_str("non-member terminal equals the queried artifact id")
            }
            Self::TerminalPathMismatch { bit } => write!(
                formatter,
                "queried artifact id diverges from its terminal at branch bit {bit}"
            ),
            Self::RootMismatch { expected, actual } => write!(
                formatter,
                "artifact-set root mismatch: expected {expected:?}, reconstructed {actual:?}"
            ),
        }
    }
}

impl Error for ArtifactSetProofError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactTerminal {
    Empty,
    Member,
    NonMember(ArtifactId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ArtifactPathStep {
    sibling: [u8; 32],
    bit: u8,
}

pub(super) trait ArtifactSetValue {
    fn artifact_id(&self) -> ArtifactId;
}

impl ArtifactSetValue for AcceptedArtifactRecord {
    fn artifact_id(&self) -> ArtifactId {
        self.artifact_id()
    }
}

pub(super) struct AuthenticatedArtifactSet<V> {
    root: Option<NodeRef>,
    leaves: Vec<V>,
    branches: Vec<Branch>,
    search_path: Vec<usize>,
}

impl<V> Default for AuthenticatedArtifactSet<V> {
    fn default() -> Self {
        Self {
            root: None,
            leaves: Vec::new(),
            branches: Vec::new(),
            search_path: Vec::new(),
        }
    }
}

impl<V: ArtifactSetValue> AuthenticatedArtifactSet<V> {
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

    pub(crate) fn root(&self) -> ArtifactSetRoot {
        self.root.map_or_else(ArtifactSetRoot::empty, |root| {
            ArtifactSetRoot(self.node_digest(root))
        })
    }

    pub(crate) fn projected_root(&self, artifact_id: ArtifactId) -> (ArtifactSetRoot, bool) {
        let Some(mut node) = self.root else {
            return (ArtifactSetRoot(leaf_digest(artifact_id)), false);
        };

        let mut path = [0_usize; KEY_BITS];
        let mut path_len = 0;
        while node.is_branch() {
            let branch_index = node.index();
            path[path_len] = branch_index;
            path_len += 1;
            let branch = &self.branches[branch_index];
            node = if key_bit(artifact_id, branch.bit) {
                branch.right
            } else {
                branch.left
            };
        }

        let terminal_id = self.leaves[node.index()].artifact_id();
        if terminal_id == artifact_id {
            return (self.root(), true);
        }

        let differing_bit = first_differing_bit(artifact_id, terminal_id);
        let insertion_position =
            path[..path_len].partition_point(|branch| self.branches[*branch].bit < differing_bit);
        let old_subtree = if insertion_position == path_len {
            node
        } else {
            NodeRef::branch(path[insertion_position])
        };
        let old_digest = self.node_digest(old_subtree);
        let new_digest = leaf_digest(artifact_id);
        let mut subtree = if key_bit(artifact_id, differing_bit) {
            branch_digest(differing_bit, old_digest, new_digest)
        } else {
            branch_digest(differing_bit, new_digest, old_digest)
        };

        for position in (0..insertion_position).rev() {
            let branch = &self.branches[path[position]];
            subtree = if key_bit(artifact_id, branch.bit) {
                branch_digest(branch.bit, self.node_digest(branch.left), subtree)
            } else {
                branch_digest(branch.bit, subtree, self.node_digest(branch.right))
            };
        }
        (ArtifactSetRoot(subtree), false)
    }

    pub(crate) fn get(&self, artifact_id: ArtifactId) -> Option<&V> {
        let mut node = self.root?;
        loop {
            if node.is_branch() {
                let branch = &self.branches[node.index()];
                node = if key_bit(artifact_id, branch.bit) {
                    branch.right
                } else {
                    branch.left
                };
            } else {
                let value = &self.leaves[node.index()];
                return (value.artifact_id() == artifact_id).then_some(value);
            }
        }
    }

    pub(crate) fn proof(&self, artifact_id: ArtifactId) -> ArtifactSetProof {
        let Some(mut node) = self.root else {
            return ArtifactSetProof {
                terminal: ArtifactTerminal::Empty,
                path: Box::new([]),
            };
        };

        let mut path = Vec::with_capacity(16);
        while node.is_branch() {
            let branch = &self.branches[node.index()];
            let goes_right = key_bit(artifact_id, branch.bit);
            let sibling = if goes_right {
                branch.left
            } else {
                branch.right
            };
            path.push(ArtifactPathStep {
                sibling: self.node_digest(sibling),
                bit: branch.bit,
            });
            node = if goes_right {
                branch.right
            } else {
                branch.left
            };
        }

        let terminal = self.leaves[node.index()].artifact_id();
        ArtifactSetProof {
            terminal: if terminal == artifact_id {
                ArtifactTerminal::Member
            } else {
                ArtifactTerminal::NonMember(terminal)
            },
            path: path.into_boxed_slice(),
        }
    }

    pub(crate) fn insert(&mut self, value: V) -> Option<&V> {
        let artifact_id = value.artifact_id();
        let Some(mut node) = self.root else {
            self.leaves.push(value);
            self.root = Some(NodeRef::leaf(0));
            return self.leaves.first();
        };

        self.search_path.clear();
        while node.is_branch() {
            let branch_index = node.index();
            let branch = &self.branches[branch_index];
            let goes_right = key_bit(artifact_id, branch.bit);
            self.search_path.push(branch_index);
            node = if goes_right {
                branch.right
            } else {
                branch.left
            };
        }

        let terminal_id = self.leaves[node.index()].artifact_id();
        if terminal_id == artifact_id {
            return None;
        }
        let differing_bit = first_differing_bit(artifact_id, terminal_id);
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
        let (left, right) = if key_bit(artifact_id, differing_bit) {
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
            let goes_right = key_bit(artifact_id, self.branches[parent_index].bit);
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
            leaf_digest(self.leaves[node.index()].artifact_id())
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
                .expect("artifact-set leaf arena cannot exhaust usize"),
        )
    }

    fn branch(index: usize) -> Self {
        Self(
            index
                .checked_mul(2)
                .and_then(|value| value.checked_add(Self::BRANCH_BIT))
                .expect("artifact-set branch arena cannot exhaust usize"),
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

fn key_bit(artifact_id: ArtifactId, bit: u8) -> bool {
    let bit = bit as usize;
    let byte = artifact_id.as_bytes()[bit / 8];
    byte & (1 << (7 - bit % 8)) != 0
}

fn first_differing_bit(left: ArtifactId, right: ArtifactId) -> u8 {
    for (byte_index, (left, right)) in left.as_bytes().iter().zip(right.as_bytes()).enumerate() {
        let difference = left ^ right;
        if difference != 0 {
            return u8::try_from(byte_index * 8 + difference.leading_zeros() as usize)
                .expect("ArtifactId bit positions fit u8");
        }
    }
    unreachable!("callers compare ArtifactIds before finding their differing bit")
}

fn leaf_digest(artifact_id: ArtifactId) -> [u8; 32] {
    tagged_digest(LEAF_TAG, &[artifact_id.as_bytes()])
}

fn branch_digest(bit: u8, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    tagged_digest(BRANCH_TAG, &[&[bit], &left, &right])
}

fn tagged_digest(tag: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ARTIFACT_SET_DOMAIN);
    hasher.update([tag]);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
