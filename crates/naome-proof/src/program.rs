//! Incrementally appended proof programs. Records have bounded width, while a
//! program and the formula DAG it constructs have no global size/work ceiling.
use crate::{DerivationId, ProofId, StatementId};
use naome_foundation::{
    Formula,
    graph::{Node, Properties, Variable},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FORMAT: &str = "naome:proof-program";
/// Current program-manifest framing, distinct from certificate payloads.
pub const MANIFEST_MAGIC: &[u8] = b"\xffNAOP\0";
const GRAPH_NODE_DOMAIN: &[u8] = b"naome:formula-graph\0";
/// An individual command is small; splitting an input into commands never
/// changes its mathematical meaning or imposes a total program byte limit.
pub const RECORD_BYTES: usize = 4096;
pub const CHUNK_RECORDS: usize = 1024;
pub const CHUNK_BYTES: usize = 32 * 1024;

mod stream;
pub use stream::{
    ChunkReader, MANIFEST_BYTES, Prefix, PreparedRecord, Progress, decode_command, encode_command,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    pub start: u64,
    pub previous: [u8; 32],
    pub next: [u8; 32],
    pub records: Vec<Command>,
}

/// A fixed-size claim about a complete immutable program. It grants neither
/// mathematical validity nor permission to fetch or publish its contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub commands: u64,
    pub input_bytes: u64,
    pub program_hash: [u8; 32],
    pub stream_root: [u8; 32],
    pub conclusion: [u8; 32],
    pub statement: [u8; 32],
}

impl Manifest {
    /// The common artifact address of this exact program proof.
    pub fn artifact_id(&self) -> crate::ArtifactId {
        self.proof_id().into()
    }
    pub fn proof_id(&self) -> ProofId {
        ProofId::from_bytes(self.address(b"naome:program-proof\0"))
    }
    pub fn statement_id(&self) -> StatementId {
        StatementId::from_bytes(self.statement)
    }
    pub fn derivation_id(&self) -> DerivationId {
        DerivationId::from_bytes(self.address(b"naome:program-derivation\0"))
    }
    fn address(&self, domain: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(naome_foundation::FOUNDATION_ID);
        hash.update(self.commands.to_be_bytes());
        hash.update(self.input_bytes.to_be_bytes());
        hash.update(self.program_hash);
        hash.update(self.stream_root);
        hash.update(self.conclusion);
        hash.update(self.statement);
        hash.finalize().into()
    }
}

pub fn command_hash(previous: [u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FORMAT);
    hash.update(previous);
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

/// A reverse commitment permits authenticating each forward transfer chunk
/// against the immutable manifest before saving any of its records.
pub fn stream_hash(bytes: &[u8], next: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:program-stream\0");
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
    hash.update(next);
    hash.finalize().into()
}

/// Stable constant-size formula-node encoding, including authenticated
/// structural properties. A node's children are content addresses.
pub fn graph_node_bytes(node: Node<[u8; 32]>, properties: Properties) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(GRAPH_NODE_DOMAIN);
    for child in node.children().into_iter().flatten() {
        bytes.extend_from_slice(&child);
    }
    bytes.push(match node {
        Node::Equal(..) => 0,
        Node::Member(..) => 1,
        Node::Not(_) => 2,
        Node::Implies(..) => 3,
        Node::ForAll(_) => 4,
    });
    if let Node::Equal(a, b) | Node::Member(a, b) = node {
        for variable in [a, b] {
            let (tag, value) = match variable {
                Variable::Free(v) => (0, u64::from(v)),
                Variable::Bound(v) => (1, v),
            };
            bytes.push(tag);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    bytes.push(u8::from(properties.has_free_variables));
    bytes.extend_from_slice(&properties.required_binders.to_be_bytes());
    bytes
}

pub fn graph_node_hash(node: Node<[u8; 32]>, properties: Properties) -> [u8; 32] {
    Sha256::digest(graph_node_bytes(node, properties)).into()
}

pub fn formula_hash(formula: &Formula) -> [u8; 32] {
    formula
        .fold_graph(|node: Node<([u8; 32], Properties)>| {
            let properties = node
                .properties(
                    node.children()
                        .map(|child| child.map(|(_, properties)| properties)),
                )
                .expect("well-formed formula properties");
            Ok::<_, std::convert::Infallible>((
                graph_node_hash(node.map(|(hash, _)| hash), properties),
                properties,
            ))
        })
        .expect("infallible formula hash")
        .0
}

/// Large conclusions have a domain-separated DAG address. Conclusions which
/// fit the certificate codec retain their existing StatementId instead.
pub fn graph_statement_id(root: [u8; 32]) -> StatementId {
    let mut hash = Sha256::new();
    hash.update(b"naome:graph-statement\0");
    hash.update(naome_foundation::FOUNDATION_ID);
    hash.update(root);
    StatementId::from_bytes(hash.finalize().into())
}

pub fn decode_graph_node(bytes: &[u8]) -> Result<(Node<[u8; 32]>, Properties), String> {
    let body = bytes
        .strip_prefix(GRAPH_NODE_DOMAIN)
        .ok_or("formula node domain")?;
    let offset = match body.len() {
        28 => 0,
        42 => 32,
        74 => 64,
        _ => return Err("formula node width".into()),
    };
    let child = |at| -> Result<[u8; 32], String> {
        body.get(at..at + 32)
            .ok_or("formula child width")?
            .try_into()
            .map_err(|_| "formula child width".into())
    };
    let variable = |at| -> Result<Variable, String> {
        let value = u64::from_be_bytes(
            body.get(at + 1..at + 9)
                .ok_or("formula variable width")?
                .try_into()
                .map_err(|_| "formula variable width")?,
        );
        match body[at] {
            0 => u32::try_from(value)
                .map(Variable::Free)
                .map_err(|_| "free variable width".into()),
            1 => Ok(Variable::Bound(value)),
            _ => Err("formula variable tag".into()),
        }
    };
    let node = match (offset, body[offset]) {
        (0, 0) => Node::Equal(variable(1)?, variable(10)?),
        (0, 1) => Node::Member(variable(1)?, variable(10)?),
        (32, 2) => Node::Not(child(0)?),
        (64, 3) => Node::Implies(child(0)?, child(32)?),
        (32, 4) => Node::ForAll(child(0)?),
        _ => return Err("formula node tag".into()),
    };
    let tail = body.len() - 9;
    let has_free_variables = match body[tail] {
        0 => false,
        1 => true,
        _ => return Err("formula property flag".into()),
    };
    let required_binders = u64::from_be_bytes(
        body[tail + 1..]
            .try_into()
            .map_err(|_| "formula property width")?,
    );
    let properties = Properties {
        has_free_variables,
        required_binders,
    };
    if graph_node_bytes(node, properties) != bytes {
        return Err("noncanonical formula node".into());
    }
    Ok((node, properties))
}

/// Materialize only formulas admitted by the existing tree codec. Exceeding
/// that representation returns None, without rejecting the graph formula.
pub fn bounded_formula<I: Copy>(
    root: I,
    mut load: impl FnMut(I) -> Result<Node<I>, String>,
) -> Result<Option<Formula>, String> {
    let mut pending = vec![(root, 0u32)];
    let mut bytes = Vec::new();
    let mut count = 0;
    while let Some((id, depth)) = pending.pop() {
        if depth > naome_foundation::FORMULA_MAX_DEPTH
            || count == naome_foundation::FORMULA_MAX_NODES
        {
            return Ok(None);
        }
        count += 1;
        let node = load(id)?;
        bytes.push(match node {
            Node::Equal(..) => 0,
            Node::Member(..) => 1,
            Node::Not(_) => 2,
            Node::Implies(..) => 3,
            Node::ForAll(_) => 4,
        });
        if let Node::Equal(a, b) | Node::Member(a, b) = node {
            for variable in [a, b] {
                let (tag, value) = match variable {
                    Variable::Free(v) => (0, v),
                    Variable::Bound(v) => {
                        let Ok(v) = u32::try_from(v) else {
                            return Ok(None);
                        };
                        (1, v)
                    }
                };
                bytes.push(tag);
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        if bytes.len() > naome_foundation::FORMULA_MAX_BYTES {
            return Ok(None);
        }
        for child in node.children().into_iter().rev().flatten() {
            pending.push((child, depth + 1));
        }
    }
    Formula::decode_canonical(&bytes)
        .map(Some)
        .map_err(|e| e.to_string())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Expand a selected conservative definition into an unproved formula.
    DefinedRelation {
        definition_id: [u8; 32],
        arguments: Vec<u32>,
    },
    Equal {
        left: u32,
        right: u32,
    },
    Member {
        element: u32,
        set: u32,
    },
    Not {
        formula: u64,
    },
    Implies {
        antecedent: u64,
        consequent: u64,
    },
    ForAll {
        variable: u32,
        body: u64,
    },
    Substitute {
        from: u32,
        to: u32,
        body: u64,
    },
    Simplification {
        antecedent: u64,
        consequent: u64,
    },
    Frege {
        first: u64,
        second: u64,
        third: u64,
    },
    Contraposition {
        antecedent: u64,
        consequent: u64,
    },
    Distribution {
        variable: u32,
        antecedent: u64,
        consequent: u64,
    },
    Vacuous {
        formula: u64,
    },
    Instantiation {
        variable: u32,
        replacement: u32,
        body: u64,
    },
    Reflexivity {
        variable: u32,
    },
    Substitution {
        from: u32,
        to: u32,
        body: u64,
    },
    Axiom {
        axiom: Axiom,
    },
    /// Reuse one concrete proof from the receiver's checker-owned context.
    /// The identity alone grants no validity; evaluation resolves and imports
    /// its authenticated conclusion before producing a proved result.
    ProofReference {
        proof_id: [u8; 32],
    },
    Separation {
        predicate: u64,
        element: u32,
        source: u32,
        result: u32,
    },
    Replacement {
        predicate: u64,
        input: u32,
        output: u32,
        witness: u32,
        source: u32,
        result: u32,
    },
    ModusPonens {
        premise: u64,
        implication: u64,
    },
    Generalization {
        premise: u64,
        variable: u32,
    },
    /// Return the same checked result, retaining an explicit module boundary.
    Alias {
        input: u64,
    },
    /// A seal accepts only a proved, closed conclusion after the entire prefix
    /// has been mathematically checked. No later append is permitted.
    Seal {
        proof: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axiom {
    Extensionality,
    Pairing,
    Union,
    PowerSet,
    Infinity,
    Foundation,
    Choice,
}
impl From<Axiom> for naome_foundation::ZfcAxiom {
    fn from(value: Axiom) -> Self {
        match value {
            Axiom::Extensionality => Self::Extensionality,
            Axiom::Pairing => Self::Pairing,
            Axiom::Union => Self::Union,
            Axiom::PowerSet => Self::PowerSet,
            Axiom::Infinity => Self::Infinity,
            Axiom::Foundation => Self::Foundation,
            Axiom::Choice => Self::Choice,
        }
    }
}
