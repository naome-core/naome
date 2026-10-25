//! Closed formal research targets, independent of source syntax and checking.
use naome_foundation::{FOUNDATION_ID, Formula};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};

/// Maximum primitive formula nodes in each expanded target.
pub const QUESTION_TARGET_MAX_NODES: usize = 1024;
/// Maximum nested primitive nodes in each expanded target, counting the root.
pub const QUESTION_TARGET_MAX_DEPTH: usize = 32;

/// A rejected formal question source or canonical encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuestionError {
    Truncated,
    TrailingBytes,
    Limit(&'static str),
    Invalid(&'static str),
    Overflow,
    Mathematical(String),
}

impl fmt::Display for QuestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated question value"),
            Self::TrailingBytes => f.write_str("trailing question bytes"),
            Self::Limit(name) => write!(f, "question limit exceeded: {name}"),
            Self::Invalid(reason) => write!(f, "invalid question: {reason}"),
            Self::Overflow => f.write_str("question arithmetic overflow"),
            Self::Mathematical(reason) => write!(f, "invalid question formula: {reason}"),
        }
    }
}

impl Error for QuestionError {}

/// A bounded closed target and its exact resolution family. Construction
/// establishes shape and identity, never a proof or admission permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuestionTarget {
    formula: Formula,
    core: Formula,
    canonical_core: Vec<u8>,
    negative_target: Formula,
    negation_parity: bool,
    resolution_id: [u8; 32],
}
impl QuestionTarget {
    pub fn from_formula(formula: Formula) -> Result<Self, QuestionError> {
        if !formula.is_closed() {
            return Err(QuestionError::Invalid("question has free variables"));
        }
        let encoded = formula
            .encode_canonical()
            .map_err(|e| QuestionError::Mathematical(e.to_string()))?;
        let (nodes, depth) = formula.view().node_count_and_depth();
        // 0x02 is the existing Foundation canonical NOT tag. Removing only
        // leading NOT tags preserves all internal structure and De Bruijn binders.
        let leading = encoded.iter().take_while(|&&tag| tag == 0x02).count();
        let core_nodes = nodes - leading;
        let core_depth = depth - leading;
        if core_nodes + 1 > QUESTION_TARGET_MAX_NODES {
            return Err(QuestionError::Limit("question target nodes"));
        }
        if core_depth + 1 > QUESTION_TARGET_MAX_DEPTH {
            return Err(QuestionError::Limit("question target depth"));
        }
        let canonical_core = encoded[leading..].to_vec();
        let core =
            Formula::decode_canonical_with_node_limit(&canonical_core, QUESTION_TARGET_MAX_NODES)
                .map_err(|error| QuestionError::Mathematical(error.to_string()))?
                .0;
        let resolution_id = hash(
            b"naome:state:resolution:v1\0",
            &[FOUNDATION_ID.as_bytes(), &canonical_core],
        );
        Ok(Self {
            formula,
            negative_target: Formula::negate(core.clone()),
            core,
            canonical_core,
            negation_parity: leading % 2 != 0,
            resolution_id,
        })
    }

    pub const fn formula(&self) -> &Formula {
        &self.formula
    }
    pub const fn core(&self) -> &Formula {
        &self.core
    }
    pub fn canonical_core(&self) -> &[u8] {
        &self.canonical_core
    }
    pub const fn negation_parity(&self) -> bool {
        self.negation_parity
    }
    /// The exact R target, independently of its presentation as PROVED/REFUTED.
    pub const fn positive_target(&self) -> &Formula {
        &self.core
    }
    /// The exact not(R) target, independently of presentation.
    pub const fn negative_target(&self) -> &Formula {
        &self.negative_target
    }
    /// The target whose checked certificate establishes the question as PROVED.
    pub fn proved_target(&self) -> &Formula {
        if self.negation_parity {
            &self.negative_target
        } else {
            &self.core
        }
    }
    /// The opposite target, whose checked certificate establishes REFUTED.
    pub fn refuted_target(&self) -> &Formula {
        if self.negation_parity {
            &self.core
        } else {
            &self.negative_target
        }
    }
    pub const fn resolution_id(&self) -> &[u8; 32] {
        &self.resolution_id
    }
}

fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

#[cfg(test)]
mod tests;
