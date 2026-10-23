//! Incrementally appended proof programs. Records have bounded width, while a
//! program and the formula DAG it constructs have no global size/work ceiling.
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "naome:proof-program:v1";
/// An individual command is small; splitting an input into commands never
/// changes its mathematical meaning or imposes a total program byte limit.
pub const RECORD_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
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
