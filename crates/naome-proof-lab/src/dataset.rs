//! Frozen synthetic provenance. Unknown means no supplied relation witness.
use crate::graph::Graph;
use naome_authoring::compile_against_proof_context;
use naome_checker::{ArtifactState, normalize_and_check_with_state};
use naome_foundation::FOUNDATION_ID;
use naome_proof::{ProofCertificate, ProofId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const POLICY: &str = "checked-relations-v1";
pub const LABELS: [&str; 4] = [
    "same_derivation",
    "shorter_independent",
    "witnessed_equivalence",
    "unknown",
];
#[derive(Clone, Serialize, Deserialize)]
pub struct Record {
    pub family: usize,
    pub variant: String,
    pub foundation: String,
    pub proof_id: String,
    pub statement_id: String,
    pub derivation_id: String,
    pub dependencies: Vec<String>,
    pub source: String,
    pub canonical: Vec<u8>,
    pub graph: Graph,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Pair {
    pub a: usize,
    pub b: usize,
    pub label: usize,
    pub witnesses: Vec<usize>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub schema: u32,
    pub policy: String,
    pub records: Vec<Record>,
    pub pairs: Vec<Pair>,
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn formula(n: usize, reverse_outer: bool) -> String {
    // Fixed-length bit constructors make each family structurally distinct.
    let mut f = "equal(x, x)".to_string();
    for bit in 0..12 {
        let atom = if n & (1 << bit) == 0 {
            "equal(x, y)"
        } else {
            "member(y, x)"
        };
        f = if reverse_outer && bit == 11 {
            format!("implies({f}, {atom})")
        } else {
            format!("implies({atom}, {f})")
        };
    }
    format!("forall(x, forall(y, {f}))")
}
fn source(statement: &str, steps: &str, root: &str) -> String {
    format!("foundation = \"naome:zfc\"\nstatement = {statement}\nproof:\n{steps}\nreturn {root}\n")
}
pub fn generate(families: usize) -> Result<Corpus, String> {
    if !(8..=2048).contains(&families) {
        return Err("families must be in 8..=2048".into());
    }
    let mut records = Vec::with_capacity(families * 8);
    let mut pairs = Vec::new();
    for family in 0..families {
        let a = formula(family, false);
        let b = "forall(z, equal(z, z))";
        let t = format!("implies({a}, implies({b}, {a}))");
        let u = format!("implies({b}, implies({a}, {b}))");
        // Distribution is deliberately independent of the family partition.
        let (uncertain_variant, adjacent) = match (family / 8 + family) % 4 {
            0 => ("uncertain_negation", format!("not_({a})")),
            1 => (
                "uncertain_quantifier_order",
                a.replacen("forall(x, forall(y,", "forall(y, forall(x,", 1),
            ),
            2 => (
                "uncertain_binding_arguments",
                a.replace("equal(x, y)", "equal(y, x)")
                    .replace("member(y, x)", "member(x, y)"),
            ),
            _ => ("uncertain_implication_direction", formula(family, true)),
        };
        let altered = format!("implies({adjacent}, implies({b}, {adjacent}))");
        let mut state = ArtifactState::new();
        let mut graphs = BTreeMap::new();
        let start = records.len();
        let mut append = |variant: &str, src: String| -> Result<usize, String> {
            let compiled =
                compile_against_proof_context(&src, &state).map_err(|e| e.to_string())?;
            let certificate =
                ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes())
                    .map_err(|e| e.to_string())?;
            let checked =
                normalize_and_check_with_state(certificate, &state).map_err(|e| e.to_string())?;
            let (graph, expanded) = Graph::checked(&checked, &state, &graphs)?;
            let proof_id = checked.proof_id();
            let id = hex(proof_id.as_bytes());
            records.push(Record {
                family,
                variant: variant.into(),
                foundation: FOUNDATION_ID.into(),
                proof_id: id,
                statement_id: hex(checked.statement_id().as_bytes()),
                derivation_id: hex(checked.derivation_id().as_bytes()),
                dependencies: checked
                    .direct_artifact_dependencies()
                    .iter()
                    .map(|d| hex(d.as_bytes()))
                    .collect(),
                source: src,
                canonical: compiled.canonical_proof_bytes().to_vec(),
                graph: graph.clone(),
            });
            if !state.contains_proof(proof_id) {
                state
                    .register_proof_for_replication(checked)
                    .map_err(|e| e.to_string())?;
                graphs.insert(proof_id, expanded);
            }
            Ok(records.len() - 1)
        };
        append(
            "direct",
            source(&t, &format!("p0 = simplification({a}, {b})"), "p0"),
        )?;
        append(
            "detour",
            source(
                &t,
                &format!(
                    "p0 = simplification({a}, {b})\np1 = simplification({t}, {t})\np2 = modus_ponens(p0, p1)\np3 = modus_ponens(p0, p2)"
                ),
                "p3",
            ),
        )?;
        // Resolve the already checked concrete direct certificate by its fixed hash.
        let direct_source = source(&t, &format!("p0 = simplification({a}, {b})"), "p0");
        let direct = naome_authoring::compile(&direct_source).map_err(|e| e.to_string())?;
        let tid = hex(direct.proof_id().as_bytes());
        append(
            "citation",
            source(&t, &format!("p0 = cite(\"{tid}\")"), "p0"),
        )?;
        append(
            "alpha_rename",
            direct_source
                .replace("x", "renamed_x")
                .replace("y", "renamed_y"),
        )?;
        append(
            "implication_order",
            source(&u, &format!("p0 = simplification({b}, {a})"), "p0"),
        )?;
        append(
            uncertain_variant,
            source(
                &altered,
                &format!("p0 = simplification({adjacent}, {b})"),
                "p0",
            ),
        )?;
        let u_source = source(&u, &format!("p0 = simplification({b}, {a})"), "p0");
        let uid = hex(naome_authoring::compile(&u_source)
            .map_err(|e| e.to_string())?
            .proof_id()
            .as_bytes());
        append(
            "witness_u_to_t",
            source(
                &format!("implies({u}, {t})"),
                &format!(
                    "p0 = cite(\"{tid}\")\np1 = simplification({t}, {u})\np2 = modus_ponens(p0, p1)"
                ),
                "p2",
            ),
        )?;
        append(
            "witness_t_to_u",
            source(
                &format!("implies({t}, {u})"),
                &format!(
                    "p0 = cite(\"{uid}\")\np1 = simplification({u}, {t})\np2 = modus_ponens(p0, p1)"
                ),
                "p2",
            ),
        )?;
        for (a, b, label) in [
            (0, 0, 0),
            (2, 0, 0),
            (3, 0, 0),
            (0, 1, 1),
            (0, 4, 2),
            (0, 5, 3),
            (1, 5, 3),
            (4, 5, 3),
        ] {
            pairs.push(Pair {
                a: start + a,
                b: start + b,
                label,
                witnesses: if label == 2 {
                    vec![start + 6, start + 7]
                } else {
                    Vec::new()
                },
            });
        }
    }
    let corpus = Corpus {
        schema: 1,
        policy: POLICY.into(),
        records,
        pairs,
    };
    corpus.validate()?;
    Ok(corpus)
}
impl Corpus {
    pub fn digest(&self) -> String {
        digest(&serde_json::to_vec(self).expect("finite checked corpus"))
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 || self.policy != POLICY {
            return Err("unsupported corpus policy".into());
        }
        if self.records.is_empty()
            || self.records.len() > 16384
            || self.pairs.is_empty()
            || self.pairs.len() > 16384
        {
            return Err("corpus exceeds finite input envelope".into());
        }
        let mut identities = BTreeMap::new();
        for r in &self.records {
            for (kind, id) in [
                (0, &r.proof_id),
                (1, &r.statement_id),
                (2, &r.derivation_id),
            ] {
                if let Some(partition) = identities.insert((kind, id), split(r.family))
                    && partition != split(r.family)
                {
                    return Err("mathematical identity crosses frozen partitions".into());
                }
            }
            if r.foundation != FOUNDATION_ID
                || r.graph.nodes.is_empty()
                || r.graph.root >= r.graph.nodes.len()
                || r.graph.edges.len() != r.graph.nodes.len()
                || r.graph.nodes.len() > crate::graph::MAX_NODES
                || r.graph.cost == 0
                || r.graph.nodes.iter().flatten().any(|v| !v.is_finite())
                || r.graph
                    .edges
                    .iter()
                    .flatten()
                    .any(|(to, channel)| *to >= r.graph.nodes.len() || *channel >= 3)
            {
                return Err("invalid corpus binding/graph".into());
            }
        }
        for p in &self.pairs {
            if p.a >= self.records.len()
                || p.b >= self.records.len()
                || p.label >= 4
                || p.witnesses.iter().any(|w| *w >= self.records.len())
            {
                return Err("invalid pair".into());
            }
            let a = &self.records[p.a];
            let b = &self.records[p.b];
            if a.family != b.family {
                return Err("pair crosses family".into());
            }
            let expected = if a.derivation_id == b.derivation_id {
                0
            } else if a.statement_id == b.statement_id && a.graph.cost < b.graph.cost {
                1
            } else if p.witnesses.len() == 2 {
                2
            } else {
                3
            };
            if p.label != expected {
                return Err("label contradicts checked witness policy".into());
            }
        }
        Ok(())
    }
    /// Rebuild all mathematical and graph witnesses from source, never trust JSON labels.
    pub fn replay(&self) -> Result<(), String> {
        self.validate()?;
        let mut state = ArtifactState::new();
        let mut graphs = BTreeMap::<ProofId, ProofCertificate>::new();
        for r in &self.records {
            let compiled =
                compile_against_proof_context(&r.source, &state).map_err(|e| e.to_string())?;
            let checked = normalize_and_check_with_state(
                ProofCertificate::from_canonical_bytes(compiled.canonical_proof_bytes())
                    .map_err(|e| e.to_string())?,
                &state,
            )
            .map_err(|e| e.to_string())?;
            let (g, expanded) = Graph::checked(&checked, &state, &graphs)?;
            if compiled.canonical_proof_bytes() != r.canonical
                || hex(checked.proof_id().as_bytes()) != r.proof_id
                || hex(checked.statement_id().as_bytes()) != r.statement_id
                || hex(checked.derivation_id().as_bytes()) != r.derivation_id
                || g != r.graph
                || checked
                    .direct_artifact_dependencies()
                    .iter()
                    .map(|d| hex(d.as_bytes()))
                    .collect::<Vec<_>>()
                    != r.dependencies
            {
                return Err("replay mismatch".into());
            }
            let id = checked.proof_id();
            if !state.contains_proof(id) {
                state
                    .register_proof_for_replication(checked)
                    .map_err(|e| e.to_string())?;
                graphs.insert(id, expanded);
            }
        }
        // Two checked directional implications are the equivalence evidence.
        for p in self.pairs.iter().filter(|p| p.label == 2) {
            let decode = |i: usize| -> Result<naome_foundation::Formula, String> {
                let r = &self.records[i];
                let c = ProofCertificate::from_canonical_bytes(&r.canonical)
                    .map_err(|e| e.to_string())?;
                Ok(normalize_and_check_with_state(c, &state)
                    .map_err(|e| e.to_string())?
                    .conclusion()
                    .clone())
            };
            let a = decode(p.a)?;
            let b = decode(p.b)?;
            if decode(p.witnesses[0])? != naome_foundation::Formula::implies(b.clone(), a.clone())
                || decode(p.witnesses[1])? != naome_foundation::Formula::implies(a, b)
            {
                return Err("wrong equivalence witness".into());
            }
        }
        Ok(())
    }
    pub fn counts(&self) -> serde_json::Value {
        serde_json::json!({"rows":self.records.len(),"proofs":self.records.iter().map(|r|&r.proof_id).collect::<BTreeSet<_>>().len(),"statements":self.records.iter().map(|r|&r.statement_id).collect::<BTreeSet<_>>().len(),"derivations":self.records.iter().map(|r|&r.derivation_id).collect::<BTreeSet<_>>().len(),"families":self.records.iter().map(|r|r.family).collect::<BTreeSet<_>>().len(),"graph_nodes":self.records.iter().map(|r|r.graph.nodes.len()).sum::<usize>(),"graph_edges":self.records.iter().map(|r|r.graph.edges.iter().map(Vec::len).sum::<usize>()).sum::<usize>(),"scientific_diversity":"one synthetic simplification schema; bit-encoded closed payload families", "alpha_duplicates_per_family":1,"citation_aliases_per_family":1})
    }
}
pub fn split(family: usize) -> usize {
    match family % 8 {
        0 => 2,
        1 => 1,
        _ => 0,
    }
}
