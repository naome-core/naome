//! Graphs use checked proof dependencies or validated closed question/context formulas.
use naome_checker::{ArtifactState, CheckedProof, normalize_and_check_with_state};
use naome_foundation::Formula;
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const FEATURES: usize = 24;
pub const MAX_NODES: usize = 8192;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Graph {
    pub nodes: Vec<[f64; FEATURES]>,
    /// Ordered argument, second argument, and binder/conclusion channels.
    pub edges: Vec<Vec<(usize, usize)>>,
    pub root: usize,
    /// Proofs count expanded primitive inference nodes; questions count AST graph nodes.
    pub cost: usize,
}
impl Graph {
    pub(crate) fn question(formula: &Formula) -> Result<Self, String> {
        if !formula.is_closed() {
            return Err("question graph requires a closed validated target".into());
        }
        let mut graph = Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            root: 0,
            cost: 0,
        };
        graph.root = graph.formula(formula, &mut BTreeMap::new())?;
        graph.cost = graph.nodes.len();
        Ok(graph)
    }
    /// Full bounded receiver context; no labels, reason codes or family metadata.
    pub(crate) fn question_context(parts: &[(Formula, usize)]) -> Result<Self, String> {
        if parts.is_empty() || parts.len() > 512 {
            return Err("question context is missing or exceeds its full-scan ceiling".into());
        }
        let mut graph = Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            root: 0,
            cost: 0,
        };
        let root = graph.node(20)?;
        for (formula, role) in parts {
            if *role > 2 || !formula.is_closed() {
                return Err("invalid receiver context graph".into());
            }
            let child = graph.formula(formula, &mut BTreeMap::new())?;
            graph.edges[root].push((child, *role));
        }
        graph.cost = graph.nodes.len();
        Ok(graph)
    }

    fn node(&mut self, kind: usize) -> Result<usize, String> {
        if self.nodes.len() >= MAX_NODES {
            return Err("offline graph node ceiling reached".into());
        }
        let mut features = [0.0; FEATURES];
        features[kind] = 1.0;
        let id = self.nodes.len();
        self.nodes.push(features);
        self.edges.push(Vec::new());
        Ok(id)
    }
    fn formula(&mut self, f: &Formula, free: &mut BTreeMap<u32, usize>) -> Result<usize, String> {
        let bytes = f.encode_canonical().map_err(|e| e.to_string())?;
        let mut pos = 0;
        let root = self.parse(&bytes, &mut pos, &mut Vec::new(), free)?;
        if pos != bytes.len() {
            return Err("unexpected canonical formula suffix".into());
        }
        Ok(root)
    }
    fn parse(
        &mut self,
        bytes: &[u8],
        pos: &mut usize,
        binders: &mut Vec<usize>,
        free: &mut BTreeMap<u32, usize>,
    ) -> Result<usize, String> {
        let tag = bytes[*pos] as usize;
        *pos += 1;
        let root = self.node(tag)?;
        match tag {
            0 | 1 => {
                for channel in 0..2 {
                    let kind = bytes[*pos];
                    *pos += 1;
                    let id = u32::from_be_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
                    *pos += 4;
                    let variable = if kind == 0 {
                        if let Some(v) = free.get(&id) {
                            *v
                        } else {
                            let v = self.node(5)?;
                            self.nodes[v][22] = id as f64 / 65536.0;
                            free.insert(id, v);
                            v
                        }
                    } else {
                        let v = self.node(6)?;
                        self.nodes[v][22] = id as f64 / 256.0;
                        let binder = *binders
                            .get(
                                binders
                                    .len()
                                    .checked_sub(id as usize + 1)
                                    .ok_or("dangling binder")?,
                            )
                            .ok_or("dangling binder")?;
                        self.edges[v].push((binder, 2));
                        v
                    };
                    self.edges[root].push((variable, channel));
                }
            }
            2 => {
                let c = self.parse(bytes, pos, binders, free)?;
                self.edges[root].push((c, 0));
            }
            3 => {
                for channel in 0..2 {
                    let c = self.parse(bytes, pos, binders, free)?;
                    self.edges[root].push((c, channel));
                }
            }
            4 => {
                binders.push(root);
                let c = self.parse(bytes, pos, binders, free)?;
                binders.pop();
                self.edges[root].push((c, 0));
            }
            _ => return Err("unsupported formula constructor".into()),
        }
        Ok(root)
    }
    pub fn checked(
        proof: &CheckedProof,
        state: &ArtifactState,
        dependencies: &BTreeMap<ProofId, ProofCertificate>,
    ) -> Result<(Self, ProofCertificate), String> {
        let mut expanded = Vec::new();
        let mut roots = Vec::new();
        for step in proof.normal_form().certificate().steps() {
            if let ProofStep::ProofReference { proof_id } = step {
                let dep = dependencies
                    .get(proof_id)
                    .ok_or("missing checked graph dependency")?;
                let offset = expanded.len() as u32;
                for s in dep.steps() {
                    expanded.push(remap(s, |r| r + offset));
                    if expanded.len() > 4096 {
                        return Err("expanded inference ceiling".into());
                    }
                }
                roots.push(expanded.len() as u32 - 1);
            } else {
                expanded.push(remap(step, |r| roots[r as usize]));
                roots.push(expanded.len() as u32 - 1);
            }
        }
        let certificate = ProofCertificate::new(expanded).map_err(|e| e.to_string())?;
        let expanded =
            normalize_and_check_with_state(certificate, state).map_err(|e| e.to_string())?;
        if expanded.derivation_id() != proof.derivation_id()
            || expanded.conclusion() != proof.conclusion()
        {
            return Err("reference-transparent expansion changed checked derivation".into());
        }
        let graph = Self::primitive(&expanded, state)?;
        Ok((graph, expanded.into_normal_form().certificate().clone()))
    }
    fn primitive(proof: &CheckedProof, state: &ArtifactState) -> Result<Self, String> {
        let steps = proof.normal_form().certificate().steps();
        let mut g = Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            root: 0,
            cost: 0,
        };
        let mut roots = Vec::new();
        let mut free = BTreeMap::new();
        for step in steps {
            let kind = match step.canonical_tag() {
                0..=7 => 7 + step.canonical_tag() as usize,
                16 => 15,
                17 => 16,
                18 => 17,
                32 => 18,
                33 => 19,
                _ => return Err("unsupported inference".into()),
            };
            let node = g.node(kind)?;
            g.cost += 1;
            for (channel, reference) in step.local_references().into_iter().enumerate() {
                if let Some(r) = reference {
                    g.edges[node].push((roots[r as usize], channel));
                }
            }
            let mut formulas = Vec::new();
            let mut variables = Vec::new();
            match step {
                ProofStep::Simplification {
                    antecedent,
                    consequent,
                }
                | ProofStep::ClassicalContraposition {
                    antecedent,
                    consequent,
                } => formulas.extend([antecedent, consequent]),
                ProofStep::UniversalDistribution {
                    variable,
                    antecedent,
                    consequent,
                } => {
                    formulas.extend([antecedent, consequent]);
                    variables.push(*variable);
                }
                ProofStep::Frege {
                    first,
                    second,
                    third,
                } => formulas.extend([first, second, third]),
                ProofStep::VacuousUniversal { formula } => formulas.push(formula),
                ProofStep::UniversalInstantiation {
                    variable,
                    replacement,
                    body,
                } => {
                    formulas.push(body);
                    variables.extend([*variable, *replacement]);
                }
                ProofStep::EqualityReflexivity { variable }
                | ProofStep::Generalization { variable, .. } => variables.push(*variable),
                ProofStep::EqualitySubstitution { from, to, body } => {
                    formulas.push(body);
                    variables.extend([*from, *to]);
                }
                ProofStep::ZfcAxiom(axiom) => g.nodes[node][22] = *axiom as u8 as f64 / 8.0,
                ProofStep::Separation(s) => {
                    formulas.push(&s.predicate);
                    variables.extend([s.element, s.source, s.result]);
                    variables.extend(&s.parameters);
                }
                ProofStep::Replacement(s) => {
                    formulas.push(&s.predicate);
                    variables.extend([s.input, s.output, s.uniqueness_witness, s.source, s.result]);
                    variables.extend(&s.parameters);
                }
                ProofStep::ProofReference { .. } | ProofStep::ModusPonens { .. } => {}
            }
            for (role, f) in formulas.into_iter().enumerate() {
                let f = f.expand_with(state).map_err(|e| e.to_string())?;
                let r = g.formula(&f, &mut free)?;
                g.nodes[r][23] = role as f64;
                g.edges[node].push((r, role.min(2)));
            }
            for (role, v) in variables.into_iter().enumerate() {
                let id = v.identifier();
                let r = if let Some(r) = free.get(&id) {
                    *r
                } else {
                    let r = g.node(5)?;
                    g.nodes[r][22] = id as f64 / 65536.0;
                    free.insert(id, r);
                    r
                };
                // An explicit role node preserves arbitrary schema parameter order.
                let edge = g.node(20)?;
                g.nodes[edge][23] = role as f64;
                g.edges[edge].push((r, 0));
                g.edges[node].push((edge, 2));
            }
            roots.push(node);
        }
        g.root = *roots.last().ok_or("empty checked graph")?;
        let conclusion = g.formula(proof.conclusion(), &mut free)?;
        g.edges[g.root].push((conclusion, 2));
        Ok(g)
    }
}

fn remap(step: &ProofStep, map: impl Fn(u32) -> u32) -> ProofStep {
    match step {
        ProofStep::ModusPonens {
            premise,
            implication,
        } => ProofStep::ModusPonens {
            premise: map(*premise),
            implication: map(*implication),
        },
        ProofStep::Generalization { premise, variable } => ProofStep::Generalization {
            premise: map(*premise),
            variable: *variable,
        },
        _ => step.clone(),
    }
}
