//! Bounded definition references derived from the checked graph, not a second store.
use super::{
    graph::Graph,
    model::{Binding, Candidate, Decision, Ranker, Rule},
};
use naome_checker::ArtifactState;
use naome_foundation::{Formula, FreeVariable, graph::Node};
use naome_proof::{
    ArtifactId, DefinedFormula, DefinitionCertificate, DefinitionKind, ProofCertificate,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const CAPACITY: usize = 8;
pub const BYTES: usize = 8 * 1024;

/// Exact untrusted inputs. Every use reconstructs ordinary selected checker state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub certificate: Vec<u8>,
    pub obligation: Option<Vec<u8>>,
}
impl Entry {
    pub fn certificate(&self) -> Result<DefinitionCertificate, String> {
        DefinitionCertificate::from_canonical_bytes(&self.certificate).map_err(|e| e.to_string())
    }
    pub fn address(&self) -> Result<ArtifactId, String> {
        Ok(self.certificate()?.definition_id().into())
    }
    pub fn body(&self) -> Result<Formula, String> {
        self.certificate()?
            .body()
            .clone()
            .into_primitive()
            .map_err(|e| e.to_string())
    }
    pub fn bytes(&self) -> usize {
        self.certificate.len() + self.obligation.as_ref().map_or(0, Vec::len)
    }
    pub fn source(&self, known: &[Entry]) -> Result<String, String> {
        let certificate = self.certificate()?;
        let arity = certificate.relation_arity();
        let parameters = (0..arity)
            .map(|i| format!("f{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let kind = match certificate.kind() {
            DefinitionKind::Relation { .. } => "relation",
            DefinitionKind::Function { .. } => "function",
        };
        let body = expression(&self.body()?, known)?;
        Ok(format!(
            "{}def learned = {kind}({parameters}): {body}",
            aliases(known)?
        ))
    }
}

pub fn context(entries: &[Entry]) -> Result<ArtifactState, String> {
    if entries.len() > CAPACITY || entries.iter().map(Entry::bytes).sum::<usize>() > BYTES {
        return Err("definition reference snapshot capacity".into());
    }
    let mut context = ArtifactState::new();
    for entry in entries {
        if let Some(bytes) = &entry.obligation {
            let proof = ProofCertificate::from_canonical_bytes(bytes).map_err(|e| e.to_string())?;
            let checked = naome_checker::normalize_and_check_with_state(proof, &context)
                .map_err(|e| e.to_string())?;
            context.register_proof(checked).map_err(|e| e.to_string())?;
        }
        let checked = naome_checker::check_definition_with_state(entry.certificate()?, &context)
            .map_err(|e| e.to_string())?;
        context
            .register_definition(checked)
            .map_err(|e| e.to_string())?;
    }
    Ok(context)
}

pub fn aliases(entries: &[Entry]) -> Result<String, String> {
    if entries.is_empty() {
        return Ok(String::new());
    }
    let mut output = String::from("defs:\n");
    for (i, entry) in entries.iter().enumerate() {
        output.push_str(&format!(
            "    d{i} = \"{}\"\n",
            crate::hex(entry.certificate()?.definition_id().as_bytes())
        ));
    }
    Ok(output)
}

fn canonical(formula: &Formula) -> (Formula, Vec<FreeVariable>) {
    let mut names = HashMap::new();
    let mut arguments = Vec::new();
    let formula = formula.clone().map_free_variables(|v| {
        *names.entry(v).or_insert_with(|| {
            let id = FreeVariable::new(arguments.len() as u32);
            arguments.push(v);
            id
        })
    });
    (formula, arguments)
}

/// IDs route the reference; only its actual expanded body enters model features.
pub fn application(formula: &Formula, entries: &[Entry]) -> Result<Option<String>, String> {
    fn variable(
        pattern: naome_foundation::graph::Variable,
        actual: naome_foundation::graph::Variable,
        arguments: &mut [Option<FreeVariable>],
    ) -> bool {
        use naome_foundation::graph::Variable;
        match (pattern, actual) {
            (Variable::Bound(a), Variable::Bound(b)) => a == b,
            (Variable::Free(p), Variable::Free(v)) => {
                let Some(argument) = arguments.get_mut(p as usize) else {
                    return false;
                };
                match argument {
                    Some(previous) => previous.identifier() == v,
                    None => {
                        *argument = Some(FreeVariable::new(v));
                        true
                    }
                }
            }
            _ => false,
        }
    }
    fn matches(
        pattern: naome_foundation::FormulaView<'_>,
        actual: naome_foundation::FormulaView<'_>,
        arguments: &mut [Option<FreeVariable>],
    ) -> bool {
        match (pattern.graph_node(), actual.graph_node()) {
            (Node::Equal(a, b), Node::Equal(c, d)) | (Node::Member(a, b), Node::Member(c, d)) => {
                variable(a, c, arguments) && variable(b, d, arguments)
            }
            (Node::Not(a), Node::Not(b)) | (Node::ForAll(a), Node::ForAll(b)) => {
                matches(a, b, arguments)
            }
            (Node::Implies(a, b), Node::Implies(c, d)) => {
                matches(a, c, arguments) && matches(b, d, arguments)
            }
            _ => false,
        }
    }
    for (i, entry) in entries.iter().enumerate() {
        let mut arguments = vec![None; entry.certificate()?.relation_arity() as usize];
        if matches(entry.body()?.view(), formula.view(), &mut arguments)
            && arguments.iter().all(Option::is_some)
        {
            return Ok(Some(format!(
                "d{i}({})",
                arguments
                    .iter()
                    .map(|v| format!("f{}", v.expect("matched definition argument").identifier()))
                    .collect::<Vec<_>>()
                    .join(",")
            )));
        }
    }
    Ok(None)
}

pub fn expression(formula: &Formula, entries: &[Entry]) -> Result<String, String> {
    if let Some(reference) = application(formula, entries)? {
        return Ok(reference);
    }
    Ok(match formula.view().graph_node() {
        Node::Not(body) => format!("not({})", expression(&body.to_owned(), entries)?),
        Node::Implies(a, b) => format!(
            "imp({},{})",
            expression(&a.to_owned(), entries)?,
            expression(&b.to_owned(), entries)?
        ),
        Node::ForAll(_) => {
            let used = formula.free_variables();
            let v = (0..=u32::MAX)
                .map(FreeVariable::new)
                .find(|v| !used.contains(v))
                .ok_or("definition binder space")?;
            format!(
                "all(f{},{})",
                v.identifier(),
                expression(
                    &formula.open_outer_universal(v).ok_or("definition binder")?,
                    entries
                )?
            )
        }
        _ => formula.to_source(),
    })
}

/// Preserve the concrete certificate's reference placement and argument binding.
pub fn exact_expression(formula: &DefinedFormula, entries: &[Entry]) -> Result<String, String> {
    use naome_proof::{DefinedFormulaNode as N, DefinedVariable as V};
    fn variable(v: V, binders: &[FreeVariable]) -> Result<String, String> {
        let v = match v {
            V::Free(v) => v,
            V::Bound(index) => *binders
                .get(
                    binders
                        .len()
                        .checked_sub(index as usize + 1)
                        .ok_or("definition source binder")?,
                )
                .ok_or("definition source binder")?,
        };
        Ok(format!("f{}", v.identifier()))
    }
    fn render(
        f: naome_proof::DefinedFormulaView<'_>,
        entries: &[Entry],
        binders: &mut Vec<FreeVariable>,
        free: &std::collections::BTreeSet<FreeVariable>,
    ) -> Result<String, String> {
        Ok(match f.node() {
            N::Equal(a, b) => format!("eq({},{})", variable(a, binders)?, variable(b, binders)?),
            N::Member(a, b) => format!("mem({},{})", variable(a, binders)?, variable(b, binders)?),
            N::Not(body) => format!("not({})", render(body, entries, binders, free)?),
            N::Implies(a, b) => format!(
                "imp({},{})",
                render(a, entries, binders, free)?,
                render(b, entries, binders, free)?
            ),
            N::ForAll(body) => {
                let v = (0..=u32::MAX)
                    .map(FreeVariable::new)
                    .find(|v| !free.contains(v) && !binders.contains(v))
                    .ok_or("definition source variable space")?;
                binders.push(v);
                let body = render(body, entries, binders, free)?;
                binders.pop();
                format!("all(f{},{body})", v.identifier())
            }
            N::DefinedRelation {
                definition_id,
                arguments,
            } => {
                let index = entries
                    .iter()
                    .position(|e| {
                        e.certificate()
                            .is_ok_and(|c| c.definition_id() == definition_id)
                    })
                    .ok_or("definition source reference absent")?;
                let arguments = arguments
                    .iter()
                    .map(|v| variable(*v, binders))
                    .collect::<Result<Vec<_>, _>>()?
                    .join(",");
                format!("d{index}({arguments})")
            }
        })
    }
    render(
        formula.view(),
        entries,
        &mut Vec::new(),
        &formula.free_variables(),
    )
}

/// Propose an eliminable relation for repeated structure, without asserting a theorem.
pub fn discover(target: &Formula) -> Result<Option<Entry>, String> {
    fn visit(
        f: &Formula,
        counts: &mut BTreeMap<Vec<u8>, (Formula, usize)>,
        work: &mut usize,
    ) -> Result<(), String> {
        *work += 1;
        if *work > 2048 {
            return Ok(());
        }
        let (body, arguments) = canonical(f);
        let nodes = body.view().node_count_and_depth().0;
        if (1..=4).contains(&arguments.len()) && (5..=64).contains(&nodes) {
            let bytes = body.encode_canonical().map_err(|e| e.to_string())?;
            if bytes.len() <= 768 {
                counts.entry(bytes).or_insert((body, 0)).1 += 1;
            }
        }
        match f.view().graph_node() {
            Node::Not(body) => visit(&body.to_owned(), counts, work)?,
            Node::Implies(a, b) => {
                visit(&a.to_owned(), counts, work)?;
                visit(&b.to_owned(), counts, work)?;
            }
            Node::ForAll(_) => {
                let used = f.free_variables();
                let v = (0..=u32::MAX)
                    .map(FreeVariable::new)
                    .find(|v| !used.contains(v))
                    .ok_or("definition proposal binder")?;
                visit(
                    &f.open_outer_universal(v)
                        .ok_or("definition proposal universal")?,
                    counts,
                    work,
                )?;
            }
            _ => {}
        }
        Ok(())
    }
    let mut counts = BTreeMap::new();
    visit(target, &mut counts, &mut 0)?;
    let best = counts
        .into_values()
        .filter(|(_, n)| *n >= 2)
        .max_by_key(|(body, n)| {
            let nodes = body.view().node_count_and_depth().0;
            n.saturating_mul(nodes.saturating_sub(body.free_variables().len() + 1))
                .saturating_sub(nodes)
        });
    let Some((body, count)) = best else {
        return Ok(None);
    };
    let nodes = body.view().node_count_and_depth().0;
    let arity = body.free_variables().len();
    if count.saturating_mul(nodes.saturating_sub(arity + 1)) <= nodes {
        return Ok(None);
    }
    let certificate = DefinitionCertificate::relation(
        arity as u32,
        DefinedFormula::from_primitive(&body).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let entry = Entry {
        certificate: certificate.to_canonical_bytes(),
        obligation: None,
    };
    let _ = context(std::slice::from_ref(&entry))?;
    Ok(Some(entry))
}

pub fn decision(target: &Formula, entries: &[Entry], selected: usize) -> Result<Graph, String> {
    let mut graph = Graph::encode(&features(target, entries, selected)?)?;
    graph.binding = super::digest(&(
        target.encode_canonical().map_err(|e| e.to_string())?,
        entries,
    ));
    Ok(graph)
}
fn features(target: &Formula, entries: &[Entry], selected: usize) -> Result<Decision, String> {
    Ok(Decision {
        context: vec![Binding {
            formula: target.clone(),
        }],
        goal: target.clone(),
        expert: selected,
        candidates: entries
            .iter()
            .map(|e| {
                Ok(Candidate {
                    rule: Rule::DefinitionReference,
                    premises: vec![0],
                    consequences: vec![e.body()?],
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}
pub fn choices(target: &Formula, known: &[Entry]) -> Result<Vec<Entry>, String> {
    let mut entries = known.iter().take(CAPACITY - 1).cloned().collect::<Vec<_>>();
    if let Some(proposed) = discover(target)?
        && !entries.contains(&proposed)
        && entries.iter().map(Entry::bytes).sum::<usize>() + proposed.bytes() <= BYTES
    {
        entries.push(proposed);
    }
    Ok(entries)
}
pub fn choose(
    target: &Formula,
    known: &[Entry],
    ranker: &mut dyn Ranker,
) -> Result<Option<(Vec<Entry>, usize)>, String> {
    let entries = choices(target, known)?;
    if entries.is_empty() {
        return Ok(None);
    }
    let _ = context(&entries)?;
    let decision = features(target, &entries, 0)?;
    if Graph::encode(&decision).is_err() {
        return Ok(None);
    }
    let scores = ranker.scores(&decision)?;
    if scores.len() != entries.len() || scores.iter().any(|s| !s.is_finite()) {
        return Err("definition reference scores differ".into());
    }
    let selected = (0..scores.len())
        .max_by(|a, b| scores[*a].total_cmp(&scores[*b]).then(b.cmp(a)))
        .ok_or("definition choices empty")?;
    Ok(Some((entries, selected)))
}

pub fn helpers(tree: &super::search::Tree) -> Result<Vec<String>, String> {
    let super::search::Tree::Definitions {
        entries,
        selected,
        available,
        ..
    } = tree
    else {
        return Ok(Vec::new());
    };
    let entry = entries.get(*selected).ok_or("definition selection index")?;
    let known = entries
        .get(..*available)
        .ok_or("definition availability differs")?
        .iter()
        .filter(|e| *e != entry)
        .cloned()
        .collect::<Vec<_>>();
    let mut sources = Vec::new();
    if let Some(bytes) = &entry.obligation {
        let context = context(std::slice::from_ref(entry))?;
        let certificate =
            ProofCertificate::from_canonical_bytes(bytes).map_err(|e| e.to_string())?;
        let checked = naome_checker::normalize_and_check_with_state(certificate, &context)
            .map_err(|e| e.to_string())?;
        let verified = super::proof::Verified {
            certificate: checked.normal_form().certificate().clone(),
            target: checked.conclusion().clone(),
            native_id: checked.proof_id(),
            payload_bytes: checked.normal_form().canonical_bytes().len(),
            definitions: Vec::new(),
        };
        sources.push(super::proof::source(&verified)?);
    }
    sources.push(entry.source(&known)?);
    Ok(sources)
}

pub fn selected(tree: &super::search::Tree) -> Result<Vec<Entry>, String> {
    match tree {
        super::search::Tree::Definitions {
            entries, selected, ..
        } => Ok(vec![
            entries
                .get(*selected)
                .ok_or("definition selection index")?
                .clone(),
        ]),
        super::search::Tree::Certificate(bytes) => super::peer::definitions(bytes),
        _ => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{proof, search};
    use super::*;
    use std::time::{Duration, Instant};
    fn entry(source: &str) -> Entry {
        let naome_authoring::CompiledArtifact::Definition(definition) =
            naome_authoring::compile_artifact(source).unwrap()
        else {
            panic!("definition")
        };
        Entry {
            certificate: definition.canonical_definition_bytes().to_vec(),
            obligation: None,
        }
    }
    #[test]
    fn discovered_definitions_are_atomic_references_and_reused_after_restart() {
        let q = naome_authoring::CompiledQuestion::compile(
            "goal=all(x,all(y,imp(and(mem(x,y),and(mem(y,x),eq(x,x))),and(mem(x,y),and(mem(y,x),eq(x,x))))))",
        ).unwrap();
        let proposed = discover(q.proved_target())
            .unwrap()
            .expect("repeated relation");
        let known = entry("def self_equal=relation(x): eq(x,x)");
        struct Ordered;
        impl Ranker for Ordered {
            fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
                Ok(vec![0.; d.candidates.len()])
            }
        }
        let mut ranker = Ordered;
        let tree = search::solve(q.proved_target(), &mut ranker, 128)
            .unwrap()
            .tree
            .unwrap();
        let wrapped = search::Tree::Definitions {
            entries: vec![known.clone(), proposed.clone()],
            selected: 1,
            available: 1,
            proof: Box::new(tree),
        };
        let (_, graphs) = search::compile(q.proved_target(), &wrapped).unwrap();
        assert!(
            graphs
                .iter()
                .any(|g| g.nodes[g.candidates[1]].kind == Rule::DefinitionReference.kind())
        );
        let (_, _, checked) = search::core::checked(q.proved_target(), &wrapped).unwrap();
        let source = proof::source(&checked).unwrap();
        let helper_sources = helpers(&wrapped).unwrap();
        let directory = crate::checkpoint::tests::Directory::new();
        let mut graph = crate::Graph::open(&directory.0).unwrap();
        graph.produce(&known.source(&[]).unwrap()).unwrap();
        let (root, batch) = graph
            .prepare_generated(&source, &helper_sources, &q)
            .unwrap();
        assert!(!graph.contains(proposed.address().unwrap()).unwrap());
        graph
            .commit_batch(root, batch, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(graph.contains(proposed.address().unwrap()).unwrap());
        assert_eq!(
            graph
                .learning_definition(proposed.address().unwrap())
                .unwrap(),
            Some(proposed.clone())
        );
        let expected = graph.content_root();
        drop(graph);
        let graph = crate::Graph::open(&directory.0).unwrap();
        assert_eq!(graph.content_root(), expected);
        let q2 = naome_authoring::CompiledQuestion::compile(
            "goal=all(x,all(y,imp(and(mem(x,y),and(mem(y,x),eq(x,x))),or(and(mem(x,y),and(mem(y,x),eq(x,x))),eq(y,y)))))",
        ).unwrap();
        let tree = search::solve(q2.proved_target(), &mut ranker, 128)
            .unwrap()
            .tree
            .unwrap();
        let tree = search::Tree::Definitions {
            entries: vec![proposed.clone()],
            selected: 0,
            available: 1,
            proof: Box::new(tree),
        };
        let (_, _, checked) = search::core::checked(q2.proved_target(), &tree).unwrap();
        let source = proof::source(&checked).unwrap();
        let (root, batch) = graph
            .prepare_generated(&source, &helpers(&tree).unwrap(), &q2)
            .unwrap();
        assert_ne!(
            root,
            ArtifactId::from_proof_id(
                proof::verify(
                    &search::compile(q.proved_target(), &wrapped).unwrap().0,
                    q.proved_target()
                )
                .unwrap()
                .native_id
            )
        );
        drop(batch);
    }
    #[test]
    fn natural_number_predicate_reuses_checked_empty_successor_and_inductive_definitions() {
        let mut graph = crate::Graph::default();
        let (empty, _) = graph
            .produce("def empty=relation(x): all(y,not(mem(y,x)))")
            .unwrap();
        let (successor, _) = graph
            .produce("def successor=relation(x,s): all(y,iff(mem(y,s),or(mem(y,x),eq(y,x))))")
            .unwrap();
        let empty_id = crate::hex(empty.definition_id().unwrap().unwrap().as_bytes());
        let successor_id = crate::hex(successor.definition_id().unwrap().unwrap().as_bytes());
        let source = format!(
            "defs: e=\"{empty_id}\" s=\"{successor_id}\" def inductive=relation(i): and(ex(z,and(e(z),mem(z,i))),all(n,imp(mem(n,i),ex(t,and(s(n,t),mem(t,i))))))"
        );
        let (inductive, _) = graph.produce(&source).unwrap();
        let inductive_id = crate::hex(inductive.definition_id().unwrap().unwrap().as_bytes());
        let (natural, _) = graph
            .produce(&format!(
                "defs: i=\"{inductive_id}\" def natural=relation(n): all(s,imp(i(s),mem(n,s)))"
            ))
            .unwrap();
        let id = ArtifactId::from_definition_id(natural.definition_id().unwrap().unwrap());
        let snapshot = graph.learning_definition(id).unwrap().unwrap();
        assert_eq!(snapshot.address().unwrap(), id);
        assert!(context(&[snapshot]).is_ok());
        assert!(
            graph.describe(id).unwrap().is_none(),
            "a conservative predicate does not assert existence of a natural-number set"
        );
    }
    #[test]
    fn definition_meaning_and_argument_sharing_survive_alpha_renaming() {
        let known = entry("def directed=relation(x,y): imp(mem(x,y),mem(y,x))");
        let x = FreeVariable::new(9);
        let y = FreeVariable::new(2);
        let f = Formula::implies(Formula::member(x, y), Formula::member(y, x));
        assert_eq!(
            application(&f, std::slice::from_ref(&known)).unwrap(),
            Some("d0(f9,f2)".into())
        );
        let aliased = Formula::implies(Formula::member(x, x), Formula::member(x, y));
        assert!(application(&aliased, &[known]).unwrap().is_none());
    }
}
