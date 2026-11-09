//! Bounded definition references derived from the checked graph, not a second store.
use super::{
    graph::Graph,
    model::{Binding, Candidate, Decision, Ranker, Rule},
};
use naome_checker::ArtifactState;
use naome_foundation::{Formula, FreeVariable, graph::Node};
use naome_proof::{ArtifactId, DefinedFormula, DefinitionCertificate, ProofCertificate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const CAPACITY: usize = 8;
pub const BYTES: usize = 8 * 1024;

/// Exact untrusted inputs. Every use reconstructs ordinary selected checker state.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub certificate: Vec<u8>,
    pub obligation: Option<Vec<u8>>,
}
impl Entry {
    pub fn certificate(&self) -> Result<DefinitionCertificate, crate::Error> {
        DefinitionCertificate::from_canonical_bytes(&self.certificate)
            .map_err(|error| crate::object::definition_error(&self.certificate, error))
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
    pub fn artifact(&self) -> Result<String, crate::Error> {
        Ok(crate::hex(
            &naome_proof::ArtifactPayload::Definition(self.certificate()?).to_canonical_bytes(),
        ))
    }
}

// The graph admits each tagged artifact against the earlier checked prefix.
pub(super) fn append_artifacts(
    entries: &[Entry],
    sources: &mut Vec<String>,
) -> Result<(), crate::Error> {
    for entry in entries {
        if let Some(bytes) = &entry.obligation {
            let certificate = ProofCertificate::from_canonical_bytes(bytes)
                .map_err(|error| crate::object::certificate_error(bytes, error))?;
            let witness = super::proof::artifact(&certificate);
            if !sources.contains(&witness) {
                sources.push(witness);
            }
        }
        let definition = entry.artifact()?;
        if !sources.contains(&definition) {
            sources.push(definition);
        }
    }
    Ok(())
}

pub(crate) fn fits(entries: &[Entry]) -> bool {
    entries.len() <= CAPACITY && entries.iter().map(Entry::bytes).sum::<usize>() <= BYTES
}

pub fn context(entries: &[Entry]) -> Result<ArtifactState, crate::Error> {
    if !fits(entries) {
        return Err(crate::ResearchFailure::DefinitionSnapshotCapacity.into());
    }
    let mut context = ArtifactState::new();
    for entry in entries {
        register(&mut context, entry)?;
    }
    Ok(context)
}

pub fn register(context: &mut ArtifactState, entry: &Entry) -> Result<(), crate::Error> {
    if entry.bytes() > BYTES {
        return Err(crate::ResearchFailure::DefinitionSnapshotCapacity.into());
    }
    if let Some(bytes) = &entry.obligation {
        let certificate = ProofCertificate::from_canonical_bytes(bytes)
            .map_err(|error| crate::object::certificate_error(bytes, error))?;
        let checked = super::proof::check(certificate, context)?;
        if !context.contains_proof(checked.proof_id()) {
            context.register_proof_for_verification(checked)?;
        }
    }
    let checked = naome_checker::check_definition_with_state(entry.certificate()?, context)?;
    if !context.contains_definition(entry.certificate()?.definition_id()) {
        context.register_definition(checked)?;
    }
    Ok(())
}
pub fn proof_context(tree: &super::search::Tree) -> Result<ArtifactState, crate::Error> {
    use super::search::Tree;
    match tree {
        Tree::Scoped { target, actions } => {
            let verified = super::search::scope::verified(target, actions)?;
            Ok(super::proof::lemma_context(
                &verified.definitions,
                &verified.lemmas,
            )?)
        }
        Tree::Knowledge { .. } => {
            let verified = super::knowledge::verified(tree)?;
            Ok(super::proof::lemma_context(
                &verified.definitions,
                &verified.lemmas,
            )?)
        }
        Tree::Constructed { packet, .. }
        | Tree::Composed { packet, .. }
        | Tree::Certificate(packet) => Ok(super::evidence::context(packet)?),
        Tree::Definitions {
            entries,
            selected,
            proof,
            ..
        } => {
            let mut context = proof_context(proof)?;
            register(
                &mut context,
                entries
                    .get(*selected)
                    .ok_or(crate::ResearchFailure::DefinitionSelectionIndex)?,
            )?;
            Ok(context)
        }
        Tree::Stored { .. } => Err(crate::ResearchFailure::DefinitionTraceSnapshotMissing.into()),
        _ => Ok(ArtifactState::new()),
    }
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
fn application(formula: &Formula, entries: &[Entry]) -> Result<Option<DefinedFormula>, String> {
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
    for entry in entries {
        let certificate = entry.certificate()?;
        let mut arguments = vec![None; certificate.relation_arity() as usize];
        if matches(entry.body()?.view(), formula.view(), &mut arguments)
            && let Some(arguments) = arguments.into_iter().collect::<Option<Vec<_>>>()
        {
            return Ok(Some(DefinedFormula::defined_relation(
                certificate.definition_id(),
                arguments,
            )));
        }
    }
    Ok(None)
}

pub(super) fn represent(
    formula: &Formula,
    entries: &[Entry],
) -> Result<naome_proof::ProofFormula, String> {
    fn defined(f: &Formula, entries: &[Entry]) -> Result<DefinedFormula, String> {
        if let Some(reference) = application(f, entries)? {
            return Ok(reference);
        }
        Ok(match f.view().graph_node() {
            Node::Not(body) => DefinedFormula::negate(defined(&body.to_owned(), entries)?),
            Node::Implies(a, b) => DefinedFormula::implies(
                defined(&a.to_owned(), entries)?,
                defined(&b.to_owned(), entries)?,
            ),
            Node::ForAll(_) => {
                let used = f.free_variables();
                let variable = (0..=u32::MAX)
                    .map(FreeVariable::new)
                    .find(|v| !used.contains(v))
                    .ok_or("definition binder space")?;
                let body = f
                    .open_outer_universal(variable)
                    .ok_or("definition binder")?;
                DefinedFormula::for_all(variable, defined(&body, entries)?)
            }
            _ => DefinedFormula::from_primitive(f).map_err(|error| error.to_string())?,
        })
    }
    naome_proof::ProofFormula::from_defined(defined(formula, entries)?)
        .map_err(|error| error.to_string())
}

pub fn discover(target: &Formula) -> Result<Option<Entry>, String> {
    Ok(discover_many(target, 1)?.into_iter().next())
}
/// Conservative proposals are available before construction search starts.
/// The bound and byte budget are shared with the checked definition snapshot.
pub fn discover_many(target: &Formula, maximum: usize) -> Result<Vec<Entry>, String> {
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
    let mut candidates: Vec<_> = counts.into_values().filter(|(_, n)| *n >= 2).collect();
    let gain = |(body, count): &(Formula, usize)| {
        let nodes = body.view().node_count_and_depth().0;
        count
            .saturating_mul(nodes.saturating_sub(body.free_variables().len() + 1))
            .saturating_sub(nodes)
    };
    candidates.sort_by(|a, b| {
        gain(b).cmp(&gain(a)).then_with(|| {
            b.0.encode_canonical()
                .unwrap()
                .cmp(&a.0.encode_canonical().unwrap())
        })
    });
    let mut entries = Vec::new();
    let mut bytes = 0;
    for (body, count) in candidates {
        if entries.len() >= maximum.min(CAPACITY) {
            break;
        }
        let nodes = body.view().node_count_and_depth().0;
        let arity = body.free_variables().len();
        if count.saturating_mul(nodes.saturating_sub(arity + 1)) <= nodes {
            continue;
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
        if bytes + entry.bytes() > BYTES {
            continue;
        }
        let _ = context(std::slice::from_ref(&entry))?;
        bytes += entry.bytes();
        entries.push(entry);
    }
    Ok(entries)
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
                    replacement: None,
                    consequences: vec![e.body()?],
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}
pub fn choices(
    target: &Formula,
    known: &[Entry],
    available_only: bool,
) -> Result<Vec<Entry>, String> {
    let fragments = super::knowledge::fragments(target);
    let mut ranked = Vec::new();
    for (i, entry) in known.iter().enumerate() {
        let score = super::knowledge::fragments(&entry.body()?)
            .intersection(&fragments)
            .map(Vec::len)
            .sum::<usize>();
        if score > 0 {
            ranked.push((score, i, entry));
        }
    }
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut entries = ranked
        .into_iter()
        .take(CAPACITY - 1)
        .map(|(_, _, entry)| entry.clone())
        .collect::<Vec<_>>();
    if !available_only
        && let Some(proposed) = discover(target)?
        && !entries.contains(&proposed)
        && entries.iter().map(Entry::bytes).sum::<usize>() + proposed.bytes() <= BYTES
    {
        entries.push(proposed);
    }
    Ok(entries)
}
pub fn construction_choices(target: &Formula, known: &[Entry]) -> Result<Vec<Entry>, String> {
    let mut entries = choices(target, known, false)?;
    for entry in discover_many(target, CAPACITY)? {
        if !entries.contains(&entry)
            && entries.len() < CAPACITY
            && entries.iter().map(Entry::bytes).sum::<usize>() + entry.bytes() <= BYTES
        {
            entries.push(entry);
        }
    }
    Ok(entries)
}
pub fn choose(
    target: &Formula,
    known: &[Entry],
    available_only: bool,
    ranker: &mut dyn Ranker,
) -> Result<Option<(Vec<Entry>, usize)>, String> {
    let entries = choices(target, known, available_only)?;
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

pub fn helpers(tree: &super::search::Tree) -> Result<Vec<String>, crate::Error> {
    if let super::search::Tree::Scoped { target, actions } = tree {
        return Ok(super::knowledge::helpers(&super::search::scope::verified(
            target, actions,
        )?)?);
    }
    if matches!(tree, super::search::Tree::Knowledge { .. }) {
        return Ok(super::knowledge::helpers(&super::knowledge::verified(
            tree,
        )?)?);
    }
    if let super::search::Tree::Constructed { packet: bytes, .. }
    | super::search::Tree::Composed { packet: bytes, .. }
    | super::search::Tree::Certificate(bytes) = tree
    {
        return super::evidence::helpers(bytes);
    }
    let super::search::Tree::Definitions {
        entries,
        selected,
        available,
        proof,
    } = tree
    else {
        return Ok(Vec::new());
    };
    let entry = entries
        .get(*selected)
        .ok_or(crate::ResearchFailure::DefinitionSelectionIndex)?;
    entries
        .get(..*available)
        .ok_or(crate::ResearchFailure::DefinitionAvailability)?;
    let mut sources = helpers(proof)?;
    append_artifacts(std::slice::from_ref(entry), &mut sources)?;
    Ok(sources)
}

pub fn selected(tree: &super::search::Tree) -> Result<Vec<Entry>, crate::Error> {
    match tree {
        super::search::Tree::Knowledge { .. } => Ok(super::knowledge::verified(tree)?.definitions),
        super::search::Tree::Constructed { packet, .. }
        | super::search::Tree::Composed { packet, .. } => super::evidence::selected(packet),
        super::search::Tree::Definitions {
            entries,
            selected: index,
            proof,
            ..
        } => {
            let mut selected_entries = selected(proof)?;
            let entry = entries
                .get(*index)
                .ok_or(crate::ResearchFailure::DefinitionSelectionIndex)?;
            if !selected_entries.contains(entry) {
                selected_entries.push(entry.clone());
            }
            Ok(selected_entries)
        }
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
        let naome_proof::ArtifactPayload::Definition(definition) =
            naome_proof::ArtifactPayload::from_canonical_bytes(&crate::unhex(source).unwrap())
                .unwrap()
        else {
            panic!("definition")
        };
        Entry {
            certificate: definition.canonical_bytes().to_vec(),
            obligation: None,
        }
    }
    #[test]
    fn invalid_definition_and_obligation_retain_structured_diagnostics() {
        let invalid = Entry {
            certificate: vec![255],
            obligation: None,
        };
        let error = context(&[invalid]).err().unwrap();
        assert!(matches!(error, crate::Error::CertificateFormat(ref value)
        if matches!(value.reason, crate::FormatFailure::UnknownTag {
            domain: crate::FormatTagClass::DefinitionKind, tag: 255
        })));

        let mut invalid_witness = entry("0100000000010000000b0000000000000000000000");
        let certificate = ProofCertificate::new(vec![naome_proof::ProofStep::ProofReference {
            proof_id: naome_proof::ProofId::from_bytes([7; 32]),
        }])
        .unwrap();
        invalid_witness.obligation = Some(certificate.to_canonical_bytes());
        let error = context(&[invalid_witness]).err().unwrap();
        assert!(error.diagnostic().is_some());
    }

    #[test]
    fn discovered_definitions_are_atomic_references_and_reused_after_restart() {
        let q = naome_checker::question::ResearchQuestion::from_hex(
            "040403020301010000000101000000000202030101000000000100000001020001000000010100000001020301010000000101000000000202030101000000000100000001020001000000010100000001",
        ).unwrap();
        let proposed = discover(q.proved_target())
            .unwrap()
            .expect("repeated relation");
        let known = entry("0100000000010000000b0000000000000000000000");
        struct Ordered;
        impl Ranker for Ordered {
            fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, crate::Error> {
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
        let error = proof::source_with_definitions(&checked, &[]).unwrap_err();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::ResearchFailure::ProofReferenceReplacement)
        );
        let source = proof::source(&checked).unwrap();
        let helper_sources = helpers(&wrapped).unwrap();
        let directory = crate::checkpoint::tests::Directory::new();
        let mut graph = crate::Graph::open(&directory.0).unwrap();
        graph.produce(&known.artifact().unwrap()).unwrap();
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
        let q2 = naome_checker::question::ResearchQuestion::from_hex(
            "04040302030101000000010100000000020203010100000000010000000102000100000001010000000103020203010100000001010000000002020301010000000001000000010200010000000101000000010001000000000100000000",
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
            .produce("0100000000010000000d04020101000000000000000000")
            .unwrap();
        let (successor, _) = graph
            .produce("0100000000020000004c04020303010100000000000000000103020101000000000000000000000100000000000000000002030302010100000000000000000000010000000000000000000101000000000000000001")
            .unwrap();
        let empty_id = empty.definition_id().unwrap().unwrap();
        let successor_id = successor.definition_id().unwrap().unwrap();
        let (argument, first, second, third) = (
            FreeVariable::new(0),
            FreeVariable::new(1),
            FreeVariable::new(2),
            FreeVariable::new(3),
        );
        let inductive = DefinedFormula::conjunction(
            DefinedFormula::exists(
                first,
                DefinedFormula::conjunction(
                    DefinedFormula::defined_relation(empty_id, [first]),
                    DefinedFormula::member(first, argument),
                ),
            ),
            DefinedFormula::for_all(
                second,
                DefinedFormula::implies(
                    DefinedFormula::member(second, argument),
                    DefinedFormula::exists(
                        third,
                        DefinedFormula::conjunction(
                            DefinedFormula::defined_relation(successor_id, [second, third]),
                            DefinedFormula::member(third, argument),
                        ),
                    ),
                ),
            ),
        );
        let mut checked = ArtifactState::new();
        for object in [&empty, &successor] {
            let raw = crate::unhex(&object.payload).unwrap();
            let naome_proof::ArtifactPayload::Definition(certificate) =
                naome_proof::ArtifactPayload::from_canonical_bytes(&raw).unwrap()
            else {
                panic!("checked definition artifact");
            };
            let definition =
                naome_checker::check_definition_with_state(certificate, &checked).unwrap();
            checked.register_definition(definition).unwrap();
        }
        let inductive =
            DefinedFormula::from_primitive(&inductive.expand_with(&checked).unwrap()).unwrap();
        let inductive = DefinitionCertificate::relation(1, inductive).unwrap();
        checked
            .register_definition(
                naome_checker::check_definition_with_state(inductive.clone(), &checked).unwrap(),
            )
            .unwrap();
        graph
            .produce(&crate::test_inputs::definition(&inductive))
            .unwrap();
        let natural = DefinedFormula::for_all(
            first,
            DefinedFormula::implies(
                DefinedFormula::defined_relation(inductive.definition_id(), [first]),
                DefinedFormula::member(argument, first),
            ),
        );
        let natural =
            DefinedFormula::from_primitive(&natural.expand_with(&checked).unwrap()).unwrap();
        let natural = DefinitionCertificate::relation(1, natural).unwrap();
        let (natural, _) = graph
            .produce(&crate::test_inputs::definition(&natural))
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
        let known = entry("010000000002000000170301000000000000000000010100000000010000000000");
        let x = FreeVariable::new(9);
        let y = FreeVariable::new(2);
        let f = Formula::implies(Formula::member(x, y), Formula::member(y, x));
        assert_eq!(
            application(&f, std::slice::from_ref(&known)).unwrap(),
            Some(DefinedFormula::defined_relation(
                known.certificate().unwrap().definition_id(),
                [x, y]
            ))
        );
        let aliased = Formula::implies(Formula::member(x, x), Formula::member(x, y));
        assert!(application(&aliased, &[known]).unwrap().is_none());
    }
}
