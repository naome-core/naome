//! Bounded checked theorem snapshots. The canonical graph remains the owner.
use super::{evidence, proof, search::Tree};
use naome_foundation::{Formula, graph::Node};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CAPACITY: usize = 8;
pub const BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    #[serde(with = "packet")]
    pub packet: Vec<u8>,
}
// Snapshot JSON is metered against the existing State byte bound. Encoding
// the already bounded native packet directly avoids decimal-array overhead
// evicting the diverse replay needed to start training. Raw proof bytes and
// the independent native admission/checking boundary remain unchanged.
mod packet {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        crate::hex(bytes).serialize(serializer)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > 2 * super::BYTES {
            return Err(serde::de::Error::custom("theorem snapshot capacity"));
        }
        crate::object::unhex(&value).map_err(serde::de::Error::custom)
    }
}
impl Entry {
    pub fn verified(&self) -> Result<proof::Verified, String> {
        if self.packet.len() > BYTES {
            return Err("theorem snapshot capacity".into());
        }
        let verified = evidence::checked(&self.packet)?;
        if !verified.target.free_variables().is_empty() {
            return Err("theorem is not closed".into());
        }
        Ok(verified)
    }
    pub fn term(&self) -> Result<proof::Term, String> {
        let verified = self.verified()?;
        Ok(proof::Term::Native {
            certificate: verified.certificate,
            lemmas: verified.lemmas,
            definitions: verified.definitions,
            target: verified.target,
        })
    }
}

/// Primitive structure is visible; object addresses and corpus tags are not.
pub fn fragments(formula: &Formula) -> BTreeSet<Vec<u8>> {
    fn visit(f: &Formula, output: &mut BTreeSet<Vec<u8>>, work: &mut usize) {
        *work += 1;
        if *work > 2048 {
            return;
        }
        let mut variables = std::collections::BTreeMap::new();
        let canonical = f.clone().map_free_variables(|v| {
            let next = naome_foundation::FreeVariable::new(variables.len() as u32);
            *variables.entry(v).or_insert(next)
        });
        if let Ok(bytes) = canonical.encode_canonical() {
            output.insert(bytes);
        }
        match f.view().graph_node() {
            Node::Not(a) => visit(&a.to_owned(), output, work),
            Node::Implies(a, b) => {
                visit(&a.to_owned(), output, work);
                visit(&b.to_owned(), output, work);
            }
            Node::ForAll(_) => {
                let used = f.free_variables();
                let v = (0..=u32::MAX)
                    .map(naome_foundation::FreeVariable::new)
                    .find(|v| !used.contains(v))
                    .expect("bounded formula variables");
                if let Some(body) = f.open_outer_universal(v) {
                    visit(&body, output, work);
                }
            }
            _ => {}
        }
    }
    let mut output = BTreeSet::new();
    visit(formula, &mut output, &mut 0);
    output
}
pub fn relevance(formula: &Formula, target: &Formula) -> usize {
    let target = fragments(target);
    fragments(formula).intersection(&target).map(Vec::len).sum()
}
pub fn proof_ids(entries: &[Entry]) -> Result<BTreeSet<naome_proof::ProofId>, String> {
    let mut ids = BTreeSet::new();
    for entry in entries {
        let verified = entry.verified()?;
        ids.insert(verified.native_id);
        let context = proof::lemma_context(&verified.definitions, &verified.lemmas)?;
        ids.extend(context.proof_conclusions().map(|(id, _, _, _)| id));
    }
    Ok(ids)
}
pub fn retrieve(target: &Formula, entries: &[Entry]) -> Result<Vec<Entry>, String> {
    let mut ranked = Vec::new();
    let mut bytes = 0;
    let requested = fragments(target);
    for entry in entries {
        let verified = entry.verified()?;
        // Shared atoms alone do not establish a useful proof prerequisite.
        // Require the actual closed statement, or a complete non-atomic
        // universal body, among the question's structural subgoals.
        let mut statement = verified.target.clone();
        let mut relevant =
            requested.contains(&statement.encode_canonical().map_err(|e| e.to_string())?);
        for index in 0..naome_authoring::QUESTION_TARGET_MAX_DEPTH {
            if relevant {
                break;
            }
            let Some(body) =
                statement.open_outer_universal(naome_foundation::FreeVariable::new(index as u32))
            else {
                break;
            };
            statement = body;
            if matches!(
                statement.view().graph_node(),
                Node::Member(..) | Node::Equal(..)
            ) {
                break;
            }
            let canonical = statement.clone().map_free_variables({
                let mut names = std::collections::BTreeMap::new();
                move |variable| {
                    let next = naome_foundation::FreeVariable::new(names.len() as u32);
                    *names.entry(variable).or_insert(next)
                }
            });
            relevant =
                requested.contains(&canonical.encode_canonical().map_err(|e| e.to_string())?);
        }
        if !relevant {
            continue;
        }
        let score = relevance(&verified.target, target);
        if score > 0 {
            ranked.push((score, verified.native_id, entry));
        }
    }
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut output = Vec::new();
    for (_, _, entry) in ranked {
        if output.len() < CAPACITY && bytes + entry.packet.len() <= BYTES {
            bytes += entry.packet.len();
            output.push(entry.clone());
        }
    }
    Ok(output)
}
pub fn validate(entries: &[Entry]) -> Result<(), String> {
    if entries.len() > CAPACITY || entries.iter().map(|e| e.packet.len()).sum::<usize>() > BYTES {
        return Err("theorem snapshot capacity".into());
    }
    let mut ids = BTreeSet::new();
    for entry in entries {
        if !ids.insert(entry.verified()?.native_id) {
            return Err("duplicate theorem snapshot".into());
        }
    }
    Ok(())
}
pub fn verified(tree: &Tree) -> Result<proof::Verified, String> {
    let Tree::Knowledge { target, .. } = tree else {
        return Err("theorem trace missing".into());
    };
    let target = Formula::decode_canonical(target).map_err(|e| e.to_string())?;
    proof::verify(&super::search::compile(&target, tree)?.0, &target)
}
pub fn helpers(verified: &proof::Verified) -> Result<Vec<String>, String> {
    let mut output = verified
        .definitions
        .iter()
        .map(|e| e.source(&[]))
        .collect::<Result<Vec<_>, _>>()?;
    output.extend(proof::lemma_sources(
        &verified.definitions,
        &verified.lemmas,
    )?);
    Ok(output)
}

pub fn validate_availability(
    target: &Formula,
    tree: &Tree,
    known: &[Entry],
    definitions: &[super::definitions::Entry],
) -> Result<(), String> {
    match tree {
        Tree::Knowledge { entries, proof, .. } => {
            if *entries != retrieve(target, known)? {
                return Err("theorem availability differs from owner snapshot".into());
            }
            validate_availability(target, proof, known, definitions)?;
        }
        Tree::Constructed {
            selection: Some(selection),
            ..
        } => {
            if selection.known != retrieve(target, known)? || selection.definitions != definitions {
                return Err("construction availability differs from owner snapshot".into());
            }
        }
        Tree::Definitions {
            entries,
            available,
            proof,
            ..
        } => {
            if *entries != super::definitions::choices(target, definitions)?
                || *available
                    != entries
                        .iter()
                        .take_while(|entry| definitions.contains(entry))
                        .count()
            {
                return Err("definition availability differs from owner snapshot".into());
            }
            validate_availability(target, proof, known, definitions)?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{
        calculus,
        model::{Decision, Ranker},
        search,
    };
    use super::*;
    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    #[test]
    fn a_checked_library_does_not_starve_diverse_replay_at_the_existing_state_byte_bound() {
        use super::super::{Example, Origin, State};
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fixture {
            provenance: serde_json::Value,
            examples: Vec<Record>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Record {
            question: String,
            proof_id: String,
            refuted: bool,
            tree: Tree,
            source: String,
            helpers: Vec<String>,
        }
        // Resource-boundary coverage must not depend on platform-sensitive
        // floating-point rankings finding the fixture proofs. These original
        // own-search artifacts are independently admitted again below.
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../tests/fixtures/checked-learning-library.json"
        ))
        .unwrap();
        assert_eq!(fixture.provenance["seed"], 2089);
        assert_eq!(fixture.examples.len(), 7);
        let mut examples = fixture.examples;
        let own = super::super::tests::own_solution();
        examples.push(Record {
            question: super::super::tests::own_question() + &" ".repeat(4096),
            proof_id: own.proof_id,
            refuted: own.refuted,
            tree: own.tree,
            source: own.source,
            helpers: own.helpers,
        });
        let mut state = State::fresh();
        let mut graph = crate::Graph::default();
        // A parser-valid longer owner input must not lose the unchanged quorum
        // simply because its already checked knowledge uses verbose JSON.
        let mut frozen_library = Vec::new();
        for (i, record) in examples.into_iter().enumerate() {
            if i == 7 {
                frozen_library = state.knowledge.clone();
            }
            let q = naome_authoring::CompiledQuestion::compile(&record.question).unwrap();
            let (root, batch) = graph
                .prepare_generated(&record.source, &record.helpers, &q)
                .unwrap();
            assert_eq!(
                root,
                crate::object::proof_address(&record.proof_id).unwrap()
            );
            graph
                .commit_batch(
                    root,
                    batch,
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                )
                .unwrap();
            let selected = super::super::definitions::selected(&record.tree).unwrap();
            assert!(
                state
                    .accept(Example {
                        origin: Origin::Local,
                        job: 1 + i as u64,
                        question: record.question,
                        proof_id: record.proof_id,
                        refuted: record.refuted,
                        tree: record.tree
                    })
                    .unwrap()
            );
            if i < 7 {
                assert!(
                    state
                        .remember_theorem(Entry {
                            packet: graph.learning_certificate(root).unwrap().unwrap()
                        })
                        .unwrap()
                );
                for definition in selected {
                    state.remember_definition(definition).unwrap();
                }
            }
        }
        state.validate().unwrap();
        assert_eq!(state.knowledge, frozen_library);
        let raw_bytes = state
            .knowledge
            .iter()
            .map(|e| e.packet.len())
            .sum::<usize>();
        assert!(
            raw_bytes > BYTES * 3 / 4,
            "exercise a nearly full checked byte budget: {raw_bytes}"
        );
        assert_eq!(state.replay.len(), 8);
        assert!(
            state.needs_training(),
            "checked knowledge must coexist with the unchanged diverse training quorum"
        );
        let bytes = crate::checkpoint::encode(&state).unwrap();
        assert!(bytes.len() <= crate::resources::limits().closure_bytes.min(128 * 1024) / 4);
        let restored: State = crate::checkpoint::decode(&bytes).unwrap();
        restored.validate().unwrap();
        assert!(restored.needs_training());
        assert_eq!(restored.knowledge, state.knowledge);
    }
    #[test]
    fn atom_overlap_does_not_offer_an_unrelated_closed_theorem() {
        let axiom = naome_foundation::ZfcAxiom::Infinity;
        let term = super::super::calculus::axiom(naome_proof::ProofStep::ZfcAxiom(axiom)).unwrap();
        let proof = proof::verify(&term, &axiom.formula()).unwrap();
        let entry = Entry {
            packet: evidence::pack(&proof).unwrap(),
        };
        let question = naome_authoring::CompiledQuestion::compile(
            "goal=all(x,all(y,imp(imp(mem(x,y),mem(y,x)),imp(mem(x,y),mem(y,x)))))",
        )
        .unwrap();
        assert!(relevance(&axiom.formula(), question.proved_target()) > 0);
        assert!(
            retrieve(question.proved_target(), std::slice::from_ref(&entry))
                .unwrap()
                .is_empty()
        );
        let offered = retrieve(question.proved_target(), &[entry]).unwrap();
        let before = search::solve(question.proved_target(), &mut Ordered, 32).unwrap();
        let after = search::solve_with_knowledge(
            question.proved_target(),
            &mut Ordered,
            32,
            std::time::Instant::now(),
            &offered,
        )
        .unwrap();
        assert!(before.tree.is_some());
        assert_eq!(
            serde_json::to_value(before.tree).unwrap(),
            serde_json::to_value(after.tree).unwrap()
        );
    }
    #[test]
    fn checked_closed_lemmas_compose_through_native_citations_and_exact_replay() {
        let axiom = naome_foundation::ZfcAxiom::Pairing;
        let term = calculus::axiom(naome_proof::ProofStep::ZfcAxiom(axiom)).unwrap();
        let lemma = proof::verify(&term, &axiom.formula()).unwrap();
        let entry = Entry {
            packet: evidence::pack(&lemma).unwrap(),
        };
        let x = naome_foundation::FreeVariable::new(0);
        let target = Formula::implies(Formula::for_all(x, Formula::equal(x, x)), axiom.formula());
        let q = naome_authoring::CompiledQuestion::from_formula(target.clone()).unwrap();
        assert!(
            search::solve(&target, &mut Ordered, 16)
                .unwrap()
                .tree
                .is_none()
        );
        let found = search::solve_with_knowledge(
            &target,
            &mut Ordered,
            32,
            std::time::Instant::now(),
            std::slice::from_ref(&entry),
        )
        .unwrap();
        let tree = found
            .tree
            .expect("known ZFC lemma must serve a new conditional goal");
        let (_, _, checked) = search::core::checked(&target, &tree).unwrap();
        assert!(
            checked
                .certificate
                .steps()
                .iter()
                .any(|s| matches!(s, naome_proof::ProofStep::ProofReference { .. }))
        );
        assert_eq!(checked.lemmas.len(), 1);
        let graphs = search::compile(&target, &tree).unwrap().1;
        assert!(graphs.iter().any(|g| {
            g.candidates
                .iter()
                .any(|i| g.nodes[*i].kind == super::super::model::Rule::LemmaReference.kind())
        }));
        assert!(validate_availability(&target, &tree, &[], &[]).is_err());
        assert!(validate_availability(&target, &tree, std::slice::from_ref(&entry), &[]).is_ok());
        let naome_authoring::CompiledArtifact::Definition(d) =
            naome_authoring::compile_artifact("def equality=relation(x,y): eq(x,y)").unwrap()
        else {
            panic!("definition")
        };
        let meaning = super::super::definitions::Entry {
            certificate: d.canonical_definition_bytes().to_vec(),
            obligation: None,
        };
        let wrapped = Tree::Definitions {
            entries: vec![meaning],
            selected: 0,
            available: 1,
            proof: Box::new(tree.clone()),
        };
        let (_, _, extended) = super::super::search::core::checked(&target, &wrapped).unwrap();
        let context = proof::lemma_context(&extended.definitions, &extended.lemmas).unwrap();
        assert!(
            extended
                .lemmas
                .iter()
                .any(|c| proof::check(c.clone(), &context).unwrap().proof_id() == lemma.native_id)
        );
        let solution = super::super::Solution {
            source: proof::source(&extended).unwrap(),
            helpers: super::super::definitions::helpers(&wrapped).unwrap(),
            proof_id: crate::hex(extended.native_id.as_bytes()),
            refuted: false,
            tree: wrapped,
            cost: Box::default(),
        };
        assert_eq!(
            crate::hex(solution.checked().unwrap().proof_id().as_bytes()),
            solution.proof_id
        );
        let source = proof::source(&checked).unwrap();
        let helpers = super::super::definitions::helpers(&tree).unwrap();
        let mut graph = crate::Graph::default();
        let (root, batch) = graph.prepare_generated(&source, &helpers, &q).unwrap();
        graph
            .commit_batch(
                root,
                batch,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .unwrap();
        let packet = graph
            .learning_certificate(root)
            .unwrap()
            .expect("modular checked proof snapshot");
        let (_, _) = super::super::peer::compile(&target, &packet).unwrap();
        assert_eq!(
            Entry { packet }.verified().unwrap().native_id,
            checked.native_id
        );
        let mut corrupt = entry;
        corrupt.packet[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(corrupt.verified().is_err());
        let Tree::Knowledge {
            mut target,
            entries,
            proof,
        } = tree
        else {
            panic!("snapshot");
        };
        target[0] ^= 1;
        assert!(
            search::compile(
                q.proved_target(),
                &Tree::Knowledge {
                    target,
                    entries,
                    proof
                }
            )
            .is_err()
        );
    }
}
