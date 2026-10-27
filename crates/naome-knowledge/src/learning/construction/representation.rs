//! Checked, conservative meaning references compress constructed derivations.
use super::super::{definitions, proof};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use std::collections::{BTreeMap, BTreeSet};

pub fn apply(
    mut original: proof::Verified,
    entries: &[definitions::Entry],
    protected: &BTreeSet<ProofId>,
) -> Result<proof::Verified, String> {
    if entries.is_empty() || protected.contains(&original.native_id) {
        return Ok(original);
    }
    let mut context = definitions::context(entries)?;
    let mut primitive = naome_checker::ArtifactState::new();
    let mut identities = BTreeMap::<ProofId, ProofId>::new();
    let mut lemmas = Vec::new();
    let mut used = BTreeSet::new();
    for (position, certificate) in original
        .lemmas
        .iter()
        .chain(std::iter::once(&original.certificate))
        .enumerate()
    {
        let old = crate::learning::proof::check(certificate.clone(), &primitive)
            .map_err(|e| e.to_string())?;
        let target = old.conclusion().clone();
        let old_id = old.proof_id();
        if protected.contains(&old_id) {
            let certificate = old.normal_form().certificate().clone();
            primitive.register_proof(old).map_err(|e| e.to_string())?;
            let checked = proof::check(certificate.clone(), &context).map_err(|e| e.to_string())?;
            context.register_proof(checked).map_err(|e| e.to_string())?;
            identities.insert(old_id, old_id);
            lemmas.push(certificate);
            continue;
        }
        primitive.register_proof(old).map_err(|e| e.to_string())?;
        let steps = certificate
            .steps()
            .iter()
            .map(|step| match step {
                ProofStep::ProofReference { proof_id } => Ok(ProofStep::ProofReference {
                    proof_id: *identities
                        .get(proof_id)
                        .ok_or("construction lemma dependency order")?,
                }),
                _ => Ok(step.clone()),
            })
            .collect::<Result<Vec<_>, String>>()?;
        let candidate = proof::Verified {
            certificate: ProofCertificate::new(steps).map_err(|e| e.to_string())?,
            target,
            native_id: old_id,
            payload_bytes: 0,
            lemmas: lemmas.clone(),
            definitions: Vec::new(),
        };
        let source = proof::source_with_definitions(&candidate, entries)?;
        let checked = naome_authoring::compile_against_proof_context(&source, &context)
            .map_err(|e| e.to_string())?
            .into_checked_proof();
        if checked.conclusion() != &candidate.target {
            return Err("construction meaning rewrite changed the claim".into());
        }
        identities.insert(old_id, checked.proof_id());
        used.extend(checked.direct_artifact_dependencies().iter().copied());
        if position == original.lemmas.len() {
            original.certificate = checked.normal_form().certificate().clone();
            original.native_id = checked.proof_id();
            original.payload_bytes = checked.normal_form().canonical_bytes().len();
            original.definitions = entries
                .iter()
                .filter(|e| e.address().is_ok_and(|id| used.contains(&id)))
                .cloned()
                .collect();
            original.lemmas = lemmas;
            return Ok(original);
        }
        lemmas.push(checked.normal_form().certificate().clone());
        context.register_proof(checked).map_err(|e| e.to_string())?;
    }
    Err("missing construction root".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::{
        calculus, knowledge,
        model::{Decision, Ranker},
        search,
    };
    use naome_foundation::{Formula, FreeVariable};
    struct Ordered;
    impl Ranker for Ordered {
        fn scores(&mut self, d: &Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; d.candidates.len()])
        }
    }
    #[test]
    fn new_meanings_rewrite_only_generated_proofs_and_preserve_existing_lemma_identity() {
        let original = crate::learning::tests::own_solution();
        let q = naome_authoring::CompiledQuestion::compile(&crate::learning::tests::own_question())
            .unwrap();
        let known = search::core::checked(q.proved_target(), &original.tree)
            .unwrap()
            .2;
        let entry = knowledge::Entry {
            packet: crate::learning::evidence::pack(&known).unwrap(),
        };
        let naome_authoring::CompiledArtifact::Definition(d) =
            naome_authoring::compile_artifact("def equality=relation(x,y): eq(x,y)").unwrap()
        else {
            panic!("definition")
        };
        let meaning = definitions::Entry {
            certificate: d.canonical_definition_bytes().to_vec(),
            obligation: None,
        };
        let x = FreeVariable::new(40);
        let y = FreeVariable::new(41);
        let target = Formula::for_all(
            x,
            Formula::for_all(
                y,
                Formula::implies(Formula::member(x, y), q.proved_target().clone()),
            ),
        );
        let (found, _, selection) = super::super::construct_with(
            &target,
            128,
            std::time::Instant::now(),
            &mut Ordered,
            std::slice::from_ref(&entry),
            std::slice::from_ref(&meaning),
        )
        .unwrap();
        let found = found.expect("known closed lemma applies to a new conditional target");
        let context = proof::lemma_context(&found.definitions, &found.lemmas).unwrap();
        assert!(
            found
                .lemmas
                .iter()
                .any(|c| proof::check(c.clone(), &context).unwrap().proof_id() == known.native_id)
        );
        assert!(found.lemmas.iter().chain(std::iter::once(&found.certificate)).flat_map(|c|c.steps()).any(|s|matches!(s,ProofStep::ProofReference{proof_id} if *proof_id==known.native_id)));
        assert!(
            super::super::selection::graph(&target, &selection.unwrap(), &found)
                .unwrap()
                .is_none(),
            "one available plan has no ambiguous selection label"
        );
        let text = proof::source(&found).unwrap();
        assert_eq!(
            naome_authoring::compile_against_proof_context(&text, &context)
                .unwrap()
                .proof_id(),
            found.native_id
        );
    }
    #[test]
    fn a_lemma_application_plan_cannot_succeed_without_using_its_selected_source() {
        let term =
            calculus::axiom(ProofStep::ZfcAxiom(naome_foundation::ZfcAxiom::Pairing)).unwrap();
        let known = proof::verify(&term, &term.formula()).unwrap();
        let entry = knowledge::Entry {
            packet: crate::learning::evidence::pack(&known).unwrap(),
        };
        let x = FreeVariable::new(0);
        let p = Formula::member(x, x);
        let target = Formula::for_all(x, Formula::implies(p.clone(), p));
        let (found, work, _) = super::super::construct_with(
            &target,
            32,
            std::time::Instant::now(),
            &mut Ordered,
            &[entry],
            &[],
        )
        .unwrap();
        assert!(found.is_none());
        assert!(
            work > 0,
            "a valid independent proof is not a checked use of this source"
        );
    }
}
