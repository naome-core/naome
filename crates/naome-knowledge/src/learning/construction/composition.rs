//! Bounded AND/OR reconstruction from exact, independently checked inputs.
use super::{logic, proof};
use naome_foundation::Formula;
use std::{collections::BTreeSet, time::Instant};

pub fn used(verified: &proof::Verified, inputs: &[String]) -> Result<Vec<String>, String> {
    let context = proof::lemma_context(&verified.definitions, &verified.lemmas)?;
    let mut ids = context
        .proof_conclusions()
        .map(|(id, _, _, _)| crate::hex(id.as_bytes()))
        .collect::<BTreeSet<_>>();
    ids.insert(crate::hex(verified.native_id.as_bytes()));
    Ok(inputs
        .iter()
        .filter(|id| ids.contains(*id))
        .cloned()
        .collect())
}
pub fn validate(packet: &[u8], inputs: &[String], work: usize) -> Result<(), String> {
    if inputs.is_empty()
        || inputs.len() > super::super::knowledge::CAPACITY
        || inputs.iter().collect::<BTreeSet<_>>().len() != inputs.len()
        || work == 0
        || work > 16
    {
        return Err("composition trace capacity".into());
    }
    let verified = super::super::evidence::checked(packet)?;
    if used(&verified, inputs)? != inputs {
        return Err("composition input binding differs".into());
    }
    let mut state = super::super::definitions::context(&verified.definitions)?;
    let mut preceding = Vec::new();
    let mut available = std::collections::BTreeMap::new();
    for certificate in verified
        .lemmas
        .iter()
        .chain(std::iter::once(&verified.certificate))
    {
        let checked = proof::check(certificate.clone(), &state).map_err(|e| e.to_string())?;
        let id = crate::hex(checked.proof_id().as_bytes());
        if inputs.contains(&id) {
            available.insert(
                id,
                proof::Term::Native {
                    certificate: certificate.clone(),
                    lemmas: preceding.clone(),
                    definitions: verified.definitions.clone(),
                    target: checked.conclusion().clone(),
                },
            );
        }
        preceding.push(certificate.clone());
        if !state.contains_proof(checked.proof_id()) {
            state.register_proof(checked).map_err(|e| e.to_string())?;
        }
    }
    let terms = inputs
        .iter()
        .map(|id| {
            available
                .remove(id)
                .ok_or("composition checked input missing")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (replayed, replay_work) = construct(&verified.target, &terms, work, Instant::now())?;
    if replay_work > work || replayed.is_none_or(|p| p.native_id != verified.native_id) {
        return Err(format!(
            "composition reconstruction differs at work {replay_work}/{work}"
        ));
    }
    Ok(())
}

/// Reuse only an actual checker-issued positive certificate for an internal
/// obligation. This neither registers a research question nor changes intake.
fn deductions(
    target: &Formula,
    terms: &mut Vec<proof::Term>,
    maximum: usize,
    started: Instant,
) -> Result<usize, String> {
    fn missing(target: &Formula, terms: &[proof::Term], depth: usize, output: &mut Vec<Formula>) {
        if depth >= 2 {
            return;
        }
        if let Some((a, b)) = logic::conjunction(target) {
            for part in [a, b] {
                if !terms.iter().any(|t| t.formula() == part) {
                    let closed = proof::close(part.clone());
                    if !output.contains(&closed) {
                        output.push(closed);
                    }
                    missing(&part, terms, depth + 1, output);
                }
            }
        }
    }
    let mut pending = Vec::new();
    missing(target, terms, 0, &mut pending);
    if pending.is_empty() {
        return Ok(0);
    }
    let mut definitions = Vec::new();
    let mut lemmas = Vec::new();
    for term in terms.iter() {
        // Pruning here keeps replay independent of unrelated packet members.
        let checked = proof::verify(term, &term.formula())?;
        for entry in checked.definitions {
            if !definitions.contains(&entry) {
                definitions.push(entry);
            }
        }
        for certificate in checked
            .lemmas
            .into_iter()
            .chain(std::iter::once(checked.certificate))
        {
            if !lemmas.contains(&certificate) {
                lemmas.push(certificate);
            }
        }
    }
    let mut state = proof::lemma_context(&definitions, &lemmas)?;
    let limits = crate::resources::limits();
    let mut bytes = definitions
        .iter()
        .map(super::super::definitions::Entry::bytes)
        .sum::<usize>()
        + lemmas
            .iter()
            .map(|c| c.to_canonical_bytes().len())
            .sum::<usize>();
    let mut steps = lemmas.iter().map(|c| c.steps().len()).sum::<usize>();
    let registry = naome_checker::question::QuestionRegistry::new();
    let mut work = 0;
    let mut generated_objects = 0;
    for part in pending {
        if work >= maximum
            || started.elapsed() > std::time::Duration::from_millis(2500)
            || lemmas.len() + definitions.len() + generated_objects + 1 >= limits.closure_objects
        {
            break;
        }
        let Ok(question) = naome_authoring::CompiledQuestion::from_formula(part.clone()) else {
            continue;
        };
        work += 1;
        let Ok(request) = naome_checker::question::AssessmentQuestion::new(
            naome_foundation::FOUNDATION_ID,
            question.formula(),
            question.source().as_bytes(),
            &[],
            None,
        ) else {
            continue;
        };
        let snapshot =
            naome_checker::question::KnowledgeSnapshot::new(state.snapshot_id(), &state, &registry);
        let decision =
            naome_checker::question::assess_question(&request, &snapshot, &Default::default());
        if !decision.has_answer() {
            // Interest simplification is not a proof. A small deterministic
            // tableau may discharge such a clause; its expansions consume this
            // same allowance, leaving room for the final conjunction assembly.
            let (derived, spent) = primitive(&part, maximum.saturating_sub(work + 3), started)?;
            work += spent;
            if let Some(derived) = derived {
                let objects = 1 + derived.lemmas.len() + derived.definitions.len();
                let added_bytes = derived.certificate.to_canonical_bytes().len()
                    + derived
                        .lemmas
                        .iter()
                        .map(|c| c.to_canonical_bytes().len())
                        .sum::<usize>()
                    + derived
                        .definitions
                        .iter()
                        .map(super::super::definitions::Entry::bytes)
                        .sum::<usize>();
                let added_steps = derived.certificate.steps().len()
                    + derived
                        .lemmas
                        .iter()
                        .map(|c| c.steps().len())
                        .sum::<usize>();
                if lemmas.len() + definitions.len() + generated_objects + objects
                    < limits.closure_objects
                    && bytes.saturating_add(added_bytes) <= limits.closure_bytes
                    && steps.saturating_add(added_steps) <= limits.closure_steps
                {
                    terms.push(proof::Term::Native {
                        certificate: derived.certificate,
                        lemmas: derived.lemmas,
                        definitions: derived.definitions,
                        target: derived.target,
                    });
                    generated_objects += objects;
                    bytes += added_bytes;
                    steps += added_steps;
                }
            }
            continue;
        }
        let Some(witness) = decision.deduction else {
            continue;
        };
        if witness.canonical_certificate().len() > limits.proof_bytes {
            continue;
        }
        if witness
            .original_proofs()
            .iter()
            .any(|id| !state.contains_proof(*id))
        {
            return Err("temporary deduction original source missing".into());
        }
        let certificate =
            naome_proof::ProofCertificate::from_canonical_bytes(witness.canonical_certificate())
                .map_err(|e| e.to_string())?;
        let checked = proof::check(certificate, &state).map_err(|e| e.to_string())?;
        if checked.proof_id() != witness.proof_id() {
            return Err("temporary deduction identity differs".into());
        }
        // An answered obligation can be refuted; only its exact positive
        // conclusion supplies this requested conjunction prerequisite.
        if checked.conclusion() != &part {
            continue;
        }
        let certificate = checked.normal_form().certificate().clone();
        let next_bytes = bytes.saturating_add(checked.normal_form().canonical_bytes().len());
        let next_steps = steps.saturating_add(certificate.steps().len());
        if next_bytes > limits.closure_bytes || next_steps > limits.closure_steps {
            continue;
        }
        terms.push(proof::Term::Native {
            certificate: certificate.clone(),
            lemmas: lemmas.clone(),
            definitions: definitions.clone(),
            target: part,
        });
        if !state.contains_proof(checked.proof_id()) {
            state.register_proof(checked).map_err(|e| e.to_string())?;
            lemmas.push(certificate);
            bytes = next_bytes;
            steps = next_steps;
        }
    }
    Ok(work)
}
fn primitive(
    target: &Formula,
    maximum: usize,
    started: Instant,
) -> Result<(Option<proof::Verified>, usize), String> {
    if maximum == 0 {
        return Ok((None, 0));
    }
    struct Ordered;
    impl super::super::model::Ranker for Ordered {
        fn scores(&mut self, decision: &super::super::model::Decision) -> Result<Vec<f32>, String> {
            Ok(vec![0.; decision.candidates.len()])
        }
    }
    let result =
        super::super::search::solve_with_knowledge(target, &mut Ordered, maximum, started, &[])?;
    let verified = result
        .tree
        .map(|tree| {
            super::super::search::core::checked(target, &tree).map(|(_, _, verified)| verified)
        })
        .transpose()?;
    Ok((verified, result.expansions))
}
pub fn construct(
    target: &Formula,
    context: &[proof::Term],
    maximum: usize,
    started: Instant,
) -> Result<(Option<proof::Verified>, usize), String> {
    let maximum = maximum.min(16);
    let mut context = context.to_vec();
    let deduction_work = deductions(target, &mut context, maximum, started)?;
    let mut search = logic::Search::new(maximum.saturating_sub(deduction_work), started);
    let term = search.prove(target, &context)?;
    let proof = term.map(|term| proof::verify(&term, target)).transpose()?;
    Ok((proof, deduction_work + search.work))
}
