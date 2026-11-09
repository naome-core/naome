//! Repair checked construction output before it crosses the packet boundary.
mod partition;

use super::super::{definitions, evidence, knowledge, proof};
use super::selection::Selection;
use naome_checker::{ArtifactState, CheckedProof};
use naome_proof::{ProofCertificate, ProofId, ProofStep};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub(super) struct Budget {
    started: Instant,
    limit: usize,
    spent: usize,
}

impl Budget {
    pub(super) fn new(started: Instant, remaining: usize) -> Self {
        Self {
            started,
            limit: remaining.min(32),
            spent: 0,
        }
    }

    pub(super) fn spent(&self) -> usize {
        self.spent
    }

    fn check_time(&self) -> Result<(), String> {
        if self.started.elapsed() >= Duration::from_millis(2500) {
            return Err("construction repair deadline".into());
        }
        Ok(())
    }

    fn charge(&mut self, work: usize) -> Result<(), String> {
        self.check_time()?;
        if work > self.limit - self.spent {
            return Err("construction repair work allowance".into());
        }
        self.spent += work;
        Ok(())
    }
}

pub(super) fn portable_packet(
    original: &proof::Verified,
    selection: Option<&Selection>,
    budget: &mut Budget,
) -> Result<Vec<u8>, String> {
    let limits = crate::resources::limits();
    // Rechecking the closure is part of the original construction allowance.
    budget.charge(1)?;
    let protected = selection
        .map(|selection| knowledge::proof_ids(&selection.known))
        .transpose()?
        .unwrap_or_default();
    if protected.contains(&original.native_id) {
        return Err("construction repair would replace a supplied proof".into());
    }
    let mut original_context = definitions::context(&original.definitions)?;
    let mut repaired_context = original_context.clone();
    let mut replacements = BTreeMap::new();
    let mut lemmas = Vec::new();
    for lemma in &original.lemmas {
        budget.charge(1)?;
        let checked = proof::check(lemma.clone(), &original_context).map_err(|e| e.to_string())?;
        let id = checked.proof_id();
        let target = checked.conclusion().clone();
        original_context
            .register_proof(checked)
            .map_err(|e| e.to_string())?;

        let repaired = rewrite(lemma, &replacements, &repaired_context)?;
        if repaired.conclusion() != &target {
            return Err("construction repair changed a helper conclusion".into());
        }
        let repaired = partition::fit(
            repaired,
            &original.definitions,
            &mut repaired_context,
            &mut lemmas,
            budget,
        )?;
        if repaired.proof_id() != id && protected.contains(&id) {
            return Err("construction repair would replace a supplied helper".into());
        }
        replacements.insert(id, repaired.proof_id());
        partition::append(repaired, &mut repaired_context, &mut lemmas)?;
    }

    budget.charge(1)?;
    let root = rewrite(&original.certificate, &replacements, &repaired_context)?;
    if root.conclusion() != &original.target {
        return Err("construction repair changed the root conclusion".into());
    }
    let root = partition::fit(
        root,
        &original.definitions,
        &mut repaired_context,
        &mut lemmas,
        budget,
    )?;
    budget.charge(1)?;
    let verified = proof::verify_native(
        root.normal_form().certificate().clone(),
        original.definitions.clone(),
        lemmas,
        Some(&original.target),
    )?;
    let packet = evidence::pack(&verified)?;
    let source = proof::source(&verified);
    let helpers = evidence::helpers(&packet)?;
    if source.len() > 2 * limits.proof_bytes
        || helpers.len() >= limits.closure_objects
        || helpers
            .iter()
            .any(|helper| helper.len() > 2 * limits.proof_bytes)
        || source.len() + helpers.iter().map(String::len).sum::<usize>() > 2 * limits.closure_bytes
    {
        return Err("repaired construction source closure exceeds capacity".into());
    }
    budget.check_time()?;
    Ok(packet)
}

fn rewrite(
    certificate: &ProofCertificate,
    replacements: &BTreeMap<ProofId, ProofId>,
    context: &ArtifactState,
) -> Result<CheckedProof, String> {
    let mut steps = certificate.steps().to_vec();
    for step in &mut steps {
        if let ProofStep::ProofReference { proof_id } = step {
            *proof_id = *replacements
                .get(proof_id)
                .ok_or("construction repair dependency order")?;
        }
    }
    let certificate = ProofCertificate::new(steps).map_err(|e| e.to_string())?;
    proof::check(certificate, context).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning::{Solution, construction::pack_candidate, search::Tree};
    use naome_foundation::{Formula, FreeVariable};

    fn oversized_derivation() -> proof::Verified {
        let free = FreeVariable::new(7);
        let equality = Formula::equal(free, free);
        let antecedent = Formula::for_all(free, equality.clone());
        let mut target = equality;
        let mut steps = vec![ProofStep::EqualityReflexivity { variable: free }];
        let limit = crate::resources::limits().proof_bytes;
        for _ in 0..256 {
            let premise = (steps.len() - 1) as u32;
            steps.push(ProofStep::Simplification {
                antecedent: target.clone().into(),
                consequent: antecedent.clone().into(),
            });
            steps.push(ProofStep::ModusPonens {
                premise,
                implication: premise + 1,
            });
            target = Formula::implies(antecedent.clone(), target);
            let mut closed = steps.clone();
            closed.push(ProofStep::Generalization {
                premise: (steps.len() - 1) as u32,
                variable: free,
            });
            let certificate = ProofCertificate::new(closed).unwrap();
            if certificate.to_canonical_bytes().len() > limit {
                let expected = Formula::for_all(free, target);
                let verified =
                    proof::verify_native(certificate, vec![], vec![], Some(&expected)).unwrap();
                assert!(verified.payload_bytes > limit);
                return verified;
            }
        }
        panic!("fixture never reached the current proof limit")
    }

    fn check_packet(original: &proof::Verified) -> proof::Verified {
        assert!(evidence::pack(original).is_err());
        let mut exhausted = 1;
        assert!(pack_candidate(original, None, Instant::now(), &mut exhausted).is_err());
        assert_eq!(exhausted, 0);

        let mut remaining = 128;
        let packet = pack_candidate(original, None, Instant::now(), &mut remaining).unwrap();
        assert!((96..128).contains(&remaining));
        let verified = evidence::checked(&packet).unwrap();
        assert_eq!(verified.target, original.target);
        assert_ne!(verified.native_id, original.native_id);
        assert!(!verified.lemmas.is_empty());
        let after_repair = remaining;
        let unchanged = pack_candidate(&verified, None, Instant::now(), &mut remaining).unwrap();
        assert_eq!(unchanged, packet);
        assert_eq!(remaining, after_repair);

        let solution = Solution {
            source: proof::source(&verified),
            helpers: evidence::helpers(&packet).unwrap(),
            proof_id: crate::hex(verified.native_id.as_bytes()),
            cost: Box::default(),
            refuted: false,
            tree: Tree::Constructed {
                packet,
                selection: None,
            },
        };
        assert_eq!(solution.checked().unwrap().proof_id(), verified.native_id);
        verified
    }

    #[test]
    fn partitions_an_oversized_root_with_an_open_intermediate_conclusion() {
        check_packet(&oversized_derivation());
    }

    #[test]
    fn partitions_an_oversized_helper_and_rewrites_its_citation() {
        let helper = oversized_derivation();
        let root = ProofCertificate::new(vec![ProofStep::ProofReference {
            proof_id: helper.native_id,
        }])
        .unwrap();
        let original =
            proof::verify_native(root, vec![], vec![helper.certificate], Some(&helper.target))
                .unwrap();
        let verified = check_packet(&original);
        assert!(verified.lemmas.len() > original.lemmas.len());
        assert!(
            matches!(verified.certificate.steps(), [ProofStep::ProofReference { proof_id }] if *proof_id != helper.native_id)
        );
    }
}
