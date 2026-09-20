use super::*;
use naome_checker::check_normal_form_with_state;

pub(super) fn bounded_certificate(
    bytes: &[u8],
    profile: &Profile,
) -> Result<ProofCertificate, LedgerError> {
    if bytes.len() > profile.limits().certificate_bytes as usize {
        return Err(LedgerError::Limit("certificate bytes"));
    }
    let certificate = ProofCertificate::from_canonical_bytes(bytes).map_err(math)?;
    if certificate.steps().len() > profile.limits().certificate_steps as usize {
        return Err(LedgerError::Limit("certificate steps"));
    }
    if certificate
        .steps()
        .iter()
        .any(|step| !step.definition_references().is_empty())
    {
        return Err(LedgerError::Invalid(
            "definitions are not published in this MVP",
        ));
    }
    Ok(certificate)
}

pub(super) fn dependencies(certificate: &ProofCertificate) -> Vec<ProofId> {
    certificate
        .steps()
        .iter()
        .filter_map(|step| match step {
            ProofStep::ProofReference { proof_id } => Some(*proof_id),
            _ => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

impl VerificationWork {
    fn check(&mut self, bytes: usize, steps: usize, profile: &Profile) -> Result<(), LedgerError> {
        let mut next = *self;
        next.checker_calls = self
            .checker_calls
            .checked_add(1)
            .ok_or(LedgerError::Overflow)?;
        next.checker_input_bytes = self
            .checker_input_bytes
            .checked_add(bytes as u64)
            .ok_or(LedgerError::Overflow)?;
        next.dag_steps = self
            .dag_steps
            .checked_add(steps as u64)
            .ok_or(LedgerError::Overflow)?;
        let l = profile.limits();
        if next.checker_calls > l.checker_calls_per_record {
            return Err(LedgerError::Limit("checker calls"));
        }
        if next.checker_input_bytes > l.checker_input_bytes_per_record {
            return Err(LedgerError::Limit("checker input bytes"));
        }
        if next.dag_steps > l.dag_steps_per_record {
            return Err(LedgerError::Limit("DAG steps"));
        }
        *self = next;
        Ok(())
    }
    fn normalization(&mut self, steps: usize, profile: &Profile) -> Result<(), LedgerError> {
        let next = self
            .normalization_steps
            .checked_add(steps as u64)
            .ok_or(LedgerError::Overflow)?;
        if next > profile.limits().normalization_steps_per_record {
            return Err(LedgerError::Limit("normalization steps"));
        }
        self.normalization_steps = next;
        Ok(())
    }
}

pub(super) fn strict_check(
    bytes: &[u8],
    state: &ArtifactState,
    profile: &Profile,
    work: &mut VerificationWork,
) -> Result<CheckedProof, LedgerError> {
    let certificate = bounded_certificate(bytes, profile)?;
    work.check(bytes.len(), certificate.steps().len(), profile)?;
    let normal = certificate.into_unchecked_normal_form();
    if normal.canonical_bytes() != bytes {
        return Err(LedgerError::Invalid(
            "certificate is not strict root normal form",
        ));
    }
    check_normal_form_with_state(normal, state).map_err(math)
}

/// Bounds the entire selected dependency closure before any mathematical calls.
fn old_closure(
    library: &ProofLibrary,
    starts: &BTreeSet<ProofId>,
    profile: &Profile,
) -> Result<Vec<ProofId>, LedgerError> {
    let mut pending = starts.clone();
    let mut found = BTreeSet::new();
    let mut bytes = 0usize;
    while let Some(id) = pending.pop_first() {
        if !found.insert(id) {
            continue;
        }
        if found.len() > profile.limits().dependency_proofs as usize {
            return Err(LedgerError::Limit("older dependency count"));
        }
        let proof = library
            .lookup(id)
            .ok_or(LedgerError::Invalid("missing selected proof dependency"))?;
        let _ = bounded_certificate(&proof.bytes, profile)?;
        bytes = bytes
            .checked_add(proof.bytes.len())
            .ok_or(LedgerError::Overflow)?;
        if bytes > profile.limits().dependency_bytes as usize {
            return Err(LedgerError::Limit("older dependency bytes"));
        }
        for dependency in &proof.dependencies {
            if !found.contains(dependency) {
                pending.insert(*dependency);
            }
        }
    }
    let mut remaining = found;
    let mut depth = BTreeMap::<ProofId, usize>::new();
    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        let id = remaining
            .iter()
            .find(|id| {
                library.records[*id]
                    .dependencies
                    .iter()
                    .all(|id| depth.contains_key(id))
            })
            .copied()
            .ok_or(LedgerError::Invalid("cyclic selected dependency closure"))?;
        let maximum = library.records[&id]
            .dependencies
            .iter()
            .map(|id| depth[id])
            .max()
            .unwrap_or(0)
            + 1;
        if maximum > profile.limits().dependency_depth as usize {
            return Err(LedgerError::Limit("older dependency depth"));
        }
        depth.insert(id, maximum);
        remaining.remove(&id);
        ordered.push(id);
    }
    Ok(ordered)
}

fn verify_old(
    library: &ProofLibrary,
    ids: &[ProofId],
    profile: &Profile,
    work: &mut VerificationWork,
) -> Result<ArtifactState, LedgerError> {
    let mut state = ArtifactState::new();
    for id in ids {
        let stored = &library.records[id];
        let checked = strict_check(&stored.bytes, &state, profile, work)?;
        if checked.proof_id() != *id
            || checked.statement_id() != stored.statement_id
            || checked.conclusion() != &stored.conclusion
            || dependencies(checked.normal_form().certificate()) != stored.dependencies
        {
            return Err(LedgerError::Invalid("stored proof metadata mismatch"));
        }
        state.register_proof(checked).map_err(math)?;
    }
    Ok(state)
}

pub(super) fn normalize(
    library: &ProofLibrary,
    package: &ProofPackage,
    question: &CompiledQuestion,
    profile: &Profile,
    work: &mut VerificationWork,
) -> Result<NormalizedPackage, LedgerError> {
    let previous = *work;
    // Revalidate against this profile, even if constructed under another profile.
    let original_bytes = package.encode()?;
    let package = ProofPackage::decode(&original_bytes, profile)?;
    let ids: BTreeSet<_> = package.nodes.iter().map(|(id, _)| *id).collect();
    let mut older = BTreeSet::new();
    for (_, bytes) in &package.nodes {
        older.extend(
            dependencies(&bounded_certificate(bytes, profile)?)
                .into_iter()
                .filter(|id| !ids.contains(id)),
        );
    }
    let original_closure = old_closure(library, &older, profile)?;
    let mut original_state = verify_old(library, &original_closure, profile, work)?;
    let mut originals = BTreeMap::new();
    let mut statements = BTreeMap::new();
    // This intentionally verifies every submitted node, including unused nodes
    // and helpers that a subsequent substitution will remove.
    for (id, bytes) in &package.nodes {
        let checked = strict_check(bytes, &original_state, profile, work)?;
        if checked.proof_id() != *id {
            return Err(LedgerError::Invalid("claimed proof ID mismatch"));
        }
        let conclusion_bytes = checked.conclusion().encode_canonical().map_err(math)?;
        if statements
            .insert((checked.statement_id(), conclusion_bytes), *id)
            .is_some()
        {
            return Err(LedgerError::Invalid(
                "different new certificates of one exact statement",
            ));
        }
        originals.insert(*id, record(&checked, package.author));
        if !original_state.contains_proof(*id) {
            original_state
                .register_proof_for_verification(checked)
                .map_err(math)?;
        }
    }
    let original_root = &originals[&package.root];
    let outcome = if &original_root.conclusion == question.proved_target() {
        ProofOutcome::Proved
    } else if &original_root.conclusion == question.refuted_target() {
        ProofOutcome::Refuted
    } else {
        return Err(LedgerError::Invalid(
            "root does not prove an approved target",
        ));
    };
    if library.exact_target(&original_root.conclusion).is_some() {
        return Err(LedgerError::Invalid("root target already selected"));
    }
    let mut substitutions = BTreeMap::new();
    for (id, proof) in &originals {
        if *id == package.root {
            continue;
        }
        if let Some(older) = library
            .exact_target(&proof.conclusion)
            .filter(|old| old.statement_id == proof.statement_id)
        {
            substitutions.insert(*id, older.proof_id);
        }
    }
    // Determine final reachability before rewriting. A replaced helper is a
    // leaf here; none of its discarded dependencies enters the citation pool.
    let mut reachable = BTreeSet::new();
    let mut citations = BTreeSet::new();
    let mut pending = BTreeSet::from([package.root]);
    while let Some(id) = pending.pop_first() {
        if let Some(replacement) = substitutions.get(&id) {
            citations.insert(*replacement);
            continue;
        }
        if let Some(proof) = originals.get(&id) {
            if reachable.insert(id) {
                pending.extend(proof.dependencies.iter().copied());
            }
        } else {
            if !library.records.contains_key(&id) {
                return Err(LedgerError::Invalid("missing final dependency"));
            }
            citations.insert(id);
        }
    }
    if citations.len() > profile.limits().citation_proofs as usize {
        return Err(LedgerError::Limit("citation proof count"));
    }
    let final_closure = old_closure(library, &citations, profile)?;
    // Independent second verification of every required final older certificate.
    let _verified_final_dependencies = verify_old(library, &final_closure, profile, work)?;
    let mut final_state = library.dag.clone();
    let mut rewritten_ids = substitutions.clone();
    let mut final_records = BTreeMap::new();
    for (id, bytes) in &package.nodes {
        if !reachable.contains(id) {
            continue;
        }
        let original = bounded_certificate(bytes, profile)?;
        work.normalization(original.steps().len(), profile)?;
        let steps = original
            .steps()
            .iter()
            .map(|step| match step {
                ProofStep::ProofReference { proof_id } => ProofStep::ProofReference {
                    proof_id: rewritten_ids.get(proof_id).copied().unwrap_or(*proof_id),
                },
                other => other.clone(),
            })
            .collect();
        let normal = ProofCertificate::new(steps)
            .map_err(math)?
            .into_unchecked_normal_form();
        let _ = bounded_certificate(normal.canonical_bytes(), profile)?;
        work.check(
            normal.canonical_bytes().len(),
            normal.certificate().steps().len(),
            profile,
        )?;
        let checked =
            check_normal_form_with_state(normal, final_state.artifact_state()).map_err(math)?;
        if checked.statement_id() != originals[id].statement_id
            || checked.conclusion() != &originals[id].conclusion
        {
            return Err(LedgerError::Invalid("normalization changed conclusion"));
        }
        let proof = record(&checked, package.author);
        rewritten_ids.insert(*id, proof.proof_id);
        final_state
            .admit_checked_proof(checked, proof.proof_id)
            .map_err(math)?;
        final_records.insert(proof.proof_id, proof);
    }
    let root = rewritten_ids[&package.root];
    let final_package = ProofPackage::new(
        package.author,
        root,
        final_records
            .iter()
            .map(|(id, proof)| (*id, proof.bytes.clone()))
            .collect(),
        profile,
    )?;
    let final_bytes = final_package.encode()?;
    let proofs = final_package
        .nodes
        .iter()
        .map(|(id, _)| final_records.remove(id).expect("final node exists"))
        .collect();
    Ok(NormalizedPackage {
        author: package.author,
        root,
        outcome,
        original_hash: package.original_hash(),
        parent_library_root: library.root(),
        proofs,
        substitutions,
        citations: citations.into_iter().collect(),
        final_bytes,
        work: VerificationWork {
            checker_calls: work.checker_calls - previous.checker_calls,
            checker_input_bytes: work.checker_input_bytes - previous.checker_input_bytes,
            dag_steps: work.dag_steps - previous.dag_steps,
            normalization_steps: work.normalization_steps - previous.normalization_steps,
        },
        publication_dag: final_state,
    })
}
