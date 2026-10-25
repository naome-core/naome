//! The RAM oracle and real cold file reads must yield identical full decisions.
use super::*;
use crate::{ArtifactState, ContextStorage, DiskArtifactState, normalize_and_check_with_state};
use naome_foundation::FreeVariable;
use naome_proof::ProofCertificate;
use std::{
    fs,
    io::Read,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

static DIRECTORY: AtomicU64 = AtomicU64::new(0);
struct Files {
    directory: PathBuf,
    reads: AtomicU64,
    remaining: Mutex<Option<u64>>,
    failures: Mutex<Vec<ContextError>>,
}
impl Files {
    fn new() -> Arc<Self> {
        let directory = std::env::temp_dir().join(format!(
            "naome-context-gate-{}-{}",
            std::process::id(),
            DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Arc::new(Self {
            directory,
            reads: AtomicU64::new(0),
            remaining: Mutex::new(None),
            failures: Mutex::new(Vec::new()),
        })
    }
    fn path(&self, address: [u8; 32]) -> PathBuf {
        self.directory.join(
            address
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}
impl ContextStorage for Files {
    fn record_failure(&self, error: &ContextError) {
        self.failures.lock().unwrap().push(error.clone());
    }
    fn read(&self, address: [u8; 32], maximum: usize) -> Result<Vec<u8>, ContextError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let mut remaining = self.remaining.lock().unwrap();
        if let Some(count) = remaining.as_mut() {
            if *count == 0 {
                return Err(ContextError::Storage("injected cold read failure".into()));
            }
            *count -= 1;
        }
        drop(remaining);
        let file = fs::File::open(self.path(address))
            .map_err(|error| ContextError::Storage(error.to_string()))?;
        if file
            .metadata()
            .map_err(|error| ContextError::Storage(error.to_string()))?
            .len()
            > maximum as u64
        {
            return Err(ContextError::Limit);
        }
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| ContextError::Storage(error.to_string()))?;
        if bytes.len() > maximum {
            return Err(ContextError::Limit);
        }
        Ok(bytes)
    }
    fn write(&self, address: [u8; 32], bytes: &[u8]) -> Result<(), ContextError> {
        let path = self.path(address);
        if path.exists() {
            if fs::read(path).map_err(|error| ContextError::Storage(error.to_string()))? != bytes {
                return Err(ContextError::Corrupt);
            }
        } else {
            fs::write(path, bytes).map_err(|error| ContextError::Storage(error.to_string()))?;
        }
        Ok(())
    }
}

struct Twin {
    memory: ArtifactState,
    disk: DiskArtifactState,
    files: Arc<Files>,
    records: Vec<Vec<u8>>,
}
impl Twin {
    fn new() -> Self {
        let files = Files::new();
        Self {
            memory: ArtifactState::new(),
            disk: DiskArtifactState::new(files.clone()),
            files,
            records: Vec::new(),
        }
    }
    fn register(&mut self, steps: Vec<ProofStep>) -> (ProofId, Formula) {
        let certificate = ProofCertificate::new(steps).unwrap();
        let checked = normalize_and_check_with_state(certificate.clone(), &self.memory).unwrap();
        let cold = normalize_and_check_with_state(certificate, &self.disk).unwrap();
        assert_eq!(
            checked, cold,
            "cold citation resolution preserves canonical identity"
        );
        let id = checked.proof_id();
        let conclusion = checked.conclusion().clone();
        let bytes = self.memory.register_proof_for_replication(checked).unwrap();
        assert_eq!(
            self.disk.register_proof_for_replication(cold).unwrap(),
            bytes
        );
        self.records.push(bytes.into_vec());
        assert_eq!(self.memory.snapshot_id(), self.disk.snapshot_id());
        (id, conclusion)
    }
    fn compare(
        &self,
        target: &Formula,
        registry: &QuestionRegistry,
        policy: &PrefilterPolicy,
    ) -> PrefilterDecision {
        let question = AssessmentQuestion::new(
            FOUNDATION_ID,
            target,
            b"cold context discriminator",
            &[],
            None,
        )
        .unwrap();
        let baseline = assess_question(
            &question,
            &KnowledgeSnapshot::new([7; 32], &self.memory, registry),
            policy,
        );
        let before = self.files.reads.load(Ordering::Relaxed);
        let cold = assess_question(
            &question,
            &KnowledgeSnapshot::new([7; 32], &self.disk, registry),
            policy,
        );
        assert_eq!(
            baseline, cold,
            "complete rule/reason/snapshot/witness/certificate equality"
        );
        if !self.records.is_empty() {
            assert!(
                self.files.reads.load(Ordering::Relaxed) > before,
                "no formula or node cache masks disk reads"
            );
        }
        cold
    }
    fn replay(&self) -> DiskArtifactState {
        let mut state = DiskArtifactState::new(self.files.clone());
        assert_eq!(state.snapshot_id(), ArtifactState::new().snapshot_id());
        for bytes in &self.records {
            let certificate = ProofCertificate::from_canonical_bytes(bytes).unwrap();
            let checked = normalize_and_check_with_state(certificate, &state).unwrap();
            state.register_proof_for_replication(checked).unwrap();
        }
        assert_eq!(state.snapshot_id(), self.disk.snapshot_id());
        state
    }
}
fn var(id: u32) -> FreeVariable {
    FreeVariable::new(id)
}
fn equal() -> Formula {
    Formula::for_all(var(0), Formula::equal(var(0), var(0)))
}
fn unresolved() -> Formula {
    Formula::for_all(var(0), Formula::member(var(0), var(0)))
}
fn equality_steps() -> Vec<ProofStep> {
    vec![
        ProofStep::EqualityReflexivity { variable: var(0) },
        ProofStep::Generalization {
            premise: 0,
            variable: var(0),
        },
    ]
}
fn fact_steps(pattern: &Formula) -> Vec<ProofStep> {
    let mut steps = equality_steps();
    steps.push(ProofStep::Simplification {
        antecedent: equal().into(),
        consequent: pattern.clone().into(),
    });
    steps.push(ProofStep::ModusPonens {
        premise: 1,
        implication: 2,
    });
    steps
}
fn lift(first: &Formula, second: &Formula, mut steps: Vec<ProofStep>) -> Vec<ProofStep> {
    let result = crate::normalize_and_check(ProofCertificate::new(steps.clone()).unwrap())
        .unwrap()
        .conclusion()
        .clone();
    let root = (steps.len() - 1) as u32;
    let implication = steps.len() as u32;
    steps.push(ProofStep::Simplification {
        antecedent: result.clone().into(),
        consequent: second.clone().into(),
    });
    steps.push(ProofStep::ModusPonens {
        premise: root,
        implication,
    });
    let root = (steps.len() - 1) as u32;
    let implication = steps.len() as u32;
    steps.push(ProofStep::Simplification {
        antecedent: Formula::implies(second.clone(), result).into(),
        consequent: first.clone().into(),
    });
    steps.push(ProofStep::ModusPonens {
        premise: root,
        implication,
    });
    steps
}

#[test]
fn cold_aliases_citations_full_snapshot_replay_and_rollback_match_the_ram_oracle() {
    let mut twin = Twin::new();
    let registry = QuestionRegistry::new();
    let policy = PrefilterPolicy::default();
    twin.compare(&equal(), &registry, &policy);
    let (first, _) = twin.register(equality_steps());
    let previous = twin.disk.clone();
    let (alias, _) = twin.register(vec![ProofStep::ProofReference { proof_id: first }]);
    assert_ne!(first, alias);
    assert!(matches!(
        twin.memory.validate_proof_registration(
            &normalize_and_check_with_state(
                ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: alias }]).unwrap(),
                &twin.memory
            )
            .unwrap()
        ),
        Err(crate::ArtifactStateError::DuplicateDerivation { .. })
    ));
    assert!(!previous.contains_proof(alias).unwrap());
    let result = twin.compare(&equal(), &registry, &policy);
    assert_eq!(result.witness, Some(first.min(alias)));
    let replay = twin.replay();
    assert!(replay.contains_proof(first).unwrap() && replay.contains_proof(alias).unwrap());
    let missing = ProofCertificate::new(vec![ProofStep::ProofReference {
        proof_id: ProofId::from_bytes([3; 32]),
    }])
    .unwrap();
    assert!(normalize_and_check_with_state(missing, &twin.disk).is_err());
    let mut reverse = DiskArtifactState::new(twin.files.clone());
    // Dependency order constrains replay; independent aliases can be registered
    // in another order after both have been checked in a complete context.
    for bytes in twin.records.iter().rev() {
        let checked = normalize_and_check_with_state(
            ProofCertificate::from_canonical_bytes(bytes).unwrap(),
            &twin.disk,
        )
        .unwrap();
        if checked.proof_id() == alias {
            assert!(reverse.register_proof_for_replication(checked).is_err());
        } else {
            reverse.register_proof_for_replication(checked).unwrap();
        }
    }
}

#[test]
fn cold_dynamic_mp_requires_both_seeds_and_identical_original_citations() {
    let mut twin = Twin::new();
    let registry = QuestionRegistry::new();
    let policy = PrefilterPolicy::default();
    let (_, p) = twin.register(super::tests::schema_steps(false));
    let q = crate::normalize_and_check(
        ProofCertificate::new(super::tests::schema_steps(true)).unwrap(),
    )
    .unwrap()
    .conclusion()
    .clone();
    let target = Formula::implies(unresolved(), equal());
    let _ = twin.register(lift(&p, &q, fact_steps(&unresolved())));
    assert!(twin.compare(&target, &registry, &policy).passed());
    let _ = twin.register(super::tests::schema_steps(true));
    let result = twin.compare(&target, &registry, &policy);
    assert_eq!(result.rule, "Q04_CHECKED_MP_CLOSURE");
    assert_eq!(
        result.deduction.as_ref().unwrap().original_proofs().len(),
        3
    );
    let mut exhausted = policy;
    exhausted.limits.operations = 8;
    assert_eq!(
        twin.compare(&target, &registry, &exhausted).reason,
        Some(RejectionReason::ExecutionLimit)
    );
    let replay = twin.replay();
    let question = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"cold context discriminator",
        &[],
        None,
    )
    .unwrap();
    assert_eq!(
        result,
        assess_question(
            &question,
            &KnowledgeSnapshot::new([7; 32], &replay, &registry),
            &policy
        )
    );
}

#[test]
fn target_directed_instantiation_matches_cold_replay_and_certifies_original_sources() {
    let x = var(0);
    let y = var(1);
    let p = Formula::member(x, y);
    let r = Formula::equal(x, x);
    let s = Formula::member(y, x);
    let closure = |a: Formula, b: Formula| {
        vec![
            ProofStep::Simplification {
                antecedent: a.into(),
                consequent: b.into(),
            },
            ProofStep::Generalization {
                premise: 0,
                variable: y,
            },
            ProofStep::Generalization {
                premise: 1,
                variable: x,
            },
        ]
    };
    let mut twin = Twin::new();
    let (first, _) = twin.register(closure(r.clone(), p.clone()));
    let (second, _) = twin.register(closure(Formula::implies(p.clone(), r.clone()), s.clone()));
    let target = Formula::for_all(
        x,
        Formula::for_all(y, Formula::implies(s, Formula::implies(p, r))),
    );
    let registry = QuestionRegistry::new();
    let policy = PrefilterPolicy::default();
    let result = twin.compare(&target, &registry, &policy);
    assert_eq!(result.rule, "Q07_CHECKED_INSTANTIATED_CLOSURE");
    let witness = result.deduction.as_ref().unwrap();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(witness.original_proofs(), expected);
    let certificate =
        ProofCertificate::from_canonical_bytes(witness.canonical_certificate()).unwrap();
    let replay = twin.replay();
    assert_eq!(
        normalize_and_check_with_state(certificate.clone(), &replay)
            .unwrap()
            .conclusion(),
        &target
    );
    let request = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"cold context discriminator",
        &[],
        None,
    )
    .unwrap();
    assert_eq!(
        assess_question(
            &request,
            &KnowledgeSnapshot::new([7; 32], &replay, &registry),
            &policy
        ),
        result
    );
    let mut limited = policy;
    limited.limits.certificate_steps = certificate.steps().len() - 1;
    let incomplete = twin.compare(&target, &registry, &limited);
    assert_eq!(incomplete.outcome, PrefilterOutcome::Inconclusive);
    assert_eq!(incomplete.reason, Some(RejectionReason::ExecutionLimit));
    assert!(incomplete.deduction.is_none());
}

#[test]
fn cold_mutual_implications_and_finite_universal_instances_match_exactly() {
    let mut twin = Twin::new();
    let a = unresolved();
    let (b, forward, backward) = fixtures::guarded_equivalence(&a);
    let mut registry = QuestionRegistry::new();
    registry
        .insert(RegisteredQuestion::new([1; 32], &b).unwrap())
        .unwrap();
    let policy = PrefilterPolicy::default();
    let _ = twin.register(forward);
    assert!(twin.compare(&a, &registry, &policy).passed());
    let _ = twin.register(backward);
    assert_eq!(
        twin.compare(&unresolved(), &registry, &policy).reason,
        Some(RejectionReason::ProvenEquivalent)
    );
    let mut universal = Twin::new();
    let mut steps = super::tests::schema_steps(false);
    let target = crate::normalize_and_check(ProofCertificate::new(steps.clone()).unwrap())
        .unwrap()
        .conclusion()
        .clone();
    steps.push(ProofStep::Generalization {
        premise: 0,
        variable: var(19),
    });
    steps.push(ProofStep::Generalization {
        premise: 1,
        variable: var(20),
    });
    let _ = universal.register(steps);
    assert_eq!(
        universal
            .compare(&target, &QuestionRegistry::new(), &policy)
            .reason,
        Some(RejectionReason::KnownLemmaInstance)
    );
}

#[test]
fn cold_large_mp_intermediate_is_never_truncated_by_the_question_limit() {
    let mut twin = Twin::new();
    let (_, p) = twin.register(super::tests::schema_steps(false));
    let mut large = unresolved();
    for _ in 0..9 {
        large = Formula::implies(large.clone(), large);
    }
    let (_, bridge) = twin.register(vec![ProofStep::Simplification {
        antecedent: p.clone().into(),
        consequent: large.into(),
    }]);
    let (_, intermediate) = bridge.implication_parts().unwrap();
    assert!(
        AssessmentQuestion::new(
            FOUNDATION_ID,
            &intermediate,
            b"oversized intermediate",
            &[],
            None
        )
        .is_err()
    );
    let target = Formula::for_all(var(19), p);
    let mut steps = super::tests::schema_steps(false);
    steps.push(ProofStep::Generalization {
        premise: 0,
        variable: var(19),
    });
    steps.push(ProofStep::Simplification {
        antecedent: target.clone().into(),
        consequent: intermediate.into(),
    });
    steps.push(ProofStep::ModusPonens {
        premise: 1,
        implication: 2,
    });
    let _ = twin.register(steps);
    assert_eq!(
        twin.compare(
            &target,
            &QuestionRegistry::new(),
            &PrefilterPolicy::default()
        )
        .rule,
        "Q04_CHECKED_MP_CLOSURE"
    );
}

#[test]
fn failed_or_corrupt_cold_reads_never_issue_novelty_or_temporary_evidence() {
    let mut twin = Twin::new();
    let _ = twin.register(equality_steps());
    let registry = QuestionRegistry::new();
    let policy = PrefilterPolicy::default();
    let target = unresolved();
    let question = AssessmentQuestion::new(
        FOUNDATION_ID,
        &target,
        b"cold context discriminator",
        &[],
        None,
    )
    .unwrap();
    let before = twin.files.reads.load(Ordering::Relaxed);
    assert!(twin.compare(&target, &registry, &policy).passed());
    let reads = twin.files.reads.load(Ordering::Relaxed) - before;
    assert!(reads > 1);
    *twin.files.remaining.lock().unwrap() = Some(reads - 1);
    let failed = assess_question(
        &question,
        &KnowledgeSnapshot::new([7; 32], &twin.disk, &registry),
        &policy,
    );
    assert_eq!(failed.reason, Some(RejectionReason::InvalidEvidence));
    assert!(failed.novelty().is_none() && failed.deduction.is_none());
    *twin.files.remaining.lock().unwrap() = None;
    let formula = equal().encode_canonical().unwrap();
    let mut hash = Sha256::new();
    hash.update(b"naome:checked-formula-storage:v1\0");
    hash.update(&formula);
    let address = hash.finalize().into();
    fs::write(twin.files.path(address), vec![0; formula.len()]).unwrap();
    let settled = equal();
    let question =
        AssessmentQuestion::new(FOUNDATION_ID, &settled, b"cold formula fault", &[], None).unwrap();
    let failed = assess_question(
        &question,
        &KnowledgeSnapshot::new([7; 32], &twin.disk, &registry),
        &policy,
    );
    assert_eq!(failed.reason, Some(RejectionReason::InvalidEvidence));
    assert!(failed.novelty().is_none() && failed.deduction.is_none());
    assert_eq!(
        twin.files.failures.lock().unwrap().last(),
        Some(&ContextError::Corrupt)
    );
    assert!(twin.replay_without_panic().is_err());
}
impl Twin {
    fn replay_without_panic(&self) -> Result<(), crate::ArtifactStateError> {
        let mut state = DiskArtifactState::new(self.files.clone());
        for bytes in &self.records {
            let checked = normalize_and_check_with_state(
                ProofCertificate::from_canonical_bytes(bytes).unwrap(),
                &state,
            )
            .unwrap();
            state.register_proof_for_replication(checked)?;
        }
        Ok(())
    }
}

#[test]
fn authenticated_header_and_operation_cache_avoid_reloading_formulas_without_changing_limits() {
    use crate::context::cache::ReadContext;
    let mut twin = Twin::new();
    let (id, formula) = twin.register(equality_steps());
    twin.files.reads.store(0, Ordering::Relaxed);
    {
        let reads = ReadContext::new(&twin.disk);
        let header = reads.proof_header(id).unwrap().unwrap();
        assert_eq!(
            reads
                .proof_formula(header, header.length)
                .unwrap()
                .unwrap()
                .as_ref(),
            &formula
        );
        let cold = twin.files.reads.load(Ordering::Relaxed);
        assert_eq!(
            cold, 4,
            "three authenticated headers followed by one formula read"
        );
        let first = reads.proof_formula(header, header.length).unwrap().unwrap();
        assert!(matches!(&first, std::borrow::Cow::Borrowed(_)));
        for _ in 0..16 {
            let warm = reads.proof_header(id).unwrap().unwrap();
            let cached = reads.proof_formula(warm, warm.length).unwrap().unwrap();
            assert!(
                std::ptr::eq(first.as_ref(), cached.as_ref()),
                "warm formulas borrow the same decoded tree"
            );
            assert_eq!(
                reads
                    .proof_formula(warm, warm.length)
                    .unwrap()
                    .unwrap()
                    .as_ref(),
                &formula
            );
        }
        assert_eq!(twin.files.reads.load(Ordering::Relaxed), cold);
        assert_eq!(
            reads.proof_formula(header, header.length - 1).unwrap_err(),
            ContextError::Limit
        );
    }
    let reads = ReadContext::new(&twin.disk);
    let header = reads.proof_header(id).unwrap().unwrap();
    assert_eq!(
        reads
            .proof_formula(header, header.length)
            .unwrap()
            .unwrap()
            .as_ref(),
        &formula
    );
    assert_eq!(
        twin.files.reads.load(Ordering::Relaxed),
        8,
        "new operations authenticate cold state again"
    );
}

#[test]
fn proof_registration_rules_match_for_duplicates_collisions_aliases_and_missing_dependencies() {
    fn checked() -> crate::CheckedProof {
        crate::normalize_and_check(ProofCertificate::new(equality_steps()).unwrap()).unwrap()
    }
    let mut twin = Twin::new();
    let (parent, _) = twin.register(equality_steps());
    for fault in 0..4 {
        let mut memory = checked();
        let mut disk = checked();
        match fault {
            0 => {}
            1 => {
                memory.derivation_id = naome_proof::DerivationId::from_bytes([9; 32]);
                disk.derivation_id = memory.derivation_id;
            }
            2 => {
                memory.proof_id = ProofId::from_bytes([8; 32]);
                disk.proof_id = memory.proof_id;
                memory.statement_id = StatementId::from_bytes([7; 32]);
                disk.statement_id = memory.statement_id;
            }
            3 => {
                memory.proof_id = ProofId::from_bytes([8; 32]);
                disk.proof_id = memory.proof_id;
                memory.derivation_id = naome_proof::DerivationId::from_bytes([9; 32]);
                disk.derivation_id = memory.derivation_id;
                memory.conclusion = Formula::negate(memory.conclusion);
                disk.conclusion = Formula::negate(disk.conclusion);
            }
            _ => unreachable!(),
        }
        let before = twin.memory.snapshot_id();
        let expected = twin
            .memory
            .register_proof_for_replication(memory)
            .unwrap_err();
        assert_eq!(
            twin.disk.register_proof_for_replication(disk).unwrap_err(),
            expected
        );
        assert_eq!(twin.memory.snapshot_id(), before);
        assert_eq!(twin.disk.snapshot_id(), before);
    }
    // A genuinely checked reference remains invalid for registration in an
    // empty replica until its real dependency is registered there.
    let certificate =
        ProofCertificate::new(vec![ProofStep::ProofReference { proof_id: parent }]).unwrap();
    let memory = normalize_and_check_with_state(certificate.clone(), &twin.memory).unwrap();
    let disk = normalize_and_check_with_state(certificate, &twin.disk).unwrap();
    let mut empty = ArtifactState::new();
    let mut cold = DiskArtifactState::new(Files::new());
    let error = empty.register_proof_for_replication(memory).unwrap_err();
    assert_eq!(
        error,
        crate::ArtifactStateError::MissingProofDependency { proof_id: parent }
    );
    assert_eq!(
        cold.register_proof_for_replication(disk).unwrap_err(),
        error
    );
    // Replication admits a distinct normalized alias for the same derivation.
    let _ = twin.register(vec![ProofStep::ProofReference { proof_id: parent }]);
}

mod equivalence;
