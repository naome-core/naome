//! Reproducible valid workload measurements. Run with --nocapture in both
//! pinned test/release profiles; timings are observations, never test thresholds.
use super::*;
use std::time::Instant;

fn obligation(formula: &Formula, profile: &Profile) -> CompiledQuestion {
    CompiledQuestion::compile(
        &format!(
            "foundation = \"naome:zfc\"\nstatement = {}\n",
            formula.to_source()
        ),
        profile,
    )
    .unwrap()
}
fn balanced(formula: &Formula, leaves: usize) -> Formula {
    if leaves == 1 {
        return formula.clone();
    }
    Formula::implies(
        balanced(formula, leaves / 2),
        balanced(formula, leaves - leaves / 2),
    )
}
fn bulky_steps(reference: Option<ProofId>, base: &Formula, leaves: usize) -> Vec<ProofStep> {
    let steps = match reference {
        Some(proof_id) => vec![ProofStep::ProofReference { proof_id }],
        None => vec![
            ProofStep::EqualityReflexivity { variable: x() },
            ProofStep::Generalization {
                premise: 0,
                variable: x(),
            },
        ],
    };
    bulky_from_prefix(steps, base, leaves)
}
fn bulky_from_prefix(mut steps: Vec<ProofStep>, base: &Formula, leaves: usize) -> Vec<ProofStep> {
    let mut current = (steps.len() - 1) as u32;
    let large = balanced(base, leaves);
    // Both large formulas occur in reachable, actually used logical axioms.
    // No unused material is available for normalization to silently remove.
    for extra in [large.clone(), Formula::negate(large)] {
        let lemma = Formula::implies(base.clone(), Formula::implies(extra.clone(), base.clone()));
        let lemma_index = steps.len() as u32;
        steps.push(ProofStep::Simplification {
            antecedent: base.clone().into(),
            consequent: extra.into(),
        });
        let introduction = steps.len() as u32;
        steps.push(ProofStep::Simplification {
            antecedent: base.clone().into(),
            consequent: lemma.into(),
        });
        let implication = steps.len() as u32;
        steps.push(ProofStep::ModusPonens {
            premise: current,
            implication: introduction,
        });
        current = steps.len() as u32;
        steps.push(ProofStep::ModusPonens {
            premise: lemma_index,
            implication,
        });
    }
    steps.push(ProofStep::Generalization {
        premise: current,
        variable: x(),
    });
    steps
}
fn largest_bulky(reference: Option<ProofId>, base: &Formula, maximum: usize) -> Vec<ProofStep> {
    let (mut low, mut high) = (1usize, 2048usize);
    while low < high {
        let middle = (low + high).div_ceil(2);
        let bytes = ProofCertificate::new(bulky_steps(reference, base, middle))
            .map(|certificate| certificate.to_canonical_bytes().len())
            .unwrap_or(usize::MAX);
        if bytes <= maximum {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    bulky_steps(reference, base, low)
}
fn measure(
    label: &str,
    library: &ProofLibrary,
    package: &ProofPackage,
    question: &CompiledQuestion,
    profile: &Profile,
) -> NormalizedPackage {
    let began = Instant::now();
    let normalized = library.normalize(package, question, profile).unwrap();
    let elapsed = began.elapsed().as_micros();
    let work = normalized.work();
    let largest_certificate_bytes = package
        .certificates()
        .iter()
        .map(|(_, bytes)| bytes.len())
        .max()
        .unwrap();
    eprintln!(
        "MVP34 {{\"scenario\":\"{label}\",\"profile\":\"{}\",\"elapsed_us\":{elapsed},\"package_bytes\":{},\"largest_certificate_bytes\":{largest_certificate_bytes},\"new_proofs\":{},\"citations\":{},\"checker_calls\":{},\"checker_input_bytes\":{},\"dag_steps\":{},\"normalization_steps\":{}}}",
        if cfg!(debug_assertions) {
            "test"
        } else {
            "release"
        },
        package.encode().unwrap().len(),
        normalized.new_proofs().len(),
        normalized.citations().len(),
        work.checker_calls,
        work.checker_input_bytes,
        work.dag_steps,
        work.normalization_steps
    );
    normalized
}

#[test]
fn qualification_actual_4096_steps_and_near_64k_certificate() {
    let profile = Profile::lab();
    let base = h_formula();
    let target = Formula::for_all(x(), base.clone());
    let task = obligation(&target, &profile);
    let mut steps = vec![
        ProofStep::EqualityReflexivity { variable: x() },
        ProofStep::Generalization {
            premise: 0,
            variable: x(),
        },
        ProofStep::UniversalInstantiation {
            variable: x(),
            replacement: x(),
            body: base.clone().into(),
        },
    ];
    let mut current = 1;
    for _ in 0..2046 {
        let general = steps.len() as u32;
        steps.push(ProofStep::Generalization {
            premise: current,
            variable: x(),
        });
        current = steps.len() as u32;
        steps.push(ProofStep::ModusPonens {
            premise: general,
            implication: 2,
        });
    }
    steps.push(ProofStep::Generalization {
        premise: current,
        variable: x(),
    });
    assert_eq!(steps.len(), 4096);
    let root = checked(steps, &mut ArtifactState::new());
    assert_eq!(
        ProofCertificate::from_canonical_bytes(&root.1)
            .unwrap()
            .steps()
            .len(),
        4096
    );
    let package = ProofPackage::new(author(1), root.0, vec![root.clone()], &profile).unwrap();
    let measured = measure(
        "4096_reachable_steps",
        &ProofLibrary::new(),
        &package,
        &task,
        &profile,
    );
    assert_eq!(measured.work().dag_steps, 8192);
    let small = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            certificate_steps: 4095,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut work = VerificationWork::default();
    assert!(matches!(
        ProofLibrary::new().normalize_with_work(
            &package,
            &obligation(&target, &small),
            &small,
            &mut work
        ),
        Err(LedgerError::Limit("certificate steps"))
    ));
    assert_eq!(work, VerificationWork::default());
    let bulky = checked(
        largest_bulky(None, &base, 64 * 1024),
        &mut ArtifactState::new(),
    );
    assert!(
        bulky.1.len() > 63 * 1024,
        "actual certificate bytes {}",
        bulky.1.len()
    );
    assert!(bulky.1.len() <= 64 * 1024);
    let package = ProofPackage::new(author(1), bulky.0, vec![bulky.clone()], &profile).unwrap();
    measure(
        "near_64k_reachable_certificate",
        &ProofLibrary::new(),
        &package,
        &task,
        &profile,
    );
    let small = Profile::with_limits(
        TimingKind::Lab,
        Limits {
            certificate_bytes: bulky.1.len() as u64 - 1,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut work = VerificationWork::default();
    assert!(matches!(
        ProofLibrary::new().normalize_with_work(
            &package,
            &obligation(&target, &small),
            &small,
            &mut work
        ),
        Err(LedgerError::Limit(_))
    ));
    assert_eq!(work, VerificationWork::default());
}

#[test]
fn qualification_17_used_nodes_near_compact_and_default_package_bounds() {
    for maximum in [64 * 1024usize, 256 * 1024] {
        let profile = Profile::with_limits(
            TimingKind::Lab,
            Limits {
                package_bytes: maximum as u64,
                ..Limits::default()
            },
        )
        .unwrap();
        let per_certificate = (maximum - 70) / 17 - 36;
        let mut context = ArtifactState::new();
        let mut nodes = Vec::new();
        let mut base = h_formula();
        let mut previous = None;
        for _ in 0..17 {
            let node = checked(
                largest_bulky(previous, &base, per_certificate),
                &mut context,
            );
            previous = Some(node.0);
            nodes.push(node);
            base = Formula::for_all(x(), base);
        }
        let package =
            ProofPackage::new(author(1), previous.unwrap(), nodes.clone(), &profile).unwrap();
        let encoded = package.encode().unwrap();
        assert!(encoded.len() > maximum * 95 / 100);
        assert!(encoded.len() <= maximum);
        let task = obligation(&base, &profile);
        let library = ProofLibrary::new();
        let normalized = measure(
            if maximum == 65536 {
                "17_nodes_near_64k_package"
            } else {
                "17_nodes_near_256k_package"
            },
            &library,
            &package,
            &task,
            &profile,
        );
        assert_eq!(normalized.new_proofs().len(), 17);
        assert_eq!(normalized.work().checker_calls, 34);
        assert_eq!(normalized.final_bytes(), encoded);
        let small = Profile::with_limits(
            TimingKind::Lab,
            Limits {
                package_bytes: encoded.len() as u64 - 1,
                certificate_bytes: (encoded.len() as u64 - 1).min(64 * 1024),
                ..Limits::default()
            },
        )
        .unwrap();
        let mut work = VerificationWork::default();
        assert!(matches!(
            library.normalize_with_work(&package, &obligation(&base, &small), &small, &mut work),
            Err(LedgerError::Limit(_))
        ));
        assert_eq!(work, VerificationWork::default());
        let extra = generalize(previous.unwrap(), &mut context);
        nodes.push(extra.clone());
        assert!(matches!(
            ProofPackage::new(author(1), extra.0, nodes, &profile),
            Err(LedgerError::Limit("new proof count"))
        ));
        let bounded = Profile::with_limits(
            TimingKind::Lab,
            Limits {
                checker_calls_per_record: 34,
                package_bytes: maximum as u64,
                ..Limits::default()
            },
        )
        .unwrap();
        let mut work = VerificationWork::default();
        library
            .normalize_with_work(&package, &obligation(&base, &bounded), &bounded, &mut work)
            .unwrap();
        let before = work;
        assert!(matches!(
            library.normalize_with_work(
                &package,
                &obligation(&base, &bounded),
                &bounded,
                &mut work
            ),
            Err(LedgerError::Limit("checker calls"))
        ));
        assert_eq!(work, before);
    }
}

fn older_target(i: usize) -> Vec<ProofStep> {
    let (left, right, binders) = if i < 64 { (i / 8, i % 8, 8) } else { (0, 8, 9) };
    let mut steps = vec![ProofStep::Simplification {
        antecedent: Formula::equal(
            FreeVariable::new(left as u32),
            FreeVariable::new(left as u32),
        )
        .into(),
        consequent: Formula::equal(
            FreeVariable::new(right as u32),
            FreeVariable::new(right as u32),
        )
        .into(),
    }];
    for variable in 0..binders {
        steps.push(ProofStep::Generalization {
            premise: (steps.len() - 1) as u32,
            variable: FreeVariable::new(variable),
        });
    }
    steps
}
fn fan_in(nodes: &[(Node, Formula)], state: &mut ArtifactState) -> Node {
    let base = nodes[0].1.clone();
    let mut steps = vec![ProofStep::ProofReference {
        proof_id: nodes[0].0.0,
    }];
    let mut current = 0;
    for (node, formula) in &nodes[1..] {
        let reference = steps.len() as u32;
        steps.push(ProofStep::ProofReference { proof_id: node.0 });
        let axiom = steps.len() as u32;
        steps.push(ProofStep::Simplification {
            antecedent: base.clone().into(),
            consequent: formula.clone().into(),
        });
        let implication = steps.len() as u32;
        steps.push(ProofStep::ModusPonens {
            premise: current,
            implication: axiom,
        });
        current = steps.len() as u32;
        steps.push(ProofStep::ModusPonens {
            premise: reference,
            implication,
        });
    }
    steps.push(ProofStep::Generalization {
        premise: current,
        variable: x(),
    });
    checked(steps, state)
}
#[test]
fn qualification_64_verified_older_citations_and_65th_reject_before_checker() {
    let profile = Profile::lab();
    let mut library = ProofLibrary::new();
    let mut context = ArtifactState::new();
    let mut nodes = Vec::new();
    for i in 0..65 {
        let node = checked(older_target(i), &mut context);
        let checked = naome_checker::check_normal_form_with_state(
            ProofCertificate::from_canonical_bytes(&node.1)
                .unwrap()
                .into_unchecked_normal_form(),
            &ArtifactState::new(),
        )
        .unwrap();
        let formula = checked.conclusion().clone();
        let package = ProofPackage::new(author(1), node.0, vec![node.clone()], &profile).unwrap();
        let normalized = library
            .normalize(&package, &obligation(&formula, &profile), &profile)
            .unwrap();
        library
            .publish(
                &normalized,
                AdmissionCoordinate {
                    height: i as u64 + 1,
                    operation_index: 0,
                },
            )
            .unwrap();
        nodes.push((node, formula));
    }
    let target = Formula::for_all(x(), nodes[0].1.clone());
    let task = obligation(&target, &profile);
    let root = fan_in(&nodes[..64], &mut context);
    let package = ProofPackage::new(author(2), root.0, vec![root], &profile).unwrap();
    let normalized = measure(
        "64_verified_older_dependencies_and_citations",
        &library,
        &package,
        &task,
        &profile,
    );
    assert_eq!(normalized.citations().len(), 64);
    assert_eq!(normalized.work().checker_calls, 130);
    let root = fan_in(&nodes, &mut context);
    let package = ProofPackage::new(author(2), root.0, vec![root], &profile).unwrap();
    let mut work = VerificationWork::default();
    assert!(matches!(
        library.normalize_with_work(&package, &task, &profile, &mut work),
        Err(LedgerError::Limit("older dependency count"))
    ));
    assert_eq!(work, VerificationWork::default());
}

#[test]
fn qualification_near_2mib_older_closure_sixteen_authenticated_candidates() {
    use crate::{
        LedgerState, SolutionRoundId,
        operations::{OperationBody, SignedOriginal},
        profile::{DOMAIN_RECORD_OVERHEAD_BYTES, Genesis},
        time::{SignedTimeReport, TimeCertificate},
    };
    use ed25519_dalek::SigningKey;
    let profile = Profile::with_limits(
        TimingKind::ShortTest,
        Limits {
            package_bytes: 64 * 1024,
            record_bytes: 128 * 1024,
            transport_frame_bytes: 192 * 1024,
            ..Limits::default()
        },
    )
    .unwrap();
    let fixture = crate::test_support::genesis();
    let keys: Vec<_> = (0..16u8)
        .map(|i| SigningKey::from_bytes(&[i + 1; 32]))
        .collect();
    let genesis = Genesis::new(
        profile.clone(),
        fixture.foundation().into(),
        fixture.checker_profile().into(),
        crate::profile::STATE_PROTOCOL_VERSION,
        100,
        [17; 32],
        keys.iter().map(|k| k.verifying_key().to_bytes()).collect(),
        fixture.validators().to_vec(),
        fixture.retirement_order().to_vec(),
    )
    .unwrap();
    let publisher = AccountId::for_key(keys[0].verifying_key().as_bytes());
    let mut library = ProofLibrary::new();
    let mut context = ArtifactState::new();
    let mut nodes = Vec::new();
    let mut older_bytes = 0;
    for i in 0..63 {
        let prefix = older_target(i);
        let seed = normalize_and_check_with_state(
            ProofCertificate::new(prefix.clone()).unwrap(),
            &ArtifactState::new(),
        )
        .unwrap();
        let base = seed.conclusion().clone();
        let (mut low, mut high) = (1usize, 2048usize);
        while low < high {
            let middle = (low + high).div_ceil(2);
            let size = ProofCertificate::new(bulky_from_prefix(prefix.clone(), &base, middle))
                .map(|c| c.to_canonical_bytes().len())
                .unwrap_or(usize::MAX);
            if size <= 32 * 1024 {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let node = checked(bulky_from_prefix(prefix, &base, low), &mut context);
        let formula = Formula::for_all(x(), base);
        older_bytes += node.1.len();
        let package = ProofPackage::new(publisher, node.0, vec![node.clone()], &profile).unwrap();
        let normalized = library
            .normalize(&package, &obligation(&formula, &profile), &profile)
            .unwrap();
        library
            .publish(
                &normalized,
                AdmissionCoordinate {
                    height: i as u64 + 1,
                    operation_index: 0,
                },
            )
            .unwrap();
        nodes.push((node, formula));
    }
    let hub = fan_in(&nodes, &mut context);
    let hub_formula = Formula::for_all(x(), nodes[0].1.clone());
    older_bytes += hub.1.len();
    let hub_package = ProofPackage::new(publisher, hub.0, vec![hub.clone()], &profile).unwrap();
    let normalized = library
        .normalize(&hub_package, &obligation(&hub_formula, &profile), &profile)
        .unwrap();
    library
        .publish(
            &normalized,
            AdmissionCoordinate {
                height: 64,
                operation_index: 0,
            },
        )
        .unwrap();
    assert_eq!(library.len(), 64);
    assert!(
        older_bytes > 2 * 1024 * 1024 * 98 / 100,
        "actual closure bytes {older_bytes}"
    );
    assert!(older_bytes <= 2 * 1024 * 1024);
    let mut target = hub_formula;
    let mut previous = hub.0;
    let mut new_nodes = Vec::new();
    for _ in 0..17 {
        let node = generalize(previous, &mut context);
        previous = node.0;
        new_nodes.push(node);
        target = Formula::for_all(x(), target);
    }
    let new_certificate_bytes: usize = new_nodes.iter().map(|(_, bytes)| bytes.len()).sum();
    let task = obligation(&target, &profile);
    let round = SolutionRoundId::from_bytes([23; 32]);
    let mut actions = Vec::new();
    let mut packages = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let author = AccountId::for_key(key.verifying_key().as_bytes());
        let package = ProofPackage::new(author, previous, new_nodes.clone(), &profile).unwrap();
        let original = SignedOriginal::sign(&genesis, round, package.clone(), key).unwrap();
        original.verify_signature(&genesis, round, author).unwrap();
        let action = OperationBody::Reveal {
            round,
            secret: [index as u8; 32],
            original,
        }
        .sign(&genesis, 1, key)
        .unwrap();
        action.verify_signature(&genesis).unwrap();
        actions.push(action);
        packages.push(package);
    }
    let input_bytes: usize = actions.iter().map(|a| 4 + a.encode().len()).sum();
    assert!(
        input_bytes + DOMAIN_RECORD_OVERHEAD_BYTES as usize
            <= profile.limits().record_bytes as usize
    );
    let mut work = VerificationWork::default();
    let start = Instant::now();
    for package in &packages {
        let normalized = library
            .normalize_with_work(package, &task, &profile, &mut work)
            .unwrap();
        assert_eq!(normalized.citations(), &[hub.0]);
        assert_eq!(normalized.new_proofs().len(), 17);
    }
    let elapsed = start.elapsed().as_micros();
    assert_eq!(work.checker_calls, 16 * 2 * (64 + 17));
    assert_eq!(
        work.checker_calls,
        profile.limits().checker_calls_per_record
    );
    assert_eq!(
        work.checker_input_bytes,
        32 * (older_bytes + new_certificate_bytes) as u64
    );
    eprintln!(
        "MVP34 {{\"scenario\":\"16_candidates_near_2mib_older_closure\",\"profile\":\"{}\",\"elapsed_us\":{elapsed},\"older_proofs\":64,\"older_dependency_depth\":2,\"older_certificate_bytes\":{older_bytes},\"authenticated_candidates\":16,\"new_proofs_per_candidate\":17,\"signed_operation_bytes\":{input_bytes},\"record_byte_limit\":{},\"checker_calls\":{},\"checker_input_bytes\":{},\"dag_steps\":{},\"normalization_steps\":{}}}",
        if cfg!(debug_assertions) {
            "test"
        } else {
            "release"
        },
        profile.limits().record_bytes,
        work.checker_calls,
        work.checker_input_bytes,
        work.dag_steps,
        work.normalization_steps
    );
    // A one-byte-smaller dependency cap rejects this exact valid closure during
    // preflight, before any mathematical check can spend the record budget.
    let mut small_limits = profile.limits().clone();
    small_limits.dependency_bytes = older_bytes as u64 - 1;
    let small = Profile::with_limits(TimingKind::ShortTest, small_limits).unwrap();
    let mut untouched = VerificationWork::default();
    assert!(matches!(
        library.normalize_with_work(
            &packages[0],
            &obligation(&target, &small),
            &small,
            &mut untouched
        ),
        Err(LedgerError::Limit("older dependency bytes"))
    ));
    assert_eq!(untouched, VerificationWork::default());
    // The real record admission boundary rejects a 17th operation before phase,
    // signature or proof processing; this is not a claim that these envelopes
    // were admitted or finalized in the empty state used for this count check.
    actions.push(actions[0].clone());
    let state = LedgerState::new(genesis);
    let time = TimeCertificate::new(
        (0..3)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.head(),
                    1,
                    100,
                    &crate::test_support::validator(i),
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.head(),
        1,
        100,
    )
    .unwrap();
    assert!(matches!(
        state.execute(time, actions),
        Err(LedgerError::Limit("operations per record"))
    ));
    // The real default aggregate checker-call ceiling is now exhausted. The
    // next call fails before adding any work, even without the action-count gate.
    let before = work;
    assert!(matches!(
        library.normalize_with_work(&packages[0], &task, &profile, &mut work),
        Err(LedgerError::Limit("checker calls"))
    ));
    assert_eq!(work, before);
}
