#[path = "../examples/support/mod.rs"]
mod support;

use ed25519_dalek::SigningKey;
use naome_checker::{ArtifactState, normalize_and_check, normalize_and_check_with_state};
use naome_foundation::FreeVariable;
use naome_ledger::{
    profile::{
        Genesis, Profile, STATE_CHECKER_PROFILE, STATE_PROTOCOL_VERSION, ValidatorRegistration,
    },
    state::LedgerState,
};
use naome_pok::{adapters::*, *};
use naome_proof::{ProofCertificate, ProofStep};
use naome_research::{
    formal::{AnswerFile, Outcome},
    state::{Action, ResearchState},
};

fn config() -> Config {
    Config {
        top_k: 2.try_into().unwrap(),
        citation_reward_nao: 2.try_into().unwrap(),
    }
}
fn imported() -> (ResearchImport, QuestionId, [SigningKey; 2]) {
    let (source, question, keys) = support::research();
    (
        ResearchImport::new(&source, config()).unwrap(),
        question,
        keys,
    )
}
fn apply(import: &mut ResearchImport, input: Input) -> Applied {
    let outcome = import
        .core
        .apply(Event {
            id: import.next_event,
            input,
        })
        .unwrap();
    import.next_event.0 += 1;
    outcome
}
fn request(
    question: QuestionId,
    key: &SigningKey,
    certificate: &ProofCertificate,
    submission: u64,
) -> Candidate {
    let checked = normalize_and_check(certificate.clone()).unwrap();
    Candidate {
        submission: SubmissionId(submission),
        question,
        result: checked.statement_id(),
        proof: checked.proof_id(),
        solver: ParticipantId::for_key(key.verifying_key().as_bytes()),
    }
}
fn select(import: &mut ResearchImport, candidate: Candidate, certificate: &ProofCertificate) {
    assert_eq!(apply(import, Input::Submit(candidate)), Applied::Accepted);
    let verified = import
        .verifier
        .verify(candidate, &certificate.to_canonical_bytes())
        .unwrap();
    assert_eq!(
        import
            .verifier
            .apply_verified(&mut import.core, import.next_event, verified)
            .unwrap(),
        Applied::Selected
    );
    import.next_event.0 += 1;
}

#[test]
fn signed_replay_snapshot_imports_full_ids_current_votes_and_native_accounts() {
    let (mut source, question, keys) = support::research();
    let coordinator = SigningKey::from_bytes(&[99; 32]);
    support::confirm(
        &mut source,
        &coordinator,
        &keys[1],
        Action::Vote {
            question: question.0,
            yes: false,
        },
    );
    let replay = ResearchState::replay(source.genesis().clone(), source.events()).unwrap();
    let imported = ResearchImport::new(&replay, config()).unwrap();
    let mut expected: Vec<_> = source.questions().keys().copied().map(QuestionId).collect();
    expected.sort();
    expected.truncate(2);
    assert_eq!(imported.core.top_questions(), expected);
    assert_eq!(imported.research_head, source.head());
    assert_eq!(imported.next_event, EventId(7)); // three questions and three current approvals
    let unknown = Candidate {
        solver: ParticipantId::from_bytes([0; 32]),
        ..request(question, &keys[0], &support::direct(), 1)
    };
    assert_eq!(
        imported
            .verifier
            .verify(unknown, &support::direct().to_canonical_bytes())
            .unwrap_err(),
        AdapterError::UnknownParticipant
    );
}

#[test]
fn real_metric_and_strict_improvement_transfer_future_citations_from_old_proof() {
    let (mut import, question, keys) = imported();
    let first = request(question, &keys[0], &support::detour(), 1);
    select(&mut import, first, &support::detour());
    assert_eq!(
        import.core.current(question).unwrap().verified_steps.get(),
        5
    );
    let citing = import
        .verifier
        .verify_citation(&support::citing(first.proof, 1).to_canonical_bytes())
        .unwrap();
    assert_eq!(citing.verified_steps().get(), 2); // one reference plus one inference
    let before = import.verifier.admit_citation(citing).unwrap()[0];
    apply(&mut import, Input::Cite(before));
    let improved = request(question, &keys[1], &support::direct(), 2);
    select(&mut import, improved, &support::direct());
    assert_eq!(first.result, improved.result);
    assert_eq!(
        import.core.current(question).unwrap().verified_steps.get(),
        2
    );
    let citing = import
        .verifier
        .verify_citation(&support::citing(first.proof, 2).to_canonical_bytes())
        .unwrap();
    let after = import.verifier.admit_citation(citing).unwrap()[0];
    apply(&mut import, Input::Cite(after));
    assert_eq!(apply(&mut import, Input::Cite(after)), Applied::Duplicate);
    let rewards: Vec<_> = import
        .core
        .pending_effects()
        .filter_map(|effect| match effect.kind {
            EffectKind::Reward(reward) => Some(reward),
            _ => None,
        })
        .collect();
    assert_eq!(rewards.len(), 3);
    assert_eq!(rewards[0].amount_nao, 1);
    assert_eq!(rewards[1].beneficiary, first.solver);
    assert_eq!(rewards[2].beneficiary, improved.solver);
}

#[test]
fn mathematical_reference_validity_does_not_admit_a_packaging_improvement() {
    let (mut import, question, keys) = imported();
    let first = request(question, &keys[0], &support::detour(), 1);
    select(&mut import, first, &support::detour());
    let mut context = ArtifactState::new();
    context
        .register_proof(normalize_and_check(support::detour()).unwrap())
        .unwrap();
    let alias = support::citing(first.proof, 0);
    let checked = normalize_and_check_with_state(alias.clone(), &context).unwrap();
    assert_eq!(checked.statement_id(), first.result);
    assert_eq!(
        checked.derivation_id(),
        normalize_and_check(support::detour())
            .unwrap()
            .derivation_id()
    );
    let candidate = Candidate {
        submission: SubmissionId(2),
        proof: checked.proof_id(),
        ..first
    };
    assert!(matches!(
        import
            .verifier
            .verify(candidate, &alias.to_canonical_bytes()),
        Err(AdapterError::Registration(_))
    ));
    assert!(matches!(
        import.verifier.verify_citation(&alias.to_canonical_bytes()),
        Err(AdapterError::Registration(_))
    ));
    assert_eq!(import.core.current(question).unwrap().candidate, first);
}

#[test]
fn inline_reference_partition_is_rejected_and_repeated_direct_references_pay_once() {
    let (mut import, question, keys) = imported();
    let first = request(question, &keys[0], &support::direct(), 1);
    select(&mut import, first, &support::direct());
    let cited = support::citing(first.proof, 1);
    let verified = import
        .verifier
        .verify_citation(&cited.to_canonical_bytes())
        .unwrap();
    import.verifier.admit_citation(verified).unwrap();
    let mut inline = support::direct().steps().to_vec();
    inline.push(ProofStep::Generalization {
        premise: 1,
        variable: FreeVariable::new(100),
    });
    let inline = ProofCertificate::new(inline).unwrap();
    assert!(matches!(
        import
            .verifier
            .verify_citation(&inline.to_canonical_bytes()),
        Err(AdapterError::Registration(_))
    ));
    let repeated = ProofCertificate::new(vec![
        ProofStep::ProofReference {
            proof_id: first.proof,
        },
        ProofStep::ProofReference {
            proof_id: first.proof,
        },
        ProofStep::Simplification {
            antecedent: normalize_and_check(support::direct())
                .unwrap()
                .conclusion()
                .clone()
                .into(),
            consequent: normalize_and_check(support::direct())
                .unwrap()
                .conclusion()
                .clone()
                .into(),
        },
        ProofStep::ModusPonens {
            premise: 0,
            implication: 2,
        },
        ProofStep::ModusPonens {
            premise: 1,
            implication: 3,
        },
    ])
    .unwrap();
    let verified = import
        .verifier
        .verify_citation(&repeated.to_canonical_bytes())
        .unwrap();
    assert_eq!(verified.citations().len(), 1);
    assert_eq!(
        verified.citations()[0].citation.citing_proof,
        verified.proof_id()
    );
    assert_eq!(verified.verified_steps().get(), 4); // normalization coalesces identical references
}

#[test]
fn cached_packaging_variant_cannot_change_selection_or_effects_after_admission() {
    let (source, first_question, keys) = support::research();
    let mut import = ResearchImport::new(&source, config()).unwrap();
    let first = request(first_question, &keys[0], &support::detour(), 1);
    select(&mut import, first, &support::detour());

    let mut inline = support::detour().steps().to_vec();
    inline.push(ProofStep::Generalization {
        premise: 4,
        variable: FreeVariable::new(100),
    });
    let inline = ProofCertificate::new(inline).unwrap();
    let long_checked = normalize_and_check(inline.clone()).unwrap();
    let question = source
        .questions()
        .iter()
        .find(|(_, question)| question.formula().unwrap() == *long_checked.conclusion())
        .map(|(id, _)| QuestionId(*id))
        .unwrap();
    let long = request(question, &keys[0], &inline, 2);
    let referenced = support::citing(first.proof, 1);
    let mut context = ArtifactState::new();
    context
        .register_proof(normalize_and_check(support::detour()).unwrap())
        .unwrap();
    let short_checked = normalize_and_check_with_state(referenced.clone(), &context).unwrap();
    assert_eq!(long_checked.derivation_id(), short_checked.derivation_id());
    assert_ne!(long_checked.proof_id(), short_checked.proof_id());
    let short = Candidate {
        submission: SubmissionId(3),
        proof: short_checked.proof_id(),
        solver: ParticipantId::for_key(keys[1].verifying_key().as_bytes()),
        ..long
    };
    apply(&mut import, Input::Submit(long));
    apply(&mut import, Input::Submit(short));
    // Both packages pass against the same context before either is admitted.
    let long_verified = import
        .verifier
        .verify(long, &inline.to_canonical_bytes())
        .unwrap();
    let short_verified = import
        .verifier
        .verify(short, &referenced.to_canonical_bytes())
        .unwrap();
    assert_eq!(
        long_verified.receipt().verdict,
        Verdict::Valid {
            verified_steps: 6.try_into().unwrap()
        }
    );
    assert_eq!(
        short_verified.receipt().verdict,
        Verdict::Valid {
            verified_steps: 2.try_into().unwrap()
        }
    );
    assert_eq!(
        import
            .verifier
            .apply_verified(&mut import.core, import.next_event, long_verified)
            .unwrap(),
        Applied::Selected
    );
    import.next_event.0 += 1;
    let selected = import.core.current(question);
    let pending: Vec<_> = import.core.pending_effects().copied().collect();
    assert!(matches!(
        import
            .verifier
            .apply_verified(&mut import.core, import.next_event, short_verified),
        Err(AdapterError::Registration(_))
    ));
    assert_eq!(import.core.current(question), selected);
    assert_eq!(
        import.core.pending_effects().copied().collect::<Vec<_>>(),
        pending
    );
    assert_eq!(selected.unwrap().candidate, long);
}

#[test]
fn non_improving_receipt_does_not_publish_or_seed_an_unselected_proof() {
    let (mut import, question, keys) = imported();
    let first = request(question, &keys[0], &support::direct(), 1);
    select(&mut import, first, &support::direct());
    let worse = request(question, &keys[1], &support::detour(), 2);
    apply(&mut import, Input::Submit(worse));
    let verified = import
        .verifier
        .verify(worse, &support::detour().to_canonical_bytes())
        .unwrap();
    assert_eq!(
        import
            .verifier
            .apply_verified(&mut import.core, import.next_event, verified)
            .unwrap(),
        Applied::NotImproved
    );
    assert_eq!(import.core.current(question).unwrap().candidate, first);
    assert_eq!(
        import
            .core
            .pending_effects()
            .filter(|effect| matches!(effect.kind, EffectKind::Publish { .. }))
            .count(),
        1
    );
    assert!(
        import
            .verifier
            .verify(worse, &support::detour().to_canonical_bytes())
            .is_ok()
    );
    assert!(matches!(
        import
            .verifier
            .verify_citation(&support::citing(worse.proof, 1).to_canonical_bytes()),
        Err(AdapterError::Checking(_))
    ));
}

#[test]
fn bad_bytes_unknown_references_wrong_target_and_mismatched_ids_cannot_pass() {
    let (mut import, question, keys) = imported();
    let direct = support::direct();
    let candidate = request(question, &keys[0], &direct, 1);
    let padded = ProofCertificate::new(vec![
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(9),
        },
        ProofStep::EqualityReflexivity {
            variable: FreeVariable::new(0),
        },
        ProofStep::Generalization {
            premise: 1,
            variable: FreeVariable::new(0),
        },
    ])
    .unwrap();
    assert_eq!(
        import
            .verifier
            .verify(candidate, &padded.to_canonical_bytes())
            .unwrap()
            .receipt()
            .verdict,
        Verdict::Valid {
            verified_steps: 2.try_into().unwrap()
        },
    );
    assert!(matches!(
        import.verifier.verify(candidate, b"broken"),
        Err(AdapterError::Certificate(_))
    ));
    let unknown = support::citing(ProofId::from_bytes([8; 32]), 1);
    assert!(matches!(
        import
            .verifier
            .verify_citation(&unknown.to_canonical_bytes()),
        Err(AdapterError::Checking(_))
    ));
    for wrong in [
        Candidate {
            proof: ProofId::from_bytes([9; 32]),
            ..candidate
        },
        Candidate {
            result: ResultId::from_bytes([9; 32]),
            ..candidate
        },
    ] {
        assert_eq!(
            import
                .verifier
                .verify(wrong, &direct.to_canonical_bytes())
                .unwrap_err(),
            AdapterError::IdentityMismatch
        );
    }
    let mut steps = direct.steps().to_vec();
    steps.push(ProofStep::Generalization {
        premise: 1,
        variable: FreeVariable::new(100),
    });
    let other = ProofCertificate::new(steps).unwrap();
    assert_eq!(
        import
            .verifier
            .verify(candidate, &other.to_canonical_bytes())
            .unwrap_err(),
        AdapterError::TargetMismatch
    );
    let verified = import
        .verifier
        .verify(candidate, &direct.to_canonical_bytes())
        .unwrap();
    assert_eq!(
        import
            .verifier
            .apply_verified(&mut import.core, import.next_event, verified),
        Err(AdapterError::Input(InputError::UnknownSubmission))
    );
    assert!(import.core.current(question).is_none());
    assert_eq!(import.core.pending_effects().count(), 0);
    assert!(
        import
            .verifier
            .verify(candidate, &direct.to_canonical_bytes())
            .is_ok()
    );
}

#[test]
fn legacy_answers_seed_references_without_retroactive_question_or_citation_rewards() {
    let (mut source, question, keys) = support::research();
    let coordinator = SigningKey::from_bytes(&[99; 32]);
    support::confirm(&mut source, &coordinator, &coordinator, Action::Tick);
    support::confirm(&mut source, &coordinator, &keys[0], Action::Answer {
        question: question.0, outcome: Outcome::Proof,
        file: AnswerFile { source: "foundation = \"naome:zfc\"\nstatement = forall(x0, equal(x0, x0))\nproof:\n p0 = equality_reflexivity(x0)\n p1 = generalization(p0, x0)\n return p1\n".into(), dependencies: vec![] },
    });
    let import = ResearchImport::new(&source, config()).unwrap();
    assert!(import.core.current(question).is_none());
    assert!(!import.core.top_questions().contains(&question));
    assert_eq!(import.core.pending_effects().count(), 0);
    let proof = normalize_and_check(support::direct()).unwrap().proof_id();
    let verified = import
        .verifier
        .verify_citation(&support::citing(proof, 1).to_canonical_bytes())
        .unwrap();
    assert!(verified.citations().is_empty());
    assert_eq!(
        import
            .verifier
            .verify(
                request(question, &keys[0], &support::detour(), 1),
                &support::detour().to_canonical_bytes()
            )
            .unwrap_err(),
        AdapterError::UnknownQuestion
    );
}

#[test]
fn balance_observation_preserves_exact_ledger_bytes_head_and_atoms() {
    let accounts: Vec<_> = (1..=4)
        .map(|n| SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes())
        .collect();
    let validators: Vec<_> = accounts
        .iter()
        .enumerate()
        .map(|(i, key)| ValidatorRegistration {
            owner: ParticipantId::for_key(key),
            consensus_key: SigningKey::from_bytes(&[100 + i as u8; 32])
                .verifying_key()
                .to_bytes(),
            transport_key: SigningKey::from_bytes(&[200 + i as u8; 32])
                .verifying_key()
                .to_bytes(),
            endpoint: format!("127.0.0.1:{}", 41000 + i),
        })
        .collect();
    let order = validators.iter().map(ValidatorRegistration::id).collect();
    let genesis = Genesis::new(
        Profile::short_test(),
        "naome:zfc".into(),
        STATE_CHECKER_PROFILE.into(),
        STATE_PROTOCOL_VERSION,
        100,
        [9; 32],
        accounts.clone(),
        validators,
        order,
    )
    .unwrap();
    let ledger = LedgerState::new(genesis);
    let before = ledger.canonical_bytes();
    let account = ParticipantId::for_key(&accounts[0]);
    let observation = observe_balance(&ledger, account).unwrap();
    assert_eq!(
        observation,
        BalanceObservation {
            ledger_head: ledger.head(),
            account,
            balance_atoms: ledger.balances().account(account).unwrap()
        }
    );
    assert_eq!(observation.balance_atoms, 0);
    assert!(observe_balance(&ledger, ParticipantId::from_bytes([0; 32])).is_none());
    assert_eq!(ledger.canonical_bytes(), before);
}
