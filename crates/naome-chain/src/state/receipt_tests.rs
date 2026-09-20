use super::test_support::{account, genesis, validator};
use super::*;
use naome_checker::{ArtifactState, check_normal_form_with_state};
use naome_foundation::{Formula, FreeVariable};
use naome_ledger::receipt::*;
use naome_ledger::{AccountId, CommitmentId, PackageHash, library::ProofPackage};
use naome_ledger::{
    LedgerState,
    authentication::SignedOperation,
    operations::{OperationBody, SignedOriginal},
    question::CompiledQuestion,
    state::FamilyResult,
    time::{SignedTimeReport, TimeCertificate},
};
use naome_proof::ProofId;
use naome_proof::{ProofCertificate, ProofStep};

fn author(index: u8) -> AccountId {
    AccountId::for_key(account(index).verifying_key().as_bytes())
}
fn apply(state: &mut LedgerState, ops: Vec<SignedOperation>, deadline: bool) {
    let utc = if deadline {
        state.active().unwrap().deadline.unwrap()
    } else {
        state.time()
    };
    let time = TimeCertificate::new(
        (0..3)
            .map(|i| {
                SignedTimeReport::sign(
                    state.genesis(),
                    state.head(),
                    state.height() + 1,
                    utc,
                    &validator(i),
                )
                .unwrap()
            })
            .collect(),
        state.genesis(),
        state.head(),
        state.height() + 1,
        state.time(),
    )
    .unwrap();
    *state = state.prepare_record(time, ops).unwrap().into_state();
}
fn action(state: &LedgerState, index: u8, body: OperationBody) -> SignedOperation {
    body.sign(
        state.genesis(),
        state.next_nonce(author(index)).unwrap(),
        &account(index),
    )
    .unwrap()
}
fn checked(steps: Vec<ProofStep>, context: &mut ArtifactState) -> (ProofId, Vec<u8>) {
    let proof = check_normal_form_with_state(
        ProofCertificate::new(steps)
            .unwrap()
            .into_unchecked_normal_form(),
        context,
    )
    .unwrap();
    let node = (
        proof.proof_id(),
        proof.normal_form().canonical_bytes().to_vec(),
    );
    context.register_proof(proof).unwrap();
    node
}
fn settle(
    state: &mut LedgerState,
    index: u8,
    formula: &str,
    nodes: Vec<(ProofId, Vec<u8>)>,
    root: ProofId,
) -> (Vec<u8>, PackageHash) {
    let question = CompiledQuestion::compile(
        &format!("foundation = \"naome:zfc\"\nstatement = {formula}\n"),
        state.genesis().profile(),
    )
    .unwrap();
    let family = question.resolution_id();
    let op = action(
        state,
        index,
        OperationBody::Submit {
            purpose: "receipt inspection test".into(),
            question,
        },
    );
    apply(state, vec![op], false);
    apply(state, vec![], false);
    let active = state.active().unwrap();
    let votes = (0..3)
        .map(|i| {
            action(
                state,
                i,
                OperationBody::Vote {
                    question: active.question,
                    attempt: active.number,
                    yes: true,
                },
            )
        })
        .collect();
    apply(state, votes, false);
    apply(state, vec![], true);
    apply(state, vec![], false);
    let round = state.active().unwrap().solution_round.unwrap();
    let package = ProofPackage::new(author(index), root, nodes, state.genesis().profile()).unwrap();
    let original = SignedOriginal::sign(state.genesis(), round, package, &account(index)).unwrap();
    let original_hash = original.original_hash();
    let secret = [42; 32];
    let commitment = CommitmentId::for_original(
        state.genesis(),
        round,
        author(index),
        original_hash,
        &secret,
    );
    let op = action(state, index, OperationBody::Commit { round, commitment });
    apply(state, vec![op], false);
    apply(state, vec![], true);
    apply(state, vec![], false);
    let op = action(
        state,
        index,
        OperationBody::Reveal {
            round,
            secret,
            original,
        },
    );
    apply(state, vec![op], false);
    apply(state, vec![], true);
    apply(state, vec![], false);
    let FamilyResult::Completed {
        normalization_receipt,
        ..
    } = state.families().get(&family).unwrap()
    else {
        panic!("settlement must complete")
    };
    (normalization_receipt.to_vec(), original_hash)
}

#[test]
fn receipt_reads_actual_settlements_and_rejects_truncation_and_reward_mutations() {
    let mut state = LedgerState::new(genesis());
    let x = FreeVariable::new(0);
    let mut context = ArtifactState::new();
    let h = checked(
        vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ],
        &mut context,
    );
    let a = checked(
        vec![
            ProofStep::ProofReference { proof_id: h.0 },
            ProofStep::Generalization {
                premise: 0,
                variable: x,
            },
        ],
        &mut context,
    );
    let (bytes, original_hash) = settle(
        &mut state,
        4,
        "forall(y,forall(x,equal(x,x)))",
        vec![h.clone(), a.clone()],
        a.0,
    );
    let receipt = NormalizationReceipt::decode(&bytes, state.genesis()).unwrap();
    assert_eq!(receipt.original_hash, original_hash);
    assert_eq!(receipt.author, author(4));
    assert_eq!(receipt.root, a.0);
    assert_eq!(receipt.new_proofs.len(), 2);
    assert!(receipt.citations.is_empty());
    assert_eq!(receipt.rewards.credits()[&author(4)], 700_000_000);
    for cut in 0..bytes.len() {
        assert!(
            NormalizationReceipt::decode(&bytes[..cut], state.genesis()).is_err(),
            "cut {cut}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(NormalizationReceipt::decode(&trailing, state.genesis()).is_err());
    let mut bad = bytes.clone();
    bad[2] ^= 1;
    assert!(NormalizationReceipt::decode(&bad, state.genesis()).is_err());
    let mut bad = bytes.clone();
    bad[278..282].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(NormalizationReceipt::decode(&bad, state.genesis()).is_err());
    let mut context = ArtifactState::new();
    let equality = Formula::equal(x, x);
    let duplicate = checked(
        vec![
            ProofStep::EqualityReflexivity { variable: x },
            ProofStep::Simplification {
                antecedent: equality.clone().into(),
                consequent: equality.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 2,
            },
            ProofStep::Generalization {
                premise: 3,
                variable: x,
            },
        ],
        &mut context,
    );
    assert_ne!(duplicate.0, h.0);
    let formula = Formula::for_all(x, Formula::equal(x, x));
    let b = checked(
        vec![
            ProofStep::ProofReference {
                proof_id: duplicate.0,
            },
            ProofStep::Simplification {
                antecedent: formula.clone().into(),
                consequent: formula.into(),
            },
            ProofStep::ModusPonens {
                premise: 0,
                implication: 1,
            },
        ],
        &mut context,
    );
    let (bytes, _) = settle(
        &mut state,
        5,
        "not_(implies(forall(x,equal(x,x)),forall(y,equal(y,y))))",
        vec![duplicate.clone(), b.clone()],
        b.0,
    );
    let receipt = NormalizationReceipt::decode(&bytes, state.genesis()).unwrap();
    // Canonical substitution ordering rejects duplicate old IDs before any
    // attacker-supplied package length is considered.
    let mut duplicate_mapping = bytes.clone();
    duplicate_mapping[278..282].copy_from_slice(&2u32.to_be_bytes());
    duplicate_mapping.splice(282..282, bytes[282..346].iter().copied());
    assert!(NormalizationReceipt::decode(&duplicate_mapping, state.genesis()).is_err());
    for offset in [98, 246] {
        let mut altered = bytes.clone();
        altered[offset] ^= 1;
        assert!(NormalizationReceipt::decode(&altered, state.genesis()).is_err());
    }
    assert_eq!(receipt.substitutions.get(&duplicate.0), Some(&h.0));
    assert_ne!(receipt.root, b.0);
    assert_eq!(receipt.citations, vec![(h.0, author(4))]);
    assert_eq!(
        receipt.rewards.citations(),
        &[(h.0, author(4), 100_000_000)]
    );
    assert_eq!(receipt.rewards.credits()[&author(5)], 600_000_000);
    // Fixed canonical widths: genesis, credit count/entries, reserve, citation count/entries.
    let reward_len = 32
        + 4
        + 48 * receipt.rewards.credits().len()
        + 16
        + 4
        + 80 * receipt.rewards.citations().len();
    for offset in bytes.len() - reward_len..bytes.len() {
        let mut mutated = bytes.clone();
        mutated[offset] ^= 1;
        assert!(
            NormalizationReceipt::decode(&mutated, state.genesis()).is_err(),
            "reward offset {offset}"
        );
    }
}

#[test]
fn rendered_closed_targets_round_trip_without_changing_canonical_formula() {
    let profile = naome_ledger::profile::Profile::short_test();
    for source in [
        "forall(x,forall(y,implies(member(x,y),not_(equal(y,x)))))",
        "not_(forall(x,forall(y,equal(y,y))))",
        "implies(forall(x,equal(x,x)),forall(y,equal(y,y)))",
    ] {
        let question = CompiledQuestion::compile(
            &format!("foundation = \"naome:zfc\"\nstatement = {source}\n"),
            &profile,
        )
        .unwrap();
        for target in [question.proved_target(), question.refuted_target()] {
            let rendered = target.to_source();
            let parsed = CompiledQuestion::compile(
                &format!("foundation = \"naome:zfc\"\nstatement = {rendered}\n"),
                &profile,
            )
            .unwrap();
            // CompiledQuestion removes leading negation to produce a shared
            // core; either exact target still reconstructs the same family.
            assert_eq!(parsed.resolution_id(), question.resolution_id());
            assert!(parsed.proved_target() == target || parsed.refuted_target() == target);
        }
    }
}
