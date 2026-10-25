use super::*;
use crate::test_support::{genesis, key};

#[test]
fn payments_conserve_value_make_change_and_reject_conflicting_spends_without_mutation() {
    let alice = key();
    let bob = WalletKey::generate().unwrap();
    let mut state = State::new(&genesis()).unwrap();
    let payment = state
        .payment(
            alice.address(),
            &alice,
            bob.address(),
            Amount::from_units(300),
        )
        .unwrap();
    state.apply(&payment).unwrap();
    assert_eq!(state.balance(alice.address()).unwrap().units(), 700);
    assert_eq!(state.balance(bob.address()).unwrap().units(), 300);
    assert_eq!(state.supply().units(), 1000);
    let after = state.clone();
    assert_eq!(state.apply(&payment), Err(Error::MissingInput));
    assert_eq!(state, after);
    let back = state
        .payment(
            bob.address(),
            &bob,
            alice.address(),
            Amount::from_units(200),
        )
        .unwrap();
    state.apply(&back).unwrap();
    assert_eq!(state.balance(alice.address()).unwrap().units(), 900);
    assert_eq!(state.balance(bob.address()).unwrap().units(), 100);
}

#[test]
fn invalid_signature_network_owner_duplicate_input_and_creation_of_value_are_rejected() {
    let alice = key();
    let bob = WalletKey::generate().unwrap();
    let mut state = State::new(&genesis()).unwrap();
    let original = state.clone();
    let payment = state
        .payment(
            alice.address(),
            &alice,
            bob.address(),
            Amount::from_units(300),
        )
        .unwrap();
    let mut wrong = payment.clone();
    wrong.network = NetworkId::from_bytes([0; 32]);
    assert_eq!(state.apply(&wrong), Err(Error::WrongNetwork));
    wrong = payment.clone();
    wrong.signer = bob.address();
    assert_eq!(state.apply(&wrong), Err(Error::InvalidSignature));
    let Operation::Payment {
        owner,
        authorization,
        inputs,
        outputs,
    } = payment.operation.clone()
    else {
        panic!()
    };
    let unauthorized = SignedTransaction::sign(state.network(), payment.operation, &bob).unwrap();
    assert_eq!(state.apply(&unauthorized), Err(Error::Unauthorized));
    let duplicate = SignedTransaction::sign(
        state.network(),
        Operation::Payment {
            owner,
            authorization,
            inputs: vec![inputs[0]; 2],
            outputs: outputs.clone(),
        },
        &alice,
    )
    .unwrap();
    assert_eq!(state.apply(&duplicate), Err(Error::DuplicateInput));
    let mut inflation = outputs.clone();
    inflation[0].amount = Amount::from_units(301);
    let inflated = SignedTransaction::sign(
        state.network(),
        Operation::Payment {
            owner,
            authorization,
            inputs: inputs.clone(),
            outputs: inflation,
        },
        &alice,
    )
    .unwrap();
    assert_eq!(state.apply(&inflated), Err(Error::ValueMismatch));
    let mut forged_input = inputs;
    forged_input[0].index = 42;
    let missing = SignedTransaction::sign(
        state.network(),
        Operation::Payment {
            owner,
            authorization,
            inputs: forged_input,
            outputs,
        },
        &alice,
    )
    .unwrap();
    assert_eq!(state.apply(&missing), Err(Error::MissingInput));
    assert_eq!(state, original);
}

#[test]
fn several_nodes_share_one_wallet_with_individual_revocation_and_no_delegation_of_authority() {
    let owner = key();
    let first = WalletKey::generate().unwrap();
    let second = WalletKey::generate().unwrap();
    let recipient = WalletKey::generate().unwrap();
    let mut state = State::new(&genesis()).unwrap();
    assert_eq!(
        state.payment(
            owner.address(),
            &first,
            recipient.address(),
            Amount::from_units(1)
        ),
        Err(Error::Unauthorized)
    );
    for node in [&first, &second] {
        let grant = state
            .access_change(owner.address(), &owner, node.address(), true)
            .unwrap();
        state.apply(&grant).unwrap();
    }
    assert_eq!(state.authorized_nodes(owner.address()).len(), 2);
    assert_eq!(
        state.access_change(owner.address(), &first, recipient.address(), true),
        Err(Error::Unauthorized)
    );
    let first_spend = state
        .payment(
            owner.address(),
            &first,
            recipient.address(),
            Amount::from_units(100),
        )
        .unwrap();
    let conflicting = state
        .payment(
            owner.address(),
            &second,
            recipient.address(),
            Amount::from_units(200),
        )
        .unwrap();
    state.apply(&first_spend).unwrap();
    assert_eq!(state.apply(&conflicting), Err(Error::MissingInput));
    let old = state
        .payment(
            owner.address(),
            &first,
            recipient.address(),
            Amount::from_units(100),
        )
        .unwrap();
    let revoke = state
        .access_change(owner.address(), &owner, first.address(), false)
        .unwrap();
    state.apply(&revoke).unwrap();
    assert_eq!(state.apply(&old), Err(Error::Unauthorized));
    assert_eq!(state.apply(&revoke), Err(Error::InvalidSequence));
    let regrant = state
        .access_change(owner.address(), &owner, first.address(), true)
        .unwrap();
    state.apply(&regrant).unwrap();
    assert_eq!(
        state.apply(&old),
        Err(Error::Unauthorized),
        "regrant must not revive old signed payments"
    );
    let self_revoke = state
        .access_change(owner.address(), &first, first.address(), false)
        .unwrap();
    state.apply(&self_revoke).unwrap();
    assert!(
        state
            .spending_authority(owner.address(), first.address())
            .is_none()
    );
    assert!(
        state
            .spending_authority(owner.address(), second.address())
            .is_some()
    );
    let payment = state
        .payment(
            owner.address(),
            &second,
            recipient.address(),
            Amount::from_units(200),
        )
        .unwrap();
    state.apply(&payment).unwrap();
    assert_eq!(state.balance(owner.address()).unwrap().units(), 700);
    assert_eq!(state.balance(recipient.address()).unwrap().units(), 300);
}

#[test]
fn the_journal_root_commits_to_order_even_for_independent_payments() {
    let alice = key();
    let bob = WalletKey::generate().unwrap();
    let mut genesis = genesis();
    genesis.outputs.push(Output {
        address: bob.address(),
        amount: Amount::from_units(500),
    });
    let initial = State::new(&genesis).unwrap();
    let first = initial
        .payment(
            alice.address(),
            &alice,
            bob.address(),
            Amount::from_units(100),
        )
        .unwrap();
    let second = initial
        .payment(
            bob.address(),
            &bob,
            alice.address(),
            Amount::from_units(200),
        )
        .unwrap();
    let mut forward = initial.clone();
    let mut reverse = initial;
    forward.apply(&first).unwrap();
    forward.apply(&second).unwrap();
    reverse.apply(&second).unwrap();
    reverse.apply(&first).unwrap();
    assert_eq!(forward.utxos, reverse.utxos);
    assert_eq!(forward.supply(), reverse.supply());
    assert_ne!(forward.journal_root(), reverse.journal_root());
}
