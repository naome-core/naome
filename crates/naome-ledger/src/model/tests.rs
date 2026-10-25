use super::*;
use crate::{
    State,
    test_support::{genesis, key},
};

#[test]
fn amounts_are_exact_and_reject_fractional_ambiguous_or_overflowing_values() {
    assert_eq!(
        "18446744073709551615".parse::<Amount>().unwrap().units(),
        u64::MAX
    );
    assert_eq!("0".parse::<Amount>().unwrap().units(), 0);
    for text in [
        "",
        "-1",
        "+1",
        "01",
        "1.0",
        "1e3",
        " 1",
        "18446744073709551616",
    ] {
        assert!(text.parse::<Amount>().is_err(), "{text}");
    }
    assert_eq!(
        Amount::from_units(u64::MAX).checked_add(Amount::from_units(1)),
        Err(Error::AmountOverflow)
    );
    assert_eq!(
        Amount::from_units(0).checked_sub(Amount::from_units(1)),
        Err(Error::AmountOverflow)
    );
    assert!(serde_json::from_str::<Amount>("1.1").is_err());
    assert!(serde_json::from_str::<Amount>("-1").is_err());
    let mut invalid = genesis();
    invalid.outputs.push(Output {
        address: key().address(),
        amount: Amount::from_units(u64::MAX),
    });
    assert_eq!(invalid.network(), Err(Error::AmountOverflow));
}

#[test]
fn canonical_network_and_payment_ids_have_independently_encoded_vectors() {
    let genesis = genesis();
    // Expected digests are independently encoded from the documented byte layout.
    assert_eq!(
        genesis.network().unwrap().to_string(),
        "6c8bef4bc1626c8570c631bec0f2c5d2e4c108e5d235d6f8ac9e520726ea5259"
    );
    let state = State::new(&genesis).unwrap();
    let payment = state
        .payment(
            key().address(),
            &key(),
            key().address(),
            Amount::from_units(300),
        )
        .unwrap();
    assert_eq!(
        payment.id().unwrap().to_string(),
        "0d95b571cffc0612e28876549de7564fb2f536b79ab227fcf6565d9fa01364a3"
    );
    let encoded = serde_json::to_vec(&payment).unwrap();
    assert_eq!(
        serde_json::from_slice::<SignedTransaction>(&encoded).unwrap(),
        payment
    );
    let mut changed = payment.clone();
    changed.network = NetworkId::from_bytes([0; 32]);
    assert_eq!(changed.verify_signature(), Err(Error::InvalidSignature));
    changed = payment;
    changed.version = 2;
    assert!(changed.verify_signature().is_err());
}

#[test]
fn record_shapes_are_bounded_and_do_not_accept_extra_fields_or_zero_outputs() {
    let state = State::new(&genesis()).unwrap();
    let key = key();
    let signed = state
        .payment(key.address(), &key, key.address(), Amount::from_units(1))
        .unwrap();
    let Operation::Payment {
        owner,
        authorization,
        inputs,
        mut outputs,
    } = signed.operation
    else {
        panic!()
    };
    outputs[0].amount = Amount::from_units(0);
    assert!(
        SignedTransaction::sign(
            state.network(),
            Operation::Payment {
                owner,
                authorization,
                inputs: inputs.clone(),
                outputs
            },
            &key
        )
        .is_err()
    );
    let output = Output {
        address: key.address(),
        amount: Amount::from_units(1),
    };
    for inputs in [vec![], vec![inputs[0]; MAX_ITEMS + 1]] {
        assert_eq!(
            SignedTransaction::sign(
                state.network(),
                Operation::Payment {
                    owner,
                    authorization,
                    inputs,
                    outputs: vec![output.clone()]
                },
                &key
            )
            .unwrap_err(),
            Error::Capacity
        );
    }
    let mut value = serde_json::to_value(genesis()).unwrap();
    value["mint"] = serde_json::json!(100);
    assert!(serde_json::from_value::<Genesis>(value).is_err());
}
