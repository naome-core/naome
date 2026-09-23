use crate::{
    AccountId,
    authority::{HandoffPlan, NextPeriodKeys},
    profile::{Genesis, Profile, ValidatorRegistration},
    state::LedgerState,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

pub(crate) fn account(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[index + 1; 32])
}
pub(crate) fn validator(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[index + 101; 32])
}
pub(crate) fn period_key(index: u8, height: u64, role: u8) -> SigningKey {
    if height == 1 {
        return if role == 1 {
            validator(index)
        } else {
            SigningKey::from_bytes(&[index + 201; 32])
        };
    }
    let mut hash = Sha256::new();
    hash.update(b"naome:test:period-key\0");
    hash.update([index, role]);
    hash.update(height.to_be_bytes());
    SigningKey::from_bytes(&hash.finalize().into())
}
pub(crate) fn handoff_plan(state: &LedgerState) -> HandoffPlan {
    let mut offers = Vec::new();
    let next_height = state.authority().effective_height() + 1;
    for unit in state.authority().units() {
        let index = (0..6)
            .find(|i| AccountId::for_key(account(*i).verifying_key().as_bytes()) == unit.owner())
            .unwrap();
        offers.push(
            NextPeriodKeys::sign(
                state.authority(),
                state.head(),
                state.commitment(),
                unit.id(),
                &account(index),
                &period_key(index, next_height, 1),
                &period_key(index, next_height, 2),
                format!("127.0.0.1:{}", 41000 + u16::from(index)),
            )
            .unwrap(),
        );
    }
    offers.sort_by_key(NextPeriodKeys::unit);
    HandoffPlan::new(offers, None).unwrap()
}

pub(crate) fn genesis() -> Genesis {
    genesis_with_profile(Profile::short_test())
}
pub(crate) fn genesis_with_profile(profile: Profile) -> Genesis {
    let retirement_registrations: Vec<_> = (0..4)
        .map(|i| ValidatorRegistration {
            owner: AccountId::for_key(account(i).verifying_key().as_bytes()),
            consensus_key: validator(i).verifying_key().to_bytes(),
            transport_key: SigningKey::from_bytes(&[i + 201; 32])
                .verifying_key()
                .to_bytes(),
            endpoint: format!("127.0.0.1:{}", 41000 + u16::from(i)),
        })
        .collect();
    let retirement_order = [2, 0, 3, 1]
        .map(|i| retirement_registrations[i].id())
        .to_vec();
    Genesis::new(
        profile,
        "naome:zfc".into(),
        crate::profile::STATE_CHECKER_PROFILE.into(),
        crate::profile::STATE_PROTOCOL_VERSION,
        100,
        [9; 32],
        (0..6)
            .map(|i| account(i).verifying_key().to_bytes())
            .collect(),
        retirement_registrations,
        retirement_order,
    )
    .unwrap()
}
