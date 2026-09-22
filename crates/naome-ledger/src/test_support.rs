use crate::{
    AccountId,
    profile::{Genesis, Profile, ValidatorRegistration},
};
use ed25519_dalek::SigningKey;

pub(crate) fn account(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[index + 1; 32])
}
pub(crate) fn validator(index: u8) -> SigningKey {
    SigningKey::from_bytes(&[index + 101; 32])
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
