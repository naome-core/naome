//! Account-authorized, fresh-key-proven offer for an exact future period.

use super::*;
use ed25519_dalek::{Signature, Signer, SigningKey};

const MAGIC: &[u8; 5] = b"NSKO5";
const OWNER_DOMAIN: &[u8] = b"naome:state:period-owner-offer:v5\0";
const CONSENSUS_DOMAIN: &[u8] = b"naome:state:period-consensus-possession:v5\0";
const TRANSPORT_DOMAIN: &[u8] = b"naome:state:period-transport-possession:v5\0";
const MAX_BYTES: usize = 5 + 32 + 32 + 32 + 32 + 8 + 32 + 32 + 4 + 128 + 3 * 64;

/// An owner proposes fresh credentials for one unit. The exact sealed
/// predecessor still decides whether this offer is selected; this object
/// cannot establish that old key material was destroyed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NextPeriodKeys {
    unit: AuthorityUnitId,
    parent_snapshot: [u8; 32],
    parent_record: RecordId,
    parent_state: StateCommitment,
    effective_height: u64,
    keys: PeriodKeys,
    owner_signature: [u8; 64],
    consensus_proof: [u8; 64],
    transport_proof: [u8; 64],
}
impl NextPeriodKeys {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        snapshot: &AuthoritySnapshot,
        parent_record: RecordId,
        parent_state: StateCommitment,
        unit: AuthorityUnitId,
        owner: &SigningKey,
        consensus: &SigningKey,
        transport: &SigningKey,
        endpoint: String,
    ) -> Result<Self, LedgerError> {
        let member = snapshot
            .unit(unit)
            .ok_or(LedgerError::Invalid("period offer unit"))?;
        if AccountId::for_key(owner.verifying_key().as_bytes()) != member.owner {
            return Err(LedgerError::Invalid("period offer owner"));
        }
        let mut offer = Self {
            unit,
            parent_snapshot: snapshot.id(),
            parent_record,
            parent_state,
            effective_height: snapshot
                .effective_height
                .checked_add(1)
                .ok_or(LedgerError::Overflow)?,
            keys: PeriodKeys::new(
                consensus.verifying_key().to_bytes(),
                transport.verifying_key().to_bytes(),
                endpoint,
            )?,
            owner_signature: [0; 64],
            consensus_proof: [0; 64],
            transport_proof: [0; 64],
        };
        let body = offer.unsigned_bytes();
        offer.owner_signature = owner.sign(&role_message(OWNER_DOMAIN, &body)).to_bytes();
        offer.consensus_proof = consensus
            .sign(&role_message(CONSENSUS_DOMAIN, &body))
            .to_bytes();
        offer.transport_proof = transport
            .sign(&role_message(TRANSPORT_DOMAIN, &body))
            .to_bytes();
        Ok(offer)
    }
    pub const fn unit(&self) -> AuthorityUnitId {
        self.unit
    }
    pub const fn effective_height(&self) -> u64 {
        self.effective_height
    }
    pub fn keys(&self) -> &PeriodKeys {
        &self.keys
    }
    pub fn verify(
        &self,
        snapshot: &AuthoritySnapshot,
        parent_record: RecordId,
        parent_state: StateCommitment,
        effective_height: u64,
        owner_key: [u8; 32],
    ) -> Result<(), LedgerError> {
        let member = snapshot
            .unit(self.unit)
            .ok_or(LedgerError::Invalid("period offer unit"))?;
        if self.parent_snapshot != snapshot.id()
            || self.parent_record != parent_record
            || self.parent_state != parent_state
            || self.effective_height != effective_height
            || effective_height
                != snapshot
                    .effective_height
                    .checked_add(1)
                    .ok_or(LedgerError::Overflow)?
            || AccountId::for_key(&owner_key) != member.owner
        {
            return Err(LedgerError::Invalid("period offer context"));
        }
        self.keys.validate()?;
        let body = self.unsigned_bytes();
        for (key, signature, domain) in [
            (&owner_key, &self.owner_signature, OWNER_DOMAIN),
            (
                &self.keys.consensus,
                &self.consensus_proof,
                CONSENSUS_DOMAIN,
            ),
            (
                &self.keys.transport,
                &self.transport_proof,
                TRANSPORT_DOMAIN,
            ),
        ] {
            let key = VerifyingKey::from_bytes(key)
                .map_err(|_| LedgerError::Invalid("period offer Ed25519 key"))?;
            if key.is_weak() {
                return Err(LedgerError::Invalid("weak period offer key"));
            }
            key.verify_strict(
                &role_message(domain, &body),
                &Signature::from_bytes(signature),
            )
            .map_err(|_| LedgerError::Invalid("period offer signature"))?;
        }
        Ok(())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = self.unsigned_bytes();
        encoded.extend_from_slice(&self.owner_signature);
        encoded.extend_from_slice(&self.consensus_proof);
        encoded.extend_from_slice(&self.transport_proof);
        encoded
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut r = Reader::new(bytes, MAX_BYTES)?;
        if r.fixed::<5>()? != *MAGIC {
            return Err(LedgerError::Invalid("period offer version"));
        }
        let result = Self {
            unit: AuthorityUnitId::from_bytes(r.fixed()?),
            parent_snapshot: r.fixed()?,
            parent_record: RecordId::from_bytes(r.fixed()?),
            parent_state: StateCommitment::from_bytes(r.fixed()?),
            effective_height: r.u64()?,
            keys: PeriodKeys::new(
                r.fixed()?,
                r.fixed()?,
                r.string(ENDPOINT_MAX_BYTES)?.to_owned(),
            )?,
            owner_signature: r.fixed()?,
            consensus_proof: r.fixed()?,
            transport_proof: r.fixed()?,
        };
        r.finish()?;
        if result.effective_height == 0 {
            return Err(LedgerError::Invalid("zero period offer height"));
        }
        Ok(result)
    }
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(MAGIC);
        w.fixed(self.unit.as_bytes());
        w.fixed(&self.parent_snapshot);
        w.fixed(self.parent_record.as_bytes());
        w.fixed(self.parent_state.as_bytes());
        w.u64(self.effective_height);
        w.fixed(&self.keys.consensus);
        w.fixed(&self.keys.transport);
        w.string(&self.keys.endpoint).expect("validated endpoint");
        w.finish()
    }
}

fn role_message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{account, genesis, validator};

    #[test]
    fn future_offer_requires_exact_owner_parent_and_next_keys() {
        let genesis = genesis();
        let snapshot = AuthoritySnapshot::from_genesis(&genesis).unwrap();
        let first = &snapshot.units()[0];
        let owner_key = (0..4)
            .map(account)
            .find(|key| AccountId::for_key(key.verifying_key().as_bytes()) == first.owner())
            .unwrap();
        let consensus = SigningKey::from_bytes(&[61; 32]);
        let transport = SigningKey::from_bytes(&[62; 32]);
        let record = RecordId::from_bytes([7; 32]);
        let state = StateCommitment::from_bytes([8; 32]);
        let offer = NextPeriodKeys::sign(
            &snapshot,
            record,
            state,
            first.id(),
            &owner_key,
            &consensus,
            &transport,
            "127.0.0.1:50001".into(),
        )
        .unwrap();
        let bytes = offer.encode();
        let decoded = NextPeriodKeys::decode(&bytes).unwrap();
        for end in 0..bytes.len() {
            assert!(NextPeriodKeys::decode(&bytes[..end]).is_err());
        }
        decoded
            .verify(
                &snapshot,
                record,
                state,
                2,
                owner_key.verifying_key().to_bytes(),
            )
            .unwrap();
        assert!(
            decoded
                .verify(
                    &snapshot,
                    record,
                    state,
                    3,
                    owner_key.verifying_key().to_bytes()
                )
                .is_err()
        );
        assert!(
            decoded
                .verify(
                    &snapshot,
                    RecordId::from_bytes([9; 32]),
                    state,
                    2,
                    owner_key.verifying_key().to_bytes()
                )
                .is_err()
        );
        assert!(
            decoded
                .verify(
                    &snapshot,
                    record,
                    StateCommitment::from_bytes([9; 32]),
                    2,
                    owner_key.verifying_key().to_bytes()
                )
                .is_err()
        );
        assert!(
            decoded
                .verify(
                    &snapshot,
                    record,
                    state,
                    2,
                    SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes()
                )
                .is_err()
        );
        let mut exchanged = decoded.clone();
        std::mem::swap(
            &mut exchanged.consensus_proof,
            &mut exchanged.transport_proof,
        );
        assert!(
            exchanged
                .verify(
                    &snapshot,
                    record,
                    state,
                    2,
                    owner_key.verifying_key().to_bytes()
                )
                .is_err()
        );
        let forbidden = snapshot
            .units()
            .iter()
            .flat_map(|unit| {
                unit.keys()
                    .into_iter()
                    .flat_map(|keys| [*keys.consensus(), *keys.transport()])
            })
            .collect();
        let mut offers = snapshot
            .units()
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, unit)| {
                let owner = (0..4)
                    .map(account)
                    .find(|key| AccountId::for_key(key.verifying_key().as_bytes()) == unit.owner())
                    .unwrap();
                NextPeriodKeys::sign(
                    &snapshot,
                    record,
                    state,
                    unit.id(),
                    &owner,
                    &SigningKey::from_bytes(&[61 + index as u8 * 2; 32]),
                    &SigningKey::from_bytes(&[62 + index as u8 * 2; 32]),
                    format!("127.0.0.1:{}", 50001 + index),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        offers.sort_by_key(NextPeriodKeys::unit);
        assert!(
            snapshot
                .successor(record, state, &offers[..2], |_| None, &forbidden)
                .is_err()
        );
        let next = snapshot
            .successor(
                record,
                state,
                &offers,
                |owner| {
                    (0..4)
                        .map(account)
                        .find(|key| AccountId::for_key(key.verifying_key().as_bytes()) == owner)
                        .map(|key| key.verifying_key().to_bytes())
                },
                &forbidden,
            )
            .unwrap();
        assert_eq!(next.effective_height(), 2);
        assert_eq!(
            next.units()
                .iter()
                .filter(|unit| unit.keys().is_some())
                .count(),
            3
        );
        // The snapshot must defend its own current and owner keys even if a
        // selected-state caller accidentally supplies an empty history set.
        let member = snapshot.unit(offers[0].unit()).unwrap();
        let owner = (0..4)
            .map(account)
            .find(|key| AccountId::for_key(key.verifying_key().as_bytes()) == member.owner())
            .unwrap();
        let old = (0..4)
            .map(validator)
            .find(|key| key.verifying_key().as_bytes() == member.keys().unwrap().consensus())
            .unwrap();
        for consensus in [&old, &owner] {
            let mut reused = offers.clone();
            reused[0] = NextPeriodKeys::sign(
                &snapshot,
                record,
                state,
                member.id(),
                &owner,
                consensus,
                &SigningKey::from_bytes(&[90; 32]),
                offers[0].keys().endpoint().to_owned(),
            )
            .unwrap();
            assert!(
                snapshot
                    .successor(
                        record,
                        state,
                        &reused,
                        |owner| {
                            (0..4)
                                .map(account)
                                .find(|key| {
                                    AccountId::for_key(key.verifying_key().as_bytes()) == owner
                                })
                                .map(|key| key.verifying_key().to_bytes())
                        },
                        &BTreeSet::new(),
                    )
                    .is_err()
            );
        }
        let mut forbidden = forbidden;
        forbidden.insert(*offers[0].keys().consensus());
        assert!(
            snapshot
                .successor(
                    record,
                    state,
                    &offers,
                    |owner| {
                        (0..4)
                            .map(account)
                            .find(|key| AccountId::for_key(key.verifying_key().as_bytes()) == owner)
                            .map(|key| key.verifying_key().to_bytes())
                    },
                    &forbidden
                )
                .is_err()
        );
    }
}
