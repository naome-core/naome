//! Stable voting units and the public keys usable in one signing period.
//!
//! A missing key binding leaves the unit's weight in the four-unit denominator.
//! The account owner can authorize a key for a future seal, never retroactively
//! for this snapshot. Sealed-history verification grants authority separately.

use crate::{
    AccountId, AuthoritySlotId, AuthorityUnitId, GenesisId, LedgerError, RecordId, ResolutionId,
    StateCommitment, ValidatorId,
    codec::{Reader, Writer},
    identity::hash,
    profile::Genesis,
};
use ed25519_dalek::VerifyingKey;
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

mod offer;
pub use offer::NextPeriodKeys;
mod plan;
pub use plan::{CandidateAdmissionOffer, HANDOFF_PLAN_MAX_BYTES, HandoffPlan};

const MAGIC: &[u8; 5] = b"NSAU5";
const MAX_BYTES: usize = 5 + 32 + 8 + 1 + 4 * (32 + 32 + 32 + 1 + 32 + 8 + 1 + 32 + 32 + 4 + 128);
const ENDPOINT_MAX_BYTES: usize = 128;

/// Original contribution order. Every bootstrap unit precedes every earned one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnitOrigin {
    Bootstrap {
        validator: ValidatorId,
        retirement_rank: u8,
    },
    Earned {
        family: ResolutionId,
        completion_ordinal: u64,
    },
}
impl UnitOrigin {
    pub fn id(self) -> AuthorityUnitId {
        match self {
            Self::Bootstrap { validator, .. } => AuthorityUnitId::for_bootstrap(validator),
            Self::Earned { family, .. } => AuthorityUnitId::for_claim(family),
        }
    }
    pub fn older_than(self, other: Self) -> bool {
        match (self, other) {
            (
                Self::Bootstrap {
                    retirement_rank: left,
                    ..
                },
                Self::Bootstrap {
                    retirement_rank: right,
                    ..
                },
            ) => left < right,
            (Self::Bootstrap { .. }, Self::Earned { .. }) => true,
            (Self::Earned { .. }, Self::Bootstrap { .. }) => false,
            (
                Self::Earned {
                    completion_ordinal: left,
                    ..
                },
                Self::Earned {
                    completion_ordinal: right,
                    ..
                },
            ) => left < right,
        }
    }
}

/// Keys and canonical endpoint usable only at the snapshot's effective height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodKeys {
    consensus: [u8; 32],
    transport: [u8; 32],
    endpoint: String,
}
impl PeriodKeys {
    pub fn new(
        consensus: [u8; 32],
        transport: [u8; 32],
        endpoint: String,
    ) -> Result<Self, LedgerError> {
        let result = Self {
            consensus,
            transport,
            endpoint,
        };
        result.validate()?;
        Ok(result)
    }
    pub const fn consensus(&self) -> &[u8; 32] {
        &self.consensus
    }
    pub const fn transport(&self) -> &[u8; 32] {
        &self.transport
    }
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
    fn validate(&self) -> Result<(), LedgerError> {
        for key in [&self.consensus, &self.transport] {
            let decoded = VerifyingKey::from_bytes(key)
                .map_err(|_| LedgerError::Invalid("period Ed25519 key"))?;
            if decoded.is_weak() {
                return Err(LedgerError::Invalid("weak period key"));
            }
        }
        if self.consensus == self.transport {
            return Err(LedgerError::Invalid("period key roles overlap"));
        }
        if self.endpoint.len() > ENDPOINT_MAX_BYTES {
            return Err(LedgerError::Limit("period endpoint bytes"));
        }
        let endpoint: SocketAddr = self
            .endpoint
            .parse()
            .map_err(|_| LedgerError::Invalid("period endpoint"))?;
        if endpoint.port() == 0
            || endpoint.ip().is_unspecified()
            || endpoint.ip().is_multicast()
            || matches!(endpoint, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
            || matches!(endpoint.ip(), IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
            || endpoint.to_string() != self.endpoint
        {
            return Err(LedgerError::Invalid("canonical period endpoint"));
        }
        Ok(())
    }
}

/// One equal-weight slot. `keys: None` means vacant, not removed from quorum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityUnit {
    slot: AuthoritySlotId,
    id: AuthorityUnitId,
    owner: AccountId,
    origin: UnitOrigin,
    keys: Option<PeriodKeys>,
}
impl AuthorityUnit {
    fn new(
        slot: AuthoritySlotId,
        owner: AccountId,
        origin: UnitOrigin,
        keys: Option<PeriodKeys>,
    ) -> Result<Self, LedgerError> {
        let result = Self {
            slot,
            id: origin.id(),
            owner,
            origin,
            keys,
        };
        result.validate_shape()?;
        Ok(result)
    }
    pub const fn slot(&self) -> AuthoritySlotId {
        self.slot
    }
    pub const fn id(&self) -> AuthorityUnitId {
        self.id
    }
    pub const fn owner(&self) -> AccountId {
        self.owner
    }
    pub const fn origin(&self) -> UnitOrigin {
        self.origin
    }
    pub fn keys(&self) -> Option<&PeriodKeys> {
        self.keys.as_ref()
    }
    fn validate_shape(&self) -> Result<(), LedgerError> {
        if self.id != self.origin.id() {
            return Err(LedgerError::Invalid("authority unit identity"));
        }
        match self.origin {
            UnitOrigin::Bootstrap { validator, .. }
                if self.slot != AuthoritySlotId::for_bootstrap(validator) =>
            {
                return Err(LedgerError::Invalid("bootstrap authority slot"));
            }
            UnitOrigin::Bootstrap {
                retirement_rank, ..
            } if retirement_rank >= 4 => {
                return Err(LedgerError::Invalid("bootstrap retirement rank"));
            }
            UnitOrigin::Earned {
                completion_ordinal: 0,
                ..
            } => return Err(LedgerError::Invalid("zero earned ordinal")),
            _ => {}
        }
        if let Some(keys) = &self.keys {
            keys.validate()?;
        }
        Ok(())
    }
}

/// Exactly four equal-weight units and their effective period keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    genesis: GenesisId,
    effective_height: u64,
    units: [AuthorityUnit; 4],
}
impl AuthoritySnapshot {
    pub fn from_genesis(genesis: &Genesis) -> Result<Self, LedgerError> {
        let units = genesis
            .validators()
            .iter()
            .map(|validator| {
                let rank = genesis
                    .retirement_order()
                    .iter()
                    .position(|id| *id == validator.id())
                    .ok_or(LedgerError::Invalid("missing bootstrap retirement rank"))?;
                AuthorityUnit::new(
                    AuthoritySlotId::for_bootstrap(validator.id()),
                    validator.owner,
                    UnitOrigin::Bootstrap {
                        validator: validator.id(),
                        retirement_rank: rank as u8,
                    },
                    Some(PeriodKeys::new(
                        validator.consensus_key,
                        validator.transport_key,
                        validator.endpoint.clone(),
                    )?),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(genesis.id(), 1, units)
    }
    fn new(
        genesis: GenesisId,
        effective_height: u64,
        mut units: Vec<AuthorityUnit>,
    ) -> Result<Self, LedgerError> {
        units.sort_by_key(AuthorityUnit::slot);
        let units: [AuthorityUnit; 4] = units
            .try_into()
            .map_err(|_| LedgerError::Limit("authority unit count"))?;
        let result = Self {
            genesis,
            effective_height,
            units,
        };
        result.validate_shape()?;
        Ok(result)
    }
    pub const fn genesis(&self) -> GenesisId {
        self.genesis
    }
    pub const fn effective_height(&self) -> u64 {
        self.effective_height
    }
    pub fn units(&self) -> &[AuthorityUnit; 4] {
        &self.units
    }
    pub fn oldest(&self) -> &AuthorityUnit {
        self.units
            .iter()
            .reduce(|oldest, unit| {
                if unit.origin.older_than(oldest.origin) {
                    unit
                } else {
                    oldest
                }
            })
            .expect("four units")
    }
    pub fn unit(&self, id: AuthorityUnitId) -> Option<&AuthorityUnit> {
        self.units.iter().find(|unit| unit.id == id)
    }
    pub fn slot(&self, id: AuthoritySlotId) -> Option<&AuthorityUnit> {
        self.units.iter().find(|unit| unit.slot == id)
    }
    pub fn consensus_unit(&self, key: &[u8; 32]) -> Option<&AuthorityUnit> {
        self.units.iter().find(|unit| {
            unit.keys
                .as_ref()
                .is_some_and(|keys| &keys.consensus == key)
        })
    }
    pub fn owner(&self, account: AccountId) -> Option<&AuthorityUnit> {
        self.units.iter().find(|unit| unit.owner == account)
    }
    pub fn active_count(&self) -> usize {
        self.units.iter().filter(|unit| unit.keys.is_some()).count()
    }
    pub(crate) fn install_candidate(
        &self,
        outgoing: AuthorityUnitId,
        family: ResolutionId,
        ordinal: u64,
        owner: AccountId,
        keys: PeriodKeys,
    ) -> Result<Self, LedgerError> {
        let mut units = self.units.to_vec();
        let old = units
            .iter_mut()
            .find(|unit| unit.id == outgoing)
            .ok_or(LedgerError::Invalid("retiring unit missing"))?;
        old.id = AuthorityUnitId::for_claim(family);
        old.origin = UnitOrigin::Earned {
            family,
            completion_ordinal: ordinal,
        };
        old.owner = owner;
        old.keys = Some(keys);
        Self::new(self.genesis, self.effective_height, units)
    }
    /// Derives the next four-slot set. Each absent offer produces a vacant
    /// weighted slot. A future selected-state caller must supply account keys
    /// and every registered or previously used consensus/transport key.
    pub fn successor(
        &self,
        parent_record: RecordId,
        parent_state: StateCommitment,
        offers: &[NextPeriodKeys],
        account_key: impl Fn(AccountId) -> Option<[u8; 32]>,
        forbidden_keys: &BTreeSet<[u8; 32]>,
    ) -> Result<Self, LedgerError> {
        if !(3..=4).contains(&offers.len()) {
            return Err(LedgerError::Invalid("period offer quorum"));
        }
        let height = self
            .effective_height
            .checked_add(1)
            .ok_or(LedgerError::Overflow)?;
        let mut previous = None;
        // The selected-state caller supplies all historical and registered
        // keys. The snapshot itself still rejects reuse of its active keys or
        // owner account keys even if that caller omits one from its history.
        let mut unavailable = forbidden_keys.clone();
        for unit in &self.units {
            if let Some(keys) = &unit.keys {
                unavailable.insert(keys.consensus);
                unavailable.insert(keys.transport);
            }
            let owner_key = account_key(unit.owner)
                .ok_or(LedgerError::Invalid("missing authority owner key"))?;
            unavailable.insert(owner_key);
        }
        let mut units = self.units.to_vec();
        for unit in &mut units {
            unit.keys = None;
        }
        for offer in offers {
            if previous.is_some_and(|id| id >= offer.unit()) {
                return Err(LedgerError::Invalid("period offer order or duplicate"));
            }
            previous = Some(offer.unit());
            let current = self
                .unit(offer.unit())
                .ok_or(LedgerError::Invalid("unknown period offer unit"))?;
            let key = account_key(current.owner)
                .ok_or(LedgerError::Invalid("missing period offer owner key"))?;
            offer.verify(self, parent_record, parent_state, height, key)?;
            if !unavailable.insert(*offer.keys().consensus())
                || !unavailable.insert(*offer.keys().transport())
            {
                return Err(LedgerError::Invalid("period key was previously used"));
            }
            let successor = units
                .iter_mut()
                .find(|unit| unit.id == current.id)
                .expect("same four units");
            successor.keys = Some(offer.keys().clone());
        }
        Self::new(self.genesis, height, units)
    }
    pub fn id(&self) -> [u8; 32] {
        hash(b"naome:state:authority-snapshot:v5\0", &[&self.encode()])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(MAGIC);
        w.fixed(self.genesis.as_bytes());
        w.u64(self.effective_height);
        w.u8(4);
        for unit in &self.units {
            w.fixed(unit.slot.as_bytes());
            w.fixed(unit.id.as_bytes());
            w.fixed(unit.owner.as_bytes());
            match unit.origin {
                UnitOrigin::Bootstrap {
                    validator,
                    retirement_rank,
                } => {
                    w.u8(1);
                    w.fixed(validator.as_bytes());
                    w.u8(retirement_rank);
                }
                UnitOrigin::Earned {
                    family,
                    completion_ordinal,
                } => {
                    w.u8(2);
                    w.fixed(family.as_bytes());
                    w.u64(completion_ordinal);
                }
            }
            match &unit.keys {
                None => w.u8(0),
                Some(keys) => {
                    w.u8(1);
                    w.fixed(&keys.consensus);
                    w.fixed(&keys.transport);
                    w.string(&keys.endpoint).expect("validated endpoint");
                }
            }
        }
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut r = Reader::new(bytes, MAX_BYTES)?;
        if r.fixed::<5>()? != *MAGIC {
            return Err(LedgerError::Invalid("authority snapshot version"));
        }
        let genesis = GenesisId::from_bytes(r.fixed()?);
        let effective_height = r.u64()?;
        if r.u8()? != 4 {
            return Err(LedgerError::Invalid("authority unit count"));
        }
        let mut units = Vec::with_capacity(4);
        for _ in 0..4 {
            let slot = AuthoritySlotId::from_bytes(r.fixed()?);
            let id = AuthorityUnitId::from_bytes(r.fixed()?);
            let owner = AccountId::from_bytes(r.fixed()?);
            let origin = match r.u8()? {
                1 => UnitOrigin::Bootstrap {
                    validator: ValidatorId::from_bytes(r.fixed()?),
                    retirement_rank: r.u8()?,
                },
                2 => UnitOrigin::Earned {
                    family: ResolutionId::from_bytes(r.fixed()?),
                    completion_ordinal: r.u64()?,
                },
                _ => return Err(LedgerError::Invalid("authority origin tag")),
            };
            let keys = match r.u8()? {
                0 => None,
                1 => Some(PeriodKeys::new(
                    r.fixed()?,
                    r.fixed()?,
                    r.string(ENDPOINT_MAX_BYTES)?.to_owned(),
                )?),
                _ => return Err(LedgerError::Invalid("authority key option")),
            };
            units.push(AuthorityUnit {
                slot,
                id,
                owner,
                origin,
                keys,
            });
        }
        r.finish()?;
        let result = Self::new(genesis, effective_height, units)?;
        if result.encode() != bytes {
            return Err(LedgerError::Invalid("noncanonical authority snapshot"));
        }
        Ok(result)
    }
    fn validate_shape(&self) -> Result<(), LedgerError> {
        if self.effective_height == 0 {
            return Err(LedgerError::Invalid("zero authority height"));
        }
        let mut identities = BTreeSet::new();
        let mut slots = BTreeSet::new();
        let mut owners = BTreeSet::new();
        let mut keys = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        let mut ages = BTreeSet::new();
        for unit in &self.units {
            unit.validate_shape()?;
            let age = match unit.origin {
                UnitOrigin::Bootstrap {
                    retirement_rank, ..
                } => (0, u64::from(retirement_rank)),
                UnitOrigin::Earned {
                    completion_ordinal, ..
                } => (1, completion_ordinal),
            };
            if !slots.insert(unit.slot) || !identities.insert(unit.id) || !ages.insert(age) {
                return Err(LedgerError::Invalid("duplicate authority unit"));
            }
            if !owners.insert(unit.owner) {
                return Err(LedgerError::Invalid("duplicate authority owner"));
            }
            if let Some(binding) = &unit.keys
                && (!keys.insert(binding.consensus)
                    || !keys.insert(binding.transport)
                    || !endpoints.insert(&binding.endpoint))
            {
                return Err(LedgerError::Invalid("authority key or endpoint collision"));
            }
        }
        if !self
            .units
            .windows(2)
            .all(|pair| pair[0].slot < pair[1].slot)
        {
            return Err(LedgerError::Invalid("authority unit order"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::genesis;

    #[test]
    fn bootstrap_units_keep_identity_when_keys_rotate_or_go_vacant() {
        let genesis = genesis();
        let original = AuthoritySnapshot::from_genesis(&genesis).unwrap();
        assert_eq!(original.effective_height(), 1);
        assert_eq!(
            original.oldest().origin(),
            UnitOrigin::Bootstrap {
                validator: genesis.retirement_order()[0],
                retirement_rank: 0,
            }
        );
        assert_eq!(
            AuthoritySnapshot::decode(&original.encode()).unwrap(),
            original
        );
        let encoded = original.encode();
        for end in 0..encoded.len() {
            assert!(AuthoritySnapshot::decode(&encoded[..end]).is_err());
        }
        let mut next = original.units().to_vec();
        let id = next[0].id();
        next[0].keys = None;
        let next = AuthoritySnapshot::new(genesis.id(), 2, next).unwrap();
        assert_eq!(next.units()[0].id(), id);
        assert_eq!(next.oldest().id(), original.oldest().id());
        assert_ne!(next.id(), original.id());
    }

    #[test]
    fn rejects_noncanonical_and_colliding_period_keys() {
        let genesis = genesis();
        let original = AuthoritySnapshot::from_genesis(&genesis).unwrap();
        let mut encoded = original.encode();
        let last = encoded.len() - 1;
        encoded.swap(46, last);
        assert!(AuthoritySnapshot::decode(&encoded).is_err());
        let mut units = original.units().to_vec();
        units[1].keys = units[0].keys.clone();
        assert!(AuthoritySnapshot::new(genesis.id(), 2, units).is_err());
        let mut units = original.units().to_vec();
        units[1].owner = units[0].owner;
        assert!(AuthoritySnapshot::new(genesis.id(), 2, units).is_err());
        let mut units = original.units().to_vec();
        let endpoint = units[0].keys.as_ref().unwrap().endpoint.clone();
        units[1].keys.as_mut().unwrap().endpoint = endpoint;
        assert!(AuthoritySnapshot::new(genesis.id(), 2, units).is_err());
        let first = original.units()[0].keys().unwrap();
        assert!(
            PeriodKeys::new(
                *first.consensus(),
                *first.transport(),
                "localhost:4000".into(),
            )
            .is_err()
        );
    }
}
