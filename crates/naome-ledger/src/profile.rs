//! Immutable, canonical parameters and public genesis for a finite trusted run.
//!
//! The storage estimate is a conservative provisioning floor, not a measured
//! performance claim. A genesis contains public material only; all balances
//! begin at zero in the state machine.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use ed25519_dalek::VerifyingKey;

use crate::ResearchError;
use crate::codec::{Reader, Writer};
use crate::identity::{AccountId, GenesisId, ProfileId, ValidatorId, hash};

/// Supported checker and research normalization contract. Unknown namespaces
/// require a distinct implementation and are rejected before a run starts.
pub const RESEARCH_CHECKER_PROFILE: &str = "naome:zfc:checker:research-mvp-v1";

/// Reserved space around one maximum user payload for canonical record headers,
/// four time reports, operation authentication, and finality signatures. The
/// integrated codec must fit this allowance; it is not permission to omit bytes
/// from the complete-record limit.
pub const DOMAIN_RECORD_OVERHEAD_BYTES: u64 = 4096;
/// Space outside the complete record for bounded transport envelope metadata.
/// A frame must fit both the largest record and this envelope allocation.
pub const TRANSPORT_ENVELOPE_OVERHEAD_BYTES: u64 = 65536;
/// Fixed v1 signer checkpoint and unsigned transcript ceilings.
pub const SIGNER_SNAPSHOT_MAX_BYTES: u64 = 8192;
pub const SIGNER_TRANSCRIPT_MAX_BYTES: u64 = 1024;
/// Four full fixed-width research votes plus the quorum count byte.
pub const RESEARCH_QUORUM_BYTES_BOUND: u64 = 1 + 4 * (5 + 32 + 32 + 8 + 8 + 1 + 1 + 32 + 32 + 64);
/// Journal preparation metadata outside one complete research record.
pub const SIGNER_FRAME_OVERHEAD_BYTES: u64 = 16384;
/// Covers the genesis-bound signer prefix, initial anchor and their metadata.
pub const SIGNER_HEADER_BYTES_BOUND: u64 = 32768;
/// Type, intent sequence, signature and canonical publication digest.
pub const SIGNER_COMPLETION_BYTES: u64 = 1 + 8 + 64 + 32;
/// Terminal signer stop plus its chained frame header/footer.
pub const SIGNER_STOP_FRAME_BYTES: u64 = 1 + 8 + 32 + 36;

const PROFILE_MAGIC: &[u8; 8] = b"NAORMVP1";
const GENESIS_MAGIC: &[u8; 8] = b"NAORGEN1";
const MAX_PROFILE_BYTES: usize = 4096;
const MAX_GENESIS_BYTES: usize = 16384;

/// Identifies the timing assumptions under which evidence was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimingKind {
    /// Five minute voting; two minute commitment and reveal windows.
    Lab,
    /// Seven day voting; one day commitment and reveal windows.
    Research,
    /// Explicitly accelerated testing only; never lab acceptance evidence.
    ShortTest,
}

/// All durations are integer seconds of certified time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timing {
    pub voting_seconds: u64,
    pub commitment_seconds: u64,
    pub reveal_seconds: u64,
    pub queue_seconds: u64,
    pub clock_error_seconds: u64,
    pub agent_call_seconds: u64,
}

macro_rules! limit_fields {
    ($($field:ident = $value:expr),+ $(,)?) => {
        /// Deterministic upper bounds, committed in full by the profile identity.
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct Limits { $(pub $field: u64,)+ }
        impl Default for Limits {
            fn default() -> Self { Self { $($field: $value,)+ } }
        }
        impl Limits {
            /// Every immutable bound in declaration order, for machine-readable
            /// operational inspection without a second list of constants.
            pub fn named_values(&self) -> impl Iterator<Item = (&'static str, u64)> {
                [$( (stringify!($field), self.$field), )+].into_iter()
            }
            fn write(&self, w: &mut Writer) { $(w.u64(self.$field);)+ }
            fn read(r: &mut Reader<'_>) -> Result<Self, ResearchError> {
                Ok(Self { $($field: r.u64()?,)+ })
            }
            fn validate(&self) -> Result<(), ResearchError> {
                let ceiling = Self::default();
                $(if self.$field == 0 || self.$field > ceiling.$field {
                    return Err(ResearchError::Limit(stringify!($field)));
                })+
                Ok(())
            }
        }
    }
}

limit_fields! {
    active_attempts = 1,
    queued_questions = 32,
    accounts = 16,
    commitments_per_account = 1,
    question_source_bytes = 16 * 1024,
    target_nodes = 1024,
    target_depth = 32,
    new_helpers = 16,
    package_bytes = 256 * 1024,
    certificate_bytes = 64 * 1024,
    certificate_steps = 4096,
    dependency_proofs = 64,
    dependency_bytes = 2 * 1024 * 1024,
    dependency_depth = 32,
    citation_proofs = 64,
    operations_per_record = 16,
    settlements_per_record = 1,
    record_bytes = 1024 * 1024,
    run_records = 8192,
    completion_records = 64,
    terminal_records = 1,
    agent_inference_attempts = 2,
    agent_tool_calls = 4,
    // Per call: retain the existing checker's formula-work bound.
    formula_work_bytes_per_call = naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES as u64,
    // Each reveal may check 17 new + 64 older proofs, original and normalized.
    checker_calls_per_record = 16 * 2 * (17 + 64),
    checker_input_bytes_per_record = 16 * 2 * (256 * 1024 + 2 * 1024 * 1024),
    // Both passes may walk every certificate step in every proof.
    dag_steps_per_record = 16 * 2 * (17 + 64) * 4096,
    normalization_steps_per_record = 16 * 17 * 4096,
    // Framing plus bounded transport/signature metadata beyond record content.
    transport_frame_bytes = 1024 * 1024 + 64 * 1024,
    transport_buffer_frames = 64,
    // Inclusive largest round index: 64 permits rounds 0 through 64.
    consensus_rounds = 64,
}

/// Exact integer issuance; distributions never depend on certificate signers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rewards {
    pub issuance_atoms: u128,
    pub author_without_citations_atoms: u128,
    pub author_with_citations_atoms: u128,
    pub citation_pool_atoms: u128,
    pub validator_atoms_each: u128,
    pub reserve_atoms: u128,
}

impl Default for Rewards {
    fn default() -> Self {
        Self {
            issuance_atoms: 1_000_000_000,
            author_without_citations_atoms: 700_000_000,
            author_with_citations_atoms: 600_000_000,
            citation_pool_atoms: 100_000_000,
            validator_atoms_each: 50_000_000,
            reserve_atoms: 100_000_000,
        }
    }
}

impl Rewards {
    fn write(&self, w: &mut Writer) {
        for value in [
            self.issuance_atoms,
            self.author_without_citations_atoms,
            self.author_with_citations_atoms,
            self.citation_pool_atoms,
            self.validator_atoms_each,
            self.reserve_atoms,
        ] {
            w.u128(value);
        }
    }
    fn read(r: &mut Reader<'_>) -> Result<Self, ResearchError> {
        Ok(Self {
            issuance_atoms: r.u128()?,
            author_without_citations_atoms: r.u128()?,
            author_with_citations_atoms: r.u128()?,
            citation_pool_atoms: r.u128()?,
            validator_atoms_each: r.u128()?,
            reserve_atoms: r.u128()?,
        })
    }
}

/// Validated immutable profile. Obtain modified bounds through `with_limits`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    kind: TimingKind,
    timing: Timing,
    limits: Limits,
    rewards: Rewards,
}

impl Profile {
    pub fn lab() -> Self {
        Self::preset(TimingKind::Lab)
    }
    pub fn research() -> Self {
        Self::preset(TimingKind::Research)
    }
    pub fn short_test() -> Self {
        Self::preset(TimingKind::ShortTest)
    }

    fn preset(kind: TimingKind) -> Self {
        let (voting_seconds, commitment_seconds, reveal_seconds, queue_seconds) = match kind {
            TimingKind::Lab => (300, 120, 120, 1800),
            TimingKind::Research => (604800, 86400, 86400, 2592000),
            // Leave room for independent CLI commands and durable quorum
            // delivery under concurrent CI compilation and process scheduling.
            TimingKind::ShortTest => (15, 8, 8, 120),
        };
        Self {
            kind,
            timing: Timing {
                voting_seconds,
                commitment_seconds,
                reveal_seconds,
                queue_seconds,
                clock_error_seconds: 2,
                agent_call_seconds: 60,
            },
            limits: Limits::default(),
            rewards: Rewards::default(),
        }
    }

    /// Starts a distinct profile with reduced bounds; never mutates a live run.
    /// The 64-slot completion reserve and separate terminal slot remain fixed.
    pub fn with_limits(kind: TimingKind, limits: Limits) -> Result<Self, ResearchError> {
        let mut profile = Self::preset(kind);
        profile.limits = limits;
        profile.validate()?;
        Ok(profile)
    }
    pub fn kind(&self) -> TimingKind {
        self.kind
    }
    pub fn timing(&self) -> &Timing {
        &self.timing
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn rewards(&self) -> &Rewards {
        &self.rewards
    }
    pub fn name(&self) -> &'static str {
        match self.kind {
            TimingKind::Lab => "research-mvp-v1-lab",
            TimingKind::Research => "research-mvp-v1-research",
            TimingKind::ShortTest => "research-mvp-v1-short-test",
        }
    }
    fn validate(&self) -> Result<(), ResearchError> {
        self.limits.validate()?;
        let l = &self.limits;
        if self.timing != Self::preset(self.kind).timing || self.rewards != Rewards::default() {
            return Err(ResearchError::Invalid("timing or reward rules"));
        }
        if l.accounts < 4
            || l.completion_records != 64
            || l.terminal_records != 1
            || l.run_records < l.completion_records + l.terminal_records
            || l.citation_proofs > l.dependency_proofs
            || l.certificate_bytes > l.package_bytes
            || l.package_bytes.checked_add(DOMAIN_RECORD_OVERHEAD_BYTES).ok_or(ResearchError::Overflow)? > l.record_bytes
            // Source and purpose each have a 16KiB absolute codec bound. Keep
            // both plus authentication/header space even for reduced profiles.
            || (32 * 1024u64).checked_add(DOMAIN_RECORD_OVERHEAD_BYTES).ok_or(ResearchError::Overflow)? > l.record_bytes
            || l.record_bytes.checked_add(TRANSPORT_ENVELOPE_OVERHEAD_BYTES).ok_or(ResearchError::Overflow)? > l.transport_frame_bytes
            || l.target_depth > l.target_nodes
            || l.formula_work_bytes_per_call != naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES as u64
        {
            return Err(ResearchError::Invalid("inconsistent research limits"));
        }
        self.required_storage_bytes()?;
        Ok(())
    }
    /// Maximum journal frames per consensus height: one author, prevote,
    /// precommit and progress event plus three completions in each round, then
    /// one durable finalized-height handoff. Duplicate retries append nothing.
    pub fn signer_height_frames(&self) -> Result<u64, ResearchError> {
        self.limits
            .consensus_rounds
            .checked_add(1)
            .and_then(|r| r.checked_mul(7))
            .and_then(|v| v.checked_add(1))
            .ok_or(ResearchError::Overflow)
    }
    /// Conservative complete signing-history reservation for one height.
    /// The bound includes every permitted round, complete record/proposal/QC
    /// recovery bytes, post-state checkpoints, signatures and chained footers.
    /// Publications are reconstructed from their anchored intent + signature,
    /// rather than storing a second copy of the complete publication body.
    pub fn signer_height_bytes(&self) -> Result<u64, ResearchError> {
        let record = self.limits.record_bytes;
        let proposal = record
            .checked_add(DOMAIN_RECORD_OVERHEAD_BYTES)
            .ok_or(ResearchError::Overflow)?;
        let per_round = record
            .checked_add(proposal.checked_mul(2).ok_or(ResearchError::Overflow)?)
            .and_then(|v| v.checked_add(2 * RESEARCH_QUORUM_BYTES_BOUND))
            .and_then(|v| v.checked_add(4 * SIGNER_SNAPSHOT_MAX_BYTES))
            .and_then(|v| v.checked_add(3 * SIGNER_TRANSCRIPT_MAX_BYTES))
            .and_then(|v| v.checked_add(4 * 128 + 3 * SIGNER_COMPLETION_BYTES + 7 * 36))
            .ok_or(ResearchError::Overflow)?;
        let advance = proposal
            .checked_add(SIGNER_SNAPSHOT_MAX_BYTES + 64 + 36)
            .ok_or(ResearchError::Overflow)?;
        per_round
            .checked_mul(
                self.limits
                    .consensus_rounds
                    .checked_add(1)
                    .ok_or(ResearchError::Overflow)?,
            )
            .and_then(|v| v.checked_add(advance))
            .ok_or(ResearchError::Overflow)
    }
    /// Full finite-run signer capacity, including a final stop and bounded header.
    pub fn signer_journal_bytes(&self) -> Result<u64, ResearchError> {
        self.signer_height_bytes()?
            .checked_mul(self.limits.run_records)
            .and_then(|v| v.checked_add(SIGNER_HEADER_BYTES_BOUND + SIGNER_STOP_FRAME_BYTES))
            .ok_or(ResearchError::Overflow)
    }
    /// Full finite archive AND worst-case signer history, staged original/final
    /// reveals with dependency closures, indexes/evidence, and a 100% margin.
    /// The default profile deliberately provisions its entire maximum run;
    /// reduced acceptance profiles must be selected before genesis.
    pub fn required_storage_bytes(&self) -> Result<u64, ResearchError> {
        let l = &self.limits;
        // One extra frame retains a verified conflict after the final run record.
        let archive = l
            .run_records
            .checked_add(1)
            .and_then(|n| n.checked_mul(l.transport_frame_bytes))
            .and_then(|v| v.checked_add(SIGNER_HEADER_BYTES_BOUND))
            .ok_or(ResearchError::Overflow)?;
        let reveal = l
            .package_bytes
            .checked_mul(2)
            .and_then(|v| v.checked_add(l.dependency_bytes.checked_mul(2)?))
            .and_then(|v| v.checked_mul(l.accounts))
            .ok_or(ResearchError::Overflow)?;
        archive
            .checked_mul(2)
            .and_then(|v| v.checked_add(self.signer_journal_bytes().ok()?))
            .and_then(|v| v.checked_add(reveal))
            .and_then(|v| v.checked_mul(2))
            .ok_or(ResearchError::Overflow)
    }
    pub fn maximum_issuance_atoms(&self) -> Result<u128, ResearchError> {
        u128::from(self.limits.run_records)
            .checked_mul(self.rewards.issuance_atoms)
            .ok_or(ResearchError::Overflow)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(PROFILE_MAGIC);
        w.u8(match self.kind {
            TimingKind::Lab => 0,
            TimingKind::Research => 1,
            TimingKind::ShortTest => 2,
        });
        for value in [
            self.timing.voting_seconds,
            self.timing.commitment_seconds,
            self.timing.reveal_seconds,
            self.timing.queue_seconds,
            self.timing.clock_error_seconds,
            self.timing.agent_call_seconds,
        ] {
            w.u64(value);
        }
        self.limits.write(&mut w);
        self.rewards.write(&mut w);
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ResearchError> {
        let mut r = Reader::new(bytes, MAX_PROFILE_BYTES)?;
        if r.fixed::<8>()? != *PROFILE_MAGIC {
            return Err(ResearchError::Invalid("profile version"));
        }
        let kind = match r.u8()? {
            0 => TimingKind::Lab,
            1 => TimingKind::Research,
            2 => TimingKind::ShortTest,
            _ => return Err(ResearchError::Invalid("timing kind")),
        };
        let timing = Timing {
            voting_seconds: r.u64()?,
            commitment_seconds: r.u64()?,
            reveal_seconds: r.u64()?,
            queue_seconds: r.u64()?,
            clock_error_seconds: r.u64()?,
            agent_call_seconds: r.u64()?,
        };
        let result = Self {
            kind,
            timing,
            limits: Limits::read(&mut r)?,
            rewards: Rewards::read(&mut r)?,
        };
        r.finish()?;
        result.validate()?;
        Ok(result)
    }
    pub fn id(&self) -> ProfileId {
        ProfileId::from_bytes(hash(b"naome:research:profile:v1\0", &[&self.encode()]))
    }
}

/// Public account registration. Addresses are always derived from keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountRegistration {
    id: AccountId,
    key: [u8; 32],
}
impl AccountRegistration {
    pub fn id(&self) -> AccountId {
        self.id
    }
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Public fixed validator assignment supplied to the genesis constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatorRegistration {
    pub owner: AccountId,
    pub consensus_key: [u8; 32],
    /// Separately registered transport identity, never a consensus signing key.
    pub transport_key: [u8; 32],
    /// Canonical IP socket address. DNS resolution cannot alter genesis routing.
    pub endpoint: String,
}
impl ValidatorRegistration {
    pub fn id(&self) -> ValidatorId {
        ValidatorId::for_key(&self.consensus_key)
    }
}

/// Canonically ordered, validated genesis. The private fields prevent mutation
/// after validation; constructing another value produces another run identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    profile: Profile,
    foundation: String,
    checker_profile: String,
    protocol_version: u16,
    start_utc: u64,
    run_nonce: [u8; 32],
    accounts: Vec<AccountRegistration>,
    validators: Vec<ValidatorRegistration>,
}

impl Genesis {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile: Profile,
        foundation: String,
        checker_profile: String,
        protocol_version: u16,
        start_utc: u64,
        run_nonce: [u8; 32],
        accounts: Vec<[u8; 32]>,
        mut validators: Vec<ValidatorRegistration>,
    ) -> Result<Self, ResearchError> {
        let mut accounts: Vec<_> = accounts
            .into_iter()
            .map(|key| AccountRegistration {
                id: AccountId::for_key(&key),
                key,
            })
            .collect();
        accounts.sort_by_key(AccountRegistration::id);
        validators.sort_by_key(ValidatorRegistration::id);
        let result = Self {
            profile,
            foundation,
            checker_profile,
            protocol_version,
            start_utc,
            run_nonce,
            accounts,
            validators,
        };
        result.validate()?;
        Ok(result)
    }
    fn validate(&self) -> Result<(), ResearchError> {
        self.profile.validate()?;
        for name in [&self.foundation, &self.checker_profile] {
            if name.is_empty() || name.len() > 128 || !name.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ResearchError::Invalid("genesis namespace"));
            }
        }
        if self.foundation != naome_foundation::FOUNDATION_ID {
            return Err(ResearchError::Invalid("unsupported Foundation"));
        }
        if self.checker_profile != RESEARCH_CHECKER_PROFILE {
            return Err(ResearchError::Invalid("unsupported checker profile"));
        }
        if self.protocol_version != 1 || self.run_nonce == [0; 32] {
            return Err(ResearchError::Invalid("genesis version or run nonce"));
        }
        // Leave enough UTC range for every timing interval without wrapping.
        self.start_utc
            .checked_add(self.profile.timing.queue_seconds)
            .and_then(|x| x.checked_add(self.profile.timing.voting_seconds))
            .and_then(|x| x.checked_add(self.profile.timing.commitment_seconds))
            .and_then(|x| x.checked_add(self.profile.timing.reveal_seconds))
            .ok_or(ResearchError::Overflow)?;
        if self.accounts.len() < 4
            || self.accounts.len() as u64 > self.profile.limits.accounts
            || self.validators.len() != 4
        {
            return Err(ResearchError::Limit("genesis membership"));
        }
        if self.accounts.windows(2).any(|w| w[0].id >= w[1].id)
            || self.validators.windows(2).any(|w| w[0].id() >= w[1].id())
        {
            return Err(ResearchError::Invalid("membership order or duplicate"));
        }
        let mut keys = BTreeSet::new();
        let mut owners = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for account in &self.accounts {
            valid_key(&account.key)?;
            if !keys.insert(account.key) {
                return Err(ResearchError::Invalid("duplicate account key"));
            }
        }
        for validator in &self.validators {
            valid_key(&validator.consensus_key)?;
            if !keys.insert(validator.consensus_key) {
                return Err(ResearchError::Invalid("key roles overlap"));
            }
            valid_key(&validator.transport_key)?;
            if !keys.insert(validator.transport_key) {
                return Err(ResearchError::Invalid("key roles overlap"));
            }
            if !owners.insert(validator.owner)
                || !self.accounts.iter().any(|a| a.id == validator.owner)
            {
                return Err(ResearchError::Invalid("validator owner"));
            }
            if validator.endpoint.len() > 128 {
                return Err(ResearchError::Limit("endpoint bytes"));
            }
            let endpoint: SocketAddr = validator
                .endpoint
                .parse()
                .map_err(|_| ResearchError::Invalid("endpoint"))?;
            if endpoint.port() == 0
                || endpoint.ip().is_unspecified()
                || endpoint.ip().is_multicast()
                || matches!(endpoint, SocketAddr::V6(ip) if ip.scope_id() != 0 || ip.flowinfo() != 0)
                || matches!(endpoint.ip(), std::net::IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
                || endpoint.to_string() != validator.endpoint
                || !endpoints.insert(endpoint)
            {
                return Err(ResearchError::Invalid("canonical unique endpoint"));
            }
        }
        Ok(())
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    pub fn foundation(&self) -> &str {
        &self.foundation
    }
    pub fn checker_profile(&self) -> &str {
        &self.checker_profile
    }
    pub fn protocol_version(&self) -> u16 {
        self.protocol_version
    }
    pub fn start_utc(&self) -> u64 {
        self.start_utc
    }
    pub fn run_nonce(&self) -> &[u8; 32] {
        &self.run_nonce
    }
    pub fn accounts(&self) -> &[AccountRegistration] {
        &self.accounts
    }
    pub fn validators(&self) -> &[ValidatorRegistration] {
        &self.validators
    }
    pub fn account_key(&self, id: AccountId) -> Option<&[u8; 32]> {
        self.accounts
            .binary_search_by_key(&id, AccountRegistration::id)
            .ok()
            .map(|i| &self.accounts[i].key)
    }
    pub fn validator(&self, id: ValidatorId) -> Option<&ValidatorRegistration> {
        self.validators
            .binary_search_by_key(&id, ValidatorRegistration::id)
            .ok()
            .map(|i| &self.validators[i])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(GENESIS_MAGIC);
        // Construction validates every string and collection far below u32::MAX.
        w.bytes(&self.profile.encode()).expect("bounded profile");
        w.string(&self.foundation).expect("bounded foundation");
        w.string(&self.checker_profile)
            .expect("bounded checker profile");
        w.u16(self.protocol_version);
        w.u64(self.start_utc);
        w.fixed(&self.run_nonce);
        w.u8(self.accounts.len() as u8);
        for account in &self.accounts {
            w.fixed(&account.key);
        }
        w.u8(self.validators.len() as u8);
        for validator in &self.validators {
            w.fixed(validator.owner.as_bytes());
            w.fixed(&validator.consensus_key);
            w.fixed(&validator.transport_key);
            w.string(&validator.endpoint).expect("bounded endpoint");
        }
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ResearchError> {
        let mut r = Reader::new(bytes, MAX_GENESIS_BYTES)?;
        if r.fixed::<8>()? != *GENESIS_MAGIC {
            return Err(ResearchError::Invalid("genesis version"));
        }
        let profile = Profile::decode(r.bytes(MAX_PROFILE_BYTES)?)?;
        let foundation = r.string(128)?.to_owned();
        let checker_profile = r.string(128)?.to_owned();
        let protocol_version = r.u16()?;
        let start_utc = r.u64()?;
        let run_nonce = r.fixed()?;
        let count = r.u8()?;
        if u64::from(count) > profile.limits.accounts || count < 4 {
            return Err(ResearchError::Limit("accounts"));
        }
        let mut accounts = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let key = r.fixed()?;
            accounts.push(AccountRegistration {
                id: AccountId::for_key(&key),
                key,
            });
        }
        let count = r.u8()?;
        if count != 4 {
            return Err(ResearchError::Limit("validators"));
        }
        let mut validators = Vec::with_capacity(4);
        for _ in 0..count {
            validators.push(ValidatorRegistration {
                owner: AccountId::from_bytes(r.fixed()?),
                consensus_key: r.fixed()?,
                transport_key: r.fixed()?,
                endpoint: r.string(128)?.to_owned(),
            });
        }
        r.finish()?;
        // Do not normalize hostile wire order: exactly one representation is valid.
        let result = Self {
            profile,
            foundation,
            checker_profile,
            protocol_version,
            start_utc,
            run_nonce,
            accounts,
            validators,
        };
        result.validate()?;
        Ok(result)
    }
    pub fn id(&self) -> GenesisId {
        GenesisId::from_bytes(hash(b"naome:research:genesis:v1\0", &[&self.encode()]))
    }
}

fn valid_key(key: &[u8; 32]) -> Result<(), ResearchError> {
    let key = VerifyingKey::from_bytes(key).map_err(|_| ResearchError::Invalid("Ed25519 key"))?;
    if key.is_weak() {
        return Err(ResearchError::Invalid("weak Ed25519 key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
