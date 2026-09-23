//! Preparation and retirement evidence for one agreed authority transition.
//! These types verify evidence; storage owns the irreversible signing sequence.

use super::{Result, StateConsensusError as Error, codec::Reader};
use crate::ConsensusKey;
use ed25519_dalek::{Signature, VerifyingKey};
use naome_ledger::{GenesisId, RecordId, StateCommitment, authority::AuthoritySnapshot};

const CONTEXT_BYTES: usize = 32 * 6 + 8;
pub const SEAL_SIGNATURE_BYTES: usize = 5 + CONTEXT_BYTES + 1 + 32 + 64;
pub const STATE_SEAL_MAX_BYTES: usize = 5 + 2 + 8 * SEAL_SIGNATURE_BYTES;

/// Exact agreed record and both authority snapshots. Quorum subsets and the
/// agreement round do not change this context or the finalized record identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealContext {
    genesis: GenesisId,
    height: u64,
    record: RecordId,
    previous: StateCommitment,
    next: StateCommitment,
    outgoing: [u8; 32],
    incoming: [u8; 32],
}
impl SealContext {
    pub(super) fn new(
        value: super::StateValue,
        outgoing: &AuthoritySnapshot,
        incoming: &AuthoritySnapshot,
    ) -> Result<Self> {
        if outgoing.genesis() != value.genesis()
            || incoming.genesis() != value.genesis()
            || outgoing.effective_height() != value.height()
            || incoming.effective_height()
                != value.height().checked_add(1).ok_or(Error::Overflow)?
        {
            return Err(Error::Invalid("seal authority height"));
        }
        Ok(Self {
            genesis: value.genesis(),
            height: value.height(),
            record: value.record_id(),
            previous: value.previous_state(),
            next: value.next_state(),
            outgoing: outgoing.id(),
            incoming: incoming.id(),
        })
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn record(&self) -> RecordId {
        self.record
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CONTEXT_BYTES);
        bytes.extend_from_slice(self.genesis.as_bytes());
        bytes.extend_from_slice(&self.height.to_be_bytes());
        for field in [
            self.record.as_bytes(),
            self.previous.as_bytes(),
            self.next.as_bytes(),
            &self.outgoing,
            &self.incoming,
        ] {
            bytes.extend_from_slice(field);
        }
        bytes
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let result = Self {
            genesis: GenesisId::from_bytes(r.fixed()?),
            height: r.u64()?,
            record: RecordId::from_bytes(r.fixed()?),
            previous: StateCommitment::from_bytes(r.fixed()?),
            next: StateCommitment::from_bytes(r.fixed()?),
            outgoing: r.fixed()?,
            incoming: r.fixed()?,
        };
        if result.height == 0 {
            return Err(Error::Invalid("zero seal height"));
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealRole {
    Ready,
    Terminal,
}
impl SealRole {
    fn tag(self) -> u8 {
        match self {
            Self::Ready => 1,
            Self::Terminal => 2,
        }
    }
}

/// Signature bytes grant no readiness or retirement claim until verified
/// against the exact agreed transition. Local retirement is a custody duty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealSignature {
    context: SealContext,
    role: SealRole,
    signer: ConsensusKey,
    signature: [u8; 64],
}
impl SealSignature {
    pub fn signing_bytes(role: SealRole, context: SealContext, signer: ConsensusKey) -> Vec<u8> {
        let mut bytes = match role {
            SealRole::Ready => b"naome:state:ready:v5\0".to_vec(),
            SealRole::Terminal => b"naome:state:terminal:v5\0".to_vec(),
        };
        bytes.extend(context.encode());
        bytes.push(role.tag());
        bytes.extend_from_slice(signer.as_bytes());
        bytes
    }
    pub fn complete(
        role: SealRole,
        context: SealContext,
        signer: ConsensusKey,
        signature: [u8; 64],
        outgoing: &AuthoritySnapshot,
        incoming: &AuthoritySnapshot,
    ) -> Result<Self> {
        let result = Self {
            context,
            role,
            signer,
            signature,
        };
        result.verify(role, context, outgoing, incoming)?;
        Ok(result)
    }
    pub const fn context(&self) -> SealContext {
        self.context
    }
    pub const fn role(&self) -> SealRole {
        self.role
    }
    pub const fn signer(&self) -> ConsensusKey {
        self.signer
    }
    pub fn verify(
        &self,
        role: SealRole,
        context: SealContext,
        outgoing: &AuthoritySnapshot,
        incoming: &AuthoritySnapshot,
    ) -> Result<()> {
        if self.context != context
            || self.role != role
            || outgoing.id() != context.outgoing
            || incoming.id() != context.incoming
            || outgoing.genesis() != context.genesis
            || incoming.genesis() != context.genesis
            || outgoing.effective_height() != context.height
            || incoming.effective_height()
                != context.height.checked_add(1).ok_or(Error::Overflow)?
        {
            return Err(Error::Invalid("seal signature context"));
        }
        let authority = match role {
            SealRole::Ready => incoming,
            SealRole::Terminal => outgoing,
        };
        if !authority.units().iter().any(|u| {
            u.keys()
                .is_some_and(|k| k.consensus() == self.signer.as_bytes())
        }) {
            return Err(Error::Invalid("seal signer authority"));
        }
        VerifyingKey::from_bytes(self.signer.as_bytes())
            .map_err(|_| Error::Invalid("seal signer key"))?
            .verify_strict(
                &Self::signing_bytes(role, context, self.signer),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::Invalid("seal signature"))
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"NSSG5".to_vec();
        bytes.extend(self.context.encode());
        bytes.push(self.role.tag());
        bytes.extend_from_slice(self.signer.as_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    /// Bounded structural decoding, with no authority inferred from wire fields.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut r = Reader::new(input, SEAL_SIGNATURE_BYTES)?;
        if r.fixed::<5>()? != *b"NSSG5" {
            return Err(Error::Invalid("seal signature format"));
        }
        let context = SealContext::read(&mut r)?;
        let role = match r.u8()? {
            1 => SealRole::Ready,
            2 => SealRole::Terminal,
            _ => return Err(Error::Invalid("seal role")),
        };
        let result = Self {
            context,
            role,
            signer: ConsensusKey::from_bytes(r.fixed()?),
            signature: r.fixed()?,
        };
        r.finish()?;
        Ok(result)
    }
}

/// Both three-of-four quorums for one agreed transition. Missing slots always
/// remain in the denominator; evidence never reduces the installed electorate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSeal {
    ready: Vec<SealSignature>,
    terminal: Vec<SealSignature>,
}
impl StateSeal {
    pub fn new(
        mut ready: Vec<SealSignature>,
        mut terminal: Vec<SealSignature>,
        context: SealContext,
        outgoing: &AuthoritySnapshot,
        incoming: &AuthoritySnapshot,
    ) -> Result<Self> {
        ready.sort_by_key(SealSignature::signer);
        terminal.sort_by_key(SealSignature::signer);
        let seal = Self { ready, terminal };
        seal.verify(context, outgoing, incoming)?;
        Ok(seal)
    }
    pub fn verify_ready(
        ready: &[SealSignature],
        context: SealContext,
        outgoing: &AuthoritySnapshot,
        incoming: &AuthoritySnapshot,
    ) -> Result<()> {
        verify_set(ready, SealRole::Ready, context, outgoing, incoming)
    }
    pub fn verify(
        &self,
        context: SealContext,
        outgoing: &AuthoritySnapshot,
        incoming: &AuthoritySnapshot,
    ) -> Result<()> {
        Self::verify_ready(&self.ready, context, outgoing, incoming)?;
        verify_set(
            &self.terminal,
            SealRole::Terminal,
            context,
            outgoing,
            incoming,
        )
    }
    pub fn ready(&self) -> &[SealSignature] {
        &self.ready
    }
    pub fn terminal(&self) -> &[SealSignature] {
        &self.terminal
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = b"NSSL5".to_vec();
        for set in [&self.ready, &self.terminal] {
            bytes.push(set.len() as u8);
            for signature in set {
                bytes.extend(signature.encode());
            }
        }
        bytes
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut r = Reader::new(input, STATE_SEAL_MAX_BYTES)?;
        if r.fixed::<5>()? != *b"NSSL5" {
            return Err(Error::Invalid("seal format"));
        }
        let mut read = || -> Result<Vec<SealSignature>> {
            let count = r.u8()?;
            if !(3..=4).contains(&count) {
                return Err(Error::Invalid("seal quorum count"));
            }
            let mut signatures = Vec::with_capacity(count as usize);
            for _ in 0..count {
                signatures.push(SealSignature::decode(r.take(SEAL_SIGNATURE_BYTES)?)?);
            }
            if signatures.windows(2).any(|p| p[0].signer >= p[1].signer) {
                return Err(Error::Invalid("seal signer order"));
            }
            Ok(signatures)
        };
        let ready = read()?;
        let terminal = read()?;
        r.finish()?;
        Ok(Self { ready, terminal })
    }
}
fn verify_set(
    signatures: &[SealSignature],
    role: SealRole,
    context: SealContext,
    outgoing: &AuthoritySnapshot,
    incoming: &AuthoritySnapshot,
) -> Result<()> {
    if !(3..=4).contains(&signatures.len())
        || signatures.windows(2).any(|p| p[0].signer >= p[1].signer)
    {
        return Err(Error::Invalid("seal quorum"));
    }
    for signature in signatures {
        signature.verify(role, context, outgoing, incoming)?;
    }
    Ok(())
}
