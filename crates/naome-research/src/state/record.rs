use super::*;
use crate::{GenesisId, codec::Reader, time::TIME_CERTIFICATE_MAX_BYTES};

const MAGIC: &[u8; 4] = b"NRRC";

/// Bounded canonical application content. Finality signatures are a separate
/// envelope; changing its sufficient signer subset never changes this identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchRecord {
    genesis: GenesisId,
    height: u64,
    parent: RecordId,
    previous: StateCommitment,
    next: StateCommitment,
    time: u64,
    pub(super) time_certificate: TimeCertificate,
    pub(super) operations: Vec<SignedOperation>,
    effects: Vec<u8>,
}
impl ResearchRecord {
    pub(super) fn new(
        parent: &ResearchState,
        next: &ResearchState,
        time_certificate: TimeCertificate,
        operations: Vec<SignedOperation>,
        effects: Vec<u8>,
    ) -> Result<Self, ResearchError> {
        let record = Self {
            genesis: parent.genesis.id(),
            height: next.height,
            parent: parent.head,
            previous: parent.commitment(),
            next: next.commitment(),
            time: next.time,
            time_certificate,
            operations,
            effects,
        };
        if record.encode()?.len() as u64 > parent.genesis.profile().limits().record_bytes {
            return Err(ResearchError::Limit("complete research record"));
        }
        Ok(record)
    }
    pub const fn genesis_id(&self) -> GenesisId {
        self.genesis
    }
    pub const fn height(&self) -> u64 {
        self.height
    }
    pub const fn parent(&self) -> RecordId {
        self.parent
    }
    pub const fn previous_state(&self) -> StateCommitment {
        self.previous
    }
    pub const fn next_state(&self) -> StateCommitment {
        self.next
    }
    pub const fn time(&self) -> u64 {
        self.time
    }
    pub fn time_certificate(&self) -> &TimeCertificate {
        &self.time_certificate
    }
    pub fn operations(&self) -> &[SignedOperation] {
        &self.operations
    }
    pub fn effects(&self) -> &[u8] {
        &self.effects
    }
    pub fn id(&self) -> RecordId {
        RecordId::from_bytes(hash(
            b"naome:research:record:v1\0",
            &[&self.encode().expect("private bounded record content")],
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>, ResearchError> {
        let mut w = Writer::new();
        w.fixed(MAGIC);
        w.u16(1);
        w.fixed(self.genesis.as_bytes());
        w.u64(self.height);
        w.fixed(self.parent.as_bytes());
        w.fixed(self.previous.as_bytes());
        w.fixed(self.next.as_bytes());
        w.u64(self.time);
        w.bytes(&self.time_certificate.encode())?;
        w.u32(self.operations.len() as u32);
        for operation in &self.operations {
            w.bytes(&operation.encode())?;
        }
        w.bytes(&self.effects)?;
        Ok(w.finish())
    }
    /// Decodes observed content and checks static framing/signature context.
    /// The selected parent is still needed to verify time, effects and state.
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, ResearchError> {
        let mut r = Reader::new(bytes, genesis.profile().limits().record_bytes as usize)?;
        if r.fixed::<4>()? != *MAGIC || r.u16()? != 1 {
            return Err(ResearchError::Invalid("research record version"));
        }
        let context = GenesisId::from_bytes(r.fixed()?);
        let height = r.u64()?;
        let parent = RecordId::from_bytes(r.fixed()?);
        let previous = StateCommitment::from_bytes(r.fixed()?);
        let next = StateCommitment::from_bytes(r.fixed()?);
        let time = r.u64()?;
        if context != genesis.id() || height == 0 {
            return Err(ResearchError::Invalid("research record context"));
        }
        // The declared time restores the wire object's cache, but grants no
        // authority. State validation recomputes time against the actual parent.
        let time_certificate = TimeCertificate::decode(
            r.bytes(TIME_CERTIFICATE_MAX_BYTES)?,
            genesis,
            parent,
            height,
            time,
        )?;
        if time_certificate.time() != time {
            return Err(ResearchError::Invalid("record time below report median"));
        }
        let count = r.u32()?;
        if u64::from(count) > genesis.profile().limits().operations_per_record {
            return Err(ResearchError::Limit("record operations"));
        }
        let mut operations = Vec::with_capacity(count as usize);
        for _ in 0..count {
            operations.push(SignedOperation::decode(
                r.bytes(genesis.profile().limits().record_bytes as usize)?,
            )?);
        }
        let effects = r
            .bytes(genesis.profile().limits().record_bytes as usize)?
            .to_vec();
        r.finish()?;
        Ok(Self {
            genesis: context,
            height,
            parent,
            previous,
            next,
            time,
            time_certificate,
            operations,
            effects,
        })
    }
}
