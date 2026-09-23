use super::{
    codec::{Reader, Writer},
    hash,
};
use naome_ledger::{
    GenesisId, LedgerError, LedgerState, RecordId, StateCommitment,
    authentication::SignedOperation,
    authority::{HANDOFF_PLAN_MAX_BYTES, HandoffPlan},
    profile::Genesis,
    time::{TIME_CERTIFICATE_MAX_BYTES, TimeCertificate},
};

const MAGIC: &[u8; 4] = b"NSRC";

/// Bounded canonical application content. Finality signatures are a separate
/// envelope; changing its sufficient signer subset never changes this identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateRecord {
    genesis: GenesisId,
    height: u64,
    parent: RecordId,
    previous: StateCommitment,
    next: StateCommitment,
    time: u64,
    pub(super) time_certificate: TimeCertificate,
    pub(super) operations: Vec<SignedOperation>,
    plan: HandoffPlan,
    effects: Vec<u8>,
}
impl StateRecord {
    pub(super) fn new(
        parent: &LedgerState,
        next: &LedgerState,
        time_certificate: TimeCertificate,
        operations: Vec<SignedOperation>,
        plan: HandoffPlan,
        effects: Vec<u8>,
    ) -> Result<Self, LedgerError> {
        let record = Self {
            genesis: parent.genesis().id(),
            height: next.height(),
            parent: parent.head(),
            previous: parent.commitment(),
            next: next.commitment(),
            time: next.time(),
            time_certificate,
            operations,
            plan,
            effects,
        };
        if record.encode()?.len() as u64 > parent.genesis().profile().limits().record_bytes {
            return Err(LedgerError::Limit("complete state record"));
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
    pub fn handoff_plan(&self) -> &HandoffPlan {
        &self.plan
    }
    pub fn effects(&self) -> &[u8] {
        &self.effects
    }
    pub fn id(&self) -> RecordId {
        RecordId::from_bytes(hash(
            b"naome:state:record:v5\0",
            &[&self.encode().expect("private bounded record content")],
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>, LedgerError> {
        let mut w = Writer::new();
        w.fixed(MAGIC);
        w.u16(5);
        w.fixed(self.genesis.as_bytes());
        w.u64(self.height);
        w.fixed(self.parent.as_bytes());
        w.fixed(self.previous.as_bytes());
        w.fixed(self.next.as_bytes());
        w.u64(self.time);
        w.bytes(&self.time_certificate.encode())?;
        w.bytes(&self.plan.encode())?;
        w.u32(self.operations.len() as u32);
        for operation in &self.operations {
            w.bytes(&operation.encode())?;
        }
        w.bytes(&self.effects)?;
        Ok(w.finish())
    }
    /// Decodes observed content and checks static framing/signature context.
    /// The selected parent is still needed to verify time, effects and state.
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, LedgerError> {
        let mut r = Reader::new(bytes, genesis.profile().limits().record_bytes as usize)?;
        if r.fixed::<4>()? != *MAGIC || r.u16()? != 5 {
            return Err(LedgerError::Invalid("state record version"));
        }
        let context = GenesisId::from_bytes(r.fixed()?);
        let height = r.u64()?;
        let parent = RecordId::from_bytes(r.fixed()?);
        let previous = StateCommitment::from_bytes(r.fixed()?);
        let next = StateCommitment::from_bytes(r.fixed()?);
        let time = r.u64()?;
        if context != genesis.id() || height == 0 {
            return Err(LedgerError::Invalid("state record context"));
        }
        // The declared time restores the wire object's cache, but grants no
        // authority. State validation recomputes time against the actual parent.
        let time_certificate =
            TimeCertificate::decode_structure(r.bytes(TIME_CERTIFICATE_MAX_BYTES)?)?;
        let plan = HandoffPlan::decode(r.bytes(HANDOFF_PLAN_MAX_BYTES)?)?;
        let count = r.u32()?;
        if u64::from(count) > genesis.profile().limits().operations_per_record {
            return Err(LedgerError::Limit("record operations"));
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
            plan,
            effects,
        })
    }
}
