//! Exact parent-bound inputs selected inside a research record for its successor seal.

use super::*;
use crate::OperationId;
use ed25519_dalek::{Signature, Signer, SigningKey};

const PLAN_MAGIC: &[u8; 5] = b"NSHP5";
const CANDIDATE_MAGIC: &[u8; 5] = b"NSCA5";
const OWNER_DOMAIN: &[u8] = b"naome:state:candidate-ready-owner:v5\0";
const CONSENSUS_DOMAIN: &[u8] = b"naome:state:candidate-ready-consensus:v5\0";
const TRANSPORT_DOMAIN: &[u8] = b"naome:state:candidate-ready-transport:v5\0";
pub const HANDOFF_PLAN_MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateAdmissionOffer {
    family: ResolutionId,
    intent_receipt: OperationId,
    parent_snapshot: [u8; 32],
    parent_record: RecordId,
    parent_state: StateCommitment,
    effective_height: u64,
    keys: PeriodKeys,
    owner_signature: [u8; 64],
    consensus_proof: [u8; 64],
    transport_proof: [u8; 64],
}
impl CandidateAdmissionOffer {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        snapshot: &AuthoritySnapshot,
        parent_record: RecordId,
        parent_state: StateCommitment,
        family: ResolutionId,
        intent_receipt: OperationId,
        owner: &SigningKey,
        consensus: &SigningKey,
        transport: &SigningKey,
        endpoint: String,
    ) -> Result<Self, LedgerError> {
        let mut result = Self {
            family,
            intent_receipt,
            parent_snapshot: snapshot.id(),
            parent_record,
            parent_state,
            effective_height: snapshot
                .effective_height()
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
        let body = result.body()?;
        result.owner_signature = owner.sign(&message(OWNER_DOMAIN, &body)).to_bytes();
        result.consensus_proof = consensus.sign(&message(CONSENSUS_DOMAIN, &body)).to_bytes();
        result.transport_proof = transport.sign(&message(TRANSPORT_DOMAIN, &body)).to_bytes();
        Ok(result)
    }
    pub const fn family(&self) -> ResolutionId {
        self.family
    }
    pub const fn intent_receipt(&self) -> OperationId {
        self.intent_receipt
    }
    pub fn keys(&self) -> &PeriodKeys {
        &self.keys
    }
    pub fn verify(
        &self,
        snapshot: &AuthoritySnapshot,
        parent_record: RecordId,
        parent_state: StateCommitment,
        account_key: [u8; 32],
    ) -> Result<(), LedgerError> {
        if self.parent_snapshot != snapshot.id()
            || self.parent_record != parent_record
            || self.parent_state != parent_state
            || self.effective_height
                != snapshot
                    .effective_height()
                    .checked_add(1)
                    .ok_or(LedgerError::Overflow)?
        {
            return Err(LedgerError::Invalid("candidate readiness context"));
        }
        self.keys.validate()?;
        let body = self.body()?;
        for (key, signature, domain) in [
            (&account_key, &self.owner_signature, OWNER_DOMAIN),
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
            VerifyingKey::from_bytes(key)
                .map_err(|_| LedgerError::Invalid("candidate readiness key"))?
                .verify_strict(&message(domain, &body), &Signature::from_bytes(signature))
                .map_err(|_| LedgerError::Invalid("candidate readiness signature"))?;
        }
        Ok(())
    }
    fn body(&self) -> Result<Vec<u8>, LedgerError> {
        let mut w = Writer::new();
        w.fixed(CANDIDATE_MAGIC);
        w.fixed(self.family.as_bytes());
        w.fixed(self.intent_receipt.as_bytes());
        w.fixed(&self.parent_snapshot);
        w.fixed(self.parent_record.as_bytes());
        w.fixed(self.parent_state.as_bytes());
        w.u64(self.effective_height);
        w.fixed(self.keys.consensus());
        w.fixed(self.keys.transport());
        w.string(self.keys.endpoint())?;
        Ok(w.finish())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body().expect("bounded candidate endpoint");
        out.extend(self.owner_signature);
        out.extend(self.consensus_proof);
        out.extend(self.transport_proof);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut r = Reader::new(bytes, 1024)?;
        if r.fixed::<5>()? != *CANDIDATE_MAGIC {
            return Err(LedgerError::Invalid("candidate readiness format"));
        }
        let result = Self {
            family: ResolutionId::from_bytes(r.fixed()?),
            intent_receipt: OperationId::from_bytes(r.fixed()?),
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
        if result.encode() != bytes {
            return Err(LedgerError::Invalid("noncanonical candidate readiness"));
        }
        Ok(result)
    }
}

fn message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(domain.len() + body.len());
    result.extend_from_slice(domain);
    result.extend_from_slice(body);
    result
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandoffPlan {
    offers: Vec<NextPeriodKeys>,
    candidate: Option<CandidateAdmissionOffer>,
}
impl HandoffPlan {
    pub fn new(
        offers: Vec<NextPeriodKeys>,
        candidate: Option<CandidateAdmissionOffer>,
    ) -> Result<Self, LedgerError> {
        if !(3..=4).contains(&offers.len())
            || offers
                .windows(2)
                .any(|pair| pair[0].unit() >= pair[1].unit())
        {
            return Err(LedgerError::Invalid("handoff offer count or order"));
        }
        let result = Self { offers, candidate };
        if result.encode().len() > HANDOFF_PLAN_MAX_BYTES {
            return Err(LedgerError::Limit("handoff plan bytes"));
        }
        Ok(result)
    }
    pub fn offers(&self) -> &[NextPeriodKeys] {
        &self.offers
    }
    pub fn candidate(&self) -> Option<&CandidateAdmissionOffer> {
        self.candidate.as_ref()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.fixed(PLAN_MAGIC);
        w.u8(self.offers.len() as u8);
        for offer in &self.offers {
            w.bytes(&offer.encode()).expect("bounded period offer");
        }
        if let Some(candidate) = &self.candidate {
            w.u8(1);
            w.bytes(&candidate.encode())
                .expect("bounded candidate offer");
        } else {
            w.u8(0);
        }
        w.finish()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut r = Reader::new(bytes, HANDOFF_PLAN_MAX_BYTES)?;
        if r.fixed::<5>()? != *PLAN_MAGIC {
            return Err(LedgerError::Invalid("handoff plan format"));
        }
        let count = r.u8()?;
        if !(3..=4).contains(&count) {
            return Err(LedgerError::Invalid("handoff offer count"));
        }
        let mut offers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            offers.push(NextPeriodKeys::decode(r.bytes(1024)?)?);
        }
        let candidate = match r.u8()? {
            0 => None,
            1 => Some(CandidateAdmissionOffer::decode(r.bytes(1024)?)?),
            _ => return Err(LedgerError::Invalid("candidate readiness option")),
        };
        r.finish()?;
        let result = Self::new(offers, candidate)?;
        if result.encode() != bytes {
            return Err(LedgerError::Invalid("noncanonical handoff plan"));
        }
        Ok(result)
    }
}
