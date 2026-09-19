//! Quorum-certified protocol time. No replay operation reads a local clock.

use crate::{
    GenesisId, LedgerError, RecordId, ValidatorId,
    codec::{Reader, Writer},
    profile::Genesis,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const MAGIC: &[u8; 4] = b"NSTM";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"naome:state:time:v1\0";
/// Exact encoded width of one signed report.
pub const TIME_REPORT_BYTES: usize = 4 + 2 + 32 + 32 + 8 + 32 + 8 + 64;
/// A fixed four-validator time certificate never exceeds this byte count.
pub const TIME_CERTIFICATE_MAX_BYTES: usize = 1 + 4 * TIME_REPORT_BYTES;

/// One validator's signed report for an exact parent and height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTimeReport {
    genesis: GenesisId,
    parent: RecordId,
    height: u64,
    validator: ValidatorId,
    utc_seconds: u64,
    signature: [u8; 64],
}

impl SignedTimeReport {
    /// Signs a report after the caller has verified its parent and local clock.
    /// Re-reporting time while a height remains undecided is permitted; retained
    /// proposals keep their original reports unchanged.
    pub fn sign(
        genesis: &Genesis,
        parent: RecordId,
        height: u64,
        utc_seconds: u64,
        key: &SigningKey,
    ) -> Result<Self, LedgerError> {
        let validator = ValidatorId::for_key(key.verifying_key().as_bytes());
        if genesis.validator(validator).is_none() {
            return Err(LedgerError::Invalid("unregistered time signer"));
        }
        if height == 0 {
            return Err(LedgerError::Invalid("zero report height"));
        }
        let mut report = Self {
            genesis: genesis.id(),
            parent,
            height,
            validator,
            utc_seconds,
            signature: [0; 64],
        };
        report.signature = key.sign(&report.signing_bytes()).to_bytes();
        Ok(report)
    }
    /// Validates a report's fixed authority and exact context.
    pub fn verify(
        &self,
        genesis: &Genesis,
        parent: RecordId,
        height: u64,
    ) -> Result<(), LedgerError> {
        if height == 0
            || self.height != height
            || self.parent != parent
            || self.genesis != genesis.id()
        {
            return Err(LedgerError::Invalid("time report context"));
        }
        let registration = genesis
            .validator(self.validator)
            .ok_or(LedgerError::Invalid("time report validator"))?;
        let key = VerifyingKey::from_bytes(&registration.consensus_key)
            .map_err(|_| LedgerError::Invalid("time signer key"))?;
        key.verify_strict(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| LedgerError::Invalid("time report signature"))
    }
    /// Returns the reporting validator.
    pub const fn validator(&self) -> ValidatorId {
        self.validator
    }
    /// Returns signed integer UTC seconds.
    pub const fn utc_seconds(&self) -> u64 {
        self.utc_seconds
    }
    /// Encodes the report including its exact signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.content_bytes();
        bytes.extend_from_slice(&self.signature);
        bytes
    }
    /// Decodes a report without granting authority.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let mut reader = Reader::new(bytes, TIME_REPORT_BYTES)?;
        if reader.fixed::<4>()? != *MAGIC || reader.u16()? != VERSION {
            return Err(LedgerError::Invalid("time report format"));
        }
        let report = Self {
            genesis: GenesisId::from_bytes(reader.fixed()?),
            parent: RecordId::from_bytes(reader.fixed()?),
            height: reader.u64()?,
            validator: ValidatorId::from_bytes(reader.fixed()?),
            utc_seconds: reader.u64()?,
            signature: reader.fixed()?,
        };
        reader.finish()?;
        if report.height == 0 {
            return Err(LedgerError::Invalid("zero report height"));
        }
        Ok(report)
    }
    fn content_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.fixed(MAGIC);
        writer.u16(VERSION);
        writer.fixed(self.genesis.as_bytes());
        writer.fixed(self.parent.as_bytes());
        writer.u64(self.height);
        writer.fixed(self.validator.as_bytes());
        writer.u64(self.utc_seconds);
        writer.finish()
    }
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(self.content_bytes());
        bytes
    }
}

/// Verified time evidence for one parent. The chosen reports are record content,
/// unlike the later consensus signature subset certifying that record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeCertificate {
    reports: Vec<SignedTimeReport>,
    time: u64,
}

#[cfg(test)]
mod tests;

impl TimeCertificate {
    /// Verifies three or four distinct reports, then sorts their wire order.
    pub fn new(
        mut reports: Vec<SignedTimeReport>,
        genesis: &Genesis,
        parent: RecordId,
        height: u64,
        parent_time: u64,
    ) -> Result<Self, LedgerError> {
        if !(3..=4).contains(&reports.len()) {
            return Err(LedgerError::Invalid("time quorum"));
        }
        reports.sort_by_key(SignedTimeReport::validator);
        for pair in reports.windows(2) {
            if pair[0].validator == pair[1].validator {
                return Err(LedgerError::Invalid("duplicate time signer"));
            }
        }
        let mut seconds = Vec::with_capacity(reports.len());
        for report in &reports {
            report.verify(genesis, parent, height)?;
            seconds.push(report.utc_seconds);
        }
        seconds.sort_unstable();
        let time = parent_time.max(seconds[(seconds.len() - 1) / 2]);
        Ok(Self { reports, time })
    }
    /// Returns max(parent time, lower median of the included signed reports).
    pub const fn time(&self) -> u64 {
        self.time
    }
    /// Returns the canonical validator-ordered reports.
    pub fn reports(&self) -> &[SignedTimeReport] {
        &self.reports
    }
    /// Encodes all chosen reports. No computed time is trusted on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.u8(self.reports.len() as u8);
        for report in &self.reports {
            writer.fixed(&report.encode());
        }
        writer.finish()
    }
    /// Decodes, rejects noncanonical order, and verifies against an exact parent.
    pub fn decode(
        bytes: &[u8],
        genesis: &Genesis,
        parent: RecordId,
        height: u64,
        parent_time: u64,
    ) -> Result<Self, LedgerError> {
        let mut reader = Reader::new(bytes, TIME_CERTIFICATE_MAX_BYTES)?;
        let count = reader.u8()?;
        if !(3..=4).contains(&count) {
            return Err(LedgerError::Invalid("time quorum"));
        }
        let mut reports = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let report = SignedTimeReport::decode(reader.take(TIME_REPORT_BYTES)?)?;
            if reports
                .last()
                .is_some_and(|last: &SignedTimeReport| last.validator >= report.validator)
            {
                return Err(LedgerError::Invalid("time report order"));
            }
            reports.push(report);
        }
        reader.finish()?;
        Self::new(reports, genesis, parent, height, parent_time)
    }
}
