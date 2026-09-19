use super::codec::{Reader, Writer};
use naome_ledger::LedgerError;

const MAGIC: &[u8; 5] = b"NSCF1";

/// Canonical wire record binding a complete state proposal to finality evidence.
///
/// Decoding checks framing and limits only: these borrowed bytes remain
/// untrusted. Consensus must authenticate the producer and quorum, check their
/// binding to the contained StateRecord, and replay against the exact parent.
/// Storage may select the successor only after those checks and durable append.
/// Different sufficient signer subsets do not change the inner StateRecord ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalizedStateRecord<'a> {
    proposal: &'a [u8],
    quorum: &'a [u8],
}
impl<'a> FinalizedStateRecord<'a> {
    pub fn decode(
        input: &'a [u8],
        maximum_bytes: usize,
        maximum_quorum_bytes: usize,
    ) -> Result<Self, LedgerError> {
        let mut reader = Reader::new(input, maximum_bytes)?;
        if reader.fixed::<5>()? != *MAGIC {
            return Err(LedgerError::Invalid("finalized state record version"));
        }
        let proposal = reader.bytes(maximum_bytes)?;
        let quorum = reader.bytes(maximum_quorum_bytes)?;
        reader.finish()?;
        Ok(Self { proposal, quorum })
    }
    pub const fn proposal(&self) -> &'a [u8] {
        self.proposal
    }
    pub const fn quorum(&self) -> &'a [u8] {
        self.quorum
    }

    /// Frames exact evidence bytes; this does not authenticate their content.
    pub fn encode_evidence(proposal: &[u8], quorum: &[u8]) -> Result<Vec<u8>, LedgerError> {
        let mut writer = Writer::new();
        writer.fixed(MAGIC);
        writer.bytes(proposal)?;
        writer.bytes(quorum)?;
        Ok(writer.finish())
    }
}
