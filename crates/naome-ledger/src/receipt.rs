//! Bounded inspection of normalization receipts. Decoding establishes neither
//! mathematical validity nor finality; obtain authority through full replay.

use crate::{
    AccountId, CommitmentId, GenesisId, OperationId, PackageHash, ProfileId, ResearchError,
    SolutionRoundId, StateCommitment,
    accounting::{CitationRecipient, RewardPlan},
    codec::{Reader, Writer},
    library::{AdmissionCoordinate, ProofPackage},
    profile::Genesis,
    state::Receipt,
};
use naome_proof::ProofId;
use std::collections::BTreeMap;

/// Canonical receipt contents with independently recomputed integer rewards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizationReceipt {
    pub genesis: GenesisId,
    pub round: SolutionRoundId,
    pub winning_commit: Receipt,
    pub commitment: CommitmentId,
    pub original_hash: PackageHash,
    pub parent: StateCommitment,
    pub profile: ProfileId,
    pub substitutions: BTreeMap<ProofId, ProofId>,
    pub package: ProofPackage,
    pub root: ProofId,
    pub author: AccountId,
    pub new_proofs: Vec<(ProofId, AccountId)>,
    pub citations: Vec<(ProofId, AccountId)>,
    pub rewards: RewardPlan,
}

impl NormalizationReceipt {
    /// Reads the exact v1 settlement format. IDs and certificate contents remain
    /// untrusted claims until the containing history has been fully replayed.
    pub fn decode(bytes: &[u8], genesis: &Genesis) -> Result<Self, ResearchError> {
        let limits = genesis.profile().limits();
        let mut r = Reader::new(bytes, limits.record_bytes as usize)?;
        if r.u16()? != 1 {
            return Err(ResearchError::Invalid("normalization receipt version"));
        }
        let genesis_id = GenesisId::from_bytes(r.fixed()?);
        if genesis_id != genesis.id() {
            return Err(ResearchError::Invalid("normalization receipt genesis"));
        }
        let round = SolutionRoundId::from_bytes(r.fixed()?);
        let winning_commit = Receipt {
            operation: OperationId::from_bytes(r.fixed()?),
            author: AccountId::from_bytes(r.fixed()?),
            nonce: r.u64()?,
            coordinate: AdmissionCoordinate {
                height: r.u64()?,
                operation_index: r.u32()?,
            },
        };
        if winning_commit.coordinate.height == 0
            || winning_commit.coordinate.height > limits.run_records
            || u64::from(winning_commit.coordinate.operation_index) >= limits.operations_per_record
        {
            return Err(ResearchError::Invalid("winning commitment coordinate"));
        }
        let commitment = CommitmentId::from_bytes(r.fixed()?);
        let original_hash = PackageHash::from_bytes(r.fixed()?);
        let parent = StateCommitment::from_bytes(r.fixed()?);
        let profile = ProfileId::from_bytes(r.fixed()?);
        if profile != genesis.profile().id() {
            return Err(ResearchError::Invalid("normalization receipt profile"));
        }
        let count = read_count(&mut r, limits.new_helpers + 1)?;
        let mut substitutions = BTreeMap::new();
        let mut previous = None;
        for _ in 0..count {
            let old = ProofId::from_bytes(r.fixed()?);
            let new = ProofId::from_bytes(r.fixed()?);
            if previous.is_some_and(|id| id >= old) {
                return Err(ResearchError::Invalid("normalization substitution order"));
            }
            previous = Some(old);
            substitutions.insert(old, new);
        }
        let package =
            ProofPackage::decode(r.bytes(limits.package_bytes as usize)?, genesis.profile())?;
        let root = ProofId::from_bytes(r.fixed()?);
        let author = AccountId::from_bytes(r.fixed()?);
        if package.root() != root
            || package.author() != author
            || winning_commit.author != author
            || genesis.account_key(author).is_none()
        {
            return Err(ResearchError::Invalid("normalization package identity"));
        }
        let count = read_count(&mut r, limits.new_helpers + 1)?;
        if count != package.certificates().len() {
            return Err(ResearchError::Invalid("normalization publication count"));
        }
        let mut new_proofs = Vec::with_capacity(count);
        for (expected, _) in package.certificates() {
            let proof = ProofId::from_bytes(r.fixed()?);
            let recipient = AccountId::from_bytes(r.fixed()?);
            if proof != *expected || recipient != author {
                return Err(ResearchError::Invalid("normalization publication identity"));
            }
            new_proofs.push((proof, recipient));
        }
        let count = read_count(&mut r, limits.citation_proofs)?;
        let mut citations = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let proof = ProofId::from_bytes(r.fixed()?);
            let recipient = AccountId::from_bytes(r.fixed()?);
            if previous.is_some_and(|id| id >= proof)
                || genesis.account_key(recipient).is_none()
                || new_proofs.iter().any(|(id, _)| *id == proof)
            {
                return Err(ResearchError::Invalid("normalization citation identity"));
            }
            previous = Some(proof);
            citations.push((proof, recipient));
        }
        let rewards = RewardPlan::new(
            genesis,
            author,
            citations
                .iter()
                .map(|&(proof, recipient)| CitationRecipient { proof, recipient })
                .collect(),
        )?;
        // Comparing the exact expected encoding checks ordering, counts,
        // aggregation, all u128 values, reserve and per-proof remainders.
        let mut expected = Writer::new();
        rewards.encode_into(&mut expected);
        let expected = expected.finish();
        if r.take(expected.len())? != expected {
            return Err(ResearchError::Invalid("normalization reward plan"));
        }
        r.finish()?;
        Ok(Self {
            genesis: genesis_id,
            round,
            winning_commit,
            commitment,
            original_hash,
            parent,
            profile,
            substitutions,
            package,
            root,
            author,
            new_proofs,
            citations,
            rewards,
        })
    }
}

fn read_count(r: &mut Reader<'_>, maximum: u64) -> Result<usize, ResearchError> {
    let count = r.u32()?;
    if u64::from(count) > maximum {
        return Err(ResearchError::Limit("normalization receipt entries"));
    }
    Ok(count as usize)
}

#[cfg(test)]
mod tests;
