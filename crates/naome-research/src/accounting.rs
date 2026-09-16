//! Exact whole-atom reward plans and atomic balance updates.

use crate::{AccountId, GenesisId, ResearchError, codec::Writer, profile::Genesis};
use naome_proof::ProofId;
use std::collections::{BTreeMap, BTreeSet};

/// Stored recipient for one distinct eligible parent proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CitationRecipient {
    pub proof: ProofId,
    pub recipient: AccountId,
}

/// Reproducible reward arithmetic. Eligibility and settlement are checked by
/// the research state machine, not established by constructing this plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardPlan {
    genesis: GenesisId,
    credits: BTreeMap<AccountId, u128>,
    reserve: u128,
    citations: Vec<(ProofId, AccountId, u128)>,
}

impl RewardPlan {
    /// Divides the fixed issuance, allocating remainders by raw ProofId order.
    pub fn new(
        genesis: &Genesis,
        author: AccountId,
        mut citations: Vec<CitationRecipient>,
    ) -> Result<Self, ResearchError> {
        if genesis.account_key(author).is_none() {
            return Err(ResearchError::Invalid("reward author account"));
        }
        if citations.len() as u64 > genesis.profile().limits().citation_proofs {
            return Err(ResearchError::Limit("citation recipients"));
        }
        citations.sort_by_key(|entry| entry.proof);
        if citations
            .windows(2)
            .any(|pair| pair[0].proof == pair[1].proof)
        {
            return Err(ResearchError::Invalid("duplicate eligible citation"));
        }
        if citations
            .iter()
            .any(|entry| genesis.account_key(entry.recipient).is_none())
        {
            return Err(ResearchError::Invalid("citation recipient account"));
        }
        let rewards = genesis.profile().rewards();
        let mut plan = Self {
            genesis: genesis.id(),
            credits: BTreeMap::new(),
            reserve: rewards.reserve_atoms,
            citations: Vec::new(),
        };
        plan.credit(
            author,
            if citations.is_empty() {
                rewards.author_without_citations_atoms
            } else {
                rewards.author_with_citations_atoms
            },
        )?;
        for validator in genesis.validators() {
            plan.credit(validator.owner, rewards.validator_atoms_each)?;
        }
        if !citations.is_empty() {
            let count = citations.len() as u128;
            let quotient = rewards.citation_pool_atoms / count;
            let remainder = rewards.citation_pool_atoms % count;
            for (index, citation) in citations.into_iter().enumerate() {
                let atoms = quotient + u128::from((index as u128) < remainder);
                plan.credit(citation.recipient, atoms)?;
                plan.citations
                    .push((citation.proof, citation.recipient, atoms));
            }
        }
        let total = plan
            .credits
            .values()
            .try_fold(plan.reserve, |total, atoms| {
                total.checked_add(*atoms).ok_or(ResearchError::Overflow)
            })?;
        if total != rewards.issuance_atoms {
            return Err(ResearchError::Invalid("reward conservation"));
        }
        Ok(plan)
    }
    fn credit(&mut self, recipient: AccountId, atoms: u128) -> Result<(), ResearchError> {
        let balance = self.credits.entry(recipient).or_default();
        *balance = balance.checked_add(atoms).ok_or(ResearchError::Overflow)?;
        Ok(())
    }
    /// Returns credits after proof-level division and recipient aggregation.
    pub fn credits(&self) -> &BTreeMap<AccountId, u128> {
        &self.credits
    }
    /// Returns the reserve allocation.
    pub const fn reserve(&self) -> u128 {
        self.reserve
    }
    /// Returns per-proof allocations in raw ProofId order.
    pub fn citations(&self) -> &[(ProofId, AccountId, u128)] {
        &self.citations
    }
    pub(crate) fn encode_into(&self, writer: &mut Writer) {
        writer.fixed(self.genesis.as_bytes());
        writer.u32(self.credits.len() as u32);
        for (recipient, atoms) in &self.credits {
            writer.fixed(recipient.as_bytes());
            writer.u128(*atoms);
        }
        writer.u128(self.reserve);
        writer.u32(self.citations.len() as u32);
        for (proof, recipient, atoms) in &self.citations {
            writer.fixed(proof.as_bytes());
            writer.fixed(recipient.as_bytes());
            writer.u128(*atoms);
        }
    }
}

/// Zero-starting monetary state. Only validated atomic settlement may credit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balances {
    accounts: BTreeMap<AccountId, u128>,
    reserve: u128,
    paid_completions: u64,
}

impl Balances {
    pub(crate) fn new(genesis: &Genesis) -> Self {
        Self {
            accounts: genesis.accounts().iter().map(|a| (a.id(), 0)).collect(),
            reserve: 0,
            paid_completions: 0,
        }
    }
    /// Returns a registered account's exact balance.
    pub fn account(&self, account: AccountId) -> Option<u128> {
        self.accounts.get(&account).copied()
    }
    /// Returns all registered balances in account-ID order.
    pub fn accounts(&self) -> &BTreeMap<AccountId, u128> {
        &self.accounts
    }
    /// Returns reserve atoms, separately from resource reservation capacity.
    pub const fn reserve(&self) -> u128 {
        self.reserve
    }
    /// Returns the number of issuance events.
    pub const fn paid_completions(&self) -> u64 {
        self.paid_completions
    }
    pub(crate) fn apply(
        &mut self,
        plan: &RewardPlan,
        genesis: &Genesis,
    ) -> Result<(), ResearchError> {
        if plan.genesis != genesis.id() {
            return Err(ResearchError::Invalid("reward plan genesis"));
        }
        let mut next = self.clone();
        for (recipient, atoms) in &plan.credits {
            let balance = next
                .accounts
                .get_mut(recipient)
                .ok_or(ResearchError::Invalid("payment account"))?;
            *balance = balance.checked_add(*atoms).ok_or(ResearchError::Overflow)?;
        }
        next.reserve = next
            .reserve
            .checked_add(plan.reserve)
            .ok_or(ResearchError::Overflow)?;
        next.paid_completions = next
            .paid_completions
            .checked_add(1)
            .ok_or(ResearchError::Overflow)?;
        next.verify_conservation(genesis)?;
        *self = next;
        Ok(())
    }
    /// Verifies complete account membership and the once-per-completion supply.
    pub fn verify_conservation(&self, genesis: &Genesis) -> Result<(), ResearchError> {
        let registered: BTreeSet<_> = genesis.accounts().iter().map(|a| a.id()).collect();
        if self.accounts.keys().copied().collect::<BTreeSet<_>>() != registered {
            return Err(ResearchError::Invalid("balance account set"));
        }
        let expected = u128::from(self.paid_completions)
            .checked_mul(genesis.profile().rewards().issuance_atoms)
            .ok_or(ResearchError::Overflow)?;
        let actual = self
            .accounts
            .values()
            .try_fold(self.reserve, |total, atoms| {
                total.checked_add(*atoms).ok_or(ResearchError::Overflow)
            })?;
        if actual != expected {
            return Err(ResearchError::Invalid("total supply conservation"));
        }
        Ok(())
    }
    pub(crate) fn encode_into(&self, writer: &mut Writer) {
        writer.u32(self.accounts.len() as u32);
        for (account, atoms) in &self.accounts {
            writer.fixed(account.as_bytes());
            writer.u128(*atoms);
        }
        writer.u128(self.reserve);
        writer.u64(self.paid_completions);
    }
}

#[cfg(test)]
mod tests;
