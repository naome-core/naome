//! Exact whole-atom reward plans and atomic balance updates.

use crate::{AccountId, GenesisId, LedgerError, codec::Writer, profile::Genesis};
use naome_proof::ProofId;
use std::collections::{BTreeMap, BTreeSet};

/// Stored recipient for one distinct eligible parent proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CitationRecipient {
    pub proof: ProofId,
    pub recipient: AccountId,
}

/// Reproducible reward arithmetic. Account registration, eligibility and
/// settlement require canonical ledger state, not construction of this plan.
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
    ) -> Result<Self, LedgerError> {
        if citations.len() as u64 > genesis.profile().limits().citation_proofs {
            return Err(LedgerError::Limit("citation recipients"));
        }
        citations.sort_by_key(|entry| entry.proof);
        if citations
            .windows(2)
            .any(|pair| pair[0].proof == pair[1].proof)
        {
            return Err(LedgerError::Invalid("duplicate eligible citation"));
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
                total.checked_add(*atoms).ok_or(LedgerError::Overflow)
            })?;
        if total != rewards.issuance_atoms {
            return Err(LedgerError::Invalid("reward conservation"));
        }
        Ok(plan)
    }
    fn credit(&mut self, recipient: AccountId, atoms: u128) -> Result<(), LedgerError> {
        let balance = self.credits.entry(recipient).or_default();
        *balance = balance.checked_add(atoms).ok_or(LedgerError::Overflow)?;
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
    /// Adds a zero balance after canonical account admission. It never issues
    /// currency or overwrites a previously registered account.
    pub(crate) fn register(&mut self, account: AccountId) -> Result<(), LedgerError> {
        match self.accounts.entry(account) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(0);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(LedgerError::Invalid("balance account already registered"))
            }
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
        registry: &BTreeMap<AccountId, [u8; 32]>,
    ) -> Result<(), LedgerError> {
        if plan.genesis != genesis.id() {
            return Err(LedgerError::Invalid("reward plan genesis"));
        }
        let mut next = self.clone();
        for (recipient, atoms) in &plan.credits {
            let balance = next
                .accounts
                .get_mut(recipient)
                .ok_or(LedgerError::Invalid("payment account"))?;
            *balance = balance.checked_add(*atoms).ok_or(LedgerError::Overflow)?;
        }
        next.reserve = next
            .reserve
            .checked_add(plan.reserve)
            .ok_or(LedgerError::Overflow)?;
        next.paid_completions = next
            .paid_completions
            .checked_add(1)
            .ok_or(LedgerError::Overflow)?;
        next.verify_conservation(genesis, registry)?;
        *self = next;
        Ok(())
    }
    /// Verifies complete account membership and the once-per-completion supply.
    pub fn verify_conservation(
        &self,
        genesis: &Genesis,
        registry: &BTreeMap<AccountId, [u8; 32]>,
    ) -> Result<(), LedgerError> {
        let registered: BTreeSet<_> = registry.keys().copied().collect();
        if self.accounts.keys().copied().collect::<BTreeSet<_>>() != registered {
            return Err(LedgerError::Invalid("balance account set"));
        }
        let expected = u128::from(self.paid_completions)
            .checked_mul(genesis.profile().rewards().issuance_atoms)
            .ok_or(LedgerError::Overflow)?;
        let actual = self
            .accounts
            .values()
            .try_fold(self.reserve, |total, atoms| {
                total.checked_add(*atoms).ok_or(LedgerError::Overflow)
            })?;
        if actual != expected {
            return Err(LedgerError::Invalid("total supply conservation"));
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
