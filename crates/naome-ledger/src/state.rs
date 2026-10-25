//! The deterministic state transition owner. Validation never mutates state.
use crate::{
    Amount, Error, Genesis, MAX_ITEMS, NetworkId, Operation, OutPoint, Output, SignedTransaction,
    TransactionId,
};
use naome_wallet::{Address, WalletKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct Access {
    sequence: u64,
    delegates: BTreeMap<Address, u64>,
}
/// Checked UTXOs and revocable node spending rights for one transaction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    network: NetworkId,
    supply: Amount,
    utxos: BTreeMap<OutPoint, Output>,
    access: BTreeMap<Address, Access>,
    count: u64,
    journal_root: [u8; 32],
}
pub(crate) struct Checked {
    pub(crate) id: TransactionId,
    operation: Operation,
}
impl State {
    pub fn new(genesis: &Genesis) -> Result<Self, Error> {
        let supply = genesis.validate()?;
        let network = genesis.network()?;
        let utxos = genesis
            .outputs
            .iter()
            .enumerate()
            .map(|(index, output)| {
                (
                    OutPoint {
                        transaction: TransactionId::from_bytes(*network.as_bytes()),
                        index: index as u32,
                    },
                    output.clone(),
                )
            })
            .collect();
        Ok(Self {
            network,
            supply,
            utxos,
            access: BTreeMap::new(),
            count: 0,
            journal_root: *network.as_bytes(),
        })
    }
    pub const fn network(&self) -> NetworkId {
        self.network
    }
    pub const fn supply(&self) -> Amount {
        self.supply
    }
    pub const fn transaction_count(&self) -> u64 {
        self.count
    }
    /// Commits to the genesis and the exact admitted transaction order.
    pub const fn journal_root(&self) -> &[u8; 32] {
        &self.journal_root
    }
    pub(crate) fn next_journal_root(&self, id: TransactionId) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"naome:ledger-journal:v1\0");
        hash.update(self.journal_root);
        hash.update(id.as_bytes());
        hash.finalize().into()
    }
    pub fn unspent(&self) -> impl Iterator<Item = (&OutPoint, &Output)> {
        self.utxos.iter()
    }
    pub fn balance(&self, address: Address) -> Result<Amount, Error> {
        self.utxos
            .values()
            .filter(|output| output.address == address)
            .try_fold(Amount::default(), |sum, output| {
                sum.checked_add(output.amount)
            })
    }
    /// Returns the current grant epoch, or zero for the owner's own key.
    pub fn spending_authority(&self, owner: Address, signer: Address) -> Option<u64> {
        if owner == signer {
            Some(0)
        } else {
            self.access.get(&owner)?.delegates.get(&signer).copied()
        }
    }
    pub fn authorized_nodes(&self, owner: Address) -> Vec<Address> {
        self.access
            .get(&owner)
            .map(|access| access.delegates.keys().copied().collect())
            .unwrap_or_default()
    }
    /// Selects inputs deterministically and returns a signed, unapplied payment.
    pub fn payment(
        &self,
        owner: Address,
        key: &WalletKey,
        recipient: Address,
        amount: Amount,
    ) -> Result<SignedTransaction, Error> {
        if amount.units() == 0 {
            return Err(Error::Invalid("payment must be positive"));
        }
        let authorization = self
            .spending_authority(owner, key.address())
            .ok_or(Error::Unauthorized)?;
        let mut inputs = Vec::new();
        let mut sum = Amount::default();
        for (point, output) in &self.utxos {
            if output.address != owner {
                continue;
            }
            if inputs.len() == MAX_ITEMS {
                return Err(Error::Capacity);
            }
            inputs.push(*point);
            sum = sum.checked_add(output.amount)?;
            if sum >= amount {
                break;
            }
        }
        let change = sum.checked_sub(amount)?;
        let mut outputs = vec![Output {
            address: recipient,
            amount,
        }];
        if change.units() > 0 {
            outputs.push(Output {
                address: owner,
                amount: change,
            });
        }
        SignedTransaction::sign(
            self.network,
            Operation::Payment {
                owner,
                authorization,
                inputs,
                outputs,
            },
            key,
        )
    }
    /// Grants full spending access, or revokes one node key. No main key is copied.
    pub fn access_change(
        &self,
        owner: Address,
        key: &WalletKey,
        delegate: Address,
        enabled: bool,
    ) -> Result<SignedTransaction, Error> {
        let sequence = self
            .access
            .get(&owner)
            .map_or(0, |access| access.sequence)
            .checked_add(1)
            .ok_or(Error::AmountOverflow)?;
        let transaction = SignedTransaction::sign(
            self.network,
            Operation::Access {
                owner,
                delegate,
                sequence,
                enabled,
            },
            key,
        )?;
        self.validate(&transaction)?;
        Ok(transaction)
    }
    pub fn apply(&mut self, transaction: &SignedTransaction) -> Result<TransactionId, Error> {
        let checked = self.validate(transaction)?;
        let id = checked.id;
        self.commit(checked);
        Ok(id)
    }
    pub(crate) fn validate(&self, transaction: &SignedTransaction) -> Result<Checked, Error> {
        if transaction.network != self.network {
            return Err(Error::WrongNetwork);
        }
        let id = transaction.verify_signature()?;
        self.count.checked_add(1).ok_or(Error::AmountOverflow)?;
        match &transaction.operation {
            Operation::Payment {
                owner,
                authorization,
                inputs,
                outputs,
            } => {
                if self.spending_authority(*owner, transaction.signer) != Some(*authorization) {
                    return Err(Error::Unauthorized);
                }
                let mut seen = BTreeSet::new();
                let mut sum = Amount::default();
                for input in inputs {
                    if !seen.insert(input) {
                        return Err(Error::DuplicateInput);
                    }
                    let output = self.utxos.get(input).ok_or(Error::MissingInput)?;
                    if output.address != *owner {
                        return Err(Error::Unauthorized);
                    }
                    sum = sum.checked_add(output.amount)?;
                }
                if crate::model::output_sum(outputs)? != sum {
                    return Err(Error::ValueMismatch);
                }
                for index in 0..outputs.len() {
                    if self.utxos.contains_key(&OutPoint {
                        transaction: id,
                        index: index as u32,
                    }) {
                        return Err(Error::Invalid("transaction output collision"));
                    }
                }
            }
            Operation::Access {
                owner,
                delegate,
                sequence,
                enabled,
            } => {
                let next = self
                    .access
                    .get(owner)
                    .map_or(0, |a| a.sequence)
                    .checked_add(1)
                    .ok_or(Error::AmountOverflow)?;
                if *sequence != next {
                    return Err(Error::InvalidSequence);
                }
                let active = self.spending_authority(*owner, *delegate).is_some();
                if transaction.signer != *owner
                    && (*enabled || transaction.signer != *delegate || !active)
                {
                    return Err(Error::Unauthorized);
                }
                if active == *enabled {
                    return Err(Error::Invalid(
                        "node spending authorization already has this state",
                    ));
                }
            }
        }
        Ok(Checked {
            id,
            operation: transaction.operation.clone(),
        })
    }
    pub(crate) fn commit(&mut self, checked: Checked) {
        self.journal_root = self.next_journal_root(checked.id);
        match checked.operation {
            Operation::Payment {
                inputs, outputs, ..
            } => {
                for input in inputs {
                    self.utxos.remove(&input);
                }
                for (index, output) in outputs.into_iter().enumerate() {
                    self.utxos.insert(
                        OutPoint {
                            transaction: checked.id,
                            index: index as u32,
                        },
                        output,
                    );
                }
            }
            Operation::Access {
                owner,
                delegate,
                sequence,
                enabled,
            } => {
                let access = self.access.entry(owner).or_default();
                access.sequence = sequence;
                if enabled {
                    access.delegates.insert(delegate, sequence);
                } else {
                    access.delegates.remove(&delegate);
                }
            }
        }
        self.count += 1;
    }
}

#[cfg(test)]
mod tests;
