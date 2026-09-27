//! Anchored local delivery custody. These bytes grant no ledger or consensus authority.

use std::{collections::BTreeMap, path::Path};

use naome_ledger::{
    AccountId, LedgerState, OperationId,
    authentication::SignedOperation,
    profile::{Genesis, PENDING_ACTION_JOURNAL_BYTES},
};

use super::{
    StateStorageError as Error,
    log::{FileLog, Limits},
};

const MAGIC: &[u8; 8] = b"NAOPEND1";
const ACCEPT: u8 = 1;
const REJECT: u8 = 2;
const MAX_REASON: usize = 512;
const MAX_EVICTIONS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingActionStatus {
    Pending,
    Deferred(String),
    Rejected(String),
}

struct Entry {
    action: SignedOperation,
    status: PendingActionStatus,
}

/// Exact accepted actions and explicit local outcomes, independent of selected history.
pub struct StatePendingActions {
    log: FileLog,
    entries: BTreeMap<OperationId, Entry>,
    live: BTreeMap<(AccountId, u64), OperationId>,
    unresolved: usize,
    genesis: Genesis,
}

impl StatePendingActions {
    pub fn create(directory: &Path, anchors: &Path, genesis: Genesis) -> Result<Self, Error> {
        let (prefix, limits) = context(&genesis)?;
        let log = FileLog::create(
            directory,
            anchors,
            "state-pending.journal",
            "state-pending.lock",
            "state-pending.anchor",
            &prefix,
            limits,
        )?;
        Ok(Self {
            log,
            entries: BTreeMap::new(),
            live: BTreeMap::new(),
            unresolved: 0,
            genesis,
        })
    }

    pub fn open(directory: &Path, anchors: &Path, genesis: Genesis) -> Result<Self, Error> {
        let (prefix, limits) = context(&genesis)?;
        let mut entries = BTreeMap::new();
        let mut live = BTreeMap::new();
        let log = FileLog::open(
            directory,
            anchors,
            "state-pending.journal",
            "state-pending.lock",
            "state-pending.anchor",
            &prefix,
            limits,
            |frame| apply(&mut entries, &mut live, frame, &genesis),
        )?;
        Ok(Self {
            log,
            unresolved: entries
                .values()
                .filter(|entry| unresolved(&entry.status))
                .count(),
            entries,
            live,
            genesis,
        })
    }

    pub fn pending(&self) -> impl Iterator<Item = &SignedOperation> {
        self.live.values().map(|id| &self.entries[id].action)
    }

    /// Discard only entries already proved by the selected ledger history.
    /// The journal remains append-only and can reconstruct them on reopen.
    pub fn forget_finalized(&mut self, state: &LedgerState) {
        let finalized: Vec<_> = self
            .entries
            .keys()
            .copied()
            .filter(|id| state.receipt(*id).is_some())
            .collect();
        self.forget(finalized);
    }

    pub fn forget_finalized_pending(&mut self, state: &LedgerState) {
        let finalized: Vec<_> = self
            .live
            .values()
            .copied()
            .filter(|id| state.receipt(*id).is_some())
            .collect();
        self.forget(finalized);
    }

    fn forget(&mut self, finalized: Vec<OperationId>) {
        for id in finalized {
            if let Some(entry) = self.entries.remove(&id) {
                if unresolved(&entry.status) {
                    self.unresolved -= 1;
                }
                let key = (entry.action.author(), entry.action.nonce());
                if self.live.get(&key) == Some(&id) {
                    self.live.remove(&key);
                }
            }
        }
    }

    pub fn status(&self, id: OperationId) -> Option<&PendingActionStatus> {
        self.entries.get(&id).map(|entry| &entry.status)
    }

    #[cfg(all(test, unix))]
    pub(super) fn exhaust_capacity_for_test(&mut self) {
        self.log.core.exhaust_capacity(true);
    }

    /// One anchored frame replaces any lower priority pending inputs and accepts
    /// the exact new bytes. A crash cannot expose only half of that transition.
    pub fn accept(
        &mut self,
        action: &SignedOperation,
        displaced: &[OperationId],
    ) -> Result<(), Error> {
        if displaced.len() > MAX_EVICTIONS {
            return Err(Error::Limit("pending action displacements"));
        }
        let bytes = action.encode();
        let mut frame = Vec::with_capacity(1 + 1 + displaced.len() * 32 + 4 + bytes.len());
        frame.push(ACCEPT);
        frame.push(displaced.len() as u8);
        for id in displaced {
            frame.extend_from_slice(id.as_bytes());
        }
        frame.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&bytes);
        action.verify_signature(&self.genesis)?;
        if bytes.len() > self.genesis.profile().limits().record_bytes as usize {
            return Err(Error::Limit("pending action bytes"));
        }
        if self.entries.get(&action.id()).is_some_and(|entry| {
            entry.action != *action || entry.status == PendingActionStatus::Pending
        }) {
            return Err(Error::Invalid("conflicting pending action identity"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for id in displaced {
            if !seen.insert(*id)
                || self
                    .entries
                    .get(id)
                    .is_none_or(|entry| entry.status != PendingActionStatus::Pending)
            {
                return Err(Error::Invalid("pending action displacement"));
            }
        }
        if self
            .live
            .get(&(action.author(), action.nonce()))
            .is_some_and(|id| !seen.contains(id))
        {
            return Err(Error::Invalid("conflicting pending action nonce"));
        }
        // Keep enough room to record an explicit outcome for every action that
        // remains locally pending if later selected state makes it ineligible.
        let outstanding = self.unresolved
            + usize::from(
                self.entries
                    .get(&action.id())
                    .is_none_or(|entry| !unresolved(&entry.status)),
            );
        let (remaining_bytes, remaining_frames) = self.log.core.remaining_capacity()?;
        let outcome_bytes = 36u64 + 1 + 32 + 2 + MAX_REASON as u64;
        if remaining_frames < 1 + outstanding as u64
            || remaining_bytes
                < (36 + frame.len() as u64)
                    .saturating_add(outcome_bytes.saturating_mul(outstanding as u64))
        {
            return Err(Error::Limit("pending action journal capacity"));
        }
        self.log.core.append(&frame)?;
        apply(&mut self.entries, &mut self.live, &frame, &self.genesis)?;
        self.unresolved = outstanding;
        Ok(())
    }

    pub fn reject(&mut self, id: OperationId, reason: &str) -> Result<(), Error> {
        self.outcome(id, reason)
    }

    fn outcome(&mut self, id: OperationId, reason: &str) -> Result<(), Error> {
        let mut end = reason.len().min(MAX_REASON);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let reason = &reason[..end];
        if reason.is_empty() {
            return Err(Error::Invalid("empty pending action reason"));
        }
        let mut frame = Vec::with_capacity(1 + 32 + 2 + reason.len());
        frame.push(REJECT);
        frame.extend_from_slice(id.as_bytes());
        frame.extend_from_slice(&(reason.len() as u16).to_be_bytes());
        frame.extend_from_slice(reason.as_bytes());
        let entry = self
            .entries
            .get(&id)
            .ok_or(Error::Invalid("unknown pending action"))?;
        if entry.status != PendingActionStatus::Pending
            && !matches!(entry.status, PendingActionStatus::Deferred(_))
        {
            return Err(Error::Invalid("pending action already resolved"));
        }
        self.log.core.append(&frame)?;
        if entry.status == PendingActionStatus::Pending {
            self.live
                .remove(&(entry.action.author(), entry.action.nonce()));
        }
        self.entries.get_mut(&id).expect("checked entry").status =
            PendingActionStatus::Rejected(reason.to_owned());
        self.unresolved -= 1;
        Ok(())
    }
}

fn unresolved(status: &PendingActionStatus) -> bool {
    matches!(
        status,
        PendingActionStatus::Pending | PendingActionStatus::Deferred(_)
    )
}

fn context(genesis: &Genesis) -> Result<(Vec<u8>, Limits), Error> {
    let mut prefix = MAGIC.to_vec();
    prefix.extend_from_slice(genesis.id().as_bytes());
    let frame_max =
        genesis.profile().limits().record_bytes as usize + 1 + 1 + MAX_EVICTIONS * 32 + 4;
    let limits = Limits {
        payload_bytes: u32::try_from(frame_max)
            .map_err(|_| Error::Limit("pending action frame"))?,
        frames: 262_144,
        file_bytes: PENDING_ACTION_JOURNAL_BYTES,
    };
    Ok((prefix, limits))
}

fn apply(
    entries: &mut BTreeMap<OperationId, Entry>,
    live: &mut BTreeMap<(AccountId, u64), OperationId>,
    frame: &[u8],
    genesis: &Genesis,
) -> Result<(), Error> {
    let Some((&tag, rest)) = frame.split_first() else {
        return Err(Error::Invalid("empty pending action frame"));
    };
    match tag {
        ACCEPT => {
            let Some((&count, rest)) = rest.split_first() else {
                return Err(Error::Invalid("pending action displacement count"));
            };
            if count as usize > MAX_EVICTIONS || rest.len() < count as usize * 32 + 4 {
                return Err(Error::Invalid("pending action displacement framing"));
            }
            let mut seen = std::collections::BTreeSet::new();
            for raw in rest[..count as usize * 32].chunks_exact(32) {
                let id = OperationId::from_bytes(raw.try_into().expect("fixed chunk"));
                if !seen.insert(id)
                    || entries
                        .get(&id)
                        .is_none_or(|e| e.status != PendingActionStatus::Pending)
                {
                    return Err(Error::Invalid("pending action displacement"));
                }
            }
            let tail = &rest[count as usize * 32..];
            let size = u32::from_be_bytes(tail[..4].try_into().expect("fixed slice")) as usize;
            if size == 0
                || size > genesis.profile().limits().record_bytes as usize
                || tail.len() != 4 + size
            {
                return Err(Error::Invalid("pending action length"));
            }
            let action = SignedOperation::decode(&tail[4..])?;
            action.verify_signature(genesis)?;
            let id = action.id();
            if entries
                .get(&id)
                .is_some_and(|e| e.action != action || e.status == PendingActionStatus::Pending)
            {
                return Err(Error::Invalid("conflicting pending action identity"));
            }
            if live
                .get(&(action.author(), action.nonce()))
                .is_some_and(|id| !seen.contains(id))
            {
                return Err(Error::Invalid("conflicting pending action nonce"));
            }
            for displaced in seen {
                let entry = entries.get_mut(&displaced).expect("checked displacement");
                live.remove(&(entry.action.author(), entry.action.nonce()));
                entry.status = PendingActionStatus::Deferred(
                    "local queue yielded to active attempt work; resubmit the saved action".into(),
                );
            }
            live.insert((action.author(), action.nonce()), id);
            entries.insert(
                id,
                Entry {
                    action,
                    status: PendingActionStatus::Pending,
                },
            );
        }
        REJECT => {
            if rest.len() < 34 {
                return Err(Error::Invalid("pending action outcome framing"));
            }
            let id = OperationId::from_bytes(rest[..32].try_into().expect("fixed slice"));
            let size = u16::from_be_bytes(rest[32..34].try_into().expect("fixed slice")) as usize;
            if size == 0 || size > MAX_REASON || rest.len() != 34 + size {
                return Err(Error::Invalid("pending action outcome length"));
            }
            let reason = std::str::from_utf8(&rest[34..])
                .map_err(|_| Error::Invalid("pending action outcome UTF-8"))?;
            let entry = entries
                .get_mut(&id)
                .ok_or(Error::Invalid("unknown pending action"))?;
            if entry.status != PendingActionStatus::Pending
                && !matches!(entry.status, PendingActionStatus::Deferred(_))
            {
                return Err(Error::Invalid("pending action already resolved"));
            }
            if entry.status == PendingActionStatus::Pending {
                live.remove(&(entry.action.author(), entry.action.nonce()));
            }
            entry.status = PendingActionStatus::Rejected(reason.into());
        }
        _ => return Err(Error::Invalid("pending action frame kind")),
    }
    Ok(())
}
