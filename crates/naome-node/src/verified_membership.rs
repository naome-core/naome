//! Operational membership inbox, candidate admission and durable node ownership.

use ed25519_dalek::SigningKey;
use naome_chain::{ARTIFACT_BLOCK_BYTES, ArtifactBlock, ArtifactBlockId};
use naome_consensus::verified_membership::*;
use naome_storage::verified_membership::{MembershipJournal, MembershipJournalError};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    fmt,
};

pub const MAX_REQUESTS: usize = 16;
pub const MAX_CANDIDATES: usize = 8;
pub const MAX_CANDIDATE_BYTES: usize = MAX_ARTIFACT_BYTES * 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipCandidate {
    pub context: MembershipContext,
    pub artifact: ArtifactBlock,
    pub payload: Vec<u8>,
}
impl MembershipCandidate {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/candidate\0";
    pub const MAX_BYTES: usize = 256 + MAX_ARTIFACT_BYTES;
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Self::MAGIC.to_vec();
        bytes.extend_from_slice(&self.context.0);
        bytes.extend_from_slice(&self.artifact.to_canonical_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipNodeError> {
        let prefix = Self::MAGIC.len() + 32 + ARTIFACT_BLOCK_BYTES + 4;
        if bytes.len() < prefix || bytes.len() > Self::MAX_BYTES || !bytes.starts_with(Self::MAGIC)
        {
            return Err(MembershipNodeError::Encoding);
        }
        let offset = Self::MAGIC.len();
        let context = MembershipContext(
            bytes[offset..offset + 32]
                .try_into()
                .map_err(|_| MembershipNodeError::Encoding)?,
        );
        let artifact = ArtifactBlock::from_canonical_bytes(&bytes[offset + 32..prefix - 4])
            .map_err(|_| MembershipNodeError::Encoding)?;
        let length = u32::from_be_bytes(
            bytes[prefix - 4..prefix]
                .try_into()
                .map_err(|_| MembershipNodeError::Encoding)?,
        ) as usize;
        if length == 0 || length > MAX_ARTIFACT_BYTES || length != bytes.len() - prefix {
            return Err(MembershipNodeError::Encoding);
        }
        Ok(Self {
            context,
            artifact,
            payload: bytes[prefix..].to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum MembershipNodeError {
    Journal(MembershipJournalError),
    Membership(MembershipError),
    Consensus(MembershipConsensusError),
    Limit,
    Encoding,
    UnknownRequest,
    PendingTransition,
    NoCandidate,
}
impl fmt::Display for MembershipNodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "membership node: {self:?}")
    }
}
impl Error for MembershipNodeError {}
impl From<MembershipJournalError> for MembershipNodeError {
    fn from(error: MembershipJournalError) -> Self {
        Self::Journal(error)
    }
}
impl From<MembershipError> for MembershipNodeError {
    fn from(error: MembershipError) -> Self {
        Self::Membership(error)
    }
}
impl From<MembershipConsensusError> for MembershipNodeError {
    fn from(error: MembershipConsensusError) -> Self {
        Self::Consensus(error)
    }
}

/// Only explicit operator calls construct approvals; network ingestion verifies
/// existing signatures and cannot invoke an approval key.
pub struct MembershipNode {
    journal: MembershipJournal,
    requests: BTreeMap<[u8; 32], MembershipRequest>,
    approvals: BTreeMap<[u8; 32], BTreeMap<[u8; 32], MembershipApproval>>,
    candidates: BTreeMap<ArtifactBlockId, MembershipCandidate>,
    rejected: BTreeSet<[u8; 32]>,
}
impl MembershipNode {
    pub fn new(journal: MembershipJournal) -> Result<Self, MembershipNodeError> {
        journal.machine()?;
        Ok(Self {
            journal,
            requests: BTreeMap::new(),
            approvals: BTreeMap::new(),
            candidates: BTreeMap::new(),
            rejected: BTreeSet::new(),
        })
    }
    pub fn machine(&self) -> Result<&MembershipMachine, MembershipNodeError> {
        Ok(self.journal.machine()?)
    }
    pub fn snapshot(&self) -> Result<&MembershipSnapshot, MembershipNodeError> {
        Ok(self.machine()?.branch().next_snapshot()?)
    }
    pub fn journal(&self) -> &MembershipJournal {
        &self.journal
    }
    pub fn requests(&self) -> &BTreeMap<[u8; 32], MembershipRequest> {
        &self.requests
    }
    pub fn rejected_requests(&self) -> &BTreeSet<[u8; 32]> {
        &self.rejected
    }
    /// Local inbox policy only; this cannot revoke an already published approval.
    pub fn reject_request(&mut self, id: [u8; 32]) -> Result<(), MembershipNodeError> {
        if self.rejected.len() >= 256 && !self.rejected.contains(&id) {
            return Err(MembershipNodeError::Limit);
        }
        self.rejected.insert(id);
        self.requests.remove(&id);
        self.approvals.remove(&id);
        Ok(())
    }
    pub fn allow_request(&mut self, id: [u8; 32]) {
        self.rejected.remove(&id);
    }
    /// Explicit operator imports take precedence over unapproved network spam.
    pub fn ingest_operator_request(
        &mut self,
        request: MembershipRequest,
    ) -> Result<bool, MembershipNodeError> {
        request.validate(self.snapshot()?)?;
        let id = request.id();
        if !self.requests.contains_key(&id)
            && self
                .machine()?
                .branch()
                .membership()
                .pending_activation()
                .is_some_and(|height| {
                    height > self.machine().expect("healthy owner").branch().height() + 1
                })
        {
            return Err(MembershipNodeError::PendingTransition);
        }
        if !self.requests.contains_key(&id) && self.requests.len() >= MAX_REQUESTS {
            let evict = self
                .requests
                .keys()
                .find(|id| self.approval_count(id) == 0)
                .copied()
                .ok_or(MembershipNodeError::Limit)?;
            self.requests.remove(&evict);
            self.approvals.remove(&evict);
        }
        self.rejected.remove(&id);
        self.ingest_request(request)
    }
    pub fn approval_count(&self, request: &[u8; 32]) -> usize {
        self.approvals.get(request).map_or(0, BTreeMap::len)
    }
    pub fn approval_messages(&self) -> Vec<MembershipApproval> {
        self.approvals
            .values()
            .flat_map(|approvals| approvals.values().cloned())
            .collect()
    }
    pub fn candidates(&self) -> Vec<MembershipCandidate> {
        self.candidates.values().cloned().collect()
    }

    pub fn ingest_request(
        &mut self,
        request: MembershipRequest,
    ) -> Result<bool, MembershipNodeError> {
        request.validate(self.snapshot()?)?;
        let id = request.id();
        if self.rejected.contains(&id) {
            return Err(MembershipNodeError::UnknownRequest);
        }
        if let Some(previous) = self.requests.get(&id) {
            return if previous == &request {
                Ok(false)
            } else {
                Err(MembershipNodeError::Encoding)
            };
        }
        if self.requests.len() >= MAX_REQUESTS {
            return Err(MembershipNodeError::Limit);
        }
        if self
            .machine()?
            .branch()
            .membership()
            .pending_activation()
            .is_some_and(|height| {
                height > self.machine().expect("healthy owner").branch().height() + 1
            })
        {
            return Err(MembershipNodeError::PendingTransition);
        }
        self.requests.insert(id, request);
        Ok(true)
    }
    pub fn ingest_approval(
        &mut self,
        approval: MembershipApproval,
    ) -> Result<bool, MembershipNodeError> {
        let request = self
            .requests
            .get(&approval.request)
            .ok_or(MembershipNodeError::UnknownRequest)?;
        approval.verify(request, self.snapshot()?)?;
        let approvals = self.approvals.entry(approval.request).or_default();
        if let Some(previous) = approvals.get(&approval.organization) {
            return if previous == &approval {
                Ok(false)
            } else {
                Err(MembershipNodeError::Encoding)
            };
        }
        if approvals.len() >= MAX_MEMBERS {
            return Err(MembershipNodeError::Limit);
        }
        approvals.insert(approval.organization, approval);
        Ok(true)
    }
    pub fn approve(
        &mut self,
        request: [u8; 32],
        organization: [u8; 32],
        key: &SigningKey,
    ) -> Result<MembershipApproval, MembershipNodeError> {
        let request = self
            .requests
            .get(&request)
            .ok_or(MembershipNodeError::UnknownRequest)?;
        let approval = MembershipApproval::sign(request, self.snapshot()?, organization, key)?;
        self.ingest_approval(approval.clone())?;
        Ok(approval)
    }

    pub fn ingest_candidate(
        &mut self,
        candidate: MembershipCandidate,
    ) -> Result<bool, MembershipNodeError> {
        if candidate.payload.len() > MAX_ARTIFACT_BYTES {
            return Err(MembershipNodeError::Limit);
        }
        if candidate.context != self.machine()?.branch().context() {
            return Err(MembershipError::Context.into());
        }
        let id = candidate.artifact.id();
        if let Some(previous) = self.candidates.get(&id) {
            return if previous == &candidate {
                Ok(false)
            } else {
                Err(MembershipNodeError::Encoding)
            };
        }
        if self.candidates.len() >= MAX_CANDIDATES
            || self
                .candidates
                .values()
                .map(|candidate| candidate.payload.len())
                .sum::<usize>()
                + candidate.payload.len()
                > MAX_CANDIDATE_BYTES
        {
            return Err(MembershipNodeError::Limit);
        }
        self.machine()?
            .branch()
            .prepare_value(candidate.artifact, None, &candidate.payload)?;
        self.candidates.insert(id, candidate);
        Ok(true)
    }

    pub fn can_author(&self) -> Result<bool, MembershipNodeError> {
        let machine = self.machine()?;
        Ok(machine.is_active()
            && machine.phase() == MembershipPhase::Proposal
            && machine.known_finality().is_none()
            && machine.signer()
                == Some(
                    machine
                        .branch()
                        .proposer(machine.round(), machine.maximum_round())?,
                )
            && (!self.candidates.is_empty() || machine.retained_value().is_some()))
    }
    pub fn author(&mut self) -> Result<Vec<MembershipPublication>, MembershipNodeError> {
        let candidate = if let Some((value, payload)) = self.machine()?.retained_value() {
            MembershipCandidate {
                context: value.context(),
                artifact: value.artifact(),
                payload: payload.to_vec(),
            }
        } else {
            self.candidates
                .values()
                .next()
                .ok_or(MembershipNodeError::NoCandidate)?
                .clone()
        };
        let mut operation = None;
        if self
            .machine()?
            .branch()
            .membership()
            .pending_activation()
            .is_none_or(|height| {
                height <= self.machine().expect("healthy owner").branch().height() + 1
            })
        {
            for (id, request) in &self.requests {
                let approvals = self
                    .approvals
                    .get(id)
                    .map(|approvals| approvals.values().cloned().collect())
                    .unwrap_or_default();
                if let Ok(approved) =
                    ApprovedMembershipRequest::new(request.clone(), approvals, self.snapshot()?)
                {
                    operation = Some(approved);
                    break;
                }
            }
        }
        self.process(MembershipMachineEvent::Author {
            artifact: candidate.artifact,
            payload: candidate.payload,
            operation,
        })
    }

    pub fn receive(
        &mut self,
        publication: MembershipPublication,
    ) -> Result<Vec<MembershipPublication>, MembershipNodeError> {
        if publication.height() <= self.machine()?.branch().height() {
            if let MembershipPublication::Finality(proof) = publication {
                self.journal.observe_historical_finality(proof)?;
            }
            return Ok(Vec::new());
        }
        self.process(publication.to_event())
    }
    pub fn process(
        &mut self,
        event: MembershipMachineEvent,
    ) -> Result<Vec<MembershipPublication>, MembershipNodeError> {
        let publications = self.journal.process(event)?;
        let mut pending: VecDeque<_> = publications.iter().cloned().collect();
        let mut output = publications;
        let mut steps = 0;
        while let Some(publication) = pending.pop_front() {
            steps += 1;
            if steps > 32 {
                return Err(MembershipNodeError::Limit);
            }
            if publication.height() <= self.machine()?.branch().height() {
                continue;
            }
            let publications = self.journal.process(publication.to_event())?;
            pending.extend(publications.iter().cloned());
            output.extend(publications);
        }
        self.prune()?;
        Ok(output)
    }
    pub fn resume_prepared(&mut self) -> Result<Vec<MembershipPublication>, MembershipNodeError> {
        let publications = self.journal.resume_prepared()?;
        let mut output = publications.clone();
        for publication in publications {
            output.extend(self.receive(publication)?);
        }
        Ok(output)
    }
    pub fn replay_publications(
        &mut self,
    ) -> Result<Vec<MembershipPublication>, MembershipNodeError> {
        let publications = self.journal.publications()?;
        let mut output = publications.clone();
        for publication in publications {
            output.extend(self.receive(publication)?);
        }
        Ok(output)
    }
    pub fn finalized_proof(
        &mut self,
        height: u64,
    ) -> Result<Option<MembershipFinalityProof>, MembershipNodeError> {
        Ok(self.journal.finalized_proof(height)?)
    }

    fn prune(&mut self) -> Result<(), MembershipNodeError> {
        let snapshot = self.snapshot()?.clone();
        self.requests
            .retain(|_, request| request.validate(&snapshot).is_ok());
        self.approvals
            .retain(|id, _| self.requests.contains_key(id));
        let parent = self.machine()?.branch().artifact().head_block_id();
        self.candidates
            .retain(|_, candidate| candidate.artifact.parent_block_id() == parent);
        Ok(())
    }
}
