//! Deterministic membership-profile consensus events and unsigned signing intents.
//!
//! Storage owns key use. A transition must be durably recorded before completing
//! its intents, and finalized successors must be durable before the next event.

use naome_chain::ArtifactBlock;
use std::collections::{BTreeMap, BTreeSet};

use super::*;
mod codec;

/// Bounded retained evidence positions per height. Exhaustion refuses new input.
pub const MAX_RETAINED_ROUNDS: usize = 8;
pub const MAX_RETAINED_PROPOSALS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MembershipPhase {
    Proposal,
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipFinalityProof {
    pub proposal: MembershipProposal,
    pub payload: Vec<u8>,
    pub certificate: MembershipCertificate,
}

impl MembershipFinalityProof {
    const MAGIC: &'static [u8] = b"naome/verified-membership/v0/finality\0";
    pub const MAX_BYTES: usize =
        64 + MembershipProposal::MAX_BYTES + MAX_ARTIFACT_BYTES + MembershipCertificate::MAX_BYTES;

    pub fn to_bytes(&self) -> Vec<u8> {
        let proposal = self.proposal.to_bytes();
        let certificate = self.certificate.to_bytes();
        let mut bytes = Self::MAGIC.to_vec();
        for part in [&proposal, &self.payload, &certificate] {
            bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
            bytes.extend_from_slice(part);
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MembershipError> {
        let mut reader = Reader::new(bytes, Self::MAX_BYTES)?;
        if reader.take(Self::MAGIC.len())? != Self::MAGIC {
            return Err(MembershipError::Encoding);
        }
        let length = reader.u32()? as usize;
        let proposal = MembershipProposal::from_bytes(reader.take(length)?)?;
        let length = reader.u32()? as usize;
        if length > MAX_ARTIFACT_BYTES {
            return Err(MembershipError::Limit);
        }
        let payload = reader.take(length)?.to_vec();
        let length = reader.u32()? as usize;
        let certificate = MembershipCertificate::from_bytes(reader.take(length)?)?;
        reader.finish()?;
        Ok(Self {
            proposal,
            payload,
            certificate,
        })
    }
}

/// External bytes and exact local timeout/authoring commands; none carries trust.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipMachineEvent {
    Proposal {
        proposal: MembershipProposal,
        payload: Vec<u8>,
    },
    Vote(MembershipVote),
    Certificate(MembershipCertificate),
    Finality(MembershipFinalityProof),
    Timeout {
        height: u64,
        round: u64,
        phase: MembershipPhase,
    },
    Author {
        artifact: ArtifactBlock,
        payload: Vec<u8>,
        operation: Option<ApprovedMembershipRequest>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipPublication {
    Proposal {
        proposal: MembershipProposal,
        payload: Vec<u8>,
    },
    Vote(MembershipVote),
    Certificate(MembershipCertificate),
    Finality(MembershipFinalityProof),
}

/// Opaque intent produced only after the state machine admits the operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSigningIntent {
    signer: [u8; 32],
    kind: SigningKind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum SigningKind {
    Vote(MembershipVoteCoordinate),
    Proposal {
        value: Box<MembershipValue>,
        round: u64,
        certificate: Option<MembershipCertificate>,
        payload: Vec<u8>,
    },
}
impl MembershipSigningIntent {
    pub const fn signer(&self) -> [u8; 32] {
        self.signer
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        match &self.kind {
            SigningKind::Vote(coordinate) => coordinate.signing_bytes(),
            SigningKind::Proposal {
                value,
                round,
                certificate,
                ..
            } => MembershipProposal::signing_bytes(value, *round, certificate.as_ref()),
        }
    }
    /// Complete only after the owner has anchored this exact intent.
    pub fn complete(&self, key: &SigningKey) -> Result<MembershipPublication, MembershipError> {
        if key.verifying_key().to_bytes() != self.signer {
            return Err(MembershipError::InvalidKey);
        }
        Ok(match &self.kind {
            SigningKind::Vote(coordinate) => {
                MembershipPublication::Vote(MembershipVote::sign(*coordinate, key))
            }
            SigningKind::Proposal {
                value,
                round,
                certificate,
                payload,
            } => MembershipPublication::Proposal {
                proposal: MembershipProposal::sign(
                    (**value).clone(),
                    *round,
                    certificate.clone(),
                    key,
                ),
                payload: payload.clone(),
            },
        })
    }

    pub fn verify_completion(
        &self,
        publication: &MembershipPublication,
    ) -> Result<(), MembershipError> {
        let signature = match (&self.kind, publication) {
            (SigningKind::Vote(expected), MembershipPublication::Vote(vote))
                if vote.coordinate == *expected && vote.signer == self.signer =>
            {
                vote.signature
            }
            (
                SigningKind::Proposal {
                    value,
                    round,
                    certificate,
                    payload,
                },
                MembershipPublication::Proposal {
                    proposal,
                    payload: actual,
                },
            ) if &proposal.value == value.as_ref()
                && proposal.round == *round
                && proposal.proposer == self.signer
                && &proposal.valid_round == certificate
                && actual == payload =>
            {
                proposal.signature
            }
            _ => return Err(MembershipError::Context),
        };
        verify(&self.signer, &self.signing_bytes(), &signature)
    }
}

#[derive(Clone)]
struct ValidValue {
    proposal: VerifiedMembershipProposal,
    certificate: MembershipCertificate,
}

/// Unsigned Tendermint-style state; its caller-selected key may be an observer.
#[derive(Clone)]
pub struct MembershipMachine {
    branch: MembershipBranch,
    signer: Option<[u8; 32]>,
    maximum_round: u64,
    round: u64,
    phase: MembershipPhase,
    locked: Option<(u64, [u8; 32])>,
    valid: Option<ValidValue>,
    authored: bool,
    proposals: BTreeMap<(u64, [u8; 32]), VerifiedMembershipProposal>,
    votes: BTreeMap<(u64, MembershipVoteRole, [u8; 32]), MembershipVote>,
    certificates: BTreeMap<MembershipVoteCoordinate, MembershipCertificate>,
    processed: BTreeSet<MembershipVoteCoordinate>,
    known_finality: Option<(u64, [u8; 32])>,
}

pub struct MembershipMachineTransition {
    next: MembershipMachine,
    intents: Vec<MembershipSigningIntent>,
    publications: Vec<MembershipPublication>,
    finalized: Option<MembershipFinalityProof>,
}
impl MembershipMachineTransition {
    pub fn intents(&self) -> &[MembershipSigningIntent] {
        &self.intents
    }
    pub fn publications(&self) -> &[MembershipPublication] {
        &self.publications
    }
    pub const fn finalized(&self) -> Option<&MembershipFinalityProof> {
        self.finalized.as_ref()
    }
    pub fn into_machine(self) -> MembershipMachine {
        self.next
    }
    pub fn next(&self) -> &MembershipMachine {
        &self.next
    }
}

impl MembershipMachine {
    pub fn new(
        branch: MembershipBranch,
        signer: Option<[u8; 32]>,
        maximum_round: u64,
    ) -> Result<Self, MembershipConsensusError> {
        branch.next_height()?;
        Ok(Self {
            branch,
            signer,
            maximum_round,
            round: 0,
            phase: MembershipPhase::Proposal,
            locked: None,
            valid: None,
            authored: false,
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            certificates: BTreeMap::new(),
            processed: BTreeSet::new(),
            known_finality: None,
        })
    }
    pub const fn branch(&self) -> &MembershipBranch {
        &self.branch
    }
    pub const fn signer(&self) -> Option<[u8; 32]> {
        self.signer
    }
    pub const fn round(&self) -> u64 {
        self.round
    }
    pub const fn phase(&self) -> MembershipPhase {
        self.phase
    }
    pub const fn locked(&self) -> Option<(u64, [u8; 32])> {
        self.locked
    }
    pub const fn maximum_round(&self) -> u64 {
        self.maximum_round
    }
    pub const fn known_finality(&self) -> Option<(u64, [u8; 32])> {
        self.known_finality
    }
    pub fn retained_value(&self) -> Option<(&MembershipValue, &[u8])> {
        self.valid
            .as_ref()
            .map(|valid| (&valid.proposal.proposal().value, valid.proposal.payload()))
    }
    pub fn is_active(&self) -> bool {
        self.signer.is_some_and(|key| {
            self.branch.next_snapshot().is_ok_and(|snapshot| {
                snapshot
                    .members()
                    .iter()
                    .any(|member| member.consensus_key == key)
            })
        })
    }

    /// Diagnostic replay commitment; excludes local secrets and publication ACKs.
    pub fn state_id(&self) -> [u8; 32] {
        let mut bytes = self.branch.ancestry().to_vec();
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.push(match self.phase {
            MembershipPhase::Proposal => 0,
            MembershipPhase::Prevote => 1,
            MembershipPhase::Precommit => 2,
        });
        bytes.push(u8::from(self.authored));
        for coordinate in [self.locked, self.known_finality] {
            match coordinate {
                None => bytes.push(0),
                Some((round, root)) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&round.to_be_bytes());
                    bytes.extend_from_slice(&root);
                }
            }
        }
        match &self.valid {
            None => bytes.push(0),
            Some(valid) => {
                bytes.push(1);
                bytes.extend_from_slice(&digest(b"valid\0", &valid.certificate.to_bytes()));
                bytes.extend_from_slice(&valid.proposal.proposal().value.root());
            }
        }
        for ((round, root), proposal) in &self.proposals {
            bytes.push(2);
            bytes.extend_from_slice(&round.to_be_bytes());
            bytes.extend_from_slice(root);
            bytes.extend_from_slice(&digest(b"proposal\0", &proposal.proposal().to_bytes()));
        }
        for vote in self.votes.values() {
            bytes.push(3);
            bytes.extend_from_slice(&digest(b"vote\0", &vote.to_bytes()));
        }
        for certificate in self.certificates.values() {
            bytes.push(4);
            bytes.extend_from_slice(&digest(b"certificate\0", &certificate.to_bytes()));
        }
        for coordinate in &self.processed {
            bytes.push(5);
            bytes.extend_from_slice(&coordinate.signing_bytes());
        }
        digest(b"naome/verified-membership/v0/machine-state\0", &bytes)
    }

    /// Pure preparation: failures leave every input and the current machine intact.
    pub fn prepare(
        &self,
        event: MembershipMachineEvent,
    ) -> Result<MembershipMachineTransition, MembershipConsensusError> {
        let mut next = self.clone();
        let mut intents = Vec::new();
        let mut publications = Vec::new();
        let mut finalized = None;
        next.apply(event, &mut intents, &mut publications, &mut finalized)?;
        if finalized.is_none() {
            next.drive_retained(&mut intents, &mut publications, &mut finalized)?;
        }
        Ok(MembershipMachineTransition {
            next,
            intents,
            publications,
            finalized,
        })
    }

    fn vote(
        &mut self,
        role: MembershipVoteRole,
        target: Option<[u8; 32]>,
        intents: &mut Vec<MembershipSigningIntent>,
    ) -> Result<(), MembershipConsensusError> {
        if self.known_finality.is_some() {
            return Ok(());
        }
        if self.is_active() {
            intents.push(MembershipSigningIntent {
                signer: self.signer.expect("active signer"),
                kind: SigningKind::Vote(self.branch.vote_coordinate(self.round, role, target)?),
            });
        }
        self.phase = match role {
            MembershipVoteRole::Prevote => MembershipPhase::Prevote,
            MembershipVoteRole::Precommit => MembershipPhase::Precommit,
        };
        Ok(())
    }

    fn apply(
        &mut self,
        event: MembershipMachineEvent,
        intents: &mut Vec<MembershipSigningIntent>,
        publications: &mut Vec<MembershipPublication>,
        finalized: &mut Option<MembershipFinalityProof>,
    ) -> Result<(), MembershipConsensusError> {
        match event {
            MembershipMachineEvent::Finality(proof) => {
                self.finalize(proof, publications, finalized)
            }
            MembershipMachineEvent::Author {
                artifact,
                payload,
                operation,
            } => {
                if !self.is_active()
                    || self.phase != MembershipPhase::Proposal
                    || self.authored
                    || self.known_finality.is_some()
                    || self.signer != Some(self.branch.proposer(self.round, self.maximum_round)?)
                {
                    return Err(MembershipConsensusError::Proposer);
                }
                let (value, certificate, payload) = match &self.valid {
                    Some(valid) => (
                        valid.proposal.proposal().value.clone(),
                        Some(valid.certificate.clone()),
                        valid.proposal.payload().to_vec(),
                    ),
                    None => (
                        self.branch.prepare_value(artifact, operation, &payload)?,
                        None,
                        payload,
                    ),
                };
                intents.push(MembershipSigningIntent {
                    signer: self.signer.expect("active signer"),
                    kind: SigningKind::Proposal {
                        value: Box::new(value),
                        round: self.round,
                        certificate,
                        payload,
                    },
                });
                self.authored = true;
                Ok(())
            }
            MembershipMachineEvent::Timeout {
                height,
                round,
                phase,
            } => {
                if height != self.branch.next_height()?
                    || round != self.round
                    || phase != self.phase
                {
                    return Err(MembershipConsensusError::Coordinate);
                }
                if self.known_finality.is_some() {
                    return Ok(());
                }
                match phase {
                    MembershipPhase::Proposal => {
                        self.vote(MembershipVoteRole::Prevote, None, intents)
                    }
                    MembershipPhase::Prevote => {
                        self.vote(MembershipVoteRole::Precommit, None, intents)
                    }
                    MembershipPhase::Precommit => self.advance(
                        self.round
                            .checked_add(1)
                            .ok_or(MembershipConsensusError::Overflow)?,
                    ),
                }
            }
            MembershipMachineEvent::Proposal { proposal, payload } => {
                let key = (proposal.round, proposal.value.root());
                let certified_finality = self.known_finality == Some(key);
                if !certified_finality
                    && key.0 > self.round.saturating_add((MAX_RETAINED_ROUNDS - 1) as u64)
                {
                    return Err(MembershipError::Limit.into());
                }
                if certified_finality {
                    self.proposals.retain(|existing, _| *existing == key);
                }
                if let Some(existing) = self.proposals.get(&key) {
                    if existing.proposal() == &proposal && existing.payload() == payload {
                        return Ok(());
                    }
                    return Err(MembershipConsensusError::Evidence);
                }
                if self.proposals.keys().any(|existing| existing.0 == key.0) {
                    return Err(MembershipConsensusError::Evidence);
                }
                if self.proposals.len() >= MAX_RETAINED_PROPOSALS {
                    // Locked and valid values are retained independently. Never
                    // let stale candidate payloads reserve the current slot.
                    self.proposals
                        .retain(|existing, _| existing.0 >= self.round);
                }
                if self.proposals.len() >= MAX_RETAINED_PROPOSALS {
                    return Err(MembershipError::Limit.into());
                }
                let verified =
                    self.branch
                        .verify_proposal(proposal, payload, self.maximum_round)?;
                let proposal = verified.proposal();
                let valid_round = proposal
                    .valid_round
                    .as_ref()
                    .map(|certificate| certificate.coordinate().round);
                let may_prevote = self.locked.is_none_or(|(round, root)| {
                    root == key.1 || valid_round.is_some_and(|valid| valid >= round)
                });
                self.proposals.insert(key, verified);
                if key.0 == self.round && self.phase == MembershipPhase::Proposal {
                    self.vote(
                        MembershipVoteRole::Prevote,
                        may_prevote.then_some(key.1),
                        intents,
                    )?;
                }
                let certificates: Vec<_> = self
                    .certificates
                    .values()
                    .filter(|certificate| certificate.coordinate().target == Some(key.1))
                    .cloned()
                    .collect();
                for certificate in certificates {
                    self.apply_certificate(certificate, intents, publications, finalized)?;
                    if finalized.is_some() {
                        break;
                    }
                }
                Ok(())
            }
            MembershipMachineEvent::Certificate(certificate) => {
                self.branch
                    .verify_certificate(&certificate, self.maximum_round)?;
                self.retain_certificate(certificate.clone())?;
                self.apply_certificate(certificate, intents, publications, finalized)
            }
            MembershipMachineEvent::Vote(vote) => {
                self.branch.verify_vote(&vote, self.maximum_round)?;
                let coordinate = vote.coordinate;
                if coordinate.round < self.round {
                    return Ok(());
                }
                if coordinate.round > self.round.saturating_add((MAX_RETAINED_ROUNDS - 1) as u64) {
                    return Err(MembershipError::Limit.into());
                }
                let key = (coordinate.round, coordinate.role, vote.signer);
                if let Some(previous) = self.votes.get(&key) {
                    return if previous == &vote {
                        Ok(())
                    } else {
                        Err(MembershipConsensusError::Evidence)
                    };
                }
                self.votes.retain(|key, _| key.0 >= self.round);
                let rounds: BTreeSet<_> = self.votes.keys().map(|key| key.0).collect();
                if rounds.len() >= MAX_RETAINED_ROUNDS && !rounds.contains(&coordinate.round) {
                    return Err(MembershipError::Limit.into());
                }
                self.votes.insert(key, vote);
                let matching: Vec<_> = self
                    .votes
                    .values()
                    .filter(|vote| vote.coordinate == coordinate)
                    .cloned()
                    .collect();
                if matching.len() >= self.branch.next_snapshot()?.quorum() {
                    let certificate =
                        MembershipCertificate::from_votes(&matching, self.branch.next_snapshot()?)?;
                    self.retain_certificate(certificate.clone())?;
                    self.apply_certificate(certificate, intents, publications, finalized)?;
                }
                if finalized.is_none()
                    && coordinate.round > self.round
                    && self.known_finality.is_none()
                {
                    let signers: BTreeSet<_> = self
                        .votes
                        .values()
                        .filter(|vote| vote.coordinate.round == coordinate.round)
                        .map(|vote| vote.signer)
                        .collect();
                    if signers.len() * 3 > self.branch.next_snapshot()?.members().len() {
                        self.advance(coordinate.round)?;
                    }
                }
                Ok(())
            }
        }
    }

    fn retain_certificate(
        &mut self,
        certificate: MembershipCertificate,
    ) -> Result<(), MembershipConsensusError> {
        let coordinate = certificate.coordinate();
        let is_finality =
            coordinate.role == MembershipVoteRole::Precommit && coordinate.target.is_some();
        if (coordinate.round < self.round || self.known_finality.is_some()) && !is_finality {
            return Ok(());
        }
        if coordinate.round > self.round && self.known_finality.is_none() {
            self.advance(coordinate.round)?;
        }
        let known = self.known_finality;
        self.certificates.retain(|key, _| {
            (known.is_none() && key.round >= self.round)
                || (key.role == MembershipVoteRole::Precommit
                    && key
                        .target
                        .is_some_and(|root| known == Some((key.round, root))))
        });
        if self.certificates.contains_key(&coordinate) {
            return Ok(());
        }
        if self.certificates.len() >= MAX_RETAINED_ROUNDS * 4 {
            return Err(MembershipError::Limit.into());
        }
        self.certificates.insert(coordinate, certificate);
        Ok(())
    }

    fn apply_certificate(
        &mut self,
        certificate: MembershipCertificate,
        intents: &mut Vec<MembershipSigningIntent>,
        publications: &mut Vec<MembershipPublication>,
        finalized: &mut Option<MembershipFinalityProof>,
    ) -> Result<(), MembershipConsensusError> {
        let coordinate = certificate.coordinate();
        if (coordinate.round < self.round || self.known_finality.is_some())
            && !(coordinate.role == MembershipVoteRole::Precommit && coordinate.target.is_some())
        {
            return Ok(());
        }
        if self.processed.contains(&coordinate) {
            return Ok(());
        }
        if coordinate.round > self.round && self.known_finality.is_none() {
            self.advance(coordinate.round)?;
        }
        match (coordinate.role, coordinate.target) {
            (MembershipVoteRole::Precommit, Some(root)) => {
                if self
                    .known_finality
                    .is_some_and(|(_, previous)| previous != root)
                {
                    return Err(MembershipConsensusError::Evidence);
                }
                self.known_finality = Some((coordinate.round, root));
                if let Some(proposal) = self.proposals.get(&(coordinate.round, root)) {
                    let proof = MembershipFinalityProof {
                        proposal: proposal.proposal().clone(),
                        payload: proposal.payload().to_vec(),
                        certificate,
                    };
                    return self.finalize(proof, publications, finalized);
                }
                return Ok(());
            }
            (MembershipVoteRole::Prevote, Some(root)) => {
                let proposal = self
                    .proposals
                    .iter()
                    .find(|((_, known), _)| *known == root)
                    .map(|(_, proposal)| proposal.clone());
                let Some(proposal) = proposal else {
                    return Ok(());
                };
                if self
                    .valid
                    .as_ref()
                    .is_none_or(|valid| valid.certificate.coordinate().round < coordinate.round)
                {
                    self.valid = Some(ValidValue {
                        proposal,
                        certificate: certificate.clone(),
                    });
                }
                if coordinate.round == self.round && self.phase != MembershipPhase::Precommit {
                    self.locked = Some((coordinate.round, root));
                    self.vote(MembershipVoteRole::Precommit, Some(root), intents)?;
                }
            }
            (MembershipVoteRole::Prevote, None) => {
                if coordinate.round == self.round && self.phase != MembershipPhase::Precommit {
                    self.vote(MembershipVoteRole::Precommit, None, intents)?;
                }
            }
            (MembershipVoteRole::Precommit, None) => {}
        }
        self.processed.insert(coordinate);
        publications.push(MembershipPublication::Certificate(certificate));
        Ok(())
    }

    fn advance(&mut self, round: u64) -> Result<(), MembershipConsensusError> {
        if round <= self.round || round > self.maximum_round {
            return Err(MembershipConsensusError::RoundLimit);
        }
        self.round = round;
        self.phase = MembershipPhase::Proposal;
        self.authored = false;
        // Lock and valid-round evidence survive. Retain recent input only; the
        // signed-intent journal still preserves all historical signing slots.
        let floor = round.saturating_sub(MAX_RETAINED_ROUNDS as u64 - 1);
        self.votes.retain(|key, _| key.0 >= floor);
        self.certificates.retain(|key, _| key.round >= floor);
        self.processed.retain(|key| key.round >= floor);
        self.proposals.retain(|key, _| key.0 >= floor);
        Ok(())
    }

    fn drive_retained(
        &mut self,
        intents: &mut Vec<MembershipSigningIntent>,
        publications: &mut Vec<MembershipPublication>,
        finalized: &mut Option<MembershipFinalityProof>,
    ) -> Result<(), MembershipConsensusError> {
        if self.phase == MembershipPhase::Proposal
            && self.known_finality.is_none()
            && let Some(((.., root), proposal)) =
                self.proposals.iter().find(|(key, _)| key.0 == self.round)
        {
            let root = *root;
            let valid_round = proposal
                .proposal()
                .valid_round
                .as_ref()
                .map(|certificate| certificate.coordinate().round);
            let allowed = self.locked.is_none_or(|(round, locked)| {
                locked == root || valid_round.is_some_and(|valid| valid >= round)
            });
            self.vote(
                MembershipVoteRole::Prevote,
                allowed.then_some(root),
                intents,
            )?;
        }
        let certificates: Vec<_> = self
            .certificates
            .values()
            .filter(|certificate| certificate.coordinate().round == self.round)
            .cloned()
            .collect();
        for certificate in certificates {
            self.apply_certificate(certificate, intents, publications, finalized)?;
            if finalized.is_some() {
                break;
            }
        }
        Ok(())
    }

    fn finalize(
        &mut self,
        proof: MembershipFinalityProof,
        publications: &mut Vec<MembershipPublication>,
        finalized: &mut Option<MembershipFinalityProof>,
    ) -> Result<(), MembershipConsensusError> {
        let transition = self.branch.verify_finality(
            proof.proposal.clone(),
            proof.payload.clone(),
            proof.certificate.clone(),
            self.maximum_round,
        )?;
        *self = Self::new(transition.into_branch(), self.signer, self.maximum_round)?;
        *finalized = Some(proof.clone());
        publications.push(MembershipPublication::Finality(proof));
        Ok(())
    }
}
