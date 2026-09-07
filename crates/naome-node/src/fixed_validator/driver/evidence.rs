//! Bounded raw custody images. Parsing never restores a trusted token.
use super::*;
use naome_consensus::{UnverifiedConsensusVoteRouteV0, UnverifiedFixedConsensusProposalRouteV0};

const HEADER: &[u8] = b"naome:fixed-validator-retained-evidence:v0\0";

/// One independently bounded retained-evidence class, not a consensus role.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FixedValidatorNodeEvidenceClassV0 {
    Higher,
    Current,
    Finality,
    NilPrecommit,
}
use FixedValidatorNodeEvidenceClassV0 as Class;
impl Class {
    fn from_byte(value: u8) -> Result<Self, Failure> {
        match value {
            0 => Ok(Self::Higher),
            1 => Ok(Self::Current),
            2 => Ok(Self::Finality),
            3 => Ok(Self::NilPrecommit),
            _ => Err(Failure::InvalidImage),
        }
    }
    pub(super) const fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// Raw evidence could not be reconstructed. No signing or finality is performed.
#[derive(Debug)]
#[non_exhaustive]
pub enum FixedValidatorNodeEvidenceErrorV0 {
    InvalidImage,
    InvalidEvidence,
    Bound,
    Allocation(TryReserveError),
    Source(Box<FixedValidatorVoteSafetyJournalErrorV0>),
    Finality(Box<naome_storage::FixedValidatorFinalityJournalErrorV0>),
    Capacity(Class),
    RequiresDisposal(Class),
    NotFresh,
}
use FixedValidatorNodeEvidenceErrorV0 as Failure;
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "retained evidence reconstruction failed: {self:?}")
    }
}
impl Error for Failure {}
impl From<TryReserveError> for Failure {
    fn from(e: TryReserveError) -> Self {
        Self::Allocation(e)
    }
}

#[derive(Clone, Copy)]
pub(in crate::fixed_validator) enum RawEvidenceRef<'a> {
    Proposal(&'a [u8], &'a [u8]),
    Vote(&'a [u8]),
}
impl RawEvidenceRef<'_> {
    fn position(self) -> Result<ConsensusPosition, Failure> {
        match self {
            Self::Proposal(control, _) => UnverifiedFixedConsensusProposalRouteV0::inspect(control)
                .map(|r| r.position())
                .map_err(|_| Failure::InvalidEvidence),
            Self::Vote(vote) => UnverifiedConsensusVoteRouteV0::inspect(vote)
                .map(|r| r.position())
                .map_err(|_| Failure::InvalidEvidence),
        }
    }
    fn destination(self) -> Result<Class, Failure> {
        match self {
            Self::Proposal(..) => Ok(Class::Current),
            Self::Vote(bytes) => {
                let route = UnverifiedConsensusVoteRouteV0::inspect(bytes)
                    .map_err(|_| Failure::InvalidEvidence)?;
                Ok(match (route.role(), route.target()) {
                    (ConsensusVoteRole::Prevote, _) => Class::Current,
                    (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(_)) => {
                        Class::Finality
                    }
                    (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil) => Class::NilPrecommit,
                })
            }
        }
    }
}

struct Inboxes {
    higher: FixedValidatorNodeHigherRoundInboxV0,
    current: CurrentRoundInboxV0,
    finality: CurrentRoundFinalityInboxV0,
    nil: CurrentRoundNilPrecommitInboxV0,
}
impl Inboxes {
    fn new(driver: &FixedValidatorNodeDriverV0<'_>) -> Self {
        Self {
            higher: FixedValidatorNodeHigherRoundInboxV0::new(driver.inbox.limits()),
            current: CurrentRoundInboxV0::new(driver.current_inbox.limits()),
            finality: CurrentRoundFinalityInboxV0::new(driver.current_finality_inbox.limits()),
            nil: CurrentRoundNilPrecommitInboxV0::new(driver.current_nil_precommit_inbox.limits()),
        }
    }
    fn insert(
        &mut self,
        driver: &FixedValidatorNodeDriverV0<'_>,
        class: Class,
        input: RawEvidenceRef<'_>,
        duplicates: bool,
    ) -> Result<(), Failure> {
        let position = input.position()?;
        if position.height() > driver.position().height()
            || position.round() > driver.inclusive_maximum_round
            || position.round().value() > driver.scope().finality.replay_limit().max_round()
        {
            return Err(Failure::InvalidEvidence);
        }
        let parent = driver
            .scope()
            .finality
            .parent_for_height(position.height())
            .map_err(|e| Failure::Finality(Box::new(e)))?
            .ok_or(Failure::InvalidEvidence)?;
        let round = derive_round(parent, position.round()).map_err(|_| Failure::InvalidEvidence)?;
        let before = match class {
            Class::Higher => self.higher.len(),
            Class::Current => self.current.len(),
            Class::Finality => self.finality.len(),
            Class::NilPrecommit => self.nil.len(),
        };
        match input {
            RawEvidenceRef::Proposal(control, payload) => {
                if class == Class::NilPrecommit {
                    return Err(Failure::InvalidImage);
                }
                let proposal =
                    verify_deferred_proposal_at_round(&round, control, try_copy_bytes(payload)?)
                        .map_err(|_| Failure::InvalidEvidence)?;
                match class {
                    Class::Higher => {
                        let _ = self
                            .higher
                            .try_insert_proposal(proposal)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::Current => {
                        self.current
                            .try_insert_proposal(proposal)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::Finality => {
                        self.finality
                            .try_insert_proposal(proposal)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::NilPrecommit => unreachable!(),
                }
            }
            RawEvidenceRef::Vote(bytes) => {
                // Authentication and membership precede the destination-specific insertion.
                let route = UnverifiedConsensusVoteRouteV0::inspect(bytes)
                    .map_err(|_| Failure::InvalidEvidence)?;
                let vote = match (route.role(), route.target()) {
                    (ConsensusVoteRole::Prevote, ConsensusVoteTarget::Proposal(_)) => round
                        .decode_and_verify_active_proposal_prevote(bytes)
                        .map_err(|_| Failure::InvalidEvidence)?,
                    (ConsensusVoteRole::Prevote, ConsensusVoteTarget::Nil) => round
                        .decode_and_verify_active_nil_prevote(bytes)
                        .map_err(|_| Failure::InvalidEvidence)?,
                    (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Proposal(_)) => round
                        .decode_and_verify_active_proposal_precommit(bytes)
                        .map_err(|_| Failure::InvalidEvidence)?,
                    (ConsensusVoteRole::Precommit, ConsensusVoteTarget::Nil) => round
                        .decode_and_verify_active_nil_precommit(bytes)
                        .map_err(|_| Failure::InvalidEvidence)?,
                };
                if class != Class::Higher && class != input.destination()? {
                    return Err(Failure::InvalidImage);
                }
                match class {
                    Class::Higher => {
                        let _ = self
                            .higher
                            .try_insert_verified_vote(round.parent_coordinate(), vote)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::Current if vote.target() == ConsensusVoteTarget::Nil => {
                        self.current
                            .try_insert_nil_prevote(&round, bytes)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::Current => {
                        self.current
                            .try_insert_prevote(&round, bytes)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::Finality => {
                        self.finality
                            .try_insert_precommit(&round, bytes)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                    Class::NilPrecommit => {
                        self.nil
                            .try_insert_nil_precommit(&round, bytes)
                            .map_err(|_| Failure::Capacity(class))?;
                    }
                }
            }
        }
        let after = match class {
            Class::Higher => self.higher.len(),
            Class::Current => self.current.len(),
            Class::Finality => self.finality.len(),
            Class::NilPrecommit => self.nil.len(),
        };
        if !duplicates && before == after {
            return Err(Failure::InvalidImage);
        }
        Ok(())
    }
}

impl FixedValidatorNodeDriverV0<'_> {
    // Read-only explicit-entry fence. Raw custody has already been admitted or
    // restored through complete verification, but its class may lag position.
    // Only ordinary step may normalize it and expose the resulting work.
    pub(super) fn retained_evidence_reuse_pending(&self) -> bool {
        let current = self.position();
        self.raw_evidence().any(|(class, input)| {
            let Ok(position) = input.position() else {
                return true;
            };
            position.height() == current.height()
                && ((class == Class::Higher && position == current)
                    || (class != Class::Higher && position.round() > current.round()))
        })
    }

    fn evidence_limits(&self) -> [(usize, u64); 4] {
        [
            (
                self.inbox.limits().max_entries(),
                self.inbox.limits().max_total_canonical_input_bytes(),
            ),
            (
                self.current_inbox.limits().max_entries(),
                self.current_inbox
                    .limits()
                    .max_total_canonical_input_bytes(),
            ),
            (
                self.current_finality_inbox.limits().max_entries(),
                self.current_finality_inbox
                    .limits()
                    .max_total_canonical_input_bytes(),
            ),
            (
                self.current_nil_precommit_inbox.limits().max_entries(),
                self.current_nil_precommit_inbox
                    .limits()
                    .max_total_canonical_input_bytes(),
            ),
        ]
    }
    fn raw_evidence(&self) -> impl Iterator<Item = (Class, RawEvidenceRef<'_>)> {
        self.inbox
            .raw_inputs()
            .map(|x| (Class::Higher, x))
            .chain(self.current_inbox.raw_inputs().map(|x| (Class::Current, x)))
            .chain(
                self.current_finality_inbox
                    .raw_inputs()
                    .map(|x| (Class::Finality, x)),
            )
            .chain(
                self.current_nil_precommit_inbox
                    .raw_inputs()
                    .map(|x| (Class::NilPrecommit, x)),
            )
    }
    pub(super) fn evidence_block_reason(&self) -> Option<FixedValidatorNodeDriverBlockReasonV0> {
        [
            Class::Higher,
            Class::Current,
            Class::Finality,
            Class::NilPrecommit,
        ]
        .into_iter()
        .find(|&class| self.evidence_refused(class))
        .map(|class| {
            FixedValidatorNodeDriverBlockReasonV0::RetainedEvidenceRequiresDisposal { class }
        })
    }
    pub(super) fn evidence_refused(&self, class: Class) -> bool {
        self.evidence_refusals & class.bit() != 0
    }
    fn refusal_mask(&self) -> u8 {
        self.evidence_refusals
            | if self.ambiguity.is_some() || self.inbox.saturation().is_some() {
                Class::Higher.bit()
            } else {
                0
            }
            | if self.current_ambiguity.is_some() || self.current_inbox.saturation().is_some() {
                Class::Current.bit()
            } else {
                0
            }
            | if self.current_finality_inbox.saturation().is_some() {
                Class::Finality.bit()
            } else {
                0
            }
            | if self.current_nil_precommit_inbox.saturation().is_some() {
                Class::NilPrecommit.bit()
            } else {
                0
            }
    }
    fn evidence_binding(&self) -> Result<Vec<u8>, Failure> {
        let history = self.publication_history().map_err(Failure::Source)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(HEADER.len() + 32 * 4 + 4 + 8 * 9)?;
        bytes.extend_from_slice(HEADER);
        bytes.extend_from_slice(history.context().chain_id().as_bytes());
        bytes.extend_from_slice(history.context().genesis_id().as_bytes());
        bytes.extend_from_slice(&history.context().protocol_version().value().to_be_bytes());
        bytes.extend_from_slice(history.fixed_set_id().as_bytes());
        bytes.extend_from_slice(history.signer().as_bytes());
        bytes.extend_from_slice(&self.inclusive_maximum_round.value().to_be_bytes());
        for (entries, length) in self.evidence_limits() {
            bytes.extend_from_slice(
                &u64::try_from(entries)
                    .map_err(|_| Failure::Bound)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&length.to_be_bytes());
        }
        Ok(bytes)
    }
    /// Checked maximum raw image length under the four existing inbox budgets.
    pub fn retained_evidence_image_limit(&self) -> Result<u64, Failure> {
        let mut bound =
            u64::try_from(HEADER.len() + 32 * 4 + 4 + 8 * 9 + 1 + 8).map_err(|_| Failure::Bound)?;
        for (entries, bytes) in self.evidence_limits() {
            bound = bound
                .checked_add(bytes)
                .and_then(|n| n.checked_add(u64::try_from(entries).ok()?.checked_mul(18)?))
                .ok_or(Failure::Bound)?;
        }
        Ok(bound)
    }
    /// Exports raw canonical custody and deny-only flags. This image grants no
    /// token, signing, selection, finality, or rollback-protection authority.
    pub fn retained_evidence_image(&self) -> Result<Vec<u8>, Failure> {
        let mut bytes = self.evidence_binding()?;
        let count = self.raw_evidence().count();
        let mut extra = 9usize;
        for (_, input) in self.raw_evidence() {
            let len = match input {
                RawEvidenceRef::Proposal(a, b) => {
                    a.len().checked_add(b.len()).and_then(|n| n.checked_add(18))
                }
                RawEvidenceRef::Vote(v) => v.len().checked_add(10),
            }
            .ok_or(Failure::Bound)?;
            extra = extra.checked_add(len).ok_or(Failure::Bound)?;
        }
        bytes.try_reserve_exact(extra)?;
        bytes.push(self.refusal_mask());
        bytes.extend_from_slice(
            &u64::try_from(count)
                .map_err(|_| Failure::Bound)?
                .to_be_bytes(),
        );
        for (class, input) in self.raw_evidence() {
            bytes.push(class as u8);
            match input {
                RawEvidenceRef::Proposal(a, b) => {
                    bytes.push(0);
                    field(&mut bytes, a)?;
                    field(&mut bytes, b)?;
                }
                RawEvidenceRef::Vote(v) => {
                    bytes.push(1);
                    field(&mut bytes, v)?;
                }
            }
        }
        debug_assert!(
            u64::try_from(bytes.len()).unwrap() <= self.retained_evidence_image_limit().unwrap()
        );
        Ok(bytes)
    }
}

impl<'node> FixedValidatorNodeDriverV0<'node> {
    /// Rebuilds every retained input through full historical-parent verification
    /// into a fresh driver before its initial arm transfers. Rejection consumes
    /// this driver and never repairs or rewrites the supplied raw image.
    pub fn restore_retained_evidence(mut self, bytes: &[u8]) -> Result<Self, Failure> {
        if self.generation != 0
            || self.due
            || !matches!(self.pending_command, Some(PendingCommandV0::Arm(_)))
            || self.raw_evidence().next().is_some()
            || self.refusal_mask() != 0
        {
            return Err(Failure::NotFresh);
        }
        if u64::try_from(bytes.len()).map_err(|_| Failure::Bound)?
            > self.retained_evidence_image_limit()?
        {
            return Err(Failure::Bound);
        }
        let binding = self.evidence_binding()?;
        let mut cursor = Cursor(bytes);
        if cursor.take(binding.len())? != binding {
            return Err(Failure::InvalidImage);
        }
        let mask = cursor.byte()?;
        if mask & !15 != 0 {
            return Err(Failure::InvalidImage);
        }
        let count = cursor.number()?;
        let max = self
            .evidence_limits()
            .into_iter()
            .try_fold(0u64, |a, (n, _)| a.checked_add(u64::try_from(n).ok()?))
            .ok_or(Failure::Bound)?;
        if count > max {
            return Err(Failure::Bound);
        }
        let mut inboxes = Inboxes::new(&self);
        let mut previous = 0;
        for _ in 0..count {
            let tag = cursor.byte()?;
            if tag < previous {
                return Err(Failure::InvalidImage);
            }
            previous = tag;
            let class = Class::from_byte(tag)?;
            let input = match cursor.byte()? {
                0 => RawEvidenceRef::Proposal(cursor.field()?, cursor.field()?),
                1 => RawEvidenceRef::Vote(cursor.field()?),
                _ => return Err(Failure::InvalidImage),
            };
            inboxes.insert(&self, class, input, false)?;
        }
        if !cursor.0.is_empty() {
            return Err(Failure::InvalidImage);
        }
        self.inbox = inboxes.higher;
        self.current_inbox = inboxes.current;
        self.current_finality_inbox = inboxes.finality;
        self.current_nil_precommit_inbox = inboxes.nil;
        self.evidence_refusals = mask;
        Ok(self)
    }

    pub(super) fn reuse_retained_evidence(&mut self) -> Result<(), Failure> {
        let current = self.position();
        let flags = self.refusal_mask();
        let mut moved = 0u8;
        for (class, input) in self.raw_evidence() {
            let position = input.position()?;
            if position.height() != current.height() {
                continue;
            }
            if class == Class::Higher && position == current {
                if flags & class.bit() != 0 {
                    return Err(Failure::RequiresDisposal(class));
                }
                moved |= class.bit() | input.destination()?.bit();
                if matches!(input, RawEvidenceRef::Proposal(..)) {
                    moved |= Class::Finality.bit();
                }
            } else if class != Class::Higher && position.round() > current.round() {
                if flags & class.bit() != 0 {
                    return Err(Failure::RequiresDisposal(class));
                }
                moved |= class.bit() | Class::Higher.bit();
            }
        }
        if moved == 0 {
            return Ok(());
        }
        for class in [
            Class::Higher,
            Class::Current,
            Class::Finality,
            Class::NilPrecommit,
        ] {
            if moved & flags & class.bit() != 0 {
                return Err(Failure::RequiresDisposal(class));
            }
        }
        let mut inboxes = Inboxes::new(self);
        // Complete scratch reconstruction precedes every ownership change and
        // every action selection. Failed capacity cannot expose a partial quorum.
        for (class, input) in self.raw_evidence() {
            let position = input.position()?;
            if class == Class::Higher && position == current {
                inboxes.insert(self, input.destination()?, input, true)?;
                if matches!(input, RawEvidenceRef::Proposal(..)) {
                    inboxes.insert(self, Class::Finality, input, true)?;
                }
            } else if class != Class::Higher
                && position.height() == current.height()
                && position.round() > current.round()
            {
                inboxes.insert(self, Class::Higher, input, true)?;
            } else {
                inboxes.insert(self, class, input, true)?;
            }
        }
        if moved & Class::Higher.bit() != 0 {
            self.inbox = inboxes.higher;
        }
        if moved & Class::Current.bit() != 0 {
            self.current_inbox = inboxes.current;
        }
        if moved & Class::Finality.bit() != 0 {
            self.current_finality_inbox = inboxes.finality;
        }
        if moved & Class::NilPrecommit.bit() != 0 {
            self.current_nil_precommit_inbox = inboxes.nil;
        }
        Ok(())
    }
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Failure> {
    out.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| Failure::Bound)?
            .to_be_bytes(),
    );
    out.extend_from_slice(bytes);
    Ok(())
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Failure> {
        let (a, b) = self.0.split_at_checked(n).ok_or(Failure::InvalidImage)?;
        self.0 = b;
        Ok(a)
    }
    fn byte(&mut self) -> Result<u8, Failure> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self) -> Result<u64, Failure> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn field(&mut self) -> Result<&'a [u8], Failure> {
        let n = usize::try_from(self.number()?).map_err(|_| Failure::Bound)?;
        self.take(n)
    }
}
