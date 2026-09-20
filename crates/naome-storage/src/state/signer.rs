//! Key custody and replayed consensus intent persistence. Public snapshots never
//! restore authority: reopen starts at genesis and re-executes every event.

use ed25519_dalek::{Signer, SigningKey};
use naome_consensus::{
    ConsensusKey,
    state::{
        STATE_QUORUM_MAX_BYTES, StateBranch, StateIntent, StateLockEvent, StateLockState,
        StatePhase, StatePublication,
    },
};
use naome_ledger::{
    LedgerState,
    profile::{
        Genesis, SIGNER_COMPLETION_BYTES, SIGNER_FRAME_OVERHEAD_BYTES, SIGNER_SNAPSHOT_MAX_BYTES,
        SIGNER_STOP_FRAME_BYTES, SIGNER_TRANSCRIPT_MAX_BYTES,
    },
};
use std::path::Path;

use super::{
    StateStorageError as Error,
    codec::{Reader, bytes},
    history::StateHistory,
    log::{FileLog, Limits},
};

const MAGIC: &[u8; 8] = b"NAOSSIG1";
const PREPARE: u8 = 1;
const COMPLETE: u8 = 2;
const ADVANCE: u8 = 3;
const STOP: u8 = 4;
const STOP_BYTES: usize = 1 + 8 + 32;
const SNAPSHOT_MAX: usize = SIGNER_SNAPSHOT_MAX_BYTES as usize;
const TRANSCRIPT_MAX: usize = SIGNER_TRANSCRIPT_MAX_BYTES as usize;

/// A preparation has synchronized both its event and its checked post-state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatePreparation {
    Prepared,
    AlreadyPrepared,
    AlreadyCompleted,
    Checkpoint,
}

/// Sole local owner of one registered state consensus key and its lineage.
/// Key bytes are never written to the journal, returned by an accessor, or
/// exposed through a Debug implementation. Secret-key drop zeroization comes
/// from the storage crate's ed25519-dalek `zeroize` feature.
pub struct StateSigner {
    key: SigningKey,
    #[cfg(test)]
    key_uses: usize,
    state: Replay,
    context: Context,
    log: FileLog,
}
struct Context {
    genesis: Genesis,
    signer: ConsensusKey,
    maximum_round: u64,
    prefix: Vec<u8>,
    limits: Limits,
    file_name: String,
    lock_name: String,
    anchor_name: String,
}
struct Replay {
    branch: StateBranch,
    lock: StateLockState,
    pending: Option<Pending>,
    completed: Option<Completed>,
    publications: Vec<StatePublication>,
    previous_votes: Vec<StatePublication>,
    sequence: u64,
    stopped: bool,
    used_height_bytes: u64,
    used_height_frames: u64,
}
struct Pending {
    sequence: u64,
    event: Vec<u8>,
    intent: StateIntent,
}
struct Completed {
    event: Vec<u8>,
    publication: StatePublication,
}

impl Replay {
    fn new(context: &Context) -> Result<Self, Error> {
        let branch = StateBranch::from_genesis(LedgerState::new(context.genesis.clone()))?;
        let lock = StateLockState::new(&branch, context.signer)?;
        Ok(Self {
            branch,
            lock,
            pending: None,
            completed: None,
            publications: Vec::with_capacity(3),
            previous_votes: Vec::with_capacity(2),
            sequence: 0,
            stopped: false,
            used_height_bytes: 0,
            used_height_frames: 0,
        })
    }
    fn apply(&mut self, body: &[u8], context: &Context) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Invalid("signer record after terminal stop"));
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Limit("signer sequence"))?;
        let mut r = Reader::new(body);
        let kind = r.u8()?;
        let usage = self.frame_usage(kind, body.len(), context)?;
        match kind {
            PREPARE => {
                if self.pending.is_some() {
                    return Err(Error::Invalid("another intent is pending"));
                }
                let event_bytes = r.bytes(context.limits.payload_bytes as usize)?.to_vec();
                let event = StateLockEvent::decode(&event_bytes, &context.genesis)?;
                let snapshot = r.bytes(SNAPSHOT_MAX)?;
                let transcript = match r.u8()? {
                    0 => None,
                    1 => Some(r.bytes(TRANSCRIPT_MAX)?),
                    _ => return Err(Error::Invalid("signing transcript option")),
                };
                r.finish()?;
                let mut next = self.lock.clone();
                let intent = next.apply(&self.branch, &event, context.maximum_round)?;
                if snapshot != next.snapshot()? || transcript != intent.signing_bytes().as_deref() {
                    return Err(Error::Invalid(
                        "intent checkpoint or transcript differs from replay",
                    ));
                }
                self.retain_previous_votes(next.round());
                self.lock = next;
                self.completed = None;
                self.pending = intent.signing_bytes().map(|_| Pending {
                    sequence,
                    event: event_bytes,
                    intent,
                });
            }
            COMPLETE => {
                let pending = self
                    .pending
                    .as_ref()
                    .ok_or(Error::Invalid("signature without a pending intent"))?;
                if r.u64()? != pending.sequence {
                    return Err(Error::Invalid("completion intent sequence"));
                }
                let signature = r.fixed()?;
                let publication_digest = r.fixed::<32>()?;
                r.finish()?;
                let publication =
                    pending
                        .intent
                        .complete(signature, &self.branch, context.maximum_round)?;
                if publication_hash(&publication)? != publication_digest {
                    return Err(Error::Invalid("completed publication bytes"));
                }
                if self.publications.len() >= 3 {
                    return Err(Error::Limit("current round publications"));
                }
                self.publications.push(publication.clone());
                self.completed = Some(Completed {
                    event: pending.event.clone(),
                    publication,
                });
                self.pending = None;
            }
            ADVANCE => {
                if self.pending.is_some() {
                    return Err(Error::Invalid("height change with pending signature"));
                }
                let finality = self.branch.decode_finality(
                    r.bytes(context.genesis.profile().limits().transport_frame_bytes as usize)?,
                    context.maximum_round,
                )?;
                let snapshot = r.bytes(SNAPSHOT_MAX)?;
                r.finish()?;
                let mut next = self.lock.clone();
                next.advance_height(&finality)?;
                if snapshot != next.snapshot()? {
                    return Err(Error::Invalid("height checkpoint differs from replay"));
                }
                self.branch = finality.into_branch();
                self.lock = next;
                self.completed = None;
                self.publications.clear();
                self.previous_votes.clear();
            }
            STOP => {
                // This only removes signing rights. The operational API requires
                // durable selected-history conflict; replay never treats these
                // diagnostic coordinates as branch or finality authority.
                let _height = r.u64()?;
                let _commitment = r.fixed::<32>()?;
                r.finish()?;
                self.pending = None;
                self.completed = None;
                self.publications.clear();
                self.previous_votes.clear();
                self.stopped = true;
            }
            _ => return Err(Error::Invalid("signer record kind")),
        }
        self.sequence = sequence;
        self.used_height_bytes = usage.0;
        self.used_height_frames = usage.1;
        Ok(())
    }
    // This cache is derived only from anchored COMPLETE records. A peer still
    // in the immediately preceding round needs these exact votes to assemble
    // the quorum that lets it follow us; no new signing authority is created.
    fn retain_previous_votes(&mut self, next_round: u64) {
        if next_round == self.lock.round() {
            return;
        }
        self.previous_votes.clear();
        if self.lock.round().checked_add(1) == Some(next_round) {
            self.previous_votes.extend(
                self.publications
                    .iter()
                    .filter(|publication| matches!(publication, StatePublication::Vote(_)))
                    .take(2)
                    .cloned(),
            );
        }
        self.publications.clear();
    }
    fn frame_usage(&self, kind: u8, bytes: usize, context: &Context) -> Result<(u64, u64), Error> {
        if kind == STOP {
            return Ok((self.used_height_bytes, self.used_height_frames));
        }
        let used_bytes = self
            .used_height_bytes
            .checked_add(bytes as u64 + 36)
            .ok_or(Error::Limit("height signing bytes"))?;
        let used_frames = self
            .used_height_frames
            .checked_add(1)
            .ok_or(Error::Limit("height signing frames"))?;
        if used_bytes > context.genesis.profile().signer_height_bytes()?
            || used_frames > context.genesis.profile().signer_height_frames()?
        {
            return Err(Error::Limit("height signing reservation"));
        }
        if kind == ADVANCE {
            Ok((0, 0))
        } else {
            Ok((used_bytes, used_frames))
        }
    }
}

impl StateSigner {
    /// Provision a new genesis signer. Existing journal/anchor paths are never
    /// replaced or inferred safe to reset.
    pub fn create(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        key: SigningKey,
        maximum_round: u64,
    ) -> Result<Self, Error> {
        signing_platform()?;
        let context = context(genesis, &key, maximum_round)?;
        let state = Replay::new(&context)?;
        let log = FileLog::create(
            directory.as_ref(),
            anchor_directory.as_ref(),
            &context.file_name,
            &context.lock_name,
            &context.anchor_name,
            &context.prefix,
            context.limits,
        )?;
        Ok(Self {
            key,
            #[cfg(test)]
            key_uses: 0,
            state,
            context,
            log,
        })
    }
    pub fn open(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        key: SigningKey,
        maximum_round: u64,
    ) -> Result<Self, Error> {
        signing_platform()?;
        let context = context(genesis, &key, maximum_round)?;
        let mut state = Replay::new(&context)?;
        let log = FileLog::open(
            directory.as_ref(),
            anchor_directory.as_ref(),
            &context.file_name,
            &context.lock_name,
            &context.anchor_name,
            &context.prefix,
            context.limits,
            |body| state.apply(body, &context),
        )?;
        Ok(Self {
            key,
            #[cfg(test)]
            key_uses: 0,
            state,
            context,
            log,
        })
    }
    fn ensure(&self) -> Result<(), Error> {
        self.log.core.ensure()?;
        if self.state.stopped {
            return Err(Error::Invalid("terminal state signer stop"));
        }
        Ok(())
    }
    #[cfg(all(test, unix))]
    pub(super) fn key_use_count(&self) -> usize {
        self.key_uses
    }
    #[cfg(all(test, unix))]
    pub(super) fn exhaust_capacity(&mut self, bytes: bool) {
        self.log.core.exhaust_capacity(bytes);
    }
    #[cfg(all(test, unix))]
    pub(super) fn anchor_file_name(&self) -> &str {
        &self.context.anchor_name
    }
    #[cfg(all(test, unix))]
    pub(super) fn journal_file_name(&self) -> &str {
        &self.context.file_name
    }
    /// Sign a repeatable TIME report for the exact selected signing parent.
    /// Unlike proposal/prevote/precommit roles, updated TIME reports are allowed
    /// while a height remains undecided and need no one-value slot reservation.
    /// The caller must enforce its local clock health before requesting this.
    pub fn sign_time_report(
        &self,
        utc_seconds: u64,
    ) -> Result<naome_ledger::time::SignedTimeReport, Error> {
        self.ensure()?;
        Ok(naome_ledger::time::SignedTimeReport::sign(
            &self.context.genesis,
            self.state.branch.state().head(),
            self.state.lock.height(),
            utc_seconds,
            &self.key,
        )?)
    }
    pub fn signer(&self) -> ConsensusKey {
        self.context.signer
    }
    pub fn height(&self) -> Result<u64, Error> {
        self.ensure()?;
        Ok(self.state.lock.height())
    }
    pub fn round(&self) -> Result<u64, Error> {
        self.ensure()?;
        Ok(self.state.lock.round())
    }
    pub fn phase(&self) -> Result<StatePhase, Error> {
        self.ensure()?;
        Ok(self.state.lock.phase())
    }
    pub fn branch(&self) -> Result<&StateBranch, Error> {
        self.ensure()?;
        Ok(&self.state.branch)
    }
    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        self.ensure()?;
        Ok(self.state.lock.snapshot()?)
    }
    pub fn pending(&self) -> Result<bool, Error> {
        self.ensure()?;
        Ok(self.state.pending.is_some())
    }
    pub fn stopped(&self) -> Result<bool, Error> {
        self.log.core.ensure()?;
        Ok(self.state.stopped)
    }
    pub fn last_publication(&self) -> Result<Option<&StatePublication>, Error> {
        self.ensure()?;
        Ok(self.state.completed.as_ref().map(|c| &c.publication))
    }
    /// Exact durably completed local messages for the current height and round.
    /// Replay retains at most one proposal, prevote, and precommit so a restart
    /// can retransmit the proposal even when the latest publication was a vote.
    pub fn current_publications(&self) -> Result<Vec<StatePublication>, Error> {
        self.ensure()?;
        Ok(self.state.publications.clone())
    }
    /// Exact retry messages: at most three current-round messages and the
    /// immediately preceding round's two own votes. Previous-round proposals
    /// are excluded, and height changes, skipped rounds, and terminal stop
    /// remove the previous votes. Replay reconstructs this cache without key use.
    pub fn retry_publications(&self) -> Result<Vec<StatePublication>, Error> {
        self.ensure()?;
        Ok(self
            .state
            .publications
            .iter()
            .chain(&self.state.previous_votes)
            .cloned()
            .collect())
    }
    /// Retained exact record and QC survive process restart through event replay.
    pub fn retained_record(&self) -> Result<Option<&[u8]>, Error> {
        self.ensure()?;
        Ok(self.state.lock.retained_record())
    }
    pub fn retained_quorum(&self) -> Result<Option<&naome_consensus::state::StateQuorum>, Error> {
        self.ensure()?;
        Ok(self.state.lock.retained_quorum())
    }

    /// Confirms the remaining journal covers every permitted consensus round
    /// for this many protected records, accounting for work already persisted
    /// at the current height, plus the separately reserved terminal stop.
    pub fn ensure_completion_capacity(&self, records: u64) -> Result<(), Error> {
        self.ensure()?;
        if records == 0 || records > self.context.genesis.profile().limits().run_records {
            return Err(Error::Limit("protected signing record count"));
        }
        let profile = self.context.genesis.profile();
        let bytes = profile
            .signer_height_bytes()?
            .checked_mul(records)
            .and_then(|v| v.checked_sub(self.state.used_height_bytes))
            .and_then(|v| v.checked_add(SIGNER_STOP_FRAME_BYTES))
            .ok_or(Error::Limit("protected signing bytes"))?;
        let frames = profile
            .signer_height_frames()?
            .checked_mul(records)
            .and_then(|v| v.checked_sub(self.state.used_height_frames))
            .and_then(|v| v.checked_add(1))
            .ok_or(Error::Limit("protected signing frames"))?;
        let available = self.log.core.remaining_capacity()?;
        if available.0 < bytes || available.1 < frames {
            return Err(Error::Limit("protected signing completion capacity"));
        }
        Ok(())
    }
    fn protected_records(&self) -> u64 {
        let state = self.state.branch.state();
        let limits = self.context.genesis.profile().limits();
        if state.reserved_records() > 0 {
            state.reserved_records() + limits.terminal_records
        } else if state.remaining_records() >= limits.completion_records + limits.terminal_records {
            limits.completion_records + limits.terminal_records
        } else {
            limits.terminal_records
        }
    }
    /// Durably record the exact event, post-checkpoint, and unsigned transcript.
    /// This performs no signing-key operation. A pending intent admits only its
    /// exact retry; a completed immediate retry reuses its durable publication.
    pub fn prepare(&mut self, event: &StateLockEvent) -> Result<StatePreparation, Error> {
        self.ensure()?;
        if self.state.branch.state().terminated() {
            return Err(Error::Invalid("state run terminated"));
        }
        self.ensure_completion_capacity(self.protected_records())?;
        event_bounds(event, &self.context.genesis)?;
        let event_bytes = event.encode()?;
        if let Some(pending) = &self.state.pending {
            if pending.event == event_bytes {
                return Ok(StatePreparation::AlreadyPrepared);
            }
            return Err(Error::Invalid("different event while signature is pending"));
        }
        if self
            .state
            .completed
            .as_ref()
            .is_some_and(|c| c.event == event_bytes)
        {
            return Ok(StatePreparation::AlreadyCompleted);
        }
        let mut next = self.state.lock.clone();
        let intent = next.apply(&self.state.branch, event, self.context.maximum_round)?;
        let snapshot = next.snapshot()?;
        let transcript = intent.signing_bytes();
        if transcript.is_some() && self.state.publications.len() >= 3 {
            return Err(Error::Limit("current round publications"));
        }
        if snapshot.len() > SNAPSHOT_MAX
            || transcript
                .as_ref()
                .is_some_and(|v| v.len() > TRANSCRIPT_MAX)
        {
            return Err(Error::Limit("signer checkpoint or transcript"));
        }
        let mut body = vec![PREPARE];
        bytes(&mut body, &event_bytes)?;
        bytes(&mut body, &snapshot)?;
        match &transcript {
            Some(value) => {
                body.push(1);
                bytes(&mut body, value)?;
            }
            None => body.push(0),
        }
        let completion_length = transcript
            .as_ref()
            .map(|_| SIGNER_COMPLETION_BYTES as usize);
        // Capacity for the exact completion AND an unconditional terminal stop
        // remains available before any key use or live kernel advancement.
        if let Some(completion) = completion_length {
            self.log
                .core
                .reserve_batch(&[body.len(), completion, STOP_BYTES])?;
        } else {
            self.log.core.reserve_batch(&[body.len(), STOP_BYTES])?;
        }
        let usage = self.state.frame_usage(PREPARE, body.len(), &self.context)?;
        let position = self.log.core.append(&body)?;
        self.state.used_height_bytes = usage.0;
        self.state.used_height_frames = usage.1;
        self.state.retain_previous_votes(next.round());
        self.state.lock = next;
        self.state.sequence = position.sequence;
        self.state.completed = None;
        if transcript.is_some() {
            self.state.pending = Some(Pending {
                sequence: position.sequence,
                event: event_bytes,
                intent,
            });
            Ok(StatePreparation::Prepared)
        } else {
            Ok(StatePreparation::Checkpoint)
        }
    }
    /// Uses the key only for an already anchored exact pending transcript.
    /// Completed public bytes are not released until completion and anchor sync.
    pub fn sign_prepared(&mut self) -> Result<StatePublication, Error> {
        self.ensure()?;
        if self.state.publications.len() >= 3 {
            return Err(Error::Limit("current round publications"));
        }
        let pending = self
            .state
            .pending
            .as_ref()
            .ok_or(Error::Invalid("no prepared signature"))?;
        let transcript = pending
            .intent
            .signing_bytes()
            .ok_or(Error::Invalid("checkpoint cannot sign"))?;
        self.ensure_completion_capacity(self.protected_records())?;
        self.log
            .core
            .reserve_batch(&[SIGNER_COMPLETION_BYTES as usize, STOP_BYTES])?;
        let usage =
            self.state
                .frame_usage(COMPLETE, SIGNER_COMPLETION_BYTES as usize, &self.context)?;
        #[cfg(test)]
        {
            self.key_uses += 1;
        }
        let signature = self.key.sign(&transcript).to_bytes();
        let publication =
            pending
                .intent
                .complete(signature, &self.state.branch, self.context.maximum_round)?;
        let mut body = vec![COMPLETE];
        body.extend_from_slice(&pending.sequence.to_be_bytes());
        body.extend_from_slice(&signature);
        body.extend_from_slice(&publication_hash(&publication)?);
        let position = self.log.core.append(&body)?;
        self.state.used_height_bytes = usage.0;
        self.state.used_height_frames = usage.1;
        let event = self.state.pending.take().expect("pending checked").event;
        self.state.publications.push(publication.clone());
        self.state.completed = Some(Completed {
            event,
            publication: publication.clone(),
        });
        self.state.sequence = position.sequence;
        Ok(publication)
    }
    pub fn apply_and_sign(
        &mut self,
        event: &StateLockEvent,
    ) -> Result<Option<StatePublication>, Error> {
        match self.prepare(event)? {
            StatePreparation::Checkpoint => Ok(None),
            StatePreparation::AlreadyCompleted => Ok(self.last_publication()?.cloned()),
            StatePreparation::Prepared | StatePreparation::AlreadyPrepared => {
                Ok(Some(self.sign_prepared()?))
            }
        }
    }
    /// Advance only through the sole selected durable history. Raw finality
    /// tokens and caller snapshots are intentionally not accepted as authority.
    pub fn advance_to_history(&mut self, history: &mut StateHistory) -> Result<(), Error> {
        self.ensure()?;
        if history.last_finalized()?.state().genesis().id() != self.context.genesis.id() {
            return Err(Error::Invalid("signer/history genesis differs"));
        }
        if history.halted()? {
            self.stop(
                history.last_finalized()?.state().height(),
                history.last_finalized()?.commitment(),
            )?;
            return Err(Error::Invalid(
                "durable research finality conflict stopped signer",
            ));
        }
        if history.last_finalized()?.state().height() < self.state.branch.state().height() {
            return Err(Error::Invalid("selected history behind signer lineage"));
        }
        let selected_parent = history.branch_at(self.state.branch.state().height())?;
        if selected_parent.commitment() != self.state.branch.commitment() {
            self.stop(
                selected_parent.state().height(),
                selected_parent.commitment(),
            )?;
            return Err(Error::Invalid(
                "selected history conflicts with signer lineage",
            ));
        }
        if self.state.pending.is_some() {
            return Err(Error::Invalid(
                "complete pending signature before height handoff",
            ));
        }
        while self.state.branch.state().height() < history.head()?.state().height() {
            let next_height = self.state.lock.height();
            let encoded = history.finality_bytes(next_height)?;
            let finality = self
                .state
                .branch
                .decode_finality(&encoded, self.context.maximum_round)?;
            let mut next = self.state.lock.clone();
            next.advance_height(&finality)?;
            let mut body = vec![ADVANCE];
            bytes(&mut body, &encoded)?;
            let snapshot = next.snapshot()?;
            if snapshot.len() > SNAPSHOT_MAX {
                return Err(Error::Limit("signer height checkpoint"));
            }
            bytes(&mut body, &snapshot)?;
            self.log.core.reserve_batch(&[body.len(), STOP_BYTES])?;
            let usage = self.state.frame_usage(ADVANCE, body.len(), &self.context)?;
            let position = self.log.core.append(&body)?;
            self.state.used_height_bytes = usage.0;
            self.state.used_height_frames = usage.1;
            self.state.branch = finality.into_branch();
            self.state.lock = next;
            self.state.completed = None;
            self.state.publications.clear();
            self.state.previous_votes.clear();
            self.state.sequence = position.sequence;
        }
        Ok(())
    }
    fn stop(&mut self, height: u64, commitment: [u8; 32]) -> Result<(), Error> {
        let mut body = vec![STOP];
        body.extend_from_slice(&height.to_be_bytes());
        body.extend_from_slice(&commitment);
        let position = self.log.core.append(&body)?;
        self.state.pending = None;
        self.state.completed = None;
        self.state.publications.clear();
        self.state.previous_votes.clear();
        self.state.stopped = true;
        self.state.sequence = position.sequence;
        Ok(())
    }
}

fn signing_platform() -> Result<(), Error> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(Error::Platform(
            crate::StoragePlatformError::UnsupportedDurableDirectorySync,
        ))
    }
}
fn context(genesis: Genesis, key: &SigningKey, maximum_round: u64) -> Result<Context, Error> {
    if maximum_round > genesis.profile().limits().consensus_rounds {
        return Err(Error::Limit("signer round ceiling"));
    }
    let signer = ConsensusKey::from_bytes(key.verifying_key().to_bytes());
    if !genesis
        .validators()
        .iter()
        .any(|v| v.consensus_key == *signer.as_bytes())
    {
        return Err(Error::Invalid("unregistered consensus signing key"));
    }
    let mut prefix = MAGIC.to_vec();
    prefix.extend_from_slice(signer.as_bytes());
    prefix.extend_from_slice(&maximum_round.to_be_bytes());
    bytes(&mut prefix, &genesis.encode())?;
    let limits = Limits {
        payload_bytes: u32::try_from(
            genesis.profile().limits().record_bytes + SIGNER_FRAME_OVERHEAD_BYTES,
        )
        .map_err(|_| Error::Limit("signer frame bytes"))?,
        frames: genesis
            .profile()
            .signer_height_frames()?
            .checked_mul(genesis.profile().limits().run_records)
            .and_then(|v| v.checked_add(1))
            .ok_or(Error::Limit("signer frames"))?,
        file_bytes: genesis.profile().signer_journal_bytes()?,
    };
    let name: String = signer
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(Context {
        genesis,
        signer,
        maximum_round,
        prefix,
        limits,
        file_name: format!("state-signer-{name}.journal"),
        lock_name: format!("state-signer-{name}.lock"),
        anchor_name: format!("state-signer-{name}.anchor"),
    })
}
fn event_bounds(event: &StateLockEvent, genesis: &Genesis) -> Result<(), Error> {
    let maximum = genesis.profile().limits().transport_frame_bytes as usize;
    let (payload, limit, proof) = match event {
        StateLockEvent::Author { record } => (
            record.as_deref(),
            genesis.profile().limits().record_bytes as usize,
            None,
        ),
        StateLockEvent::Prevote { proposal } => (proposal.as_deref(), maximum, None),
        StateLockEvent::Precommit { proposal, quorum } => {
            (proposal.as_deref(), maximum, Some(quorum.as_slice()))
        }
        StateLockEvent::ProposalTimeout => (None, 0, None),
        StateLockEvent::PrevoteTimeout { votes }
        | StateLockEvent::PrecommitTimeout { votes }
        | StateLockEvent::HigherRound { votes } => (None, 0, Some(votes.as_slice())),
        StateLockEvent::NilPrecommit { quorum } => (None, 0, Some(quorum.as_slice())),
    };
    if payload.is_some_and(|p| p.len() > limit)
        || proof.is_some_and(|p| p.len() > STATE_QUORUM_MAX_BYTES)
    {
        return Err(Error::Limit("signer event bytes"));
    }
    Ok(())
}

fn publication_hash(publication: &StatePublication) -> Result<[u8; 32], Error> {
    Ok(super::log::hash(
        b"naome:state:publication:v1\0",
        &[&publication.encode()?],
    ))
}
