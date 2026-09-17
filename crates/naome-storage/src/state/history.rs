use std::path::{Path, PathBuf};

use naome_consensus::state::{ResearchBranch, ResearchFinality};
use naome_ledger::{ResearchState, profile::Genesis};

use super::{
    ResearchStorageError as Error,
    log::{self, FileLog, Limits, Position},
};

const MAGIC: &[u8; 8] = b"NAORHIS1";
const ANCHOR: &str = "research-finality.anchor";
const FINALITY: u8 = 1;
const CONFLICT: u8 = 2;

fn authenticate_height(height: u64, bytes: &[u8], context: &Context) -> Result<(), Error> {
    let value = ResearchFinality::authenticate(bytes, &context.genesis, context.maximum_round)?;
    if value.height() != height {
        return Err(Error::Invalid(
            "authenticated finality height differs from hint",
        ));
    }
    Ok(())
}

mod sealed {
    pub trait Sealed {}
}
/// Selected state obtainable only from full anchored replay or durable append.
/// A decoded record, snapshot, or caller-constructed state cannot implement it.
pub trait SelectedResearchHistory: sealed::Sealed {
    fn selected_branch(&self) -> Result<&ResearchBranch, Error>;
    fn is_halted(&self) -> Result<bool, Error>;
}

/// Result after body, commit footer, and independent anchor are all durable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResearchAppendOutcome {
    Finalized,
    AlreadyFinalized,
    ConflictHalt,
}

/// The sole writer of the selected complete research history in a directory.
/// Shares both the journal pathname and owner lock with existing V0 storage.
/// No state is installed or returned from a failed append.
pub struct ResearchHistory {
    log: FileLog,
    replay: Replay,
    context: Context,
}
#[derive(Clone)]
struct Context {
    directory: PathBuf,
    prefix: Vec<u8>,
    limits: Limits,
    genesis: Genesis,
    maximum_round: u64,
}
struct Replay {
    branch: ResearchBranch,
    latest_parent: Option<ResearchBranch>,
    // One small authenticated log coordinate/commitment per finalized height;
    // complete states and proof bodies are not cloned for every historical row.
    coordinates: Vec<(Position, u64)>,
    commitments: Vec<[u8; 32]>,
    halted: bool,
    #[cfg(test)]
    historical_replays: std::cell::Cell<usize>,
}
impl Replay {
    fn new(context: &Context) -> Result<Self, Error> {
        let branch = ResearchBranch::from_genesis(ResearchState::new(context.genesis.clone()))?;
        let commitment = branch.commitment();
        Ok(Self {
            branch,
            latest_parent: None,
            coordinates: vec![(
                log::prefix_position(&context.prefix),
                context.prefix.len() as u64,
            )],
            commitments: vec![commitment],
            halted: false,
            #[cfg(test)]
            historical_replays: std::cell::Cell::new(0),
        })
    }
    fn apply(&mut self, body: &[u8], context: &Context) -> Result<(), Error> {
        if self.halted {
            return Err(Error::Invalid("record after research conflict halt"));
        }
        match body.first().copied() {
            Some(FINALITY) => {
                let finality = self
                    .branch
                    .decode_finality(&body[1..], context.maximum_round)?;
                self.reserve()?;
                let prior = *self.coordinates.last().expect("genesis coordinate");
                let next = log::extend_position(prior.0, prior.1, body)?;
                self.install(finality, next);
            }
            Some(CONFLICT) => {
                if body.len() < 9 {
                    return Err(Error::Invalid("conflict framing"));
                }
                let height = u64::from_be_bytes(body[1..9].try_into().expect("fixed slice"));
                self.verify_conflict(height, &body[9..], context)?;
                self.halted = true;
            }
            _ => return Err(Error::Invalid("research history frame kind")),
        }
        Ok(())
    }
    fn reserve(&mut self) -> Result<(), Error> {
        self.coordinates
            .try_reserve(1)
            .map_err(|_| Error::Limit("history coordinate allocation"))?;
        self.commitments
            .try_reserve(1)
            .map_err(|_| Error::Limit("history commitment allocation"))?;
        Ok(())
    }
    fn install(&mut self, finality: ResearchFinality, coordinate: (Position, u64)) {
        let child = finality.into_branch();
        self.latest_parent = Some(std::mem::replace(&mut self.branch, child));
        self.coordinates.push(coordinate);
        self.commitments.push(self.branch.commitment());
    }
    fn parent(&self, height: u64, context: &Context) -> Result<ResearchBranch, Error> {
        if height == 0 || height > self.branch.state().height() {
            return Err(Error::Invalid("historical finality height"));
        }
        if height == self.branch.state().height() {
            return self
                .latest_parent
                .clone()
                .ok_or(Error::Invalid("missing finalized parent"));
        }
        let (position, end) = *self
            .coordinates
            .get((height - 1) as usize)
            .ok_or(Error::Invalid("historical coordinate"))?;
        let mut branch = ResearchBranch::from_genesis(ResearchState::new(context.genesis.clone()))?;
        #[cfg(test)]
        self.historical_replays
            .set(self.historical_replays.get() + 1);
        log::prefix_replay(
            &context.directory,
            crate::JOURNAL_FILE_NAME,
            &context.prefix,
            context.limits,
            end,
            position,
            |body| {
                if body.first() != Some(&FINALITY) {
                    return Err(Error::Invalid("non-finality in selected prefix"));
                }
                branch = branch
                    .decode_finality(&body[1..], context.maximum_round)?
                    .into_branch();
                Ok(())
            },
        )?;
        if branch.commitment() != self.commitments[(height - 1) as usize] {
            return Err(Error::Invalid("historical branch commitment"));
        }
        Ok(branch)
    }
    fn verify_conflict(&self, height: u64, bytes: &[u8], context: &Context) -> Result<(), Error> {
        authenticate_height(height, bytes, context)?;
        let parent = self.parent(height, context)?;
        let conflict = parent.decode_finality(bytes, context.maximum_round)?;
        if conflict.branch().commitment() == self.commitments[height as usize] {
            return Err(Error::Invalid("finality is not a conflicting sibling"));
        }
        Ok(())
    }
}

impl ResearchHistory {
    #[cfg(test)]
    pub(super) fn historical_replay_count(&self) -> usize {
        self.replay.historical_replays.get()
    }
    pub fn create(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        maximum_round: u64,
    ) -> Result<Self, Error> {
        let context = context(directory.as_ref(), genesis, maximum_round)?;
        let replay = Replay::new(&context)?;
        let log = FileLog::create(
            directory.as_ref(),
            anchor_directory.as_ref(),
            crate::JOURNAL_FILE_NAME,
            crate::LOCK_FILE_NAME,
            ANCHOR,
            &context.prefix,
            context.limits,
        )?;
        Ok(Self {
            log,
            replay,
            context,
        })
    }
    pub fn open(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        maximum_round: u64,
    ) -> Result<Self, Error> {
        let context = context(directory.as_ref(), genesis, maximum_round)?;
        let mut replay = Replay::new(&context)?;
        let log = FileLog::open(
            directory.as_ref(),
            anchor_directory.as_ref(),
            crate::JOURNAL_FILE_NAME,
            crate::LOCK_FILE_NAME,
            ANCHOR,
            &context.prefix,
            context.limits,
            |body| replay.apply(body, &context),
        )?;
        Ok(Self {
            log,
            replay,
            context,
        })
    }
    /// Returns the operable selected branch. A durable conflict stops new work.
    pub fn head(&self) -> Result<&ResearchBranch, Error> {
        self.log.core.ensure()?;
        if self.replay.halted {
            return Err(Error::Invalid("terminal research finality conflict"));
        }
        Ok(&self.replay.branch)
    }
    /// Readable last selected state, including after a verified conflict halt.
    pub fn last_finalized(&self) -> Result<&ResearchBranch, Error> {
        self.log.core.ensure()?;
        Ok(&self.replay.branch)
    }
    pub fn halted(&self) -> Result<bool, Error> {
        self.log.core.ensure()?;
        Ok(self.replay.halted)
    }
    pub(super) fn branch_at(&self, height: u64) -> Result<ResearchBranch, Error> {
        self.log.core.ensure()?;
        if height == self.replay.branch.state().height() {
            return Ok(self.replay.branch.clone());
        }
        if height == 0 {
            return Ok(ResearchBranch::from_genesis(ResearchState::new(
                self.context.genesis.clone(),
            ))?);
        }
        self.replay.parent(
            height
                .checked_add(1)
                .ok_or(Error::Limit("history height"))?,
            &self.context,
        )
    }
    pub fn maximum_round(&self) -> u64 {
        self.context.maximum_round
    }
    /// Receive an exact-height history item or untrusted push hint. The hint
    /// grants no authority: the full envelope is checked against that height's
    /// selected parent before deciding duplicate, successor, or conflict.
    pub fn receive_finality(
        &mut self,
        height: u64,
        bytes: &[u8],
    ) -> Result<ResearchAppendOutcome, Error> {
        self.head()?;
        let selected = self.replay.branch.state().height();
        if height
            == selected
                .checked_add(1)
                .ok_or(Error::Limit("history height"))?
        {
            return self.append_finality(bytes);
        }
        if height == 0 || height > selected {
            return Err(Error::Invalid("finality history gap or zero height"));
        }
        authenticate_height(height, bytes, &self.context)?;
        // Repeated catch-up pushes use the already verified exact envelope.
        // Its indexed disk read checks the chained frame before this shortcut;
        // different sufficient signature sets still receive full validation.
        if self.finality_bytes(height)?.as_slice() == bytes {
            return Ok(ResearchAppendOutcome::AlreadyFinalized);
        }
        let parent = self.replay.parent(height, &self.context)?;
        let candidate = parent.decode_finality(bytes, self.context.maximum_round)?;
        if candidate.branch().commitment() == self.replay.commitments[height as usize] {
            return Ok(ResearchAppendOutcome::AlreadyFinalized);
        }
        self.report_conflict(height, bytes)
    }
    pub fn append_finality(&mut self, bytes: &[u8]) -> Result<ResearchAppendOutcome, Error> {
        self.head()?;
        match self
            .replay
            .branch
            .decode_finality(bytes, self.context.maximum_round)
        {
            Ok(finality) => {
                let mut body = Vec::with_capacity(bytes.len() + 1);
                body.push(FINALITY);
                body.extend_from_slice(bytes);
                self.replay.reserve()?;
                let prior = *self.replay.coordinates.last().expect("genesis coordinate");
                let next = log::extend_position(prior.0, prior.1, &body)?;
                self.log.core.append(&body)?;
                self.replay.install(finality, next);
                Ok(ResearchAppendOutcome::Finalized)
            }
            Err(original) => {
                // Repeated finality evidence may use a different sufficient
                // signature subset; compare the verified child, not raw bytes.
                if let Some(parent) = &self.replay.latest_parent
                    && let Ok(finality) = parent.decode_finality(bytes, self.context.maximum_round)
                {
                    if finality.branch().commitment() == self.replay.branch.commitment() {
                        return Ok(ResearchAppendOutcome::AlreadyFinalized);
                    }
                    return self.report_conflict(self.replay.branch.state().height(), bytes);
                }
                Err(original.into())
            }
        }
    }
    /// Verifies an arbitrary earlier sibling against its exact historical parent
    /// and durably halts. Reconstructing that parent is bounded by the run limit.
    pub fn report_conflict(
        &mut self,
        height: u64,
        bytes: &[u8],
    ) -> Result<ResearchAppendOutcome, Error> {
        self.head()?;
        self.replay.verify_conflict(height, bytes, &self.context)?;
        let mut body = Vec::with_capacity(9 + bytes.len());
        body.push(CONFLICT);
        body.extend_from_slice(&height.to_be_bytes());
        body.extend_from_slice(bytes);
        self.log.core.append(&body)?;
        self.replay.halted = true;
        Ok(ResearchAppendOutcome::ConflictHalt)
    }
    /// Exact first finality proof at this height. Re-reading verifies the stored
    /// frame checksum before exposing any bytes.
    pub fn finality_bytes(&mut self, height: u64) -> Result<Vec<u8>, Error> {
        self.log.core.ensure()?;
        if height == 0 || height > self.replay.branch.state().height() {
            return Err(Error::Invalid("finality export height"));
        }
        let body = self.log.core.payload((height - 1) as usize)?;
        if body.first() != Some(&FINALITY) {
            return Err(Error::Invalid("finality frame kind"));
        }
        Ok(body[1..].to_vec())
    }
}
impl sealed::Sealed for ResearchHistory {}
impl SelectedResearchHistory for ResearchHistory {
    fn selected_branch(&self) -> Result<&ResearchBranch, Error> {
        self.last_finalized()
    }
    fn is_halted(&self) -> Result<bool, Error> {
        self.halted()
    }
}

/// Independent read-only observation, using the identical frame, mathematical,
/// finality, and historical conflict replay paths as an operational reopen.
pub struct ResearchObserver {
    branch: ResearchBranch,
    halted: bool,
}
impl ResearchObserver {
    pub fn open(
        directory: impl AsRef<Path>,
        anchor_directory: impl AsRef<Path>,
        genesis: Genesis,
        maximum_round: u64,
    ) -> Result<Self, Error> {
        let context = context(directory.as_ref(), genesis, maximum_round)?;
        let mut replay = Replay::new(&context)?;
        log::observe(
            directory.as_ref(),
            anchor_directory.as_ref(),
            crate::JOURNAL_FILE_NAME,
            ANCHOR,
            &context.prefix,
            context.limits,
            |body| replay.apply(body, &context),
        )?;
        Ok(Self {
            branch: replay.branch,
            halted: replay.halted,
        })
    }
    pub fn branch(&self) -> &ResearchBranch {
        &self.branch
    }
    pub fn halted(&self) -> bool {
        self.halted
    }
}
impl sealed::Sealed for ResearchObserver {}
impl SelectedResearchHistory for ResearchObserver {
    fn selected_branch(&self) -> Result<&ResearchBranch, Error> {
        Ok(&self.branch)
    }
    fn is_halted(&self) -> Result<bool, Error> {
        Ok(self.halted)
    }
}

fn context(directory: &Path, genesis: Genesis, maximum_round: u64) -> Result<Context, Error> {
    if maximum_round > genesis.profile().limits().consensus_rounds {
        return Err(Error::Limit("round replay ceiling"));
    }
    let mut prefix = MAGIC.to_vec();
    prefix.extend_from_slice(&maximum_round.to_be_bytes());
    let encoded = genesis.encode();
    prefix.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    prefix.extend(encoded);
    let frame = genesis.profile().limits().transport_frame_bytes;
    // One extra terminal evidence frame can halt after the final run record.
    let frames = genesis
        .profile()
        .limits()
        .run_records
        .checked_add(1)
        .ok_or(Error::Limit("history frames"))?;
    let limits = Limits {
        payload_bytes: u32::try_from(
            frame
                .checked_sub(36)
                .ok_or(Error::Limit("frame overhead"))?,
        )
        .map_err(|_| Error::Limit("frame size"))?,
        frames,
        file_bytes: frames
            .checked_mul(frame)
            .and_then(|v| v.checked_add(prefix.len() as u64))
            .ok_or(Error::Limit("history archive bytes"))?,
    };
    Ok(Context {
        directory: directory.to_owned(),
        prefix,
        limits,
        genesis,
        maximum_round,
    })
}
