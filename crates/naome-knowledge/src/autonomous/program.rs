//! Incremental consumption of a durable untrusted provider stream.
use super::*;
use crate::{graph::program::PreparedProgram, proof_work::Work, resources::adaptive::Observer};
use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS, Command, Prefix};

struct Native {
    candidate: crate::learning::program::Candidate,
    helpers: Vec<String>,
    staged: Option<crate::graph::CheckedBatch>,
    checker_work: usize,
    checker_time: Duration,
    _memory: std::sync::Arc<crate::resources::MemoryLease>,
}

pub(super) struct Generated {
    job: u64,
    units: u32,
    unit: u32,
    prefix: Prefix,
    pending: Option<oneshot::Receiver<Result<Vec<Command>, crate::Error>>>,
    work: Option<Work>,
    checked: Option<PreparedProgram>,
    budget: Observer,
    native: Option<Native>,
}
impl Generated {
    pub(super) fn new(job: u64, units: u32) -> Self {
        Self {
            job,
            units,
            unit: 1,
            prefix: Prefix::default(),
            pending: None,
            work: None,
            checked: None,
            budget: Observer::default(),
            native: None,
        }
    }
    pub(super) fn native(
        job: u64,
        solution: crate::learning::Solution,
        question: &ResearchQuestion,
    ) -> Result<Self, crate::Error> {
        let candidate = crate::learning::program::Candidate::from_solution(&solution, question)?;
        let mut generated = Self::new(job, 0);
        let helpers = candidate.helpers(&solution)?;
        let retained = candidate.commands.capacity() * std::mem::size_of::<Command>()
            + candidate.manifest.input_bytes as usize
            + helpers.iter().map(String::capacity).sum::<usize>();
        let memory = crate::resources::MemoryLease::acquire(retained)?;
        generated.native = Some(Native {
            candidate,
            helpers,
            staged: None,
            checker_work: 0,
            checker_time: Duration::ZERO,
            _memory: memory,
        });
        Ok(generated)
    }

    fn append(
        work: &mut Work,
        prefix: &mut Prefix,
        records: &[Command],
    ) -> Result<(), crate::Error> {
        let before = *prefix;
        let mut next = before;
        for command in records {
            next.append(&naome_proof::program::encode_command(command)?)?;
        }
        let status = work.status()?;
        if status.commands == before.commands {
            if status.program_hash != crate::hex(&before.hash) {
                return Err(crate::ResearchFailure::CandidatePrefixMismatch.into());
            }
            work.append_group(records)?;
        } else if status.commands < next.commands {
            return Err(crate::ResearchFailure::CandidateCheckpointInsideGroup.into());
        }
        let status = work.status()?;
        if status.commands == next.commands && status.program_hash != crate::hex(&next.hash) {
            return Err(crate::ResearchFailure::CandidateInputMismatch.into());
        }
        *prefix = next;
        Ok(())
    }

    pub(super) fn restrict_cache(&mut self, graph: &Graph) -> Result<(), crate::Error> {
        let cache = self
            .budget
            .refresh(graph.ownership().directory())?
            .budget
            .cache_bytes;
        if let Some(work) = &mut self.work {
            work.restrict_cache(cache)?;
        }
        if let Some(proof) = &mut self.checked {
            proof.restrict_cache(cache)?;
        }
        Ok(())
    }
    pub(super) fn prepare(
        &mut self,
        graph: &Graph,
        client: &jobs::Client,
        question: &ResearchQuestion,
    ) -> Result<Option<(ArtifactId, crate::graph::CheckedBatch)>, crate::Error> {
        let snapshot = self.budget.refresh(graph.ownership().directory())?.clone();
        if snapshot.budget.paused.is_some() {
            return Ok(None);
        }
        if self.work.is_none() && self.checked.is_none() {
            let directory = graph.ownership().directory().join(".program-work");
            if let Ok(metadata) = std::fs::symlink_metadata(&directory)
                && (!metadata.is_dir() || metadata.file_type().is_symlink())
            {
                return Err(crate::InputFault::OwnedFileType.into());
            }
            self.work = Some(Work::open(
                &directory.join(format!("candidate-{}.sqlite3", self.job)),
            )?);
        }
        if let Some(work) = self.work.as_mut() {
            work.record_budget(&snapshot)?;
            if let Some(native) = &mut self.native {
                let commands = &native.candidate.commands[self.prefix.commands as usize..];
                if !commands.is_empty() {
                    let mut bytes = 0;
                    let mut count = 0;
                    for command in commands.iter().take(CHUNK_RECORDS) {
                        bytes += naome_proof::program::encode_command(command)?.len();
                        if bytes > CHUNK_BYTES {
                            break;
                        }
                        count += 1;
                    }
                    Self::append(work, &mut self.prefix, &commands[..count])?;
                    return Ok(None);
                }
                if let Some(staged) = &native.staged
                    && !graph.batch_current(staged)?
                {
                    native.staged = None;
                }
                if native.staged.is_none() && !native.helpers.is_empty() {
                    native.staged = Some(graph.prepare_generated_helpers(&native.helpers)?);
                }
            }
            if self.unit <= self.units {
                if let Some(mut pending) = self.pending.take() {
                    match pending.try_recv() {
                        Ok(result) => {
                            let records = result?;
                            Self::append(work, &mut self.prefix, &records)?;
                            self.unit = self
                                .unit
                                .checked_add(1)
                                .ok_or(crate::ResearchFailure::CandidateUnitOverflow)?;
                        }
                        Err(oneshot::error::TryRecvError::Empty) => self.pending = Some(pending),
                        Err(_) => return Err(crate::ResearchFailure::ServiceStopped.into()),
                    }
                } else {
                    self.pending = Some(client.program(self.job, self.unit)?);
                }
                return Ok(None);
            }
            let status = work.status()?;
            if status.commands != self.prefix.commands
                || status.program_hash != crate::hex(&self.prefix.hash)
            {
                return Err(crate::ResearchFailure::CandidateStreamMismatch.into());
            }
            if !status.fully_checked {
                let context = self
                    .native
                    .as_ref()
                    .and_then(|native| native.staged.as_ref())
                    .map_or_else(|| graph.checked_context(), |batch| batch.context());
                let start = Instant::now();
                let progress = work.advance(&snapshot.budget, context);
                if let Some(native) = &mut self.native {
                    native.checker_work = native
                        .checker_work
                        .saturating_add(work.last_quantum_steps());
                    native.checker_time += start.elapsed();
                }
                if !progress? && !work.status()?.fully_checked {
                    return Err(crate::ResearchFailure::CandidateSealMissing.into());
                }
                return Ok(None);
            }
            if !work.prepare_export(&snapshot.budget)? {
                return Ok(None);
            }
            let checked = self.work.take().expect("candidate work").into_checked()?;
            if let Some(native) = &self.native {
                checked
                    .proof()?
                    .check_manifest(&native.candidate.manifest)?;
            }
            question
                .classify_checked_program(checked.proof()?)
                .map_err(crate::Error::from)?;
            if let Some(native) = &self.native {
                emit(json!({
                    "event": crate::outcome::NodeEvent::NativeProgramChecked,
                    "job": self.job,
                    "id": crate::hex(native.candidate.manifest.artifact_id().as_bytes()),
                    "input_bytes": native.candidate.manifest.input_bytes,
                    "commands": native.candidate.manifest.commands,
                    "checker_work": native.checker_work,
                    "checker_micros": native.checker_time.as_micros(),
                }));
            }
            self.checked = Some(PreparedProgram::new(checked));
        }
        let checked = self
            .checked
            .as_mut()
            .ok_or(crate::ResearchFailure::CandidateCheckedMissing)?;
        let proof = checked.proof()?;
        let manifest = proof.manifest().clone();
        let store = graph.ownership();
        let progress = store.start_program(&manifest)?;
        if progress.commands < manifest.commands {
            let chunk = proof
                .input_chunk(
                    progress.commands,
                    snapshot.budget.batch_steps.clamp(1, CHUNK_RECORDS),
                    CHUNK_BYTES,
                )
                .map_err(crate::Error::from)?;
            store.append_program(&manifest, &chunk)?;
            return Ok(None);
        }
        let prefix = if checked.pending() {
            if let Some(native) = &mut self.native {
                if let Some(staged) = native.staged.take() {
                    if graph.batch_current(&staged)? {
                        Some(staged)
                    } else if native.helpers.is_empty() {
                        None
                    } else {
                        Some(graph.prepare_generated_helpers(&native.helpers)?)
                    }
                } else if native.helpers.is_empty() {
                    None
                } else {
                    Some(graph.prepare_generated_helpers(&native.helpers)?)
                }
            } else {
                None
            }
        } else {
            None
        };
        let quantum = snapshot.budget.batch_steps.max(1);
        let ready = match prefix {
            Some(prefix) => checked.advance_after(graph, quantum, Some(prefix))?,
            None => checked.advance(graph, quantum)?,
        };
        if ready {
            Ok(Some((
                manifest.artifact_id(),
                checked.take_batch().expect("prepared candidate"),
            )))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests;
