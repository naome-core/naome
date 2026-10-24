//! Canonical bounded program records, kept outside checked membership until
//! Graph publishes a complete mathematically checked manifest transaction.
use super::*;
use naome_proof::program::{
    CHUNK_BYTES, CHUNK_RECORDS, Chunk, Command, Manifest, RECORD_BYTES, command_hash,
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
thread_local! { static MANIFEST_READS: Cell<usize> = const { Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn manifest_reads() -> usize {
    MANIFEST_READS.with(Cell::get)
}

fn sql_error(error: rusqlite::Error) -> crate::Error {
    naome_checker::program::Error::Storage(error).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Progress {
    pub commands: u64,
    pub input_bytes: u64,
    pub hash: [u8; 32],
    pub remaining: [u8; 32],
}
fn ordinal(value: u64) -> Result<i64, crate::Error> {
    i64::try_from(value).map_err(|_| "physical program address exhausted".into())
}
fn positive(value: i64) -> Result<u64, crate::Error> {
    u64::try_from(value).map_err(|_| "negative program address".into())
}
fn manifest_bytes(manifest: &Manifest) -> Result<Vec<u8>, crate::Error> {
    let bytes = serde_json::to_vec(manifest).map_err(|e| e.to_string())?;
    if bytes.len() > 2048 || manifest.commands == 0 || manifest.input_bytes == 0 {
        return Err("invalid program manifest".into());
    }
    ordinal(manifest.commands)?;
    ordinal(manifest.input_bytes)?;
    Ok(bytes)
}
fn decode_manifest(bytes: &[u8]) -> Result<Manifest, crate::Error> {
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if manifest_bytes(&manifest)? != bytes {
        return Err("noncanonical program manifest".into());
    }
    Ok(manifest)
}
fn progress(connection: &Connection, manifest: &Manifest) -> Result<Progress, crate::Error> {
    type Row = (Vec<u8>, i64, i64, Vec<u8>, Vec<u8>);
    let row:Option<Row>=connection.query_row("SELECT substr(manifest,1,2049),received,input_bytes,substr(hash,1,33),substr(remaining,1,33) FROM programs WHERE id=?1",[manifest.proof_id().as_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(sql_error)?;
    let Some((bytes, commands, input_bytes, hash, remaining)) = row else {
        return Err("program staging missing".into());
    };
    if bytes != manifest_bytes(manifest)? {
        return Err("program manifest changed".into());
    }
    let value = Progress {
        commands: positive(commands)?,
        input_bytes: positive(input_bytes)?,
        hash: key(hash)?,
        remaining: key(remaining)?,
    };
    if value.commands > manifest.commands || value.input_bytes > manifest.input_bytes {
        return Err("program prefix exceeds manifest".into());
    }
    Ok(value)
}
pub(super) fn require_complete(
    connection: &Connection,
    manifest: &Manifest,
) -> Result<(), crate::Error> {
    let value = progress(connection, manifest)?;
    if value.commands != manifest.commands
        || value.input_bytes != manifest.input_bytes
        || value.hash != manifest.program_hash
        || value.remaining != [0; 32]
    {
        return Err("program input is incomplete or differs from manifest".into());
    }
    Ok(())
}
impl Catalog {
    pub(in crate::store) fn start_program(
        &self,
        manifest: &Manifest,
    ) -> Result<Progress, crate::Error> {
        self.replay_summary.set(None);
        let bytes = manifest_bytes(manifest)?;
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        self.require_validated_version(&transaction)?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO programs VALUES(?1,?2,0,0,zeroblob(32),?3)",
                params![
                    manifest.proof_id().as_bytes().as_slice(),
                    bytes,
                    manifest.stream_root.as_slice()
                ],
            )
            .map_err(sql_error)?;
        let value = progress(&transaction, manifest)?;
        transaction
            .commit()
            .map_err(|e| crate::Error::UncertainDurability(e.to_string()))?;
        Ok(value)
    }
    pub(in crate::store) fn program_manifest(
        &self,
        id: ProofId,
    ) -> Result<Option<Manifest>, crate::Error> {
        #[cfg(test)]
        MANIFEST_READS.with(|count| count.set(count.get() + 1));
        self.require_validated_version(&self.connection)?;
        let bytes: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT substr(manifest,1,2049) FROM programs WHERE id=?1",
                [id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        bytes
            .map(|bytes| {
                let manifest = decode_manifest(&bytes)?;
                if manifest.proof_id() != id {
                    return Err("program address differs".into());
                }
                Ok(manifest)
            })
            .transpose()
    }
    pub(in crate::store) fn program_progress(
        &self,
        manifest: &Manifest,
    ) -> Result<Progress, crate::Error> {
        self.require_validated_version(&self.connection)?;
        progress(&self.connection, manifest)
    }
    pub(in crate::store) fn append_program(
        &self,
        manifest: &Manifest,
        chunk: &Chunk,
    ) -> Result<Progress, crate::Error> {
        self.replay_summary.set(None);
        if chunk.records.is_empty() || chunk.records.len() > CHUNK_RECORDS {
            return Err("program chunk record capacity".into());
        }
        let mut encoded = Vec::with_capacity(chunk.records.len());
        let mut total = 0usize;
        for command in &chunk.records {
            let bytes = serde_json::to_vec(command).map_err(|e| e.to_string())?;
            total = total
                .checked_add(bytes.len())
                .ok_or("program chunk width")?;
            if bytes.len() > RECORD_BYTES || total > CHUNK_BYTES {
                return Err("program chunk byte capacity".into());
            }
            encoded.push(bytes);
        }
        let mut suffixes = vec![[0; 32]; encoded.len()];
        let mut suffix = chunk.next;
        for (index, bytes) in encoded.iter().enumerate().rev() {
            suffix = naome_proof::program::stream_hash(bytes, suffix);
            suffixes[index] = suffix;
        }
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        self.require_validated_version(&transaction)?;
        let mut value = progress(&transaction, manifest)?;
        if value.commands != chunk.start
            || value.hash != chunk.previous
            || value.remaining != suffix
        {
            return Err("program chunk authentication or prefix mismatch".into());
        }
        let end = value
            .commands
            .checked_add(encoded.len() as u64)
            .ok_or("program chunk cursor width")?;
        if end > manifest.commands || (end == manifest.commands && chunk.next != [0; 32]) {
            return Err("program chunk end mismatch".into());
        }
        for ((command, bytes), suffix) in chunk.records.iter().zip(&encoded).zip(suffixes) {
            if matches!(command, Command::Seal { .. }) && value.commands + 1 != manifest.commands {
                return Err("program seal precedes declared end".into());
            }
            let hash = command_hash(value.hash, bytes);
            transaction
                .execute(
                    "INSERT INTO program_input VALUES(?1,?2,?3,?4,?5)",
                    params![
                        manifest.proof_id().as_bytes().as_slice(),
                        ordinal(value.commands)?,
                        bytes,
                        hash.as_slice(),
                        suffix.as_slice()
                    ],
                )
                .map_err(sql_error)?;
            value.commands += 1;
            value.input_bytes = value
                .input_bytes
                .checked_add(bytes.len() as u64)
                .ok_or("program byte width")?;
            value.hash = hash;
        }
        value.remaining = chunk.next;
        if value.input_bytes > manifest.input_bytes
            || (value.commands == manifest.commands
                && (value.input_bytes != manifest.input_bytes
                    || value.hash != manifest.program_hash))
        {
            return Err("complete program hash or length mismatch".into());
        }
        transaction
            .execute(
                "UPDATE programs SET received=?2,input_bytes=?3,hash=?4,remaining=?5 WHERE id=?1",
                params![
                    manifest.proof_id().as_bytes().as_slice(),
                    ordinal(value.commands)?,
                    ordinal(value.input_bytes)?,
                    value.hash.as_slice(),
                    value.remaining.as_slice()
                ],
            )
            .map_err(sql_error)?;
        transaction
            .commit()
            .map_err(|e| crate::Error::UncertainDurability(e.to_string()))?;
        Ok(value)
    }
    pub(in crate::store) fn program_chunk(
        &self,
        manifest: &Manifest,
        start: u64,
        records: usize,
        maximum: usize,
    ) -> Result<Chunk, crate::Error> {
        self.require_validated_version(&self.connection)?;
        if records == 0 || records > CHUNK_RECORDS || maximum == 0 || maximum > CHUNK_BYTES {
            return Err("program chunk request capacity".into());
        }
        let value = progress(&self.connection, manifest)?;
        if start > value.commands {
            return Err("program cursor exceeds received prefix".into());
        }
        let previous = if start == 0 {
            [0; 32]
        } else {
            let hash: Vec<u8> = self
                .connection
                .query_row(
                    "SELECT substr(hash,1,33) FROM program_input WHERE id=?1 AND position=?2",
                    params![
                        manifest.proof_id().as_bytes().as_slice(),
                        ordinal(start - 1)?
                    ],
                    |r| r.get(0),
                )
                .map_err(sql_error)?;
            key(hash)?
        };
        let mut statement=self.connection.prepare_cached("SELECT position,substr(command,1,4097),substr(hash,1,33) FROM program_input WHERE id=?1 AND position>=?2 ORDER BY position LIMIT ?3").map_err(sql_error)?;
        let mut rows = statement
            .query(params![
                manifest.proof_id().as_bytes().as_slice(),
                ordinal(start)?,
                records as i64
            ])
            .map_err(sql_error)?;
        let mut chunk = Chunk {
            start,
            previous,
            next: [0; 32],
            records: Vec::new(),
        };
        let mut hash = previous;
        let mut bytes = 0usize;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let position: i64 = row.get(0).map_err(sql_error)?;
            let encoded: Vec<u8> = row.get(1).map_err(sql_error)?;
            let stored: Vec<u8> = row.get(2).map_err(sql_error)?;
            if positive(position)? != start + chunk.records.len() as u64
                || encoded.len() > RECORD_BYTES
            {
                return Err("program record order or width differs".into());
            }
            if encoded.len() > maximum.saturating_sub(bytes) {
                if chunk.records.is_empty() {
                    return Err("program record exceeds working chunk budget".into());
                }
                break;
            }
            let command: Command = serde_json::from_slice(&encoded).map_err(|e| e.to_string())?;
            if serde_json::to_vec(&command).map_err(|e| e.to_string())? != encoded {
                return Err("noncanonical program input".into());
            }
            hash = command_hash(hash, &encoded);
            if key(stored)? != hash {
                return Err("program record hash differs".into());
            }
            bytes += encoded.len();
            chunk.records.push(command);
        }
        if start < value.commands && chunk.records.is_empty() {
            return Err("program prefix is incomplete".into());
        }
        let end = start + chunk.records.len() as u64;
        chunk.next = if end == value.commands {
            value.remaining
        } else {
            let suffix: Vec<u8> = self
                .connection
                .query_row(
                    "SELECT substr(suffix,1,33) FROM program_input WHERE id=?1 AND position=?2",
                    params![manifest.proof_id().as_bytes().as_slice(), ordinal(end)?],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            key(suffix)?
        };
        Ok(chunk)
    }
}

/// Structural prefix validation on reopen, using bounded rows. This rebuilds
/// no mathematical trust; every published program is still replayed by Checker.
pub(super) fn validate_staging(connection: &Connection) -> Result<(), crate::Error> {
    let mut programs = connection
        .prepare("SELECT substr(id,1,33),substr(manifest,1,2049) FROM programs ORDER BY id")
        .map_err(sql_error)?;
    let mut rows = programs.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        let bytes: Vec<u8> = row.get(1).map_err(sql_error)?;
        let manifest = decode_manifest(&bytes)?;
        if manifest.proof_id().as_bytes() != &id {
            return Err("staged program identity differs".into());
        }
        let expected = progress(connection, &manifest)?;
        let mut records=connection.prepare_cached("SELECT position,substr(command,1,4097),substr(hash,1,33) FROM program_input WHERE id=?1 ORDER BY position").map_err(sql_error)?;
        let mut input = records.query([id.as_slice()]).map_err(sql_error)?;
        let mut observed = Progress {
            commands: 0,
            input_bytes: 0,
            hash: [0; 32],
            remaining: expected.remaining,
        };
        while let Some(record) = input.next().map_err(sql_error)? {
            let position: i64 = record.get(0).map_err(sql_error)?;
            let bytes: Vec<u8> = record.get(1).map_err(sql_error)?;
            let hash = key(record.get(2).map_err(sql_error)?)?;
            if positive(position)? != observed.commands || bytes.len() > RECORD_BYTES {
                return Err("staged program input order or width differs".into());
            }
            let command: Command = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            if serde_json::to_vec(&command).map_err(|e| e.to_string())? != bytes {
                return Err("noncanonical staged program record".into());
            }
            observed.hash = command_hash(observed.hash, &bytes);
            if observed.hash != hash {
                return Err("staged program input hash differs".into());
            }
            observed.commands += 1;
            observed.input_bytes = observed
                .input_bytes
                .checked_add(bytes.len() as u64)
                .ok_or("staged program byte width")?;
        }
        let mut reverse=connection.prepare_cached("SELECT substr(command,1,4097),substr(suffix,1,33) FROM program_input WHERE id=?1 ORDER BY position DESC").map_err(sql_error)?;
        let mut reverse_rows = reverse.query([id.as_slice()]).map_err(sql_error)?;
        let mut suffix = expected.remaining;
        while let Some(row) = reverse_rows.next().map_err(sql_error)? {
            let bytes: Vec<u8> = row.get(0).map_err(sql_error)?;
            let stored = key(row.get(1).map_err(sql_error)?)?;
            suffix = naome_proof::program::stream_hash(&bytes, suffix);
            if suffix != stored {
                return Err("staged program stream suffix differs".into());
            }
        }
        if suffix != manifest.stream_root {
            return Err("staged program stream root differs".into());
        }
        if observed != expected {
            return Err("staged program prefix summary differs".into());
        }
        if observed.commands == manifest.commands {
            require_complete(connection, &manifest)?;
        }
    }
    Ok(())
}
