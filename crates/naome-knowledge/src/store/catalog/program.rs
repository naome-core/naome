//! Canonical bounded program records, kept outside checked membership until
//! Graph publishes a complete mathematically checked manifest transaction.
use super::*;
use naome_proof::program::Progress;
use naome_proof::program::{Chunk, ChunkReader, Manifest, Prefix, RECORD_BYTES, decode_command};
#[cfg(test)]
thread_local! { static MANIFEST_READS: Cell<usize> = const { Cell::new(0) }; }
#[cfg(test)]
pub(crate) fn manifest_reads() -> usize {
    MANIFEST_READS.with(Cell::get)
}

fn sql_error(error: rusqlite::Error) -> crate::Error {
    naome_checker::program::Error::Storage(error).into()
}

fn ordinal(value: u64) -> Result<i64, crate::Error> {
    i64::try_from(value).map_err(|_| "physical program address exhausted".into())
}
fn positive(value: i64) -> Result<u64, crate::Error> {
    u64::try_from(value).map_err(|_| "negative program address".into())
}
fn manifest_bytes(manifest: &Manifest) -> Result<Vec<u8>, crate::Error> {
    ordinal(manifest.commands)?;
    ordinal(manifest.input_bytes)?;
    manifest.canonical_bytes().map_err(Into::into)
}
fn decode_manifest(bytes: &[u8]) -> Result<Manifest, crate::Error> {
    let manifest = Manifest::from_canonical_bytes(bytes)?;
    ordinal(manifest.commands)?;
    ordinal(manifest.input_bytes)?;
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
    progress(connection, manifest)?
        .require_complete(manifest)
        .map_err(Into::into)
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
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        self.require_validated_version(&transaction)?;
        let (value, records) = progress(&transaction, manifest)?.prepare_append(manifest, chunk)?;
        for record in records {
            transaction
                .execute(
                    "INSERT INTO program_input VALUES(?1,?2,?3,?4,?5)",
                    params![
                        manifest.proof_id().as_bytes().as_slice(),
                        ordinal(record.position)?,
                        record.bytes,
                        record.hash.as_slice(),
                        record.suffix.as_slice()
                    ],
                )
                .map_err(sql_error)?;
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
        let mut reader = ChunkReader::new(start, previous, records, maximum)?;
        while let Some(row) = rows.next().map_err(sql_error)? {
            let position: i64 = row.get(0).map_err(sql_error)?;
            let encoded: Vec<u8> = row.get(1).map_err(sql_error)?;
            let stored = key(row.get(2).map_err(sql_error)?)?;
            if !reader.push(positive(position)?, &encoded, stored)? {
                break;
            }
        }
        let end = reader.end();
        let next = if end == value.commands {
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
        reader.finish(value.commands, next).map_err(Into::into)
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
            decode_command(&bytes)?;
            let mut prefix = Prefix {
                commands: observed.commands,
                input_bytes: observed.input_bytes,
                hash: observed.hash,
            };
            prefix.append(&bytes)?;
            observed.commands = prefix.commands;
            observed.input_bytes = prefix.input_bytes;
            observed.hash = prefix.hash;
            if observed.hash != hash {
                return Err("staged program input hash differs".into());
            }
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
