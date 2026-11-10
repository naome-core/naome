//! Canonical bounded program records, kept outside checked membership until
//! Graph publishes a complete mathematically checked manifest transaction.
use super::*;
use naome_proof::program::Progress;
use naome_proof::program::{Chunk, ChunkReader, Manifest, Prefix, encode_command, stream_hash};
const BLOCK_RECORDS: usize = 16;
// Encoded scopes may expand into vectors of actions and premises. Account for
// decoded commands, re-encoding, prefix preparation and vector growth.
const CHUNK_BUFFER_BYTES: usize = 4 * naome_proof::program::CHUNK_BYTES;

fn chunk_work_bytes(bytes: usize, records: usize) -> Result<usize, crate::Error> {
    bytes
        .checked_mul(4 * std::mem::size_of::<naome_proof::program::ScopedAction>() + 32)
        .and_then(|n| {
            records
                .checked_mul(3 * std::mem::size_of::<naome_proof::program::Command>() + 128)
                .and_then(|records| n.checked_add(records))
        })
        .ok_or_else(|| crate::InputFault::CatalogProofMemoryOverflow.into())
}

fn stored_chunk_work(length: i64) -> Result<usize, crate::Error> {
    let length =
        usize::try_from(length).map_err(|_| crate::InputFault::CatalogProgramInputOrdering)?;
    if length == 0 || length > naome_proof::program::CHUNK_BYTES + 74 {
        return Err(crate::InputFault::CatalogProgramInputOrdering.into());
    }
    chunk_work_bytes(length, BLOCK_RECORDS)
}
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
    i64::try_from(value)
        .map_err(|_| crate::Error::from(crate::InputFault::CatalogProgramAddressExhausted))
}
fn positive(value: i64) -> Result<u64, crate::Error> {
    u64::try_from(value)
        .map_err(|_| crate::Error::from(crate::InputFault::CatalogProgramAddressNegative))
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
    let row:Option<Row>=connection.query_row("SELECT substr(manifest,1,2049),received,input_bytes,substr(hash,1,33),substr(remaining,1,33) FROM programs WHERE id=?1",[manifest.artifact_id().as_bytes().as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(sql_error)?;
    let Some((bytes, commands, input_bytes, hash, remaining)) = row else {
        return Err(crate::InputFault::CatalogProgramStagingMissing.into());
    };
    if bytes != manifest_bytes(manifest)? {
        return Err(crate::InputFault::CatalogProgramManifestChanged.into());
    }
    let value = Progress {
        commands: positive(commands)?,
        input_bytes: positive(input_bytes)?,
        hash: key(hash)?,
        remaining: key(remaining)?,
    };
    if value.commands > manifest.commands || value.input_bytes > manifest.input_bytes {
        return Err(crate::InputFault::CatalogProgramPrefixExceeds.into());
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
        let result = (|| {
            self.require_validated_version(&transaction)?;
            transaction
                .execute(
                    "INSERT OR IGNORE INTO programs VALUES(?1,?2,0,0,zeroblob(32),?3)",
                    params![
                        manifest.artifact_id().as_bytes().as_slice(),
                        bytes,
                        manifest.stream_root.as_slice()
                    ],
                )
                .map_err(sql_error)?;
            progress(&transaction, manifest)
        })();
        finish_program(transaction, result)
    }
    pub(in crate::store) fn program_manifest(
        &self,
        id: ArtifactId,
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
                if manifest.artifact_id() != id {
                    return Err(crate::InputFault::CatalogProgramAddressMismatch.into());
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
        let _buffer = crate::resources::MemoryLease::acquire(CHUNK_BUFFER_BYTES)?;
        let encoded_length = chunk.canonical_bytes()?.len();
        let _memory = crate::resources::MemoryLease::acquire(chunk_work_bytes(
            encoded_length,
            chunk.records.len(),
        )?)?;
        self.replay_summary.set(None);
        let transaction = begin(&self.connection, TransactionBehavior::Immediate)?;
        let result = (|| {
            self.require_validated_version(&transaction)?;
            let before = progress(&transaction, manifest)?;
            let (value, prepared) = before.prepare_append(manifest, chunk)?;
            let mut input_before = before.input_bytes;
            for (block_number, commands) in chunk.records.chunks(BLOCK_RECORDS).enumerate() {
                let first = block_number * BLOCK_RECORDS;
                let end = first + commands.len();
                let position = prepared[first].position;
                let previous = if first == 0 {
                    before.hash
                } else {
                    prepared[first - 1].hash
                };
                let next = if end == prepared.len() {
                    chunk.next
                } else {
                    prepared[end].suffix
                };
                let block = Chunk {
                    start: position,
                    previous,
                    next,
                    records: commands.to_vec(),
                };
                let bytes = block.canonical_bytes()?;
                let digest = chunk_digest(manifest.artifact_id(), position, input_before, &bytes);
                transaction
                    .execute(
                        "INSERT INTO program_input VALUES(?1,?2,?3,?4,?5)",
                        params![
                            manifest.artifact_id().as_bytes().as_slice(),
                            ordinal(position)?,
                            ordinal(input_before)?,
                            bytes,
                            digest.as_slice()
                        ],
                    )
                    .map_err(sql_error)?;
                #[cfg(test)]
                if std::env::var_os("NAOME_TEST_EXIT_PROGRAM_APPEND").is_some() {
                    std::process::exit(77);
                }
                for record in &prepared[first..end] {
                    input_before = input_before
                        .checked_add(record.bytes.len() as u64)
                        .ok_or(crate::InputFault::CatalogProgramAddressExhausted)?;
                }
            }
            if input_before != value.input_bytes {
                return Err(crate::InputFault::CatalogProgramPrefixSummary.into());
            }
            transaction.execute(
                "UPDATE programs SET received=?2,input_bytes=?3,hash=?4,remaining=?5 WHERE id=?1",
                params![manifest.artifact_id().as_bytes().as_slice(), ordinal(value.commands)?, ordinal(value.input_bytes)?, value.hash.as_slice(), value.remaining.as_slice()],
            ).map_err(sql_error)?;
            Ok(value)
        })();
        finish_program(transaction, result)
    }
    pub(in crate::store) fn program_chunk(
        &self,
        manifest: &Manifest,
        start: u64,
        records: usize,
        maximum: usize,
    ) -> Result<Chunk, crate::Error> {
        let _buffer = crate::resources::MemoryLease::acquire(CHUNK_BUFFER_BYTES)?;
        self.require_validated_version(&self.connection)?;
        let value = progress(&self.connection, manifest)?;
        if start > value.commands {
            return Err(crate::InputFault::CatalogProgramCursorBeyondPrefix.into());
        }
        if start == value.commands {
            return ChunkReader::new(start, value.hash, records, maximum)?
                .finish(value.commands, value.remaining)
                .map_err(Into::into);
        }
        let first: Option<i64> = self
            .connection
            .query_row(
                "SELECT max(position) FROM program_input WHERE id=?1 AND position<=?2",
                params![
                    manifest.artifact_id().as_bytes().as_slice(),
                    ordinal(start)?
                ],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let first = first.ok_or(crate::InputFault::CatalogProgramInputOrdering)?;
        let mut statement = self.connection.prepare_cached(
            "SELECT position,input_before,length(chunk),substr(chunk,1,32843),substr(digest,1,33) FROM program_input WHERE id=?1 AND position>=?2 ORDER BY position"
        ).map_err(sql_error)?;
        let mut rows = statement
            .query(params![manifest.artifact_id().as_bytes().as_slice(), first])
            .map_err(sql_error)?;
        let mut reader: Option<ChunkReader> = None;
        let mut expected_position = positive(first)?;
        let mut previous_end: Option<Progress> = None;
        let mut block_leases = Vec::new();
        while let Some(row) = rows.next().map_err(sql_error)? {
            let position = positive(row.get(0).map_err(sql_error)?)?;
            let input_before = positive(row.get(1).map_err(sql_error)?)?;
            let length: i64 = row.get(2).map_err(sql_error)?;
            block_leases.push(crate::resources::MemoryLease::acquire(stored_chunk_work(
                length,
            )?)?);
            let bytes: Vec<u8> = row.get(3).map_err(sql_error)?;
            let digest = key(row.get(4).map_err(sql_error)?)?;
            let chunk = decode_chunk(
                manifest.artifact_id(),
                position,
                input_before,
                &bytes,
                digest,
            )?;
            if position != expected_position || chunk.start != position {
                return Err(crate::InputFault::CatalogProgramInputOrdering.into());
            }
            let mut suffix = vec![[0; 32]; chunk.records.len() + 1];
            *suffix.last_mut().expect("nonempty suffix") = chunk.next;
            let encoded = chunk
                .records
                .iter()
                .map(encode_command)
                .collect::<Result<Vec<_>, _>>()?;
            for i in (0..encoded.len()).rev() {
                suffix[i] = stream_hash(&encoded[i], suffix[i + 1]);
            }
            let before = Progress {
                commands: position,
                input_bytes: input_before,
                hash: chunk.previous,
                remaining: suffix[0],
            };
            if previous_end
                .as_ref()
                .is_some_and(|previous| previous != &before)
            {
                return Err(crate::InputFault::CatalogProgramPrefixSummary.into());
            }
            let (end, _) = before.prepare_append(manifest, &chunk)?;
            if end.commands > value.commands {
                return Err(crate::InputFault::CatalogProgramPrefixExceeds.into());
            }
            let mut prefix = Prefix {
                commands: position,
                input_bytes: input_before,
                hash: chunk.previous,
            };
            for (i, bytes) in encoded.iter().enumerate() {
                let at = prefix.commands;
                if at == start {
                    reader = Some(ChunkReader::new(start, prefix.hash, records, maximum)?);
                }
                prefix.append(bytes)?;
                if at < start {
                    continue;
                }
                let current = reader
                    .as_mut()
                    .ok_or(crate::InputFault::CatalogProgramInputOrdering)?;
                if !current.push(at, bytes, prefix.hash)? {
                    return reader
                        .expect("initialized reader")
                        .finish(value.commands, suffix[i])
                        .map_err(Into::into);
                }
                if current.end() - start == records as u64 || current.end() == value.commands {
                    return reader
                        .expect("initialized reader")
                        .finish(value.commands, suffix[i + 1])
                        .map_err(Into::into);
                }
            }
            expected_position = end.commands;
            previous_end = Some(end);
        }
        Err(crate::InputFault::CatalogProgramInputOrdering.into())
    }
}

fn finish_program(
    transaction: Transaction<'_>,
    result: Result<Progress, crate::Error>,
) -> Result<Progress, crate::Error> {
    let value = match result {
        Ok(value) => value,
        Err(error) => {
            if !transaction.is_autocommit() {
                transaction.rollback().map_err(|rollback| {
                    crate::Error::UncertainDurability(crate::DurabilityFailure::sqlite(
                        crate::DurabilityCode::RollbackUnconfirmed,
                        &rollback,
                    ))
                })?;
            }
            return Err(error);
        }
    };
    transaction.commit().map_err(|error| {
        crate::Error::UncertainDurability(crate::DurabilityFailure::sqlite(
            crate::DurabilityCode::ProgramCommit,
            &error,
        ))
    })?;
    Ok(value)
}

fn chunk_digest(id: ArtifactId, position: u64, input_before: u64, bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"naome:program-storage-chunk\0");
    hash.update(id.as_bytes());
    hash.update(position.to_be_bytes());
    hash.update(input_before.to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

fn decode_chunk(
    id: ArtifactId,
    position: u64,
    input_before: u64,
    bytes: &[u8],
    digest: [u8; 32],
) -> Result<Chunk, crate::Error> {
    if chunk_digest(id, position, input_before, bytes) != digest {
        return Err(crate::InputFault::CatalogProgramInputHash.into());
    }
    let chunk = Chunk::from_canonical_bytes_with_record_limit(bytes, BLOCK_RECORDS)?;
    if chunk.canonical_bytes()? != bytes {
        return Err(crate::InputFault::CatalogProgramInputOrdering.into());
    }
    Ok(chunk)
}

/// Validate every staged transition without restoring mathematical trust.
pub(super) fn validate_staging(connection: &Connection) -> Result<(), crate::Error> {
    let mut programs = connection
        .prepare("SELECT substr(id,1,33),substr(manifest,1,2049) FROM programs ORDER BY id")
        .map_err(sql_error)?;
    let mut rows = programs.query([]).map_err(sql_error)?;
    while let Some(row) = rows.next().map_err(sql_error)? {
        let id = key(row.get(0).map_err(sql_error)?)?;
        let manifest = decode_manifest(&row.get::<_, Vec<u8>>(1).map_err(sql_error)?)?;
        if manifest.artifact_id().as_bytes() != &id {
            return Err(crate::InputFault::CatalogProgramIdentityMismatch.into());
        }
        let expected = progress(connection, &manifest)?;
        let mut observed = Progress {
            commands: 0,
            input_bytes: 0,
            hash: [0; 32],
            remaining: manifest.stream_root,
        };
        let _buffer = crate::resources::MemoryLease::acquire(CHUNK_BUFFER_BYTES)?;
        let mut chunks = connection.prepare_cached("SELECT position,input_before,length(chunk),substr(chunk,1,32843),substr(digest,1,33) FROM program_input WHERE id=?1 ORDER BY position").map_err(sql_error)?;
        let mut input = chunks.query([id.as_slice()]).map_err(sql_error)?;
        while let Some(row) = input.next().map_err(sql_error)? {
            let position = positive(row.get(0).map_err(sql_error)?)?;
            let input_before = positive(row.get(1).map_err(sql_error)?)?;
            let length: i64 = row.get(2).map_err(sql_error)?;
            let _memory = crate::resources::MemoryLease::acquire(stored_chunk_work(length)?)?;
            let bytes: Vec<u8> = row.get(3).map_err(sql_error)?;
            let digest = key(row.get(4).map_err(sql_error)?)?;
            let chunk = decode_chunk(
                manifest.artifact_id(),
                position,
                input_before,
                &bytes,
                digest,
            )?;
            if position != observed.commands
                || input_before != observed.input_bytes
                || chunk.start != position
            {
                return Err(crate::InputFault::CatalogProgramInputOrdering.into());
            }
            observed = observed.prepare_append(&manifest, &chunk)?.0;
        }
        if observed != expected {
            return Err(crate::InputFault::CatalogProgramPrefixSummary.into());
        }
        if observed.commands == manifest.commands {
            observed.require_complete(&manifest)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod outcome_tests;
