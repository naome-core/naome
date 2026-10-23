//! Durable untrusted local proof backlog. FIFO pages have no population or
//! lifetime ceiling; only complete checking in Graph can publish a proof.
use super::*;
use crate::{
    checkpoint::{Checkpoint, Update},
    object::BinaryProof,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u8,
    next: u64,
    cursor: Option<String>,
}
pub(super) struct PendingStore {
    checkpoint: Checkpoint,
    header: Header,
}
impl PendingStore {
    pub(super) fn open(directory: &Path) -> Result<Self, String> {
        let root = crate::jobs::research_directory(directory)?;
        let path = root.join("proof-backlog.sqlite3");
        let marker = root.join("proof-backlog.initialized");
        let established = crate::jobs::marker_valid(&marker, b"naome:proof-backlog:v1\n")?;
        let checkpoint = if std::fs::symlink_metadata(&path).is_ok() {
            Checkpoint::open(&path, "naome:proof-backlog:v1")?
        } else {
            if established {
                return Err("proof backlog is missing; refusing to discard retained work".into());
            }
            Checkpoint::create(
                &path,
                "naome:proof-backlog:v1",
                &Header {
                    version: 1,
                    next: 1,
                    cursor: None,
                },
                vec![],
            )?
        };
        checkpoint.require_kinds(&["pending", "proof", "edge"])?;
        let header: Header = checkpoint.header()?;
        if header.version != 1 || header.next == 0 {
            return Err("proof backlog version or sequence differs".into());
        }
        let mut after = None;
        let mut count = 0usize;
        let mut edges = 0usize;
        loop {
            let page = checkpoint.page(
                "pending",
                after.as_deref(),
                crate::resources::limits().pending_page,
                crate::resources::limits().active_job_bytes,
            )?;
            if page.is_empty() {
                break;
            }
            for (sequence, bytes) in page {
                after = Some(sequence.clone());
                if sequence.len() != 20
                    || sequence
                        .parse::<u64>()
                        .map_or(true, |n| n == 0 || n >= header.next)
                {
                    return Err("proof backlog FIFO sequence differs".into());
                }
                let proof = decode(&bytes)?;
                let id = crate::hex(proof.id.as_bytes());
                if checkpoint.get::<String>("proof", &id, 128)?.as_deref()
                    != Some(sequence.as_str())
                {
                    return Err("proof backlog identity index differs".into());
                }
                for dependency in &proof.dependencies {
                    if checkpoint.get::<bool>(
                        "edge",
                        &format!("{id}{}", crate::hex(dependency.as_bytes())),
                        8,
                    )? != Some(true)
                    {
                        return Err("proof backlog dependency index differs".into());
                    }
                }
                count = count.checked_add(1).ok_or("proof backlog count overflow")?;
                edges = edges
                    .checked_add(proof.dependencies.len())
                    .ok_or("proof backlog edge overflow")?;
            }
        }
        if checkpoint.count("proof")? != count || checkpoint.count("edge")? != edges {
            return Err("proof backlog index cardinality differs".into());
        }
        if !established {
            crate::jobs::write_marker(&marker, b"naome:proof-backlog:v1\n")?;
        }
        Ok(Self { checkpoint, header })
    }
    pub(super) fn contains(&self, id: ProofId) -> Result<bool, String> {
        self.checkpoint
            .get::<String>("proof", &crate::hex(id.as_bytes()), 128)
            .map(|row| row.is_some())
    }
    pub(super) fn len(&self) -> Result<usize, String> {
        self.checkpoint.count("pending")
    }
    pub(super) fn insert(&mut self, candidate: &Candidate) -> Result<(), String> {
        crate::resources::require_disk_space(
            self.checkpoint.directory(),
            candidate.bytes.len() as u64,
        )?;
        let id = crate::hex(candidate.id.as_bytes());
        let starts = candidate
            .dependencies
            .iter()
            .map(|id| crate::hex(id.as_bytes()))
            .collect::<Vec<_>>();
        if self
            .checkpoint
            .has_path(&starts, &id, crate::resources::limits().request_timeout)?
        {
            return Err("dependency cycle".into());
        }
        let sequence = format!("{:020}", self.header.next);
        self.header.next = self
            .header
            .next
            .checked_add(1)
            .ok_or("proof backlog FIFO exhausted")?;
        let mut updates = vec![
            Update::put("proof", &id, &sequence)?,
            Update::Put {
                kind: "pending",
                key: sequence,
                payload: encode(&candidate.record())?,
            },
        ];
        for dependency in &starts {
            updates.push(Update::put("edge", format!("{id}{dependency}"), &true)?);
        }
        self.checkpoint.commit(&self.header, updates)
    }
    pub(super) fn remove(&mut self, id: ProofId) -> Result<(), String> {
        let id = crate::hex(id.as_bytes());
        let Some(sequence) = self.checkpoint.get::<String>("proof", &id, 128)? else {
            return Ok(());
        };
        let bytes = self
            .checkpoint
            .get_bytes(
                "pending",
                &sequence,
                crate::resources::limits().active_job_bytes,
            )?
            .ok_or("proof backlog payload is missing")?;
        let proof = decode(&bytes)?;
        let mut updates = vec![
            Update::Remove {
                kind: "pending",
                key: sequence,
            },
            Update::Remove {
                kind: "proof",
                key: id.clone(),
            },
        ];
        for dependency in &proof.dependencies {
            updates.push(Update::Remove {
                kind: "edge",
                key: format!("{id}{}", crate::hex(dependency.as_bytes())),
            });
        }
        self.checkpoint.commit(&self.header, updates)
    }
    pub(super) fn next_page(&mut self) -> Result<Vec<BinaryProof>, String> {
        let mut page = self.checkpoint.page(
            "pending",
            self.header.cursor.as_deref(),
            crate::resources::limits().pending_page,
            crate::resources::limits().closure_bytes,
        )?;
        if page.is_empty() {
            page = self.checkpoint.page(
                "pending",
                None,
                crate::resources::limits().pending_page,
                crate::resources::limits().closure_bytes,
            )?;
        }
        let mut result = Vec::new();
        for (sequence, bytes) in page {
            self.header.cursor = Some(sequence);
            result.push(decode(&bytes)?);
        }
        if !result.is_empty() {
            self.checkpoint.commit(&self.header, vec![])?;
        }
        Ok(result)
    }
    pub(super) fn ids(&self, after: Option<&str>, limit: usize) -> Result<Vec<ProofId>, String> {
        self.checkpoint
            .page(
                "proof",
                after,
                limit.min(crate::resources::limits().id_page),
                crate::resources::limits().closure_bytes,
            )?
            .into_iter()
            .map(|(id, _)| crate::object::id_bytes(&id).map(ProofId::from_bytes))
            .collect()
    }
}
fn encode(proof: &BinaryProof) -> Result<Vec<u8>, String> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(proof.id.as_bytes());
    bytes.extend_from_slice(proof.statement.as_bytes());
    bytes.extend_from_slice(
        &u32::try_from(proof.dependencies.len())
            .map_err(|_| "proof dependency width")?
            .to_be_bytes(),
    );
    for id in &proof.dependencies {
        bytes.extend_from_slice(id.as_bytes());
    }
    bytes.extend_from_slice(
        &u32::try_from(proof.bytes.len())
            .map_err(|_| "proof payload width")?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&proof.bytes);
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> Result<BinaryProof, String> {
    let malformed = || "malformed proof backlog binary row".to_owned();
    if bytes.len() < 73 || bytes[0] != 1 {
        return Err(malformed());
    }
    let id = ProofId::from_bytes(bytes[1..33].try_into().map_err(|_| malformed())?);
    let statement =
        naome_proof::StatementId::from_bytes(bytes[33..65].try_into().map_err(|_| malformed())?);
    let count = u32::from_be_bytes(bytes[65..69].try_into().map_err(|_| malformed())?) as usize;
    if count > naome_proof::CERTIFICATE_MAX_STEPS {
        return Err(malformed());
    }
    let end = 69usize
        .checked_add(count.checked_mul(32).ok_or_else(malformed)?)
        .ok_or_else(malformed)?;
    let dependencies = bytes
        .get(69..end)
        .ok_or_else(malformed)?
        .chunks_exact(32)
        .map(|id| ProofId::from_bytes(id.try_into().expect("fixed chunk")))
        .collect::<BTreeSet<_>>();
    let length = u32::from_be_bytes(
        bytes
            .get(end..end + 4)
            .ok_or_else(malformed)?
            .try_into()
            .map_err(|_| malformed())?,
    ) as usize;
    let payload = bytes.get(end + 4..).ok_or_else(malformed)?;
    if count != dependencies.len()
        || length != payload.len()
        || length > naome_proof::CERTIFICATE_MAX_BYTES
        || crate::object::content_id(statement, payload) != id
    {
        return Err(malformed());
    }
    Ok(BinaryProof {
        id,
        statement,
        dependencies,
        bytes: payload.into(),
        _memory: Some(crate::resources::MemoryLease::acquire(
            payload.len().checked_mul(4).ok_or_else(malformed)?,
        )?),
    })
}
