use crate::{
    profile::{Document, Kind, link},
    store::{Archive, Snapshot},
    wire::{Format, Id, MAX_BYTES},
};
use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

impl Archive {
    /// Stream an exact payload into an ordered chunk descriptor. A failed import rolls back every new object.
    pub fn capture(
        &self,
        mut source: impl Read,
        media: &str,
        chunk_size: usize,
        access: Id,
        f: Format,
    ) -> Result<Id> {
        ensure!(
            !media.is_empty() && (1..=MAX_BYTES).contains(&chunk_size),
            "invalid representation or chunk size"
        );
        let tx = self.db.unchecked_transaction()?;
        let mut buf = vec![0; chunk_size];
        let mut digest = Sha256::new();
        let mut offset = 0u64;
        let mut chunks = Vec::new();
        loop {
            let mut count = 0;
            while count < buf.len() {
                match source.read(&mut buf[count..]) {
                    Ok(0) => break,
                    Ok(n) => count += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
            if count == 0 {
                break;
            }
            ensure!(
                chunks.len() < 16_384,
                "chunk manifest limit; use larger chunks"
            );
            digest.update(&buf[..count]);
            let id = self.blob(&buf[..count], access)?;
            let mut e = link("chunk", id);
            e.qualifier = offset.to_string();
            chunks.push(e);
            offset = offset
                .checked_add(count as u64)
                .context("payload length overflow")?;
            if count < chunk_size {
                break;
            }
        }
        let d = Document::new(
            Kind::Descriptor,
            media,
            "ordered-chunks-1",
            json!({"algorithm":"SHA-256","sha256":hex::encode(digest.finalize()),"length":offset,"media":media}),
            chunks,
        )?;
        let id = self.document(&d, f, access)?;
        tx.commit()?;
        Ok(id)
    }
    /// Write into an unpublished staging destination. Success certifies the complete sequence.
    pub fn materialize(
        &self,
        s: &Snapshot,
        id: Id,
        purpose: &str,
        budget: u64,
        mut output: impl Write,
    ) -> Result<u64> {
        let d = self.read(s, id, purpose)?;
        ensure!(
            d.kind == Kind::Descriptor
                && d.scope == "ordered-chunks-1"
                && d.field::<String>("algorithm")? == "SHA-256"
                && d.field::<String>("media")? == d.subject,
            "unknown descriptor"
        );
        let length: u64 = d.field("length")?;
        ensure!(length <= budget, "payload budget exhausted");
        let mut digest = Sha256::new();
        let mut offset = 0u64;
        for e in d.inputs.iter() {
            ensure!(
                e.role == "chunk"
                    && e.qualifier == offset.to_string()
                    && e.target.format().is_none(),
                "invalid position or chunk reference"
            );
            let b = self.resolve(s, e.target, purpose)?;
            ensure!(!b.is_empty(), "empty chunk");
            offset = offset
                .checked_add(b.len() as u64)
                .context("payload length overflow")?;
            ensure!(offset <= length, "payload larger than declared length");
            digest.update(&b);
            output.write_all(&b)?;
        }
        ensure!(
            offset == length && hex::encode(digest.finalize()) == d.field::<String>("sha256")?,
            "payload digest or length disagrees"
        );
        Ok(offset)
    }
}
