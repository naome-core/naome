//! Streaming commitment to the current catalog format, independent of admission.
use super::{Digest, Member, Sha256};

pub(super) struct CommitDigest {
    hash: Sha256,
    root: [u8; 32],
    remaining: usize,
    previous: Option<[u8; 32]>,
    found_root: bool,
}

impl CommitDigest {
    pub(super) fn new(root: [u8; 32], count: usize) -> Result<Self, crate::Error> {
        let width = u32::try_from(count).map_err(|_| "catalog commit count width")?;
        if count == 0 {
            return Err("invalid catalog commit membership".into());
        }
        let mut hash = Sha256::new();
        hash.update(b"naome:knowledge:catalog-commit:v1\0");
        hash.update(root);
        hash.update(width.to_be_bytes());
        Ok(Self {
            hash,
            root,
            remaining: count,
            previous: None,
            found_root: false,
        })
    }

    pub(super) fn push(&mut self, member: &Member) -> Result<(), crate::Error> {
        if self.remaining == 0 || self.previous.is_some_and(|id| id >= member.id) {
            return Err("catalog commit members are not uniquely sorted".into());
        }
        if member.length == 0
            || member.length > naome_proof::CERTIFICATE_MAX_BYTES
            || member.dependencies.len() > naome_proof::CERTIFICATE_MAX_STEPS
        {
            return Err("catalog commit member width differs".into());
        }
        self.hash.update(member.id);
        self.hash.update(member.statement);
        self.hash.update(member.compatibility);
        self.hash.update(
            u32::try_from(member.length)
                .map_err(|_| "catalog payload width")?
                .to_be_bytes(),
        );
        self.hash.update(member.digest);
        self.hash.update(
            u32::try_from(member.dependencies.len())
                .map_err(|_| "catalog dependency width")?
                .to_be_bytes(),
        );
        for dependency in &member.dependencies {
            self.hash.update(dependency);
        }
        self.previous = Some(member.id);
        self.found_root |= member.id == self.root;
        self.remaining -= 1;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<[u8; 32], crate::Error> {
        if self.remaining != 0 || !self.found_root {
            return Err("catalog commit root or member count differs".into());
        }
        Ok(self.hash.finalize().into())
    }
}
