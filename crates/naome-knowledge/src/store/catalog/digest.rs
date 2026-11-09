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
    pub(super) fn new(
        root: [u8; 32],
        count: usize,
        peer: Option<&str>,
    ) -> Result<Self, crate::Error> {
        let width = u32::try_from(count).map_err(|_| crate::InputFault::CatalogDigestCountWidth)?;
        if count == 0 {
            return Err(crate::InputFault::CatalogDigestMembership.into());
        }
        let mut hash = Sha256::new();
        hash.update(b"naome:knowledge:catalog-commit:v1\0");
        hash.update(root);
        hash.update(width.to_be_bytes());
        hash.update([u8::from(peer.is_some())]);
        if let Some(peer) = peer {
            let parsed: libp2p::PeerId = peer
                .parse()
                .map_err(|_| crate::InputFault::CatalogDigestPeerSyntax)?;
            if peer.len() > 128 || parsed.to_string() != peer {
                return Err(crate::InputFault::CatalogDigestPeerEncoding.into());
            }
            hash.update((peer.len() as u32).to_be_bytes());
            hash.update(peer.as_bytes());
        }
        Ok(Self {
            hash,
            root,
            remaining: count,
            previous: None,
            found_root: false,
        })
    }

    pub(super) fn push(
        &mut self,
        member: &Member,
        question: Option<&[u8]>,
    ) -> Result<(), crate::Error> {
        if self.remaining == 0 || self.previous.is_some_and(|id| id >= member.id) {
            return Err(crate::InputFault::CatalogDigestOrder.into());
        }
        if member.length == 0
            || member.length > naome_proof::ARTIFACT_PAYLOAD_MAX_BYTES
            || member.dependencies.len() > naome_proof::CERTIFICATE_MAX_STEPS
        {
            return Err(crate::InputFault::CatalogDigestMemberWidth.into());
        }
        if question.is_some_and(|bytes| {
            bytes.is_empty() || bytes.len() > naome_checker::question::QUESTION_BYTES
        }) {
            return Err(crate::InputFault::CatalogDigestQuestionWidth.into());
        }
        self.hash.update(member.id);
        let source = question.unwrap_or_default();
        self.hash.update((source.len() as u32).to_be_bytes());
        self.hash.update(source);
        for value in [member.statement, member.obligation] {
            self.hash.update([u8::from(value.is_some())]);
            if let Some(value) = value {
                self.hash.update(value);
            }
        }
        self.hash.update(member.compatibility);
        self.hash.update(
            u32::try_from(member.length)
                .map_err(|_| crate::InputFault::CatalogDigestPayloadWidth)?
                .to_be_bytes(),
        );
        self.hash.update(member.digest);
        self.hash.update(
            u32::try_from(member.dependencies.len())
                .map_err(|_| crate::InputFault::CatalogDigestDependencyWidth)?
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
            return Err(crate::InputFault::CatalogDigestRootCount.into());
        }
        Ok(self.hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_question_does_not_change_the_commitment() {
        let id = [1; 32];
        let member = Member {
            id,
            statement: None,
            obligation: None,
            compatibility: [2; 32],
            length: 1,
            digest: [3; 32],
            dependencies: Vec::new(),
        };
        let mut retried = CommitDigest::new(id, 1, None).unwrap();
        assert_eq!(
            retried.push(&member, Some(&[])),
            Err(crate::InputFault::CatalogDigestQuestionWidth.into())
        );
        retried.push(&member, Some(&[4])).unwrap();
        let mut fresh = CommitDigest::new(id, 1, None).unwrap();
        fresh.push(&member, Some(&[4])).unwrap();
        assert_eq!(retried.finish().unwrap(), fresh.finish().unwrap());
    }
}
