//! Complete inventories explicitly released to a configured replication group.
use super::{Archive, Snapshot, insert};
use crate::{
    profile::{Document, Kind, PROFILE, verify_attestation},
    wire::{Id, Record},
};
use anyhow::{Result, ensure};
use rusqlite::{Transaction, TransactionBehavior};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RELEASES: usize = 64;
pub const MAX_MEMBERS: usize = 512;
pub const MAX_MEMBER_BYTES: usize = 1024 * 1024;
pub const MAX_RELEASE_BYTES: usize = 16 * 1024 * 1024;

fn check_manifest(head: Id, snapshot: &Snapshot) -> Result<()> {
    ensure!(
        snapshot.version == 1
            && !snapshot.source.is_empty()
            && snapshot.source.len() <= 256
            && snapshot.parents.len() <= MAX_RELEASES
            && (1..=MAX_MEMBERS).contains(&snapshot.objects.len())
            && snapshot.id()? == head,
        "invalid or oversized release manifest"
    );
    Ok(())
}

/// Exact object bytes. Records carry their own access reference in the envelope.
#[derive(Debug)]
pub struct Member {
    pub id: Id,
    pub blob_access: Option<Id>,
    pub bytes: Vec<u8>,
}

/// Holds checked bytes until the complete inventory can be admitted atomically.
pub struct Replica {
    head: Id,
    snapshot: Snapshot,
    missing: BTreeSet<Id>,
    members: BTreeMap<Id, (Id, Vec<u8>)>,
    bytes: usize,
}

impl Replica {
    pub fn new(head: Id, snapshot: Snapshot) -> Result<Self> {
        check_manifest(head, &snapshot)?;
        Ok(Self {
            head,
            missing: snapshot.objects.clone(),
            snapshot,
            members: BTreeMap::new(),
            bytes: 0,
        })
    }

    pub fn next_member(&self) -> Option<Id> {
        self.missing.first().copied()
    }

    pub fn accept(&mut self, expected: Id, member: Member) -> Result<()> {
        ensure!(
            self.missing.contains(&expected) && member.id == expected,
            "unsolicited object"
        );
        let bytes = member.bytes;
        ensure!(
            bytes.len() <= MAX_MEMBER_BYTES,
            "object exceeds network limit"
        );
        ensure!(
            self.bytes + bytes.len() <= MAX_RELEASE_BYTES,
            "release exceeds network limit"
        );
        expected.verify(&bytes)?;
        let access = match (expected.format(), member.blob_access) {
            (Some(format), None) => Record::decode(&bytes, format)?.access,
            (None, Some(access)) => access,
            _ => anyhow::bail!("object class and access metadata disagree"),
        };
        ensure!(
            access.format().is_none() && self.snapshot.objects.contains(&access),
            "access descriptor outside release"
        );
        self.bytes += bytes.len();
        self.members.insert(expected, (access, bytes));
        self.missing.remove(&expected);
        Ok(())
    }

    pub fn commit(self, archive: &Archive) -> Result<Id> {
        ensure!(self.missing.is_empty(), "incomplete release");
        let tx = Transaction::new_unchecked(&archive.db, TransactionBehavior::Immediate)?;
        for (id, (access, bytes)) in self.members {
            insert(&tx, id, &bytes, access)?;
        }
        archive.register_release(self.head, &self.snapshot)?;
        tx.commit()?;
        Ok(self.head)
    }
}

impl Archive {
    fn head_ids(&self, sql: &str) -> Result<BTreeSet<Id>> {
        self.db
            .prepare(sql)?
            .query_map([], |r| r.get::<_, String>(0))?
            .map(|row| row?.parse())
            .collect()
    }

    pub fn releases(&self) -> Result<BTreeSet<Id>> {
        self.head_ids("SELECT head FROM available_releases")
    }

    /// Includes historical memberships whose payloads have since been withdrawn.
    pub fn observed_releases(&self) -> Result<BTreeSet<Id>> {
        self.head_ids("SELECT head FROM releases")
    }

    pub fn released_manifest(&self, head: Id) -> Result<Snapshot> {
        let released: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM available_releases WHERE head=?)",
            [head.to_string()],
            |r| r.get(0),
        )?;
        ensure!(released, "inventory has not been released");
        self.head(head)
    }

    pub fn released_member(&self, head: Id, id: Id) -> Result<Member> {
        let tx = self.db.unchecked_transaction()?;
        let s = self.released_manifest(head)?;
        ensure!(
            self.size(id)? <= MAX_MEMBER_BYTES,
            "object exceeds network limit"
        );
        let (bytes, access) =
            self.resolve_with(&s, id, |policy| crate::profile::allows(policy, "read"))?;
        if let Some(format) = id.format() {
            ensure!(
                Record::decode(&bytes, format)?.access == access,
                "stored access disagrees with record"
            );
        }
        tx.commit()?;
        Ok(Member {
            id,
            blob_access: id.format().is_none().then_some(access),
            bytes,
        })
    }

    pub fn release(&self, head: Id) -> Result<()> {
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        self.register_release(head, &self.head(head)?)?;
        tx.commit()?;
        Ok(())
    }

    // Called in the same write transaction as admission. The receiver resolves
    // every ACL against its own archive, including existing local tombstones.
    fn register_release(&self, head: Id, s: &Snapshot) -> Result<()> {
        check_manifest(head, s)?;
        let existing = self.observed_releases()?;
        ensure!(
            existing.contains(&head) || existing.len() < MAX_RELEASES,
            "release catalog full"
        );
        let mut total = 0;
        for &id in &s.objects {
            let size = self.size(id)?;
            total += size;
            ensure!(
                size <= MAX_MEMBER_BYTES && total <= MAX_RELEASE_BYTES,
                "release exceeds network limit"
            );
            let bytes = self.resolve(s, id, "read")?;
            if let Some(format) = id.format() {
                let record = Record::decode(&bytes, format)?;
                if record.profile == Id::blob(PROFILE) && record.kind == Kind::Attestation as u64 {
                    let d = Document::decode(&record)?;
                    // Integrity of the signing operation. A scientific evaluator
                    // independently decides whether this role/key is admissible.
                    verify_attestation(
                        &d,
                        d.one("signed-original")?,
                        &d.scope,
                        &d.field::<String>("role")?,
                        &d.field::<String>("context")?,
                        &[d.subject.clone()].into(),
                    )?;
                }
            }
        }
        self.save(s)?;
        self.db.execute(
            "INSERT OR IGNORE INTO releases(head) VALUES(?)",
            [head.to_string()],
        )?;
        Ok(())
    }
}

#[derive(Debug, serde::Serialize)]
pub struct ReplicaReview {
    pub review_horizon: Id,
    pub review_receipt: Id,
    pub extraction: crate::learning::Extraction,
}

impl Archive {
    /// Re-evaluate a local standing training request across its original
    /// inventory and the complete releases visible to this custodian.
    pub fn review_releases(
        &self,
        request: &crate::learning::TrainingRequest,
    ) -> Result<ReplicaReview> {
        use crate::{learning::LabelStanding, wire::Format};
        ensure!(
            request.standing == LabelStanding::Current,
            "replica review requires current standing"
        );
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let mut parents = self.observed_releases()?;
        parents.insert(request.label_head);
        let mut objects = BTreeSet::new();
        for &head in &parents {
            objects.extend(self.head(head)?.objects);
        }
        let horizon = self.save(&Snapshot {
            version: 1,
            source: "local replica review".into(),
            parents,
            objects,
        })?;
        let mut review = request.clone();
        review.label_head = horizon;
        let extraction = self.training_manifest(&review, Format::A)?;
        let mut links = vec![
            crate::profile::link("extraction", extraction.manifest),
            crate::profile::link("label-horizon", horizon),
        ];
        for (&label, reason) in &extraction.withheld {
            let mut edge = crate::profile::link("withheld-label", label);
            edge.qualifier = reason.clone();
            links.push(edge);
        }
        let audit = Document::new(
            Kind::Manifest,
            "local training review",
            "replica-review-1",
            serde_json::json!({"request":request}),
            links,
        )?;
        let review_receipt = self.document(&audit, Format::A, Id::blob(crate::profile::PUBLIC))?;
        tx.commit()?;
        Ok(ReplicaReview {
            review_horizon: horizon,
            review_receipt,
            extraction,
        })
    }
}
