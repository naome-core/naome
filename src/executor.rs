use crate::{
    profile::{Document, Kind, verify_attestation},
    store::{Archive, Snapshot},
    wire::Id,
};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub attempt: String,
    pub actor: String,
    pub subject: String,
    pub operation: String,
    pub decision: Id,
    pub authority: Id,
    pub signature: Id,
    pub costs: BTreeMap<String, u64>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum Dispatch {
    Reserved,
    AlreadyRecorded {
        state: String,
        witness: Option<String>,
    },
}
impl Archive {
    /// An operator configures the shared pool once. A retry cannot replenish capacity.
    pub fn resource(&self, unit: &str, capacity: u64) -> Result<()> {
        ensure!(!unit.is_empty(), "empty unit");
        self.db.execute(
            "INSERT INTO limits VALUES(?,?)",
            params![unit, i64::try_from(capacity)?],
        )?;
        Ok(())
    }
    /// Commit this reservation before invoking the facility. A restart leaves an ambiguous reservation closed to redispatch.
    pub fn reserve(
        &mut self,
        s: &Snapshot,
        r: &Request,
        keys: &BTreeSet<String>,
        now: u64,
    ) -> Result<Dispatch> {
        ensure!(
            !r.attempt.is_empty() && !r.costs.is_empty(),
            "empty attempt or resource request"
        );
        let bytes = serde_json::to_vec(r)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(Vec<u8>, String, Option<String>)> = tx
            .query_row(
                "SELECT request,state,witness FROM attempts WHERE id=?",
                [&r.attempt],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if let Some((old, state, witness)) = old {
            ensure!(
                old == bytes,
                "attempt identifier reused for a different request"
            );
            return Ok(Dispatch::AlreadyRecorded { state, witness });
        }
        // An immediate transaction excludes concurrent quota changes and local revocations until commit.
        let read = |id: Id| -> Result<Document> {
            ensure!(s.objects.contains(&id), "authority input outside snapshot");
            let (b, acl): (Vec<u8>, String) = tx.query_row(
                "SELECT data,access FROM objects WHERE id=?",
                [id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            id.verify(&b)?;
            ensure!(
                acl == Id::blob(crate::profile::PUBLIC).to_string()
                    && s.objects.contains(&Id::blob(crate::profile::PUBLIC))
                    && s.objects.contains(&Id::blob(crate::profile::PROFILE)),
                "operator authority requires public verifiable records"
            );
            Document::decode(&crate::wire::Record::decode(
                &b,
                id.format().context("expected record")?,
            )?)
        };
        let a = read(r.authority)?;
        ensure!(
            a.kind == Kind::Authority
                && a.subject == r.subject
                && a.field::<String>("actor")? == r.actor
                && a.field::<String>("operation")? == r.operation,
            "authority scope mismatch"
        );
        verify_attestation(
            &read(r.signature)?,
            r.authority,
            &a.scope,
            "executor",
            "research-policy-1",
            keys,
        )?;
        let [begin, end]: [u64; 2] = a.field("valid")?;
        ensure!(
            begin <= now && now <= end,
            "authority outside validity period"
        );
        let d = read(r.decision)?;
        ensure!(
            d.kind == Kind::Decision
                && d.subject == r.subject
                && d.scope == a.scope
                && d.one("authority")? == r.authority
                && d.field::<String>("attempt")? == r.attempt
                && d.field::<String>("operation")? == r.operation,
            "decision mismatch"
        );
        let max: BTreeMap<String, u64> = a.field("ceilings")?;
        let mut spent = BTreeMap::<String, u64>::new();
        {
            let mut stmt = tx.prepare("SELECT request FROM attempts")?;
            for row in stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
                let prior: Request = serde_json::from_slice(&row?)?;
                if prior.authority == r.authority {
                    for (unit, cost) in prior.costs {
                        let n = spent.entry(unit).or_default();
                        *n = n.checked_add(cost).context("quota overflow")?;
                    }
                }
            }
        }
        let revoked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocations WHERE authority=?)",
            [r.authority.to_string()],
            |row| row.get(0),
        )?;
        ensure!(!revoked, "authority revoked");
        for (unit, &cost) in &r.costs {
            let total = spent
                .get(unit)
                .copied()
                .unwrap_or(0)
                .checked_add(cost)
                .context("quota overflow")?;
            ensure!(
                cost > 0 && max.get(unit).is_some_and(|cap| total <= *cap),
                "authority quota exceeded"
            );
            let cost = i64::try_from(cost)?;
            ensure!(
                tx.execute(
                    "UPDATE limits SET capacity=capacity-? WHERE resource=? AND capacity>=?",
                    params![cost, unit, cost]
                )? == 1,
                "shared resource unavailable"
            );
        }
        tx.execute(
            "INSERT INTO attempts VALUES(?,?,'execution-unknown',NULL)",
            params![r.attempt, bytes],
        )?;
        tx.commit()?;
        Ok(Dispatch::Reserved)
    }
    pub fn revoke(&self, authority: Id) -> Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO revocations VALUES(?)",
            [authority.to_string()],
        )?;
        Ok(())
    }
    pub fn reconcile_attempt(
        &self,
        s: &Snapshot,
        attempt: &str,
        occurrence: Id,
        signature: Id,
        keys: &BTreeSet<String>,
    ) -> Result<()> {
        let input: Vec<u8> =
            self.db
                .query_row("SELECT request FROM attempts WHERE id=?", [attempt], |r| {
                    r.get(0)
                })?;
        let req: Request = serde_json::from_slice(&input)?;
        let d = self.read(s, occurrence, "read")?;
        ensure!(
            d.kind == Kind::Occurrence
                && d.subject == req.subject
                && d.field::<String>("attempt")? == attempt
                && d.one("decision")? == req.decision,
            "wrong readback"
        );
        verify_attestation(
            &self.read(s, signature, "read")?,
            occurrence,
            &d.scope,
            "readback",
            "research-policy-1",
            keys,
        )?;
        let state: String = d.field("execution")?;
        ensure!(
            ["observed", "not-executed"].contains(&state.as_str()),
            "invalid readback"
        );
        let updated = self.db.execute(
            "UPDATE attempts SET state=?,witness=? WHERE id=? AND (witness IS NULL OR witness=?)",
            params![
                state,
                occurrence.to_string(),
                attempt,
                occurrence.to_string()
            ],
        )?;
        if updated == 0 {
            bail!("conflicting readbacks require investigation")
        }
        Ok(())
    }
}
