use crate::{
    profile::{Document, Kind, PUBLIC, link},
    store::{Archive, Snapshot},
    wire::{Format, Id, Record},
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct Migration {
    pub mapping: Id,
    pub native_head: Id,
    pub exchange_head: Id,
    pub pairs: BTreeMap<Id, Id>,
    pub retained: BTreeSet<Id>,
}
fn manifest(store: &Archive, s: &Snapshot) -> Result<Id> {
    store.blob(&serde_json::to_vec(s)?, Id::blob(PUBLIC))
}
fn rewrite(mut r: Record, pairs: &BTreeMap<Id, Id>) -> Result<Record> {
    let doc = Document::decode(&r)?;
    for (e, l) in r.edges.iter_mut().zip(&doc.inputs) {
        // Detached attestations and historic inventories continue to name the original bytes.
        if doc.kind == Kind::Attestation && l.role == "signed-original" {
            continue;
        }
        if let Some(id) = pairs.get(&e.target) {
            e.target = *id
        }
    }
    Ok(r)
}
impl Archive {
    /// Retain source objects. Only the pinned research profile has a structural translation warrant.
    pub fn migrate(&self, s: &Snapshot, target: Format, issuer: &str) -> Result<Migration> {
        let tx = self.db.unchecked_transaction()?;
        let mut pending = BTreeMap::new();
        let mut retained = BTreeSet::new();
        let mut pairs = BTreeMap::new();
        for &id in &s.objects {
            let Some(f) = id.format() else { continue };
            if f == target {
                continue;
            }
            let Ok(b) = self.resolve(s, id, "read") else {
                retained.insert(id);
                continue;
            };
            let r = Record::decode(&b, f)?;
            if Document::decode(&r).is_err()
                || r.inputs().any(|x| self.resolve(s, x, "read").is_err())
            {
                retained.insert(id);
                continue;
            }
            pending.insert(id, r);
        }
        while !pending.is_empty() {
            let ready: Vec<_> = pending
                .iter()
                .filter(|(_, r)| r.edges.iter().all(|e| !pending.contains_key(&e.target)))
                .map(|(id, _)| *id)
                .collect();
            ensure!(!ready.is_empty(), "cyclic native migration");
            for id in ready {
                let r = pending.remove(&id).context("missing pending record")?;
                let native = self.record(&rewrite(r, &pairs)?, target)?;
                pairs.insert(id, native);
            }
        }
        let source_manifest = manifest(self, s)?;
        let native = Snapshot {
            version: 1,
            source: format!("{}-{:?}", s.source, target),
            parents: [s.id()?].into(),
            objects: s
                .objects
                .iter()
                .map(|i| pairs.get(i).copied().unwrap_or(*i))
                .collect(),
        };
        let native_head = self.save(&native)?;
        manifest(self, &native)?;
        let mut links = vec![
            link("source-inventory", source_manifest),
            link("target-inventory", native_head),
        ];
        for (old, new) in &pairs {
            links.push(link("source", *old));
            links.push(link("target", *new));
        }
        let fields = json!({
            "method": "research-native-1",
            "issuer": issuer,
            "format": target,
            "preserves": "typed fields, ordered roles and shared dependencies within the paired inventory",
            "retained": retained.len(),
            "source_kit": crate::kit::pin(match target{Format::A=>Format::B,Format::B=>Format::A}),
            "target_kit": crate::kit::pin(target),
        });
        let mapping = self.document(
            &Document::new(Kind::Mapping, issuer, "research-native-1", fields, links)?,
            target,
            Id::blob(PUBLIC),
        )?;
        let head = self.snapshot(&native.source, [s.id()?, native_head].into())?;
        self.verify_mapping(&head, mapping)?;
        tx.commit()?;
        Ok(Migration {
            mapping,
            native_head,
            exchange_head: head.id()?,
            pairs,
            retained,
        })
    }
    pub fn verify_mapping(&self, s: &Snapshot, id: Id) -> Result<BTreeMap<Id, Id>> {
        let d = self.read(s, id, "read")?;
        ensure!(
            d.kind == Kind::Mapping
                && d.scope == "research-native-1"
                && d.field::<String>("method")? == "research-native-1",
            "unsupported mapping"
        );
        let format: Format = d.field("format")?;
        ensure!(
            d.field::<String>("target_kit")? == crate::kit::pin(format)
                && d.field::<String>("source_kit")?
                    == crate::kit::pin(match format {
                        Format::A => Format::B,
                        Format::B => Format::A,
                    }),
            "unknown mapping kit"
        );
        let source: Snapshot =
            serde_json::from_slice(&self.resolve(s, d.one("source-inventory")?, "read")?)?;
        let target: Snapshot =
            serde_json::from_slice(&self.resolve(s, d.one("target-inventory")?, "read")?)?;
        let old = d.roles("source").collect::<Vec<_>>();
        let new = d.roles("target").collect::<Vec<_>>();
        ensure!(old.len() == new.len(), "unpaired endpoints");
        let pairs: BTreeMap<_, _> = old.iter().copied().zip(new).collect();
        ensure!(pairs.len() == old.len(), "duplicate source endpoint");
        for (&a, &b) in &pairs {
            let Some(f) = a.format() else {
                bail!("unexpected payload pair")
            };
            ensure!(
                f != format
                    && b.format() == Some(format)
                    && source.objects.contains(&a)
                    && target.objects.contains(&b),
                "endpoint outside inventory"
            );
            let r = Record::decode(&self.resolve(s, a, "read")?, f)?;
            for dep in r.inputs() {
                ensure!(source.objects.contains(&dep), "missing source dependency");
                self.resolve(s, dep, "read")?;
            }
            let expected = rewrite(r, &pairs)?;
            ensure!(
                expected.encode(format) == self.resolve(s, b, "read")?,
                "translation does not preserve referenced structure"
            );
        }
        let expected: BTreeSet<_> = source
            .objects
            .iter()
            .map(|id| pairs.get(id).unwrap_or(id))
            .copied()
            .collect();
        ensure!(expected == target.objects, "incomplete inventory mapping");
        Ok(pairs)
    }
}
#[derive(Default)]
pub struct Equivalence(BTreeMap<Id, BTreeSet<Id>>);
impl Equivalence {
    pub fn add(&mut self, pairs: BTreeMap<Id, Id>) {
        for (a, b) in pairs {
            self.0.entry(a).or_default().insert(b);
            self.0.entry(b).or_default().insert(a);
        }
    }
    pub fn endpoints(&self, id: Id) -> BTreeSet<Id> {
        let mut seen = BTreeSet::from([id]);
        let mut queue = vec![id];
        while let Some(x) = queue.pop() {
            if let Some(peers) = self.0.get(&x) {
                for &p in peers {
                    if seen.insert(p) {
                        queue.push(p);
                    }
                }
            }
        }
        seen
    }
}
