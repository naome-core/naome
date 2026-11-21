use crate::{
    evaluation::{Query, Receipt, assess, default_byte_limit},
    profile::{Document, Kind, PROFILE, PUBLIC, attest, link},
    store::{Archive, Bundle, Snapshot},
    wire::{Format, Id},
};
use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;

#[derive(Serialize)]
pub struct Projection {
    pub packet: Bundle,
    pub queries: Vec<Query>,
    pub private_mapping: Id,
}
impl Archive {
    /// The custodian explicitly authorises publishing only the hull, rules, subject and scope.
    /// Build in a clean archive. Only the source custodian retains the mapping to raw evidence.
    pub fn project_hull(
        &self,
        s: &Snapshot,
        receipt: Id,
        key: &ed25519_dalek::SigningKey,
        f: Format,
    ) -> Result<Projection> {
        let r = self.read(s, receipt, "read")?;
        ensure!(r.kind == Kind::Assessment, "expected assessment");
        let original: Query = r.field("original_query")?;
        let horizon = self.head(r.one("snapshot")?)?;
        let verified: Receipt = assess(self, &horizon, &original)?;
        ensure!(
            Some(&serde_json::to_value(&verified)?) == r.fields.get("original_transcript")
                && verified.horizon_complete
                && verified.branches.len() == 1,
            "projection needs one reproducible, complete measurement branch"
        );
        let hull: [i64; 2] = serde_json::from_value(verified.branches[0]["hull"].clone())?;
        let c = self.read(&horizon, original.target, "read")?;
        let threshold: i64 = c.field("threshold")?;
        let band: [i64; 2] = c.field("band")?;
        let archive = Archive::memory()?;
        let public = Id::blob(PUBLIC);
        let doc = |kind, fields, edges| {
            archive.document(
                &Document::new(kind, &c.subject, &c.scope, fields, edges)?,
                f,
                public,
            )
        };
        let projection = doc(
            Kind::Projection,
            json!({"hull":hull,"unit":"um","threshold":threshold,"band":band,"omissions":["readings","guarantees","calibration","physical verdicts"]}),
            vec![],
        )?;
        archive.document(
            &attest(projection, &c.scope, "projection", "research-policy-1", key)?,
            f,
            public,
        )?;
        let signer = hex::encode(key.verifying_key().to_bytes());
        let policy = archive.document(
            &Document::new(
                Kind::Policy,
                &signer,
                "research-policy-1",
                json!({
                    "keys": {"projection":[signer]},
                    "basis": "recipient must admit the projection signer independently",
                }),
                vec![],
            )?,
            f,
            public,
        )?;
        let mut queries = vec![];
        for predicate in ["score-above", "score-within", "above", "within"] {
            let target = doc(
                Kind::Claim,
                json!({"predicate":predicate,"threshold":threshold,"band":band}),
                vec![],
            )?;
            let arg = doc(
                Kind::Argument,
                json!({"method":"certified-hull"}),
                vec![link("claim", target), link("projection", projection)],
            )?;
            queries.push(Query {
                target,
                arguments: vec![arg],
                policy,
                budget: 10000,
                byte_limit: default_byte_limit(),
                previous_receipts: vec![],
                mappings: vec![],
                required_notices: vec![],
                current_at: None,
            });
        }
        let projected = archive.snapshot("certified hull", BTreeSet::new())?;
        let source_head = self.blob(&serde_json::to_vec(s)?, public)?;
        let target_head = self.blob(&serde_json::to_vec(&projected)?, public)?;
        let private = self.blob(br#"{"purposes":["custody"],"version":1}"#, public)?;
        let mapping = self.document(
            &Document::new(
                Kind::Mapping,
                &signer,
                &c.scope,
                json!({
                    "method": "certified-hull",
                    "preserves": ["score-above","score-within"],
                    "omits": ["joint bounds","physical standing"],
                    "profile": Id::blob(PROFILE).to_string(),
                }),
                vec![
                    link("source-inventory", source_head),
                    link("target-inventory", target_head),
                    link("source", receipt),
                    link("target", projection),
                ],
            )?,
            f,
            private,
        )?;
        Ok(Projection {
            packet: archive.export(&projected, "read")?,
            queries,
            private_mapping: mapping,
        })
    }
}
