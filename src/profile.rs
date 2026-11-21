use crate::wire::{Edge, Id, Record, Term};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const PROFILE: &[u8] = include_bytes!("../kits/research-profile.txt");
pub const PUBLIC: &[u8] = br#"{"purposes":["read","train"],"version":1}"#;
pub const READ_ONLY: &[u8] = br#"{"purposes":["read"],"version":1}"#;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u64)]
pub enum Kind {
    Profile = 1,
    Question,
    Plan,
    Occurrence,
    Derivation,
    Claim,
    Argument,
    Assessment,
    Notice,
    Decision,
    Attestation,
    Mapping,
    Label,
    Manifest,
    Model,
    Calibration,
    Guarantee,
    Projection,
    Policy,
    Authority,
    Closure,
    Selection,
    Descriptor,
}
impl Kind {
    pub fn decode(n: u64) -> Result<Self> {
        const ALL: [Kind; 23] = [
            Kind::Profile,
            Kind::Question,
            Kind::Plan,
            Kind::Occurrence,
            Kind::Derivation,
            Kind::Claim,
            Kind::Argument,
            Kind::Assessment,
            Kind::Notice,
            Kind::Decision,
            Kind::Attestation,
            Kind::Mapping,
            Kind::Label,
            Kind::Manifest,
            Kind::Model,
            Kind::Calibration,
            Kind::Guarantee,
            Kind::Projection,
            Kind::Policy,
            Kind::Authority,
            Kind::Closure,
            Kind::Selection,
            Kind::Descriptor,
        ];
        ALL.iter()
            .copied()
            .find(|k| *k as u64 == n)
            .context("unknown kind")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub kind: Kind,
    pub subject: String,
    pub scope: String,
    pub fields: BTreeMap<String, Value>,
    #[serde(default)]
    pub inputs: Vec<Link>,
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Link {
    pub role: String,
    pub target: Id,
    #[serde(default)]
    pub qualifier: String,
}
impl Document {
    pub fn new(
        kind: Kind,
        subject: &str,
        scope: &str,
        fields: Value,
        inputs: Vec<Link>,
    ) -> Result<Self> {
        Ok(Self {
            kind,
            subject: subject.into(),
            scope: scope.into(),
            fields: serde_json::from_value(fields)?,
            inputs,
        })
    }
    pub fn encode(&self, access: Id) -> Result<Record> {
        ensure!(
            !self.subject.is_empty() && !self.scope.is_empty(),
            "empty subject or scope"
        );
        let mut seen = BTreeSet::new();
        for l in &self.inputs {
            ensure!(
                !l.role.is_empty() && seen.insert((&l.role, l.target, &l.qualifier)),
                "duplicate or empty role"
            );
        }
        let body = Term::Bytes(serde_json::to_vec(&json!([
            self.subject,
            self.scope,
            self.fields
        ]))?);
        Ok(Record {
            kind: self.kind as u64,
            profile: Id::blob(PROFILE),
            access,
            body,
            critical: vec![],
            edges: self
                .inputs
                .iter()
                .map(|l| Edge {
                    role: 1,
                    target: l.target,
                    qualifier: Term::Array(vec![
                        Term::Text(l.role.clone()),
                        Term::Text(l.qualifier.clone()),
                    ]),
                })
                .collect(),
        })
    }
    pub fn decode(r: &Record) -> Result<Self> {
        ensure!(
            r.profile == Id::blob(PROFILE) && r.critical.is_empty(),
            "unknown profile or critical extension"
        );
        let Term::Bytes(b) = &r.body else {
            bail!("invalid research body")
        };
        let (subject, scope, fields) = serde_json::from_slice(b)?;
        let mut inputs = Vec::new();
        for e in &r.edges {
            ensure!(e.role == 1, "unknown input role");
            let Term::Array(a) = &e.qualifier else {
                bail!("invalid qualifier")
            };
            let [Term::Text(role), Term::Text(qualifier)] = a.as_slice() else {
                bail!("invalid role and qualifier")
            };
            inputs.push(Link {
                role: role.clone(),
                target: e.target,
                qualifier: qualifier.clone(),
            });
        }
        let d = Self {
            kind: Kind::decode(r.kind)?,
            subject,
            scope,
            fields,
            inputs,
        };
        ensure!(d.encode(r.access)? == *r, "noncanonical research record");
        Ok(d)
    }
    pub fn roles<'a>(&'a self, role: &'a str) -> impl Iterator<Item = Id> + 'a {
        self.inputs
            .iter()
            .filter(move |l| l.role == role)
            .map(|l| l.target)
    }
    pub fn one(&self, role: &str) -> Result<Id> {
        let mut r = self.roles(role);
        let id = r.next().with_context(|| format!("missing {role}"))?;
        ensure!(r.next().is_none(), "ambiguous {role}");
        Ok(id)
    }
    pub fn field<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        serde_json::from_value(
            self.fields
                .get(key)
                .with_context(|| format!("missing {key}"))?
                .clone(),
        )
        .with_context(|| format!("invalid {key}"))
    }
}
pub fn link(role: &str, target: Id) -> Link {
    Link {
        role: role.into(),
        target,
        qualifier: String::new(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Access {
    version: u8,
    purposes: Vec<String>,
    #[serde(default, deserialize_with = "decode_training_grant")]
    training: Option<TrainingGrant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrainingGrant {
    project: String,
    not_before: u64,
    expires: u64,
}

fn decode_training_grant<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<TrainingGrant>, D::Error> {
    TrainingGrant::deserialize(decoder).map(Some)
}

pub(crate) struct TrainingAccess<'a> {
    project: Option<&'a str>,
    now: Option<u64>,
}

impl<'a> TrainingAccess<'a> {
    pub(crate) fn new(project: Option<&'a str>) -> Result<Self> {
        ensure!(
            project.is_none_or(|name| !name.trim().is_empty()),
            "empty training project"
        );
        let now = project
            .map(|_| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs())
            })
            .transpose()?;
        Ok(Self { project, now })
    }
    pub(crate) fn checked_at(&self) -> Option<u64> {
        self.now
    }
    pub(crate) fn allows(&self, bytes: &[u8]) -> bool {
        permits_purpose(bytes, "train", self.project.zip(self.now))
    }
}

pub fn allows(bytes: &[u8], purpose: &str) -> bool {
    permits_purpose(bytes, purpose, None)
}

fn permits_purpose(bytes: &[u8], purpose: &str, context: Option<(&str, u64)>) -> bool {
    let Ok(access) = serde_json::from_slice::<Access>(bytes) else {
        return false;
    };
    if access.version != 1 || !access.purposes.iter().any(|p| p == purpose) {
        return false;
    }
    if purpose != "train" {
        return true;
    }
    access.training.is_none_or(|rule| {
        context.is_some_and(|(project, now)| {
            !rule.project.is_empty()
                && rule.project == project
                && rule.not_before <= now
                && now < rule.expires
        })
    })
}

pub fn attest(
    target: Id,
    scope: &str,
    role: &str,
    context: &str,
    key: &ed25519_dalek::SigningKey,
) -> Result<Document> {
    use ed25519_dalek::Signer;
    let public = hex::encode(key.verifying_key().to_bytes());
    let msg = signature_message(target, &public, scope, role, context)?;
    Document::new(
        Kind::Attestation,
        &public,
        scope,
        json!({"scheme":"Ed25519","role":role,"context":context,"signature":hex::encode(key.sign(&msg).to_bytes())}),
        vec![link("signed-original", target)],
    )
}
fn signature_message(
    target: Id,
    public: &str,
    scope: &str,
    role: &str,
    context: &str,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!([
        "REP-attestation-1",
        target.to_string(),
        public,
        scope,
        role,
        "Ed25519",
        context
    ]))?)
}
pub fn verify_attestation(
    d: &Document,
    target: Id,
    scope: &str,
    role: &str,
    context: &str,
    trusted: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        d.kind == Kind::Attestation && d.one("signed-original")? == target && d.scope == scope,
        "wrong attestation target or scope"
    );
    ensure!(
        d.field::<String>("scheme")? == "Ed25519"
            && d.field::<String>("role")? == role
            && d.field::<String>("context")? == context
            && trusted.contains(&d.subject),
        "untrusted credential or context"
    );
    let key = ed25519_dalek::VerifyingKey::from_bytes(
        &hex::decode(&d.subject)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong key length"))?,
    )?;
    let sig = ed25519_dalek::Signature::from_slice(&hex::decode(d.field::<String>("signature")?)?)?;
    key.verify_strict(
        &signature_message(target, &d.subject, scope, role, context)?,
        &sig,
    )?;
    Ok(())
}
