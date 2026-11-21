use crate::{
    migration::Equivalence,
    profile::{Document, Kind, PUBLIC, link, verify_attestation},
    store::{Archive, Snapshot},
    wire::{Format, Id},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    pub features: Vec<Id>,
    pub label: Id,
    pub partition: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingRequest {
    pub feature_cutoff: Id,
    #[serde(default)]
    pub forecast_plan: Option<Id>,
    #[serde(default)]
    pub mappings: Vec<Id>,
    pub label_head: Id,
    /// The recipient independently admits this policy.
    pub policy: Id,
    #[serde(default)]
    pub standing: LabelStanding,
    #[serde(default)]
    pub project: Option<String>,
    pub examples: Vec<Example>,
    pub independent_roles: BTreeSet<String>,
    pub binary: bool,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelStanding {
    #[default]
    Current,
    Historical,
}

#[derive(Debug, Serialize)]
pub struct Extraction {
    pub manifest: Id,
    pub included: Vec<Id>,
    pub withheld: BTreeMap<Id, String>,
}
fn label_value(
    receipt: &crate::evaluation::Receipt,
    check: Option<&str>,
    condition: Option<Id>,
) -> Result<Value> {
    if !receipt.horizon_complete {
        return Ok(json!("unknown"));
    }
    let mut values = BTreeSet::new();
    if let Some(name) = check {
        ensure!(
            condition.is_none(),
            "a check label cannot silently select a branch"
        );
        for test in receipt.checks.iter().filter(|test| test.test == name) {
            values.insert(
                serde_json::to_value(test.status)?
                    .as_str()
                    .context("check status")?
                    .to_owned(),
            );
        }
    } else if let Some(id) = condition {
        let key = if receipt.result.is_some() {
            "physical"
        } else {
            "score"
        };
        for branch in &receipt.branches {
            if branch.get("notice") == Some(&json!(id)) {
                values.insert(
                    branch[key]
                        .as_str()
                        .context("missing conditional outcome")?
                        .to_owned(),
                );
            }
        }
        ensure!(!values.is_empty(), "unknown branch condition");
    } else if let Some(standing) = receipt.result {
        if standing == crate::evaluation::Standing::Supported {
            let mut targets = receipt
                .branches
                .iter()
                .filter_map(|branch| branch.get("training_target"));
            if let Some(target) = targets.next() {
                return Ok(if targets.all(|other| other == target) {
                    target.clone()
                } else {
                    json!("contested")
                });
            }
        }
        return Ok(serde_json::to_value(standing)?);
    } else {
        values.extend(
            receipt
                .branches
                .iter()
                .filter_map(|branch| branch["score"].as_str().map(str::to_owned)),
        );
    }
    Ok(match values.len() {
        0 => json!("unknown"),
        1 => json!(values.into_iter().next().context("missing value")?),
        _ => json!("contested"),
    })
}

struct ValidatedExample {
    groups: BTreeSet<(String, Id)>,
    release_attestations: BTreeSet<Id>,
}

struct TrainingTrust {
    keys: BTreeMap<String, BTreeSet<String>>,
    attestations: BTreeMap<Id, Vec<(Id, Document)>>,
    notices: BTreeMap<Id, Document>,
    notice_search_complete: bool,
}

impl TrainingTrust {
    fn load(store: &Archive, head: &Snapshot, policy: Id) -> Result<Self> {
        let policy = store.read(head, policy, "read")?;
        ensure!(
            policy.kind == Kind::Policy && policy.scope == "research-policy-1",
            "unsupported training policy"
        );
        let mut attestations = BTreeMap::<Id, Vec<_>>::new();
        let mut notices = BTreeMap::new();
        let mut notice_search_complete = true;
        for &id in &head.objects {
            if id.format().is_none() {
                continue;
            }
            match store.read(head, id, "read") {
                Ok(doc) if doc.kind == Kind::Attestation => {
                    if let Ok(original) = doc.one("signed-original") {
                        attestations.entry(original).or_default().push((id, doc));
                    }
                }
                Ok(doc) if doc.kind == Kind::Notice => {
                    notices.insert(id, doc);
                }
                Err(_) => notice_search_complete &= !store.may_be_notice(head, id),
                _ => (),
            }
        }
        Ok(Self {
            keys: policy.field("keys")?,
            attestations,
            notices,
            notice_search_complete,
        })
    }

    fn signatures(
        &self,
        aliases: &Equivalence,
        target: Id,
        scope: &str,
        role: &str,
    ) -> BTreeSet<Id> {
        let Some(keys) = self.keys.get(role) else {
            return BTreeSet::new();
        };
        aliases
            .endpoints(target)
            .into_iter()
            .filter_map(|id| self.attestations.get(&id).map(|docs| (id, docs)))
            .flat_map(|(id, docs)| {
                docs.iter().filter_map(move |(sig, doc)| {
                    verify_attestation(doc, id, scope, role, "research-policy-1", keys)
                        .ok()
                        .map(|()| *sig)
                })
            })
            .collect()
    }

    fn origin(
        &self,
        store: &Archive,
        head: &Snapshot,
        receipt: &Document,
        aliases: &Equivalence,
        origin: &str,
        bound_signatures: Option<&BTreeSet<Id>>,
    ) -> Result<BTreeSet<Id>> {
        ensure!(
            ["observed", "simulated", "synthetic", "inferred"].contains(&origin),
            "unknown example origin"
        );
        let mut signatures = BTreeSet::new();
        for id in receipt.roles("argument") {
            let argument = store.read(head, id, "read")?;
            ensure!(
                argument.kind == Kind::Argument
                    && argument.subject == receipt.subject
                    && argument.scope == receipt.scope
                    && argument.field::<String>("origin")? == origin,
                "requested origin differs from the argument's declared origin"
            );
            let candidates = self.signatures(aliases, id, &argument.scope, "data-origin");
            let signature = candidates
                .into_iter()
                .find(|candidate| {
                    bound_signatures
                        .is_none_or(|bound| !aliases.endpoints(*candidate).is_disjoint(bound))
                })
                .context("missing bound, admitted data-origin attestation")?;
            signatures.insert(signature);
        }
        ensure!(!signatures.is_empty(), "no attestable argument origin");
        Ok(signatures)
    }
}

fn canonical(aliases: &Equivalence, id: Id) -> Id {
    aliases.endpoints(id).first().copied().unwrap_or(id)
}

fn canonical_set(aliases: &Equivalence, ids: &BTreeSet<Id>) -> BTreeSet<Id> {
    ids.iter().map(|id| canonical(aliases, *id)).collect()
}

fn optional_link(doc: &Document, role: &str) -> Result<Option<Id>> {
    let mut inputs = doc.roles(role);
    let value = inputs.next();
    ensure!(inputs.next().is_none(), "ambiguous {role}");
    Ok(value)
}

struct TrainingReview<'a> {
    store: &'a Archive,
    before: &'a Snapshot,
    after: &'a Snapshot,
    request: &'a TrainingRequest,
    aliases: &'a Equivalence,
    trust: &'a TrainingTrust,
    access: &'a crate::profile::TrainingAccess<'a>,
}

impl TrainingReview<'_> {
    fn validate(&self, ex: &Example) -> Result<ValidatedExample> {
        let Self {
            store,
            before,
            after,
            request,
            aliases,
            trust,
            access,
        } = *self;
        let l = store.read_for_training(after, ex.label, access)?;
        ensure!(l.kind == Kind::Label, "expected label");
        let value = l.fields.get("value").context("missing label value")?;
        let check = l
            .fields
            .get("check")
            .map(|field| field.as_str().context("invalid label check"))
            .transpose()?;
        let condition = optional_link(&l, "condition")?;
        ensure!(
            !request.binary
                || (condition.is_none()
                    && value
                        .as_str()
                        .is_some_and(|v| ["pass", "fail", "supported", "refuted"].contains(&v))),
            "label has no single unconditional binary value"
        );
        ensure!(
            !ex.features.is_empty() && !ex.partition.is_empty(),
            "empty features or partition"
        );
        let receipt_id = l.one("receipt")?;
        let receipt = store.read_for_training(after, receipt_id, access)?;
        let claim = l.one("claim")?;
        ensure!(
            receipt.kind == Kind::Assessment
                && receipt.one("claim")? == claim
                && receipt.one("snapshot")? == l.one("snapshot")?
                && receipt.subject == l.subject
                && receipt.scope == l.scope
                && check
                    .map(str::to_owned)
                    .unwrap_or(receipt.field::<String>("predicate")?)
                    == l.field::<String>("predicate")?,
            "label target or horizon differs from its receipt"
        );
        let original: crate::evaluation::Query = receipt.field("original_query")?;
        ensure!(
            aliases.endpoints(original.policy).contains(&request.policy),
            "receipt policy differs from admitted training policy"
        );
        let historical = store.head(receipt.one("snapshot")?)?;
        ensure!(
            historical.objects.is_subset(&after.objects),
            "receipt inventory outside label horizon"
        );
        ensure!(
            original.budget <= 100_000
                && original.byte_limit <= crate::evaluation::default_byte_limit(),
            "label replay exceeds local extraction budget"
        );
        let replay = crate::evaluation::assess(store, &historical, &original)?;
        let expected = crate::evaluation::receipt_document(store, &historical, &original, &replay)?
            .encode(Id::blob(PUBLIC))?;
        let endpoints = aliases.endpoints(receipt_id);
        ensure!(
            [Format::A, Format::B]
                .iter()
                .any(|f| endpoints.contains(&Id::record(*f, &expected.encode(*f)))),
            "receipt fields or dependencies do not replay"
        );
        ensure!(
            &label_value(&replay, check, condition)? == value,
            "label disagrees with the assessed predicate"
        );
        let bound_signatures = l.roles("origin-attestation").collect::<BTreeSet<_>>();
        let origins = trust.origin(
            store,
            after,
            &receipt,
            aliases,
            &l.field::<String>("origin")?,
            Some(&bound_signatures),
        )?;
        ensure!(
            bound_signatures.len() == origins.len(),
            "ambiguous origin attestations"
        );
        let mut witnesses = BTreeSet::new();
        if let Some(plan) = request.forecast_plan {
            ensure!(
                store
                    .read_for_training(before, plan, access)
                    .is_ok_and(|d| d.kind == Kind::Plan),
                "registered forecast plan unavailable at feature cutoff"
            );
            for &id in &original.arguments {
                let argument = store.read_for_training(&historical, id, access)?;
                let witness_id = argument.one("release")?;
                let witness = store.read_for_training(&historical, witness_id, access)?;
                ensure!(
                    witness.kind == Kind::Occurrence
                        && witness.subject == receipt.subject
                        && witness.scope == receipt.scope
                        && aliases.endpoints(witness.one("plan")?).contains(&plan)
                        && witness.one("feature-cutoff")? == request.feature_cutoff
                        && witness.field::<bool>("concealed")?
                        && witness.field::<u64>("sealed")? < witness.field::<u64>("released")?,
                    "missing controlled pre-outcome cutoff"
                );
                let signature = trust
                    .signatures(aliases, witness_id, &witness.scope, "release")
                    .into_iter()
                    .find(|id| store.resolve_for_training(&historical, *id, access).is_ok())
                    .context("no admitted release signature at the receipt horizon")?;
                let mut outcomes = argument
                    .inputs
                    .iter()
                    .filter(|edge| {
                        matches!(edge.role.as_str(), "reading" | "outcome" | "outcome-input")
                    })
                    .peekable();
                ensure!(
                    outcomes.peek().is_some(),
                    "argument has no declared outcome evidence"
                );
                ensure!(
                    outcomes
                        .all(|edge| aliases.endpoints(edge.target).is_disjoint(&before.objects)),
                    "outcome evidence visible at the feature cutoff"
                );
                witnesses.insert(signature);
            }
        }
        let mut axes = BTreeSet::from([("claim".to_owned(), canonical(aliases, claim))]);
        let mut checked = BTreeSet::new();
        for (s, roots) in [
            (before, ex.features.as_slice()),
            (after, std::slice::from_ref(&ex.label)),
        ] {
            let closure = store.explain_for_training(s, roots, access);
            ensure!(
                closure.frontier.is_empty(),
                "unavailable, late, or prohibited training input"
            );
            for id in closure.visited {
                if !checked.insert(id) || id.format().is_none() {
                    continue;
                }
                let doc = store.read_for_training(s, id, access)?;
                for edge in doc.inputs {
                    if request.independent_roles.contains(&edge.role) {
                        axes.insert((edge.role, canonical(aliases, edge.target)));
                    }
                }
            }
        }
        if request.standing == LabelStanding::Current {
            ensure!(
                trust.notice_search_complete,
                "requested notice horizon has unreadable notices or records of unknown kind"
            );
            let mut original = original;
            original.mappings.extend(request.mappings.iter().copied());
            original.mappings.sort_unstable();
            original.mappings.dedup();
            let current = crate::evaluation::assess(store, after, &original)?;
            ensure!(
                current.horizon_complete
                    && current.frontier.is_empty()
                    && label_value(&current, check, condition)? == *value
                    && canonical_set(aliases, &current.applicable_notices)
                        == canonical_set(aliases, &replay.applicable_notices),
                "label requires reassessment at the requested notice horizon"
            );
            for (&id, notice) in &trust.notices {
                if notice
                    .roles("target")
                    .any(|id| !aliases.endpoints(id).is_disjoint(&checked))
                    && !trust
                        .signatures(aliases, id, &notice.scope, "notice")
                        .is_empty()
                    && !current.applicable_notices.contains(&id)
                {
                    anyhow::bail!("an admitted notice affects a training dependency");
                }
            }
        }
        for axis in &request.independent_roles {
            ensure!(
                axes.iter().any(|(role, _)| role == axis),
                "unknown independence axis {axis}"
            );
        }
        Ok(ValidatedExample {
            groups: axes,
            release_attestations: witnesses,
        })
    }
}

impl Archive {
    pub fn label(
        &self,
        s: &Snapshot,
        receipt: Id,
        origin: &str,
        check: Option<&str>,
        condition: Option<Id>,
        f: Format,
    ) -> Result<Id> {
        let d = self.read(s, receipt, "read")?;
        ensure!(d.kind == Kind::Assessment, "expected assessment");
        let mut aliases = Equivalence::default();
        for mapping in d.roles("mapping") {
            aliases.add(self.verify_mapping(s, mapping)?);
        }
        let trust = TrainingTrust::load(self, s, d.one("policy")?)?;
        let origins = trust.origin(self, s, &d, &aliases, origin, None)?;
        let value = label_value(&d.field("original_transcript")?, check, condition)?;
        let predicate = check.map(str::to_owned).unwrap_or(d.field("predicate")?);
        let mut fields = json!({"value":value,"origin":origin,"predicate":predicate});
        if let Some(c) = check {
            fields["check"] = json!(c);
        }
        let mut links = vec![
            link("receipt", receipt),
            link("claim", d.one("claim")?),
            link("snapshot", d.one("snapshot")?),
        ];
        links.extend(origins.into_iter().map(|id| link("origin-attestation", id)));
        if let Some(id) = condition {
            links.push(link("condition", id));
        }
        self.document(
            &Document::new(Kind::Label, &d.subject, &d.scope, fields, links)?,
            f,
            Id::blob(PUBLIC),
        )
    }
    pub fn training_manifest(&self, request: &TrainingRequest, f: Format) -> Result<Extraction> {
        let before = self.head(request.feature_cutoff)?;
        let after = self.head(request.label_head)?;
        ensure!(
            before.objects.is_subset(&after.objects),
            "feature cutoff outside outcome history"
        );
        let mut aliases = Equivalence::default();
        for &id in &request.mappings {
            aliases.add(self.verify_mapping(&after, id)?);
        }
        let trust = TrainingTrust::load(self, &after, request.policy)?;
        let access = crate::profile::TrainingAccess::new(request.project.as_deref())?;
        let review = TrainingReview {
            store: self,
            before: &before,
            after: &after,
            request,
            aliases: &aliases,
            trust: &trust,
            access: &access,
        };
        let mut partitions: BTreeMap<(String, Id), String> = BTreeMap::new();
        let mut included = vec![];
        let mut withheld = BTreeMap::new();
        let mut links = vec![link("policy", request.policy)];
        let mut release_signatures = BTreeSet::new();
        let mut exact_rows = BTreeSet::new();
        for ex in &request.examples {
            let row = review.validate(ex).and_then(|example| {
                ensure!(
                    example
                        .groups
                        .iter()
                        .all(|x| partitions.get(x).is_none_or(|p| p == &ex.partition)),
                    "shared ancestor crosses declared partitions"
                );
                let row_key = (
                    canonical(&aliases, ex.label),
                    ex.features
                        .iter()
                        .map(|id| canonical(&aliases, *id))
                        .collect::<Vec<_>>(),
                );
                ensure!(exact_rows.insert(row_key), "duplicate training example");
                Ok(example)
            });
            match row {
                Ok(ValidatedExample {
                    groups: axes,
                    release_attestations: witnesses,
                }) => {
                    release_signatures.extend(witnesses);
                    for a in axes {
                        partitions.insert(a, ex.partition.clone());
                    }
                    included.push(ex.label);
                    let mut l = link("label", ex.label);
                    l.qualifier = format!("{}:{}", included.len(), ex.partition);
                    links.push(l);
                    for (i, &id) in ex.features.iter().enumerate() {
                        let mut l = link("feature", id);
                        l.qualifier = format!("{}:{i}", included.len());
                        links.push(l);
                    }
                }
                Err(e) => {
                    withheld.insert(ex.label, e.to_string());
                }
            }
        }
        for (role, s) in [("feature-cutoff", &before), ("label-horizon", &after)] {
            let id = self.blob(&serde_json::to_vec(s)?, Id::blob(PUBLIC))?;
            links.push(link(role, id));
        }
        if let Some(plan) = request.forecast_plan {
            links.push(link("forecast-plan", plan));
        }
        links.extend(request.mappings.iter().map(|id| link("mapping", *id)));
        links.extend(
            release_signatures
                .into_iter()
                .map(|id| link("release-attestation", id)),
        );
        let d = Document::new(
            Kind::Manifest,
            "training extraction",
            "research-training-1",
            json!({
                "rule": "as-of-feature-and-label",
                "label_standing": request.standing,
                "project": request.project,
                "permission_checked_at": access.checked_at(),
                "split_identity": "claim and declared dependency roles",
                "exposure": if included.is_empty() { "no eligible examples" }
                    else if request.forecast_plan.is_some() { "controlled release" }
                    else { "retrospective or unknown" },
                "binary": request.binary,
                "independent_roles": request.independent_roles,
                "withheld_count": request.examples.len()-included.len(),
                "requested": request.examples.len(),
            }),
            links,
        )?;
        Ok(Extraction {
            manifest: self.document(&d, f, Id::blob(PUBLIC))?,
            included,
            withheld,
        })
    }
    pub fn impact(
        &self,
        s: &Snapshot,
        notice: Id,
        mappings: &[Id],
        budget: usize,
    ) -> Result<Impact> {
        let n = self.read(s, notice, "read")?;
        ensure!(n.kind == Kind::Notice, "expected notice");
        let mut eq = Equivalence::default();
        for &m in mappings {
            eq.add(self.verify_mapping(s, m)?);
        }
        let (initial, filter) = if n.roles("calibration").next().is_some() {
            (
                eq.endpoints(n.one("calibration")?),
                Some((n.field::<String>("mode")?, n.field::<[i64; 2]>("interval")?)),
            )
        } else {
            (eq.endpoints(n.one("target")?), None)
        };
        let mut affected = initial.clone();
        let mut docs = BTreeMap::new();
        let mut frontier = BTreeSet::new();
        for (i, &id) in s.objects.iter().enumerate() {
            if i >= budget {
                frontier.insert(id);
                continue;
            }
            if id.format().is_some() {
                match self.read(s, id, "read") {
                    Ok(d) => {
                        docs.insert(id, d);
                    }
                    Err(_) => {
                        frontier.insert(id);
                    }
                }
            }
        }
        loop {
            let count = affected.len();
            for (&id, d) in &docs {
                if matches!(
                    d.kind,
                    Kind::Notice | Kind::Mapping | Kind::Attestation | Kind::Policy
                ) || affected.contains(&id)
                {
                    continue;
                }
                // Changing differential bias changes the scientific scores and bounds. Both branches
                // still replay the pinned integer operation; this label describes replay alone.
                if d.kind == Kind::Label
                    && d.fields.get("check").and_then(|v| v.as_str()) == Some("arithmetic replay")
                    && n.field::<i64>("bias").is_ok()
                {
                    continue;
                }
                if d.inputs.iter().any(|e| {
                    if !affected.contains(&e.target) {
                        return false;
                    }
                    if initial.contains(&e.target)
                        && let Some((mode, [first, last])) = &filter
                    {
                        if d.scope != n.scope {
                            return false;
                        }
                        if let Some(v) = d.fields.get("mode")
                            && v.as_str() != Some(mode.as_str())
                        {
                            return false;
                        }
                        if let Ok(event) = d.field::<i64>("event")
                            && !(*first..=*last).contains(&event)
                        {
                            return false;
                        }
                    }
                    true
                }) {
                    affected.insert(id);
                }
            }
            if affected.len() == count {
                break;
            }
        }
        let mut by_kind: BTreeMap<String, BTreeSet<Id>> = BTreeMap::new();
        for id in affected.difference(&initial) {
            if let Some(d) = docs.get(id) {
                by_kind
                    .entry(
                        serde_json::to_value(d.kind)?
                            .as_str()
                            .context("kind")?
                            .into(),
                    )
                    .or_default()
                    .insert(*id);
            }
        }
        Ok(Impact {
            notice,
            by_kind,
            frontier,
        })
    }
}
#[derive(Serialize)]
pub struct Impact {
    pub notice: Id,
    pub by_kind: BTreeMap<String, BTreeSet<Id>>,
    pub frontier: BTreeSet<Id>,
}
