use crate::{
    profile::{Document, Kind, PUBLIC, link, verify_attestation},
    store::{Archive, Snapshot},
    wire::{Format, Id},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adoption {
    pub plan: Id,
    pub sealed_head: Id,
    pub observation: Id,
    pub signature: Id,
}
impl Archive {
    /// Evaluate the registered paired-count rule. The caller pins the controller's key independently.
    pub fn adoption(
        &self,
        s: &Snapshot,
        request: &Adoption,
        keys: &BTreeSet<String>,
        f: Format,
    ) -> Result<Id> {
        let plan = self.read(s, request.plan, "read")?;
        let o = self.read(s, request.observation, "read")?;
        let sealed = self.head(request.sealed_head)?;
        ensure!(
            sealed.objects.contains(&request.plan)
                && sealed.objects.is_subset(&s.objects)
                && !sealed.objects.contains(&request.observation),
            "invalid precommitment horizon"
        );
        ensure!(
            plan.kind == Kind::Plan
                && plan.field::<String>("rule")? == "paired-count-v1"
                && o.kind == Kind::Occurrence
                && o.one("plan")? == request.plan
                && o.one("sealed-head")? == request.sealed_head
                && o.scope == plan.scope,
            "trial protocol mismatch"
        );
        let attestation = self.read(s, request.signature, "read")?;
        verify_attestation(
            &attestation,
            request.observation,
            &plan.scope,
            "trial-controller",
            "research-policy-1",
            keys,
        )?;
        let candidate = plan.one("candidate")?;
        let parent = plan.one("parent")?;
        let model = self.read(s, candidate, "read")?;
        let baseline = self.read(s, parent, "read")?;
        ensure!(
            candidate != parent
                && model.kind == Kind::Model
                && baseline.kind == Kind::Model
                && model.one("parent")? == parent
                && model.field::<String>("controller")? != attestation.subject
                && baseline.field::<String>("controller")? != attestation.subject,
            "independent trial control not established"
        );
        let training = model.one("training")?;
        let protected = plan.one("protected")?;
        ensure!(
            o.one("candidate")? == candidate
                && o.one("parent")? == parent
                && o.one("protected")? == protected
                && o.field::<bool>("concealed_until_test")?
                && o.field::<u64>("previous_exposures")? == 0,
            "protected evaluation or pairing mismatch"
        );
        let arm_budget: BTreeMap<String, u64> = plan.field("per_arm_budget")?;
        ensure!(
            !arm_budget.is_empty()
                && o.field::<BTreeMap<String, u64>>("candidate_budget")? == arm_budget
                && o.field::<BTreeMap<String, u64>>("parent_budget")? == arm_budget,
            "resource mismatch"
        );
        let tasks = self.read(s, protected, "read")?;
        let t = self.read(s, training, "read")?;
        ensure!(
            tasks.kind == Kind::Manifest && t.kind == Kind::Manifest,
            "expected trial manifests"
        );
        let held: BTreeSet<_> = tasks.roles("task").collect();
        ensure!(
            !held.is_empty() && held.len() == tasks.roles("task").count(),
            "missing or duplicated protected tasks"
        );
        let train = self.explain(s, &[training], "read", s.objects.len(), 48);
        ensure!(
            train.frontier.is_empty() && held.is_disjoint(&train.visited),
            "training overlap or unknown lineage"
        );
        let candidate_wins: BTreeSet<Id> = o.roles("candidate-success").collect();
        let parent_wins: BTreeSet<Id> = o.roles("parent-success").collect();
        ensure!(
            candidate_wins.is_subset(&held)
                && parent_wins.is_subset(&held)
                && o.field::<u64>("completed_per_arm")? == held.len() as u64,
            "incomplete paired results"
        );
        let required = plan.field::<usize>("minimum_gain")?;
        let accepted = candidate_wins.len() > parent_wins.len()
            && candidate_wins.len() - parent_wins.len() >= required;
        let decision = Document::new(
            Kind::Decision,
            &model.subject,
            &plan.scope,
            json!({
                "adopted": accepted,
                "use_range": plan.field::<String>("use_range")?,
                "reassess_when": plan.field::<String>("reassess_when")?,
                "tested": held.len(),
                "candidate_successes": candidate_wins.len(),
                "parent_successes": parent_wins.len(),
                "regressions": parent_wins.difference(&candidate_wins).count(),
                "basis": "signed paired counts on the named finite collection",
            }),
            vec![
                link("plan", request.plan),
                link("assessment-evidence", request.observation),
                link("signature", request.signature),
                link("candidate", candidate),
                link("rollback", parent),
                link("training", training),
                link("protected", protected),
            ],
        )?;
        self.document(&decision, f, Id::blob(PUBLIC))
    }
}
