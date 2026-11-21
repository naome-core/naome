use crate::{
    executor::{Dispatch, Request},
    profile::{Document, Kind, PUBLIC, attest, link},
    store::{Archive, Snapshot},
    wire::{Format, Id},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;

/// Each outcome row contains joint integer masses for its outcome and the possible worlds.
/// All feasible decisions remain available after observation; losses share one unit.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationModel {
    pub losses: Vec<Vec<i64>>,
    pub joint_masses: Vec<Vec<u64>>,
    pub loss_unit: String,
    pub acquisition_cost: i64,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ValueOfInformation {
    pub prior_loss_numerator: i128,
    pub posterior_loss_numerator: i128,
    pub net_gain_numerator: i128,
    pub denominator: i128,
}
impl ObservationModel {
    pub fn evaluate(&self) -> Result<ValueOfInformation> {
        ensure!(
            !self.loss_unit.is_empty()
                && self.acquisition_cost >= 0
                && !self.losses.is_empty()
                && !self.joint_masses.is_empty(),
            "incomplete decision problem"
        );
        let worlds = self.losses[0].len();
        ensure!(
            worlds > 0
                && self.losses.iter().all(|r| r.len() == worlds)
                && self.joint_masses.iter().all(|r| r.len() == worlds),
            "unaligned worlds"
        );
        let mut prior = vec![0i128; worlds];
        let min_loss = |mass: &[i128]| -> Result<i128> {
            self.losses
                .iter()
                .map(|d| {
                    d.iter().zip(mass).try_fold(0i128, |sum, (v, w)| {
                        sum.checked_add(i128::from(*v).checked_mul(*w)?)
                    })
                })
                .collect::<Option<Vec<_>>>()
                .context("loss arithmetic overflow")?
                .into_iter()
                .min()
                .context("no feasible decision")
        };
        let mut posterior = 0i128;
        for row in &self.joint_masses {
            let mass: Vec<_> = row.iter().copied().map(i128::from).collect();
            for (p, w) in prior.iter_mut().zip(&mass) {
                *p = p.checked_add(*w).context("mass overflow")?;
            }
            posterior = posterior
                .checked_add(min_loss(&mass)?)
                .context("expected loss overflow")?;
        }
        let total = prior
            .iter()
            .try_fold(0i128, |s, w| s.checked_add(*w))
            .context("mass overflow")?;
        ensure!(total > 0, "zero probability mass");
        let before = min_loss(&prior)?;
        let net = before
            .checked_sub(posterior)
            .and_then(|v| v.checked_sub(total.checked_mul(i128::from(self.acquisition_cost))?))
            .context("net benefit overflow")?;
        Ok(ValueOfInformation {
            prior_loss_numerator: before,
            posterior_loss_numerator: posterior,
            net_gain_numerator: net,
            denominator: total,
        })
    }
}
#[derive(Serialize)]
pub struct Execution {
    pub state: String,
    pub occurrence: Option<Id>,
    pub closure: Option<Id>,
}
impl Archive {
    /// Built-in computational action. A facility can use the reservation and readback API for other operations.
    pub fn execute_payload_check(
        &mut self,
        s: &Snapshot,
        r: &Request,
        authority_keys: &BTreeSet<String>,
        witness: &ed25519_dalek::SigningKey,
        now: u64,
        f: Format,
    ) -> Result<Execution> {
        ensure!(
            r.operation == "verify-payload",
            "unsupported local operation"
        );
        let decision = self.read(s, r.decision, "read")?;
        let plan_id = decision.one("plan")?;
        let plan = self.read(s, plan_id, "read")?;
        let target = plan.one("descriptor")?;
        ensure!(
            plan.kind == Kind::Plan
                && plan.scope == decision.scope
                && plan.subject == r.subject
                && plan.field::<u64>("planned_count")? == 1
                && plan.field::<String>("stopping")? == "one-payload"
                && plan.field::<String>("predicate")? == "exact-bytes",
            "incompatible execution plan"
        );
        let question = self.read(s, plan.one("question")?, "read")?;
        ensure!(
            question.kind == Kind::Question && question.subject == plan.subject,
            "plan question mismatch"
        );
        let limit = *r.costs.get("bytes").context("need byte reservation")?;
        if let Dispatch::AlreadyRecorded { state, witness } =
            self.reserve(s, r, authority_keys, now)?
        {
            let occurrence = witness.map(|x| x.parse()).transpose()?;
            let closure = if let Some(id) = occurrence {
                Some(self.close_payload_check(f, r, &decision, plan_id, id)?)
            } else {
                None
            };
            return Ok(Execution {
                state,
                occurrence,
                closure,
            });
        }
        let checked = self.materialize(s, target, "read", limit, std::io::sink());
        let (passed, detail) = match checked {
            Ok(n) => (true, format!("verified {n} bytes")),
            Err(e) => (false, e.to_string()),
        };
        let report = Document::new(
            Kind::Occurrence,
            &r.subject,
            &decision.scope,
            json!({
                "attempt": r.attempt,
                "execution": "observed",
                "operation": r.operation,
                "passed": passed,
                "detail": detail,
                "source": "local computation",
                "time": now,
            }),
            vec![link("decision", r.decision), link("descriptor", target)],
        )?;
        let tx = self.db.unchecked_transaction()?;
        let public = Id::blob(PUBLIC);
        let id = self.document(&report, f, public)?;
        let signature = self.document(
            &attest(
                id,
                &decision.scope,
                "readback",
                "research-policy-1",
                witness,
            )?,
            f,
            public,
        )?;
        let head = self.snapshot("local-executor", [s.id()?].into())?;
        let trusted = [hex::encode(witness.verifying_key().to_bytes())].into();
        self.reconcile_attempt(&head, &r.attempt, id, signature, &trusted)?;
        let closure = self.close_payload_check(f, r, &decision, plan_id, id)?;
        tx.commit()?;
        Ok(Execution {
            state: "observed".into(),
            occurrence: Some(id),
            closure: Some(closure),
        })
    }
    fn close_payload_check(
        &self,
        f: Format,
        r: &Request,
        decision: &Document,
        plan: Id,
        id: Id,
    ) -> Result<Id> {
        let head = self.snapshot("local-readback", BTreeSet::new())?;
        let readback = self.read(&head, id, "read")?;
        let result = if readback.field::<bool>("passed")? {
            "success"
        } else {
            "inconclusive"
        };
        self.document(
            &Document::new(
                Kind::Closure,
                &r.subject,
                &decision.scope,
                json!({
                    "attempt": r.attempt,
                    "result": result,
                    "planned_count": 1,
                    "completed_count": 1,
                    "reserved_costs": r.costs,
                    "exclusions": [],
                }),
                vec![
                    link("plan", plan),
                    link("decision", r.decision),
                    link("occurrence", id),
                ],
            )?,
            f,
            Id::blob(PUBLIC),
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub question: Id,
    pub proposals: BTreeSet<Id>,
    pub ceilings: std::collections::BTreeMap<String, u64>,
    pub objective: String,
    pub loss_unit: String,
}
impl Archive {
    /// Rank observational plans for one decision problem. Execution independently rechecks authority.
    pub fn select(&self, s: &Snapshot, request: &Selection, f: Format) -> Result<Id> {
        let question = self.read(s, request.question, "read")?;
        ensure!(
            question.kind == Kind::Question && !request.proposals.is_empty(),
            "need a question and proposed plans"
        );
        let losses: Vec<Vec<i64>> = question.field("losses")?;
        let prior: Vec<u64> = question.field("prior_masses")?;
        ensure!(
            !prior.is_empty() && prior.iter().any(|n| *n > 0),
            "no prior mass"
        );
        let mut best = None;
        let mut scores = vec![];
        let mut links = vec![link("question", request.question)];
        for &id in &request.proposals {
            links.push(link("proposal", id));
            let evaluation = (|| -> Result<ValueOfInformation> {
                let plan = self.read(s, id, "read")?;
                ensure!(
                    plan.kind == Kind::Plan
                        && plan.one("question")? == request.question
                        && plan.subject == question.subject
                        && plan.scope == question.scope,
                    "proposal outside question"
                );
                ensure!(
                    plan.field::<String>("objective")? == request.objective
                        && plan.field::<String>("action_type")? == "observation",
                    "incompatible objective or action"
                );
                let costs: std::collections::BTreeMap<String, u64> = plan.field("costs")?;
                ensure!(
                    costs
                        .iter()
                        .all(|(u, n)| request.ceilings.get(u).is_some_and(|cap| n <= cap)),
                    "resource ceiling"
                );
                let model: ObservationModel = plan.field("observation_model")?;
                ensure!(
                    model.loss_unit == request.loss_unit,
                    "incommensurate acquisition cost"
                );
                ensure!(
                    model.losses == losses
                        && model
                            .joint_masses
                            .iter()
                            .all(|row| row.len() == prior.len()),
                    "different decision problem"
                );
                for (i, &mass) in prior.iter().enumerate() {
                    ensure!(
                        model
                            .joint_masses
                            .iter()
                            .try_fold(0u64, |sum, row| sum.checked_add(row[i]))
                            == Some(mass),
                        "observation does not preserve registered prior masses"
                    );
                }
                model.evaluate()
            })();
            match evaluation {
                Ok(v) => {
                    scores.push(json!({"gain_numerator":v.net_gain_numerator.to_string(),"denominator":v.denominator.to_string()}));
                    if v.net_gain_numerator > 0 {
                        let better = match best {
                            None => true,
                            Some((_, num, den)) => v
                                .net_gain_numerator
                                .checked_mul(den)
                                .zip(v.denominator.checked_mul(num))
                                .map(|(a, b)| a > b)
                                .context("selection arithmetic overflow")?,
                        };
                        if better {
                            best = Some((id, v.net_gain_numerator, v.denominator));
                        }
                    }
                }
                Err(e) => scores.push(json!({"open":e.to_string()})),
            }
        }
        if let Some((id, _, _)) = best {
            links.push(link("selected", id));
        }
        let head = self.blob(&serde_json::to_vec(s)?, Id::blob(PUBLIC))?;
        links.push(link("snapshot", head));
        self.document(
            &Document::new(
                Kind::Selection,
                &question.subject,
                &question.scope,
                json!({
                    "objective": request.objective,
                    "criterion": "positive expected reduction in loss after acquisition cost",
                    "loss_unit": request.loss_unit,
                    "ceilings": request.ceilings,
                    "scores_in_proposal_order": scores,
                    "tie_rule": "ascending content identifier",
                    "status": if best.is_some(){"selected"}else{"abstained"},
                }),
                links,
            )?,
            f,
            Id::blob(PUBLIC),
        )
    }
}
