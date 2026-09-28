use super::{Result, files};
use naome_ledger::{LedgerState, OperationId, receipt::NormalizationReceipt, state::FamilyResult};
use naome_proof::ProofId;
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::BTreeMap;

/// Human-readable summary of the fixed research admission rules. Numerical
/// ceilings remain in the immutable profile's `limits` output.
pub fn research_policy() -> Value {
    json!({
        "question_source": {
            "required_fields": ["foundation = \"naome:zfc\"", "statement = <closed formula>"],
            "optional_field": "success = \"resolve\"",
            "assumptions": "unsupported",
            "library_references": "unsupported in question source",
            "definitions": "unsupported in question source"
        },
        "solution_admission": {
            "new_objects": "root and bounded helper proof certificates only",
            "older_references": "selected sealed-parent proofs, checked with dependency closure",
            "duplicate_helper_replacement": "automatic for matching StatementId and exact canonical conclusion in the sealed parent",
            "definitions": "offline authoring only; not published by settlement",
            "resource_bounds": "immutable genesis profile limits; no per-question override"
        }
    })
}

pub fn receipt(value: &NormalizationReceipt) -> Value {
    json!({"round":files::hex(value.round.as_bytes()),"winning_commit":{"operation":files::hex(value.winning_commit.operation.as_bytes()),"height":value.winning_commit.coordinate.height,"operation_index":value.winning_commit.coordinate.operation_index},"commitment":files::hex(value.commitment.as_bytes()),"original_hash":files::hex(value.original_hash.as_bytes()),"parent_state":files::hex(value.parent.as_bytes()),"profile":files::hex(value.profile.as_bytes()),"normalized_root":files::hex(value.root.as_bytes()),"author":files::hex(value.author.as_bytes()),"substitutions":value.substitutions.iter().map(|(old,new)|json!({"original":files::hex(old.as_bytes()),"replacement":files::hex(new.as_bytes())})).collect::<Vec<_>>(),"new_proofs":value.new_proofs.iter().map(|(proof,author)|json!({"proof":files::hex(proof.as_bytes()),"recipient":files::hex(author.as_bytes())})).collect::<Vec<_>>(),"citation_payments":value.rewards.citations().iter().map(|(proof,recipient,atoms)|json!({"proof":files::hex(proof.as_bytes()),"recipient":files::hex(recipient.as_bytes()),"atoms":atoms.to_string()})).collect::<Vec<_>>(),"credits":value.rewards.credits().iter().map(|(account,atoms)|json!({"account":files::hex(account.as_bytes()),"atoms":atoms.to_string()})).collect::<Vec<_>>(),"reserve_atoms":value.rewards.reserve().to_string()})
}
pub fn question(state: &LedgerState, id: OperationId) -> Result<Value> {
    let q = state.question(id).ok_or("question not finalized")?;
    let mut value = json!({"status":format!("{:?}",q.status()),"source":q.question().source(),"purpose":q.purpose(),"author":files::hex(q.author().as_bytes()),"family":files::hex(q.question().resolution_id().as_bytes()),"question":q.opened_question().map(|v|files::hex(v.as_bytes())),"expires":q.expires(),"formal_targets":{"R":q.question().positive_target().to_source(),"not_R":q.question().negative_target().to_source(),"submitted_negation_parity":q.question().negation_parity()},"admission":{"height":q.admitted().height,"operation_index":q.admitted().operation_index}});
    match state.families().get(&q.question().resolution_id()) {
        Some(FamilyResult::KnownUnpaid { proof }) => {
            value["known_proof"] = json!(files::hex(proof.as_bytes()));
            value["completion_reward_atoms"] = json!("0");
        }
        Some(FamilyResult::Completed {
            proof,
            outcome,
            ordinal,
            normalization_receipt,
            ..
        }) => {
            value["outcome"] = json!(format!("{outcome:?}").to_uppercase());
            value["completion_ordinal"] = json!(ordinal);
            let recorded_genesis = normalization_receipt
                .get(2..34)
                .ok_or("historical normalization receipt truncated")?;
            value["normalization"] = if recorded_genesis == state.genesis().id().as_bytes() {
                receipt(&NormalizationReceipt::decode_recorded(
                    normalization_receipt,
                    state.genesis(),
                )?)
            } else if state.genesis().predecessor().is_some() {
                json!({
                    "historical_genesis": files::hex(recorded_genesis),
                    "recorded_sha256": files::hex(&sha2::Sha256::digest(normalization_receipt)),
                    "recorded_len": normalization_receipt.len(),
                    "detail": "inspect the original run archive for the decoded receipt"
                })
            } else {
                return Err("normalization receipt belongs to another genesis".into());
            };
            let selected = state
                .library()
                .lookup(*proof)
                .ok_or("completed root absent")?;
            value["checked_conclusion"] = json!(selected.conclusion().to_source());
            let family = q.question().resolution_id();
            let active_rights = state.authority().units().iter().any(|unit| {
                matches!(unit.origin(), naome_ledger::authority::UnitOrigin::Earned { family: selected, .. } if selected == family)
                    && unit.keys().is_some() && !state.terminated()
            });
            value["eligibility_claim"]=json!(state.claims().get(&family).map(|c|json!({"author":files::hex(c.author.as_bytes()),"ordinal":c.completion_ordinal,"consumed":state.consumed_claims().contains(&family),"active_voting_rights":active_rights})));
            value["join_intent"] = json!(state.join_intent(q.question().resolution_id()).map(
                |entry| {
                    let intent = entry.intent();
                    let receipt = entry.receipt();
                    json!({
                        "status": if state.consumed_claims().contains(&family) { "CONSUMED" }
                            else if entry.expires() <= state.time() { "EXPIRED" } else { "QUEUED" },
                        "operation": files::hex(receipt.operation.as_bytes()),
                        "author": files::hex(receipt.author.as_bytes()),
                        "completion_ordinal": intent.completion_ordinal(),
                        "consensus_key": files::hex(intent.consensus_key()),
                        "transport_key": files::hex(intent.transport_key()),
                        "endpoint": intent.endpoint(),
                        "height": receipt.coordinate.height,
                        "operation_index": receipt.coordinate.operation_index,
                        "active_voting_rights": active_rights,
                        "expires": entry.expires(),
                        "first_admission_height": entry.first_receipt().coordinate.height,
                        "first_admission_operation_index": entry.first_receipt().coordinate.operation_index,
                    })
                }
            ));
        }
        None => {}
    }
    Ok(value)
}

// Successors restart heights. A cursor belongs to one selected state snapshot.
fn result_snapshot(state: &LedgerState) -> String {
    let mut digest = sha2::Sha256::new();
    digest.update(state.genesis().id().as_bytes());
    digest.update(state.head().as_bytes());
    files::hex(&digest.finalize())
}
fn result_cursor(state: &LedgerState, height: u64, index: u32, id: OperationId) -> String {
    format!(
        "{}{height:016x}{index:08x}{}",
        result_snapshot(state),
        files::hex(id.as_bytes())
    )
}

pub fn results(state: &LedgerState, cursor: Option<&str>, limit: u8) -> Result<Value> {
    if !(1..=20).contains(&limit) {
        return Err("result page limit must be 1 through 20".into());
    }
    let after = match cursor {
        Some(value) => {
            if value.len() != 152 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid result cursor".into());
            }
            if value[..64] != result_snapshot(state) {
                return Err("result cursor is stale; restart discovery".into());
            }
            let height = u64::from_str_radix(&value[64..80], 16)?;
            let index = u32::from_str_radix(&value[80..88], 16)?;
            let id = OperationId::from_bytes(files::unhex(&value[88..])?);
            Some((height, index, id))
        }
        None => None,
    };
    let mut entries = BTreeMap::new();
    let mut found_cursor = after.is_none();
    for q in state.questions() {
        let key = (
            q.admitted().height,
            q.admitted().operation_index,
            q.submission(),
        );
        if after == Some(key) {
            found_cursor = true;
        }
        if after.is_some_and(|previous| key <= previous) {
            continue;
        }
        entries.insert(key, q);
        if entries.len() > usize::from(limit) + 1 {
            entries.pop_last();
        }
    }
    if !found_cursor {
        return Err("result cursor does not name a finalized question".into());
    }
    let mut page = Vec::new();
    let mut next = None;
    for ((height, index, id), q) in entries {
        if page.len() == usize::from(limit) {
            next = page
                .last()
                .map(|(cursor, _): &(String, Value)| cursor.clone());
            break;
        }
        let family = state.families().get(&q.question().resolution_id());
        let root = match family {
            Some(FamilyResult::Completed { proof, .. } | FamilyResult::KnownUnpaid { proof }) => {
                Some(files::hex(proof.as_bytes()))
            }
            None => None,
        };
        let cursor = result_cursor(state, height, index, id);
        page.push((cursor.clone(),json!({"submission":files::hex(id.as_bytes()),"cursor":cursor,
            "purpose":q.purpose(),
            "status":format!("{:?}",q.status()),"family":files::hex(q.question().resolution_id().as_bytes()),
            "root_proof":root,"admission":{"height":height,"operation_index":index}})));
    }
    Ok(
        json!({"status":"node_finalized_view","height":state.height(),"head":files::hex(state.head().as_bytes()),
        "items":page.into_iter().map(|(_,value)|value).collect::<Vec<_>>(),"next_cursor":next,
        "notice":"node view; independently replay an archive to verify finality"}),
    )
}

pub fn result_detail(state: &LedgerState, id: OperationId) -> Result<Value> {
    let q = state
        .question(id)
        .ok_or("question not in finalized state")?;
    let family = state.families().get(&q.question().resolution_id());
    let (root, outcome) = match family {
        Some(FamilyResult::Completed { proof, outcome, .. }) => (
            Some(files::hex(proof.as_bytes())),
            Some(format!("{outcome:?}").to_uppercase()),
        ),
        Some(FamilyResult::KnownUnpaid { proof }) => (Some(files::hex(proof.as_bytes())), None),
        None => (None, None),
    };
    Ok(
        json!({"status":"node_finalized_view","submission":files::hex(id.as_bytes()),
        "question_status":format!("{:?}",q.status()),"source":q.question().source(),
        "purpose":q.purpose(),"author":files::hex(q.author().as_bytes()),
        "question":q.opened_question().map(|id|files::hex(id.as_bytes())),
        "family":files::hex(q.question().resolution_id().as_bytes()),
        "formal_targets":{"R":q.question().positive_target().to_source(),
            "not_R":q.question().negative_target().to_source()},
        "root_proof":root,"outcome":outcome,
        "admission":{"height":q.admitted().height,"operation_index":q.admitted().operation_index},
        "height":state.height(),"head":files::hex(state.head().as_bytes()),
        "notice":"node view; independently replay an archive to verify finality"}),
    )
}

pub fn result_proof(state: &LedgerState, id: ProofId) -> Result<Value> {
    let proof = state
        .library()
        .lookup(id)
        .ok_or("proof not in finalized library")?;
    let limits = state.genesis().profile().limits();
    if proof.canonical_bytes().len() > limits.certificate_bytes as usize {
        return Err("selected proof exceeds response bound".into());
    }
    Ok(
        json!({"status":"node_finalized_view","proof":files::hex(id.as_bytes()),
        "bytes":files::hex(proof.canonical_bytes()),"dependencies":proof.dependencies().iter()
            .map(|id|files::hex(id.as_bytes())).collect::<Vec<_>>(),
        "statement":files::hex(proof.statement_id().as_bytes()),
        "conclusion":proof.conclusion().to_source(),
        "author":files::hex(proof.author().as_bytes()),
        "admission":{"height":proof.coordinate().height,"operation_index":proof.coordinate().operation_index},
        "height":state.height(),"head":files::hex(state.head().as_bytes()),
        "notice":"check certificate mathematics locally; archive replay separately verifies finality"}),
    )
}

pub fn compiled_question(question: &naome_ledger::question::CompiledQuestion) -> Value {
    json!({"verification":"well-formed formal obligation; mathematical truth not established","profile":files::hex(question.profile_id().as_bytes()),"family":files::hex(question.resolution_id().as_bytes()),"source":question.source(),"R":question.positive_target().to_source(),"not_R":question.negative_target().to_source(),"submitted_negation_parity":question.negation_parity()})
}

#[cfg(test)]
mod policy_tests {
    use super::research_policy;
    use naome_ledger::{profile::Profile, question::CompiledQuestion};

    #[test]
    fn policy_preview_matches_question_admission() {
        let policy = research_policy();
        let prefix = "foundation = \"naome:zfc\" statement = forall(x,equal(x,x))";
        assert!(CompiledQuestion::compile(prefix, &Profile::lab()).is_ok());
        assert!(
            CompiledQuestion::compile(&format!("{prefix} success = \"resolve\""), &Profile::lab())
                .is_ok()
        );
        for field in [
            "assumptions = []",
            "references = []",
            "allow_substitution = false",
        ] {
            assert!(
                CompiledQuestion::compile(&format!("{prefix} {field}"), &Profile::lab()).is_err()
            );
        }
        assert_eq!(policy["question_source"]["assumptions"], "unsupported");
        assert_eq!(
            policy["question_source"]["library_references"],
            "unsupported in question source"
        );
        assert_eq!(
            policy["solution_admission"]["resource_bounds"],
            "immutable genesis profile limits; no per-question override"
        );
    }
}
