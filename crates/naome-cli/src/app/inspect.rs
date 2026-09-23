use super::{Result, files};
use naome_ledger::{LedgerState, OperationId, receipt::NormalizationReceipt, state::FamilyResult};
use serde_json::{Value, json};

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
            let decoded =
                NormalizationReceipt::decode_recorded(normalization_receipt, state.genesis())?;
            value["outcome"] = json!(format!("{outcome:?}").to_uppercase());
            value["completion_ordinal"] = json!(ordinal);
            value["normalization"] = receipt(&decoded);
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

pub fn compiled_question(question: &naome_ledger::question::CompiledQuestion) -> Value {
    json!({"verification":"well-formed formal obligation; mathematical truth not established","profile":files::hex(question.profile_id().as_bytes()),"family":files::hex(question.resolution_id().as_bytes()),"source":question.source(),"R":question.positive_target().to_source(),"not_R":question.negative_target().to_source(),"submitted_negation_parity":question.negation_parity()})
}
