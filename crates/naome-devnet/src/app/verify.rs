use super::{Result, config::RoleConfig, hex, workload};
use naome_consensus::ConsensusHeight;
use naome_storage::{FixedValidatorAnchoredFinalityJournalV0, FixedValidatorFinalityReplayLimitV0};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn verify(root: &Path, height: usize) -> Result<Value> {
    let role = RoleConfig::load(root)?;
    if role.publisher || height == 0 || height > role.deployment.heights {
        return Err("validator role and configured height required".into());
    }
    let d = role.deployment;
    let journal = FixedValidatorAnchoredFinalityJournalV0::open(
        root.join("finality-journal"),
        root.join("finality-anchor"),
        d.definition()?,
        d.context()?,
        &d.entries()?,
        FixedValidatorFinalityReplayLimitV0::new(64)?,
    )?;
    if journal.halt()?.is_some() || journal.finalized_len()? != height {
        return Err("halted or incomplete finality history".into());
    }
    let expected = workload::prefix(d.definition()?, height)?;
    let mut digest = Sha256::new();
    let mut previous = None;
    for (i, (block, payload)) in expected.iter().enumerate() {
        let record = journal
            .finality_record(ConsensusHeight::new(i as u64 + 1))?
            .ok_or("missing finalized height")?;
        if record.value().artifact_block() != *block || record.canonical_artifact_bytes() != payload
        {
            return Err("finalized workload differs".into());
        }
        if previous.is_some_and(|ancestry| ancestry != record.value().parent_ancestry_id()) {
            return Err("finality ancestry gap".into());
        }
        previous = Some(record.value().ancestry_id());
        digest.update(record.value().ancestry_id().as_bytes());
    }
    Ok(
        json!({"event":"devnet_verified","role":role.name,"height":height,"head":hex(journal.artifact_head_block_id()?.as_bytes()),"ancestry_sha256":hex(&digest.finalize()),"verification":"anchored_finality_replay_and_exact_workload"}),
    )
}
