//! Read-only canonical archive replay shared by the operator and verifier.
//! No control socket, private key, signing, or state-directory writes are used.

use naome_consensus::state::StateBranch;
use naome_ledger::{LedgerState, PackageHash, operations::SignedOriginal, profile::Genesis};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::Path};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) version: u16,
    pub(crate) genesis: String,
    pub(crate) head: String,
    pub(crate) state: String,
    pub(crate) height: u64,
    pub(crate) maximum_round: u64,
}

pub(crate) struct ReplayedArchive {
    pub(crate) branch: StateBranch,
    pub(crate) originals: BTreeMap<PackageHash, SignedOriginal>,
}

pub(crate) fn replay(
    genesis_path: &Path,
    root: &Path,
    inspected: Option<&str>,
) -> Result<ReplayedArchive> {
    let genesis = Genesis::decode(&read(genesis_path, 16384)?)?;

    let manifest: Manifest = serde_json::from_slice(&read(&root.join("manifest.json"), 16384)?)?;
    if manifest.version != 1
        || manifest.genesis != hex(genesis.id().as_bytes())
        || manifest.height > genesis.profile().limits().run_records
        || manifest.maximum_round > genesis.profile().limits().consensus_rounds
    {
        return Err("archive manifest context or bounds mismatch".into());
    }
    let maximum = genesis.profile().limits().transport_frame_bytes as usize;
    let mut branch = StateBranch::from_genesis(LedgerState::new(genesis.clone()))?;
    let mut originals = std::collections::BTreeMap::new();
    for height in 1..=manifest.height {
        let bytes = read(&root.join(format!("{height:08}.finality")), maximum)?;
        let finality = branch.decode_finality(&bytes, manifest.maximum_round)?;
        if inspected.is_some()
            && branch
                .state()
                .active()
                .is_some_and(|a| inspected == Some(hex(a.submission.as_bytes()).as_str()))
        {
            let record =
                naome_chain::StateRecord::decode(finality.proposal().record_bytes(), &genesis)?;
            for operation in record.operations() {
                if let naome_ledger::operations::OperationBody::Reveal { original, .. } =
                    naome_ledger::operations::OperationBody::decode(operation.payload(), &genesis)?
                {
                    originals.insert(original.original_hash(), original);
                }
            }
        }
        branch = finality.into_branch();
    }
    if manifest.head != hex(branch.state().head().as_bytes())
        || manifest.state != hex(branch.state().commitment().as_bytes())
    {
        return Err("replayed tip does not match archive manifest".into());
    }
    Ok(ReplayedArchive { branch, originals })
}

pub(crate) fn verify(genesis_path: &Path, root: &Path) -> Result<Value> {
    let archive = replay(genesis_path, root, None)?;
    debug_assert!(archive.originals.is_empty());
    let mut report = status(archive.branch.state());
    report["verification"] = json!("independent full finality and mathematical replay");
    report["consensus_commitment"] = json!(hex(&archive.branch.commitment()));
    Ok(report)
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = regular(path)?;
    if file.metadata()?.len() > maximum as u64 {
        return Err("archive input is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("archive input grew beyond its size limit".into());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn regular(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::File::options()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("archive input is not a regular file".into());
    }
    Ok(file)
}

#[cfg(windows)]
#[path = "archive_windows.rs"]
mod windows;
#[cfg(windows)]
use windows::regular;

#[cfg(not(any(unix, windows)))]
fn regular(_: &Path) -> Result<std::fs::File> {
    Err("archive input unsupported on this platform".into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn status(state: &LedgerState) -> Value {
    let active = state.active().map(|attempt| json!({
        "submission": hex(attempt.submission.as_bytes()),
        "question": hex(attempt.question.as_bytes()),
        "family": hex(attempt.family.as_bytes()),
        "attempt": attempt.number,
        "phase": format!("{:?}", attempt.phase),
        "deadline": attempt.deadline,
        "round": attempt.solution_round.map(|round| hex(round.as_bytes())),
        "electorate": attempt.electorate.iter().map(|owner| hex(owner.as_bytes())).collect::<Vec<_>>(),
        "votes": attempt.votes.iter().map(|(owner, yes)| json!({
            "owner": hex(owner.as_bytes()), "yes": yes,
        })).collect::<Vec<_>>(),
        "commitments": attempt.commitments,
        "reveals": attempt.reveals,
    }));
    let validators = state
        .authority()
        .units()
        .iter()
        .enumerate()
        .map(|(index, unit)| {
            json!({
                "index": index,
                "slot": hex(unit.slot().as_bytes()),
                "unit": hex(unit.id().as_bytes()),
                "owner": hex(unit.owner().as_bytes()),
                "endpoint": unit.keys().map(|keys| keys.endpoint()),
                "consensus_key": unit.keys().map(|keys| hex(keys.consensus())),
                "transport_key": unit.keys().map(|keys| hex(keys.transport())),
                "available": unit.keys().is_some() && !state.terminated(),
            })
        })
        .collect::<Vec<_>>();
    let accounts = state
        .balances()
        .accounts()
        .iter()
        .map(|(account, balance)| {
            json!({
                "account": hex(account.as_bytes()),
                "balance_atoms": balance.to_string(),
                "next_nonce": state.next_nonce(*account),
            })
        })
        .collect::<Vec<_>>();
    let claims = state
        .claims()
        .values()
        .map(|claim| {
            json!({
                "family": hex(claim.family.as_bytes()),
                "author": hex(claim.author.as_bytes()),
                "ordinal": claim.completion_ordinal,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "status": "finalized",
        "genesis": hex(state.genesis().id().as_bytes()),
        "profile": hex(state.genesis().profile().id().as_bytes()),
        "height": state.height(),
        "head": hex(state.head().as_bytes()),
        "state": hex(state.commitment().as_bytes()),
        "time": state.time(),
        "active": active,
        "library_root": hex(&state.library().root()),
        "proof_count": state.library().len(),
        "queued": state.queued().count(),
        "registered_accounts": state.accounts().len(),
        "remaining_account_slots": state.genesis().profile().limits().registered_accounts
            .saturating_sub(state.accounts().len() as u64),
        "registration_available": state.registration_available(),
        "accounts": accounts,
        "authority": {
            "id": hex(&state.authority().id()),
            "effective_height": state.authority().effective_height(),
            "active_slots": state.authority().active_count(),
            "terminated": state.terminated(),
        },
        "validators": validators,
        "reserve_atoms": state.balances().reserve().to_string(),
        "paid_completions": state.balances().paid_completions(),
        "join_intents_count": state.join_intents().len(),
        "join_queue": state.join_queue().iter().map(|family| hex(family.as_bytes())).collect::<Vec<_>>(),
        "consumed_claims": state.consumed_claims().iter().map(|family| hex(family.as_bytes())).collect::<Vec<_>>(),
        "claims": claims,
        "remaining_records": state.remaining_records(),
        "reserved_records": state.reserved_records(),
        "remaining_bytes": state.remaining_bytes(),
        "reserved_bytes": state.reserved_bytes(),
        "terminated": state.terminated(),
    })
}
