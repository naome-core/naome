//! Current native rows and their derived indexes are checked before recovery.
use super::*;

const CHECKED_EXAMPLES: usize = 128;
const CHECKED_ARTIFACTS: usize = 64;

/// Reuse only exact checks within one journal scan. Each reference still
/// checks its own source row, sample, provenance and admission receipt.
#[derive(Default)]
struct CheckedReplay {
    examples: std::collections::BTreeSet<String>,
    artifacts: std::collections::BTreeMap<u64, (String, naome_proof::ArtifactId)>,
}

impl CheckedReplay {
    fn matches(
        &mut self,
        example: &crate::learning::Example,
        solution: &crate::learning::Solution,
    ) -> bool {
        let key = crate::learning::digest(&(example, solution));
        if self.examples.contains(&key) {
            return true;
        }
        if !example.matches_solution(solution) {
            return false;
        }
        if self.examples.len() < CHECKED_EXAMPLES {
            self.examples.insert(key);
        }
        true
    }

    fn artifact(
        &mut self,
        job: u64,
        solution: &crate::learning::Solution,
        question: &str,
    ) -> Result<naome_proof::ArtifactId, crate::Error> {
        let binding = crate::learning::digest(&(question, solution));
        if let Some((previous, artifact)) = self.artifacts.get(&job)
            && *previous == binding
        {
            return Ok(*artifact);
        }
        let artifact = crate::learning::program::Candidate::artifact(solution, question)?;
        if self.artifacts.len() < CHECKED_ARTIFACTS || self.artifacts.contains_key(&job) {
            self.artifacts.insert(job, (binding, artifact));
        }
        Ok(artifact)
    }
}

fn record(c: &crate::checkpoint::Checkpoint, id: u64) -> Result<Record, crate::Error> {
    c.get("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
        .ok_or(crate::ResearchFailure::JournalNativeSourceJobMissing.into())
}
fn refs(
    c: &crate::checkpoint::Checkpoint,
    owner: &str,
    state: Option<&crate::learning::State>,
) -> Result<Vec<crate::learning::Blob>, crate::Error> {
    let mut refs = if owner == "global" {
        state.into_iter().flat_map(|s| s.blobs().cloned()).collect()
    } else {
        let id = owner
            .strip_prefix("job")
            .ok_or(crate::ResearchFailure::JournalNativeModelOwnerSyntax)?
            .parse::<u64>()
            .map_err(|_| crate::ResearchFailure::JournalNativeModelOwnerIdentity)?;
        if id == 0 || owner != format!("job{id}") {
            return Err(crate::ResearchFailure::JournalNativeModelOwnerEncoding.into());
        }
        Disk::record_model_refs(&record(c, id)?)
    };
    refs.sort();
    refs.dedup();
    Ok(refs)
}
fn owner(
    c: &crate::checkpoint::Checkpoint,
    key: &str,
) -> Result<Vec<crate::learning::Blob>, crate::Error> {
    Ok(
        c.get("model_owner", key, crate::resources::limits().closure_bytes)?
            .unwrap_or_default(),
    )
}
pub(super) fn validate_source(
    c: &crate::checkpoint::Checkpoint,
    example: &crate::learning::Example,
    source: &Record,
) -> Result<(), crate::Error> {
    validate_source_with(c, example, source, None)
}

fn validate_source_with(
    c: &crate::checkpoint::Checkpoint,
    example: &crate::learning::Example,
    source: &Record,
    mut checked: Option<&mut CheckedReplay>,
) -> Result<(), crate::Error> {
    let q = naome_checker::question::ResearchQuestion::from_hex(&example.question)?;
    if c.get::<u64>("sample", &crate::hex(q.resolution_id()), 64)?
        .is_none()
        || c.get::<u64>("replay_seen", &example.proof_id, 64)? != Some(example.job)
    {
        return Err(crate::ResearchFailure::ReplaySampleMismatch.into());
    }
    let Some(Output::Native {
        solution: Some(solution),
        ..
    }) = &source.result
    else {
        return Err(crate::ResearchFailure::ReplayResultMissing.into());
    };
    if source.id != example.job
        || source.state != State::Complete
        || solution.proof_id != example.proof_id
        || solution.refuted != example.refuted
        || !match checked.as_deref_mut() {
            Some(memo) => memo.matches(example, solution),
            None => example.matches_solution(solution),
        }
    {
        return Err(crate::ResearchFailure::ReplayIdentityMismatch.into());
    }
    match (&example.origin, &source.input) {
        (crate::learning::Origin::Local, Input::Solve { question })
            if question == &example.question =>
        {
            let root = match checked {
                Some(memo) => memo.artifact(source.id, solution, question),
                None => crate::learning::program::Candidate::artifact(solution, question),
            }?;
            if c.get::<String>("learned", &example.job.to_string(), 256)?
                .as_deref()
                != Some(&crate::hex(root.as_bytes()))
            {
                return Err(crate::ResearchFailure::ReplayOwnReceiptMissing.into());
            }
        }
        (
            crate::learning::Origin::Peer { artifact, peer },
            Input::Peer {
                question,
                artifact: actual,
                peer: supplier,
                evidence,
            },
        ) if question == &example.question && artifact == actual && peer == supplier => {
            crate::learning::peer::validate_source(question, artifact, evidence, solution)?;
            let receipt: PeerReceipt = c
                .get(
                    "peer_receipt",
                    artifact,
                    crate::resources::limits().closure_bytes,
                )?
                .ok_or(crate::ResearchFailure::ReplayPeerReceiptMissing)?;
            if !matches!(receipt.status,PeerStatus::Learned{conversion_job,ref trace_proof} if conversion_job==example.job && trace_proof==&example.proof_id)
            {
                return Err(crate::ResearchFailure::ReplayPeerReceiptMismatch.into());
            }
        }
        _ => return Err(crate::ResearchFailure::ReplayProvenanceMismatch.into()),
    }
    Ok(())
}
fn validate_sources(
    c: &crate::checkpoint::Checkpoint,
    state: &crate::learning::State,
    checked: &mut CheckedReplay,
) -> Result<(), crate::Error> {
    for example in state.examples() {
        validate_source_with(c, example, &record(c, example.job)?, Some(checked))?;
    }
    for experience in state.meta_experiences() {
        let source = record(c, experience.job)?;
        let update = source
            .native
            .as_ref()
            .and_then(|n| n.progress.as_ref())
            .and_then(|p| p.meta_update.as_ref())
            .ok_or(crate::ResearchFailure::JournalMetaTrialSourceUpdateAbsent)?;
        if !matches!(source.input, Input::Train { .. })
            || source.state != State::Complete
            || crate::learning::digest(&update.experience) != crate::learning::digest(experience)
        {
            return Err(
                crate::ResearchFailure::JournalMetaTrialExperienceDiffersFromItsOriginalOwnedJob
                    .into(),
            );
        }
    }
    Ok(())
}
pub(in crate::jobs::journal) fn validate_rows(
    c: &crate::checkpoint::Checkpoint,
    state: Option<&crate::learning::State>,
) -> Result<(), crate::Error> {
    if c.count("learning")? != 1 {
        return Err(crate::ResearchFailure::JournalNativeLearningSingletonDiffers.into());
    }
    let mut checked = CheckedReplay::default();
    if let Some(state) = state {
        validate_sources(c, state, &mut checked)?;
    }
    c.scan("record", crate::checkpoint::MAX_ROW, |key, bytes| {
        let source: Record = crate::checkpoint::decode(bytes)?;
        if let Some(native) = &source.native {
            for evidence in &native.evidence {
                let origin = record(c, evidence.job)?;
                let Some(Output::Native {
                    solution: Some(solution),
                    ..
                }) = &origin.result
                else {
                    return Err(crate::ResearchFailure::JournalNativeReplaySnapshotResultMissing.into());
                };
                if origin.state != State::Complete
                    || solution.proof_id != evidence.proof_id
                    || crate::learning::digest(&solution.tree)
                        != crate::learning::digest(&evidence.trace)
                {
                    return Err(crate::ResearchFailure::JournalNativeReplaySnapshotSourceDiffers.into());
                }
                match &origin.input {
                    Input::Peer {
                        question,
                        artifact,
                        evidence,
                        ..
                    } => crate::learning::peer::validate_source(
                        question, artifact, evidence, solution,
                    )?,
                    Input::Solve { question } => {
                        let expected =
                            crate::hex(checked.artifact(origin.id, solution, question)?.as_bytes());
                        if c.get::<String>("learned", &origin.id.to_string(), 256)?
                            .as_deref()
                            != Some(expected.as_str())
                        {
                            return Err(crate::ResearchFailure::JournalNativeSnapshotLacksAdmittedLocalReceipt.into());
                        }
                    }
                    _ => return Err(crate::ResearchFailure::JournalNativeReplaySnapshotOriginRoleDiffers.into()),
                }
            }
        }
        let expected = Disk::record_model_refs(&source);
        if owner(c, &format!("job{key}"))? != expected {
            return Err(crate::ResearchFailure::JournalNativeRecordModelOwnerIndexDiffers.into());
        }
        if !source.acknowledged
            && let Some(native) = &source.native
        {
            validate_sources(c, &native.base, &mut checked)?;
        }
        Ok(())
    })?;
    if owner(c, "global")? != refs(c, "global", state)? {
        return Err(crate::ResearchFailure::JournalNativeGlobalModelOwnerIndexDiffers.into());
    }
    c.scan(
        "model_owner",
        crate::resources::limits().closure_bytes,
        |key, bytes| {
            let actual: Vec<crate::learning::Blob> = crate::checkpoint::decode(bytes)?;
            if actual.is_empty() || actual != refs(c, key, state)? {
                return Err(crate::ResearchFailure::JournalNativeModelOwnerIndexDiffers.into());
            }
            for blob in actual {
                blob.validate()?;
                if c.get::<crate::learning::Blob>(
                    "model_use",
                    &format!("{}:{key}", blob.sha256),
                    4096,
                )?
                .as_ref()
                    != Some(&blob)
                {
                    return Err(crate::ResearchFailure::JournalNativeModelUseIndexMissing.into());
                }
            }
            Ok(())
        },
    )?;
    c.scan("model_use", 4096, |key, bytes| {
        let blob: crate::learning::Blob = crate::checkpoint::decode(bytes)?;
        blob.validate()?;
        let (hash, name) = key
            .split_once(':')
            .ok_or(crate::ResearchFailure::JournalNativeModelUseKey)?;
        if hash != blob.sha256 || !owner(c, name)?.contains(&blob) {
            return Err(crate::ResearchFailure::JournalNativeModelUseOwnerDiffers.into());
        }
        Ok(())
    })?;
    c.scan("model_gc", 4096, |key, bytes| {
        let blob: crate::learning::Blob = crate::checkpoint::decode(bytes)?;
        blob.validate()?;
        if key != blob.sha256 {
            return Err(crate::ResearchFailure::JournalNativeModelReclamationKeyDiffers.into());
        }
        Ok(())
    })?;
    c.scan(
        "model",
        crate::resources::limits().native_model_chunk_bytes,
        |key, bytes| {
            let (hash, index) = key
                .split_once(':')
                .ok_or(crate::ResearchFailure::JournalNativeModelChunkKey)?;
            let index = index
                .parse::<usize>()
                .map_err(|_| crate::ResearchFailure::JournalNativeModelChunkIndex)?;
            let uses = c.page("model_use", Some(&format!("{hash}:")), 1, 4096)?;
            let blob = if let Some((name, payload)) = uses
                .first()
                .filter(|(name, _)| name.starts_with(&format!("{hash}:")))
            {
                let _ = name;
                crate::checkpoint::decode(payload)?
            } else {
                c.get::<crate::learning::Blob>("model_gc", hash, 4096)?
                    .ok_or(
                    crate::ResearchFailure::JournalNativeModelChunkHasNoOwnerOrReclamationReceipt,
                )?
            };
            if key != blob.key(index) || bytes.len() != blob.chunk_len(index)? {
                return Err(
                    crate::ResearchFailure::JournalNativeModelChunkIdentityOrLengthDiffers.into(),
                );
            }
            Ok(())
        },
    )?;
    c.scan("replay_seen", 64, |key, bytes| {
        crate::object::id_bytes(key)?;
        let id: u64 = crate::checkpoint::decode(bytes)?;
        let source = record(c, id)?;
        if source.state != State::Complete || !source.acknowledged
            || !matches!(&source.result, Some(Output::Native { solution: Some(s), .. }) if s.proof_id == key) {
            return Err(crate::ResearchFailure::JournalSeenProofSourceDiffers.into());
        }
        Ok(())
    })?;
    c.scan("learned", 256, |key, bytes| {
        validate_learned(c, key, bytes, &mut checked)
    })?;
    c.scan(
        "peer_receipt",
        crate::resources::limits().closure_bytes,
        |key, bytes| validate_peer(c, state, key, bytes),
    )?;
    let mut local = 0u64;
    let mut peer = 0u64;
    c.scan("sample", 64, |key, bytes| {
        match validate_sample(c, key, bytes)? {
            true => peer += 1,
            false => local += 1,
        }
        Ok(())
    })?;
    if let Some(s) = state {
        if s.sample_counts() != (local, peer) {
            return Err(crate::ResearchFailure::JournalNativeSampleProvenanceCountersDiffer.into());
        }
    } else if local + peer > 0 {
        return Err(crate::ResearchFailure::JournalNativeSamplesLackLearningState.into());
    }
    c.scan(
        "peer_pending",
        crate::resources::limits().closure_bytes,
        |key, bytes| {
            let a: PeerAdmission = crate::checkpoint::decode(bytes)?;
            let receipt: PeerReceipt = c
                .get(
                    "peer_receipt",
                    &a.artifact,
                    crate::resources::limits().closure_bytes,
                )?
                .ok_or(crate::ResearchFailure::JournalPeerPendingReceiptMissing)?;
            if key != format!("{:020}", a.ordinal)
                || receipt.admission != a
                || !matches!(receipt.status, PeerStatus::Queued)
            {
                return Err(crate::ResearchFailure::JournalPeerPendingSourceDiffers.into());
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn validate_learned(
    c: &crate::checkpoint::Checkpoint,
    key: &str,
    bytes: &[u8],
    checked: &mut CheckedReplay,
) -> Result<(), crate::Error> {
    let id = key
        .parse::<u64>()
        .map_err(|_| crate::ResearchFailure::JournalOwnLearningReceiptIdentity)?;
    let root: String = crate::checkpoint::decode(bytes)?;
    crate::object::id_bytes(&root)?;
    let source = record(c, id)?;
    let matching = if let (
        Some(Output::Native {
            solution: Some(solution),
            ..
        }),
        Input::Solve { question },
    ) = (&source.result, &source.input)
    {
        let expected = checked.artifact(source.id, solution, question)?;
        crate::hex(expected.as_bytes()) == root
    } else {
        false
    };
    if id == 0
        || key != id.to_string()
        || !source.acknowledged
        || source.state != State::Complete
        || !matches!(source.input, Input::Solve { .. })
        || !matching
    {
        return Err(crate::ResearchFailure::JournalOwnLearningAdmissionReceiptDiffers.into());
    }
    Ok(())
}
fn validate_peer(
    c: &crate::checkpoint::Checkpoint,
    state: Option<&crate::learning::State>,
    key: &str,
    bytes: &[u8],
) -> Result<(), crate::Error> {
    let receipt: PeerReceipt = crate::checkpoint::decode(bytes)?;
    let a = &receipt.admission;
    crate::object::id_bytes(key)?;
    a.binding.validate()?;
    let peer: libp2p::PeerId = a
        .peer
        .parse()
        .map_err(|_| crate::ResearchFailure::JournalPeerAdmissionSyntax)?;
    if key != a.artifact
        || a.ordinal == 0
        || state.is_none_or(|s| a.ordinal > s.peer_cursor)
        || peer.to_string() != a.peer
    {
        return Err(crate::ResearchFailure::JournalPeerAdmissionSourceDiffers.into());
    }
    if let Some(evidence) = &a.evidence {
        evidence.validate_width()?;
    }
    if let Some(question) = &a.question {
        naome_checker::question::ResearchQuestion::from_hex(question)?;
    }
    let pending = c.get::<PeerAdmission>(
        "peer_pending",
        &format!("{:020}", a.ordinal),
        crate::resources::limits().closure_bytes,
    )?;
    if matches!(receipt.status, PeerStatus::Queued) {
        if pending.as_ref() != Some(a) {
            return Err(crate::ResearchFailure::JournalPeerAdmissionPendingIndexDiffers.into());
        }
    } else if pending.is_some() {
        return Err(crate::ResearchFailure::JournalFinishedPeerAdmissionRemainsQueued.into());
    }
    let job = match &receipt.status {
        PeerStatus::Running { job } => Some((*job, None)),
        PeerStatus::Learned {
            conversion_job,
            trace_proof,
        } => Some((*conversion_job, Some(trace_proof))),
        _ => None,
    };
    if let Some((id, proof)) = job {
        let source = record(c, id)?;
        let matching = matches!(&source.input,Input::Peer{question,artifact,peer,evidence} if Some(question)==a.question.as_ref() && artifact==&a.artifact && peer==&a.peer && Some(evidence)==a.evidence.as_ref());
        if !matching {
            return Err(crate::ResearchFailure::JournalPeerConversionJobSourceDiffers.into());
        }
        if let Some(proof) = proof {
            let matching = matches!(&source.result,Some(Output::Native{solution:Some(solution),..}) if !solution.refuted && &solution.proof_id==proof);
            if !source.acknowledged || source.state != State::Complete || !matching {
                return Err(
                    crate::ResearchFailure::JournalPeerConversionProofReceiptDiffers.into(),
                );
            }
        }
    }
    Ok(())
}
fn validate_sample(
    c: &crate::checkpoint::Checkpoint,
    key: &str,
    bytes: &[u8],
) -> Result<bool, crate::Error> {
    let id: u64 = crate::checkpoint::decode(bytes)?;
    let source = record(c, id)?;
    let (peer, question) = match &source.input {
        Input::Solve { question } => (false, question),
        Input::Peer { question, .. } => (true, question),
        _ => return Err(crate::ResearchFailure::JournalNativeSampleSourceRoleDiffers.into()),
    };
    let q = naome_checker::question::ResearchQuestion::from_hex(question)?;
    if key != crate::hex(q.resolution_id())
        || !crate::learning::State::eligible(question)
        || source.state != State::Complete
        || !source.acknowledged
        || !matches!(
            source.result,
            Some(Output::Native {
                solution: Some(_),
                ..
            })
        )
    {
        return Err(crate::ResearchFailure::JournalNativeSampleSourceIdentityDiffers.into());
    }
    match &source.input {
        Input::Solve { .. } => {
            if c.get::<String>("learned", &id.to_string(), 256)?.is_none() {
                return Err(crate::ResearchFailure::JournalNativeSampleOwnAdmissionAbsent.into());
            }
        }
        Input::Peer { artifact, .. } => {
            let receipt: PeerReceipt = c
                .get(
                    "peer_receipt",
                    artifact,
                    crate::resources::limits().closure_bytes,
                )?
                .ok_or(crate::ResearchFailure::JournalNativeSamplePeerAdmissionAbsent)?;
            if !matches!(receipt.status,PeerStatus::Learned{conversion_job,..} if conversion_job==id)
            {
                return Err(
                    crate::ResearchFailure::JournalNativeSamplePeerConversionDiffers.into(),
                );
            }
        }
        _ => unreachable!(),
    }
    Ok(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_memo_rechecks_changed_solution_and_question() {
        let example = crate::learning::tests::own_example();
        let solution = crate::learning::tests::own_solution();
        let mut checked = CheckedReplay::default();

        assert!(checked.matches(&example, &solution));
        let artifact = checked
            .artifact(example.job, &solution, &example.question)
            .unwrap();

        let mut changed = solution.clone();
        changed.proof_id = "00".repeat(32);
        assert!(!checked.matches(&example, &changed));
        assert!(
            checked
                .artifact(example.job, &changed, &example.question)
                .is_err()
        );
        assert!(checked.artifact(example.job, &solution, "invalid").is_err());

        assert!(checked.matches(&example, &solution));
        assert_eq!(
            checked
                .artifact(example.job, &solution, &example.question)
                .unwrap(),
            artifact
        );
        assert_eq!(checked.examples.len(), 1);
        assert_eq!(checked.artifacts.len(), 1);
    }
    #[test]
    fn reopening_rejects_a_model_owner_index_not_derived_from_current_state() {
        malformed_model_row(false);
    }
    #[test]
    fn reopening_rejects_a_model_chunk_without_owner_or_reclamation_custody() {
        malformed_model_row(true);
    }
    fn malformed_model_row(chunk: bool) {
        let path = std::env::temp_dir().join(format!(
            "naome-native-index-{}-{}-{}",
            std::process::id(),
            u8::from(chunk),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        let settings = Settings {
            native_proof_learning: true,
            ..Settings::default()
        };
        let (mut disk, journal) = Disk::open(&path, settings, 0).unwrap();
        let blob = crate::learning::Blob::of(b"orphaned-current-model");
        let update = if chunk {
            crate::checkpoint::Update::Put {
                kind: "model",
                key: blob.key(0),
                payload: b"orphaned-current-model".to_vec(),
            }
        } else {
            crate::checkpoint::Update::put("model_owner", "global", &vec![blob]).unwrap()
        };
        disk.checkpoint
            .commit(&journal.header(), vec![update])
            .unwrap();
        drop(disk);
        let error = Disk::open(&path, settings, 0)
            .err()
            .expect("current model index corruption must stop reopening");
        let expected = if chunk {
            crate::ResearchFailure::JournalNativeModelChunkHasNoOwnerOrReclamationReceipt
        } else {
            crate::ResearchFailure::JournalNativeGlobalModelOwnerIndexDiffers
        };
        assert_eq!(error, crate::Error::from(expected));
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(expected)
        );
        std::fs::remove_dir_all(path).unwrap();
    }
}
