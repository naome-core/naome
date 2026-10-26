//! Current native rows and their derived indexes are checked before recovery.
use super::*;
fn record(c: &crate::checkpoint::Checkpoint, id: u64) -> Result<Record, String> {
    c.get("record", &id.to_string(), crate::checkpoint::MAX_ROW)?
        .ok_or("native source job missing".into())
}
fn refs(
    c: &crate::checkpoint::Checkpoint,
    owner: &str,
    state: Option<&crate::learning::State>,
) -> Result<Vec<crate::learning::Blob>, String> {
    let mut refs = if owner == "global" {
        state.into_iter().flat_map(|s| s.blobs().cloned()).collect()
    } else {
        let id = owner
            .strip_prefix("job")
            .ok_or("native model owner syntax")?
            .parse::<u64>()
            .map_err(|_| "native model owner identity")?;
        if id == 0 || owner != format!("job{id}") {
            return Err("native model owner encoding".into());
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
) -> Result<Vec<crate::learning::Blob>, String> {
    Ok(
        c.get("model_owner", key, crate::resources::limits().closure_bytes)?
            .unwrap_or_default(),
    )
}
fn validate_sources(
    c: &crate::checkpoint::Checkpoint,
    state: &crate::learning::State,
) -> Result<(), String> {
    for example in state.examples() {
        let q = naome_authoring::CompiledQuestion::compile(&example.question)
            .map_err(|e| e.to_string())?;
        if c.get::<u64>("sample", &crate::hex(q.resolution_id()), 64)? != Some(example.job) {
            return Err("native replay sample source differs".into());
        }
        let source = record(c, example.job)?;
        let Some(Output::Native {
            solution: Some(solution),
            ..
        }) = &source.result
        else {
            return Err("native replay source result absent".into());
        };
        if source.state != State::Complete
            || solution.proof_id != example.proof_id
            || solution.refuted != example.refuted
        {
            return Err("native replay source identity differs".into());
        }
        match (&example.origin, &source.input) {
            (crate::learning::Origin::Local, Input::Solve { question })
                if question == &example.question =>
            {
                if c.get::<String>("learned", &example.job.to_string(), 256)?
                    .as_ref()
                    != Some(&example.proof_id)
                {
                    return Err("native replay lacks admitted own receipt".into());
                }
            }
            (
                crate::learning::Origin::Peer { artifact, peer },
                Input::Peer {
                    question,
                    artifact: actual,
                    peer: supplier,
                },
            ) if question == &example.question && artifact == actual && peer == supplier => {
                let receipt: PeerReceipt = c
                    .get(
                        "peer_receipt",
                        artifact,
                        crate::resources::limits().closure_bytes,
                    )?
                    .ok_or("native peer replay receipt absent")?;
                if !matches!(receipt.status,PeerStatus::Learned{conversion_job,ref trace_proof} if conversion_job==example.job && trace_proof==&example.proof_id)
                {
                    return Err("native peer replay receipt differs".into());
                }
            }
            _ => return Err("native replay source provenance differs".into()),
        }
    }
    Ok(())
}
pub(in crate::jobs::journal) fn validate_rows(
    c: &crate::checkpoint::Checkpoint,
    state: Option<&crate::learning::State>,
) -> Result<(), String> {
    if c.count("learning")? != 1 {
        return Err("native learning singleton differs".into());
    }
    if let Some(state) = state {
        validate_sources(c, state)?;
    }
    c.scan("record", crate::checkpoint::MAX_ROW, |key, bytes| {
        let source: Record = crate::checkpoint::decode(bytes)?;
        let expected = Disk::record_model_refs(&source);
        if owner(c, &format!("job{key}"))? != expected {
            return Err("native record model owner index differs".into());
        }
        if !source.acknowledged
            && let Some(native) = &source.native
        {
            validate_sources(c, &native.base)?;
        }
        Ok(())
    })?;
    if owner(c, "global")? != refs(c, "global", state)? {
        return Err("native global model owner index differs".into());
    }
    c.scan(
        "model_owner",
        crate::resources::limits().closure_bytes,
        |key, bytes| {
            let actual: Vec<crate::learning::Blob> = crate::checkpoint::decode(bytes)?;
            if actual.is_empty() || actual != refs(c, key, state)? {
                return Err("native model owner index differs".into());
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
                    return Err("native model use index missing".into());
                }
            }
            Ok(())
        },
    )?;
    c.scan("model_use", 4096, |key, bytes| {
        let blob: crate::learning::Blob = crate::checkpoint::decode(bytes)?;
        blob.validate()?;
        let (hash, name) = key.split_once(':').ok_or("native model use key")?;
        if hash != blob.sha256 || !owner(c, name)?.contains(&blob) {
            return Err("native model use owner differs".into());
        }
        Ok(())
    })?;
    c.scan("model_gc", 4096, |key, bytes| {
        let blob: crate::learning::Blob = crate::checkpoint::decode(bytes)?;
        blob.validate()?;
        if key != blob.sha256 {
            return Err("native model reclamation key differs".into());
        }
        Ok(())
    })?;
    c.scan(
        "model",
        crate::resources::limits().native_model_chunk_bytes,
        |key, bytes| {
            let (hash, index) = key.split_once(':').ok_or("native model chunk key")?;
            let index = index
                .parse::<usize>()
                .map_err(|_| "native model chunk index")?;
            let uses = c.page("model_use", Some(&format!("{hash}:")), 1, 4096)?;
            let blob = if let Some((name, payload)) = uses
                .first()
                .filter(|(name, _)| name.starts_with(&format!("{hash}:")))
            {
                let _ = name;
                crate::checkpoint::decode(payload)?
            } else {
                c.get::<crate::learning::Blob>("model_gc", hash, 4096)?
                    .ok_or("native model chunk has no owner or reclamation receipt")?
            };
            if key != blob.key(index) || bytes.len() != blob.chunk_len(index)? {
                return Err("native model chunk identity or length differs".into());
            }
            Ok(())
        },
    )?;
    c.scan("learned", 256, |key, bytes| validate_learned(c, key, bytes))?;
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
            return Err("native sample provenance counters differ".into());
        }
    } else if local + peer > 0 {
        return Err("native samples lack learning state".into());
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
                .ok_or("peer pending receipt missing")?;
            if key != format!("{:020}", a.ordinal)
                || receipt.admission != a
                || !matches!(receipt.status, PeerStatus::Queued)
            {
                return Err("peer pending source differs".into());
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
) -> Result<(), String> {
    let id = key
        .parse::<u64>()
        .map_err(|_| "own learning receipt identity")?;
    let root: String = crate::checkpoint::decode(bytes)?;
    crate::object::id_bytes(&root)?;
    let source = record(c, id)?;
    let matching = matches!(source.result, Some(Output::Native{solution:Some(ref solution),..}) if solution.proof_id==root);
    if id == 0
        || key != id.to_string()
        || !source.acknowledged
        || source.state != State::Complete
        || !matches!(source.input, Input::Solve { .. })
        || !matching
    {
        return Err("own learning admission receipt differs".into());
    }
    Ok(())
}
fn validate_peer(
    c: &crate::checkpoint::Checkpoint,
    state: Option<&crate::learning::State>,
    key: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let receipt: PeerReceipt = crate::checkpoint::decode(bytes)?;
    let a = &receipt.admission;
    crate::object::id_bytes(key)?;
    a.binding.validate()?;
    let peer: libp2p::PeerId = a.peer.parse().map_err(|_| "peer admission syntax")?;
    if key != a.artifact
        || a.ordinal == 0
        || state.is_none_or(|s| a.ordinal > s.peer_cursor)
        || peer.to_string() != a.peer
    {
        return Err("peer admission source differs".into());
    }
    if let Some(question) = &a.question {
        naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
    }
    let pending = c.get::<PeerAdmission>(
        "peer_pending",
        &format!("{:020}", a.ordinal),
        crate::resources::limits().closure_bytes,
    )?;
    if matches!(receipt.status, PeerStatus::Queued) {
        if pending.as_ref() != Some(a) {
            return Err("peer admission pending index differs".into());
        }
    } else if pending.is_some() {
        return Err("finished peer admission remains queued".into());
    }
    let job = match &receipt.status {
        PeerStatus::Running { job } => Some((*job, None)),
        PeerStatus::Learned {
            conversion_job,
            trace_proof,
        } => Some((*conversion_job, Some(trace_proof))),
        PeerStatus::Unsupported { reason } => {
            if reason.len() > crate::resources::limits().closure_bytes {
                return Err("peer disposition capacity".into());
            }
            None
        }
        _ => None,
    };
    if let Some((id, proof)) = job {
        let source = record(c, id)?;
        let matching = matches!(&source.input,Input::Peer{question,artifact,peer} if Some(question)==a.question.as_ref() && artifact==&a.artifact && peer==&a.peer);
        if !matching {
            return Err("peer conversion job source differs".into());
        }
        if let Some(proof) = proof {
            let matching = matches!(&source.result,Some(Output::Native{solution:Some(solution),..}) if !solution.refuted && &solution.proof_id==proof);
            if !source.acknowledged || source.state != State::Complete || !matching {
                return Err("peer conversion proof receipt differs".into());
            }
        }
    }
    Ok(())
}
fn validate_sample(
    c: &crate::checkpoint::Checkpoint,
    key: &str,
    bytes: &[u8],
) -> Result<bool, String> {
    let id: u64 = crate::checkpoint::decode(bytes)?;
    let source = record(c, id)?;
    let (peer, question) = match &source.input {
        Input::Solve { question } => (false, question),
        Input::Peer { question, .. } => (true, question),
        _ => return Err("native sample source role differs".into()),
    };
    let q = naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
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
        return Err("native sample source identity differs".into());
    }
    match &source.input {
        Input::Solve { .. } => {
            if c.get::<String>("learned", &id.to_string(), 256)?.is_none() {
                return Err("native sample own admission absent".into());
            }
        }
        Input::Peer { artifact, .. } => {
            let receipt: PeerReceipt = c
                .get(
                    "peer_receipt",
                    artifact,
                    crate::resources::limits().closure_bytes,
                )?
                .ok_or("native sample peer admission absent")?;
            if !matches!(receipt.status,PeerStatus::Learned{conversion_job,..} if conversion_job==id)
            {
                return Err("native sample peer conversion differs".into());
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
        assert!(error.contains("model"), "{error}");
        std::fs::remove_dir_all(path).unwrap();
    }
}
