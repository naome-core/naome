use super::{Result, config::RoleConfig, files, hex};
use naome_chain::{ArtifactBlock, ArtifactChainDefinition, ArtifactChainState, ArtifactDag};
use naome_network::CandidateOffer;
use naome_proof::{ArtifactPayload, ProofCertificate};
use naome_storage::{
    ArtifactBlockCandidateStore, ArtifactBlockCandidateStoreLimits, ArtifactChainJournal,
    ArtifactPayloadStoreLimits, CandidateBranchRecoveryBundleLimits, CanonicalArtifactPayloadStore,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// A bounded synthetic mathematical workload, with no votes or finality authority.
/// It is generated on demand after startup, not installed in validator directories.
pub(super) fn prefix(
    definition: ArtifactChainDefinition,
    height: usize,
) -> Result<Vec<(ArtifactBlock, Vec<u8>)>> {
    if !(1..=super::MAX_HEIGHTS).contains(&height) {
        return Err("workload height limit".into());
    }
    let mut state = ArtifactChainState::new(definition);
    let mut result = Vec::new();
    for height in 1..=height {
        let steps = height as u32 + 1;
        let mut certificate = steps.to_be_bytes().to_vec();
        certificate.extend_from_slice(&[0x06, 0, 0, 0, 0]);
        for premise in 0..steps - 1 {
            certificate.push(0x21);
            certificate.extend_from_slice(&premise.to_be_bytes());
            certificate.extend_from_slice(&0u32.to_be_bytes());
        }
        let payload = ArtifactPayload::Proof(ProofCertificate::from_canonical_bytes(&certificate)?)
            .to_canonical_bytes();
        let artifact = ArtifactDag::new()
            .apply_canonical_artifact_bytes(payload.clone())?
            .artifact_id();
        let block = state.prepare_block(artifact)?;
        state.apply_block(&block, payload.clone())?;
        result.push((block, payload));
    }
    Ok(result)
}

pub(super) fn publish(root: &Path, height: usize) -> Result<Value> {
    let role = RoleConfig::load(root)?;
    if !role.publisher || height == 0 || height > role.deployment.heights {
        return Err("publisher role and configured workload height required".into());
    }
    let producer = root.join("producer");
    let owner = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(producer.join("owner.lock"))?;
    owner.try_lock()?;
    let scratch = producer.join("staging");
    // An interrupted build remains inspectable and refuses reuse. It has no
    // signing/source-store authority; operator cleanup is documented explicitly.
    files::directory(&scratch)?;
    for name in ["journal", "candidates", "payloads"] {
        files::directory(&scratch.join(name))?;
    }
    let definition = role.deployment.definition()?;
    let journal = ArtifactChainJournal::create(scratch.join("journal"), definition)?;
    let mut candidates = ArtifactBlockCandidateStore::create(
        scratch.join("candidates"),
        definition,
        ArtifactBlockCandidateStoreLimits::new(super::MAX_HEIGHTS)?,
    )?;
    let mut payloads = CanonicalArtifactPayloadStore::create(
        scratch.join("payloads"),
        ArtifactPayloadStoreLimits::new(super::MAX_HEIGHTS, 8_388_608)?,
    )?;
    let entries = prefix(definition, height)?;
    for (block, bytes) in &entries {
        let _ = candidates.insert(block)?;
        let _ =
            payloads.insert(ArtifactDag::new().apply_canonical_artifact_bytes(bytes.clone())?)?;
    }
    let target = entries.last().ok_or("empty workload")?.0.id();
    let bytes = journal
        .export_candidate_branch_recovery_bundle_v0(
            target,
            &mut candidates,
            &mut payloads,
            CandidateBranchRecoveryBundleLimits::new(super::MAX_HEIGHTS, 8_388_608, 8_454_144)?,
        )?
        .into_canonical_bytes();
    drop((journal, candidates, payloads));
    let relative = format!("producer/source-{height}.bundle");
    let path = root.join(&relative);
    if path.exists() {
        if files::read(&path, 8_454_144)? != bytes {
            return Err("existing workload bundle differs".into());
        }
    } else {
        files::create(&path, &bytes)?;
    }
    let offer = CandidateOffer::new(definition.id(), vec![target])?;
    files::replace(
        &root.join("offer.json"),
        &serde_json::to_vec(
            &json!({"candidates":[hex(target.as_bytes())],"bundle_file":relative}),
        )?,
    )?;
    fs::remove_dir_all(&scratch)?;
    Ok(
        json!({"event":"workload_published","height":height,"head":hex(target.as_bytes()),"chain_id":hex(definition.id().as_bytes()),"offer_sha256":hex(&Sha256::digest(offer.to_wire_bytes())),"bundle_bytes":bytes.len()}),
    )
}
