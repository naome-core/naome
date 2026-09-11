use super::*;
use ed25519_dalek::SigningKey;
use naome_node::verified_membership::MembershipCandidate;

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Status {
        id: u64,
    },
    Members {
        id: u64,
        offset: usize,
        limit: usize,
    },
    Request {
        id: u64,
        request_id: String,
    },
    Apply {
        id: u64,
    },
    Approve {
        id: u64,
        request_id: String,
    },
    Reject {
        id: u64,
        request_id: String,
    },
    Allow {
        id: u64,
        request_id: String,
    },
    Exit {
        id: u64,
    },
    Remove {
        id: u64,
        organization: String,
    },
    SubmitRequest {
        id: u64,
        file: PathBuf,
    },
    SubmitApproval {
        id: u64,
        file: PathBuf,
    },
    Offer {
        id: u64,
        file: PathBuf,
    },
    Candidate {
        id: u64,
        block_file: PathBuf,
        payload_file: PathBuf,
    },
    ExportRequest {
        id: u64,
        request_id: String,
        file: PathBuf,
    },
    ExportApproval {
        id: u64,
        request_id: String,
        file: PathBuf,
    },
    ExportProof {
        id: u64,
        height: u64,
        file: PathBuf,
    },
    ImportProof {
        id: u64,
        file: PathBuf,
    },
    Shutdown {
        id: u64,
    },
}
impl Command {
    pub fn id(&self) -> u64 {
        match self {
            Self::Status { id }
            | Self::Members { id, .. }
            | Self::Request { id, .. }
            | Self::Apply { id }
            | Self::Approve { id, .. }
            | Self::Reject { id, .. }
            | Self::Allow { id, .. }
            | Self::Exit { id }
            | Self::Remove { id, .. }
            | Self::SubmitRequest { id, .. }
            | Self::SubmitApproval { id, .. }
            | Self::Offer { id, .. }
            | Self::Candidate { id, .. }
            | Self::ExportRequest { id, .. }
            | Self::ExportApproval { id, .. }
            | Self::ExportProof { id, .. }
            | Self::ImportProof { id, .. }
            | Self::Shutdown { id } => *id,
        }
    }
}

pub(super) fn execute(
    command: Command,
    config: &Config,
    base: &Path,
    runtime: &mut MembershipRuntime,
) -> Result<(Value, bool)> {
    let organization = super::super::config::hex32(&config.organization)?;
    let mut changed_inbox = false;
    let mut stop = false;
    let result = match command {
        Command::Status { .. } => json!({"event":"membership_status", "state":status(runtime)?}),
        Command::Members { offset, limit, .. } => {
            if limit == 0 || limit > 16 || offset > MAX_MEMBERS {
                return Err("membership_page_limit");
            }
            let snapshot = runtime
                .node()
                .snapshot()
                .map_err(|_| "membership_snapshot")?;
            let members: Vec<_> = snapshot
                .members()
                .iter()
                .skip(offset)
                .take(limit)
                .map(member_json)
                .collect();
            json!({"event":"membership_members", "generation":snapshot.generation(), "total":snapshot.members().len(), "offset":offset, "members":members})
        }
        Command::Request { request_id, .. } => {
            let id = super::super::config::hex32(&request_id)?;
            let request = runtime
                .node()
                .requests()
                .get(&id)
                .ok_or("membership_unknown_request")?;
            let action = match request.action() {
                MembershipAction::Join { member, .. } => {
                    json!({"kind":"join", "member":member_json(member)})
                }
                MembershipAction::Exit { organization, .. } => {
                    json!({"kind":"exit", "organization":hex(organization)})
                }
                MembershipAction::Remove { organization } => {
                    json!({"kind":"remove", "organization":hex(organization)})
                }
            };
            json!({"event":"membership_request", "request_id":request_id, "action":action, "approvals":runtime.node().approval_count(&id), "quorum":runtime.node().snapshot().map_err(|_| "membership_snapshot")?.quorum()})
        }
        Command::Apply { .. } => {
            let consensus = SigningKey::from_bytes(&*files::seed(
                &base.join(
                    config
                        .consensus_seed_file
                        .as_ref()
                        .ok_or("membership_consensus_key_required")?,
                ),
            )?);
            let approval = approval_key(config, base)?;
            let network =
                SigningKey::from_bytes(&*files::seed(&base.join(&config.network_seed_file))?);
            if runtime
                .node()
                .machine()
                .map_err(|_| "membership_state")?
                .signer()
                != Some(consensus.verifying_key().to_bytes())
            {
                return Err("membership_consensus_key_changed");
            }
            let identity = naome_network::Keypair::ed25519_from_bytes(
                files::seed(&base.join(&config.network_seed_file))?.as_mut(),
            )
            .map_err(|_| "membership_identity")?;
            if identity.public().to_peer_id() != runtime.network().local_peer_id() {
                return Err("membership_network_key_changed");
            }
            let member = Member {
                organization,
                consensus_key: consensus.verifying_key().to_bytes(),
                approval_key: approval.verifying_key().to_bytes(),
                network_key: network.verifying_key().to_bytes(),
            };
            let request = MembershipRequest::join(
                runtime
                    .node()
                    .snapshot()
                    .map_err(|_| "membership_snapshot")?,
                member,
                [&consensus, &approval, &network],
            )
            .map_err(|_| "membership_application")?;
            let id = request.id();
            runtime
                .node_mut()
                .ingest_operator_request(request)
                .map_err(|_| "membership_request_admission")?;
            changed_inbox = true;
            json!({"event":"membership_application_created", "request_id":hex(&id), "member":member_json(&member)})
        }
        Command::Approve { request_id, .. } => {
            let request = super::super::config::hex32(&request_id)?;
            let key = approval_key(config, base)?;
            let approval = runtime
                .node_mut()
                .approve(request, organization, &key)
                .map_err(|_| "membership_approval")?;
            changed_inbox = true;
            json!({"event":"membership_approved", "request_id":hex(&approval.request), "organization":hex(&organization), "approvals":runtime.node().approval_count(&request)})
        }
        Command::Reject { request_id, .. } => {
            runtime
                .node_mut()
                .reject_request(super::super::config::hex32(&request_id)?)
                .map_err(|_| "membership_rejection_limit")?;
            changed_inbox = true;
            json!({"event":"membership_request_rejected_locally", "request_id":request_id})
        }
        Command::Allow { request_id, .. } => {
            runtime
                .node_mut()
                .allow_request(super::super::config::hex32(&request_id)?);
            changed_inbox = true;
            json!({"event":"membership_request_allowed_locally", "request_id":request_id})
        }
        Command::Exit { .. } => {
            let request = MembershipRequest::exit(
                runtime
                    .node()
                    .snapshot()
                    .map_err(|_| "membership_snapshot")?,
                organization,
                &approval_key(config, base)?,
            )
            .map_err(|_| "membership_exit")?;
            let id = request.id();
            runtime
                .node_mut()
                .ingest_operator_request(request)
                .map_err(|_| "membership_request_admission")?;
            changed_inbox = true;
            json!({"event":"membership_exit_requested", "request_id":hex(&id)})
        }
        Command::Remove { organization, .. } => {
            let request = MembershipRequest::remove(
                runtime
                    .node()
                    .snapshot()
                    .map_err(|_| "membership_snapshot")?,
                super::super::config::hex32(&organization)?,
            )
            .map_err(|_| "membership_removal")?;
            let id = request.id();
            runtime
                .node_mut()
                .ingest_operator_request(request)
                .map_err(|_| "membership_request_admission")?;
            changed_inbox = true;
            json!({"event":"membership_removal_requested", "request_id":hex(&id)})
        }
        Command::SubmitRequest { file, .. } => {
            let request = MembershipRequest::from_bytes(&files::bytes(
                &base.join(file),
                MembershipRequest::MAX_BYTES,
            )?)
            .map_err(|_| "membership_request_decode")?;
            let id = request.id();
            runtime
                .node_mut()
                .ingest_operator_request(request)
                .map_err(|_| "membership_request_admission")?;
            changed_inbox = true;
            json!({"event":"membership_request_received", "request_id":hex(&id)})
        }
        Command::SubmitApproval { file, .. } => {
            let approval = MembershipApproval::from_bytes(&files::bytes(
                &base.join(file),
                MembershipApproval::MAX_BYTES,
            )?)
            .map_err(|_| "membership_approval_decode")?;
            let id = approval.request;
            runtime
                .node_mut()
                .ingest_approval(approval)
                .map_err(|_| "membership_approval_admission")?;
            changed_inbox = true;
            json!({"event":"membership_approval_received", "request_id":hex(&id)})
        }
        Command::Offer { file, .. } => {
            let candidate = MembershipCandidate::from_bytes(&files::bytes(
                &base.join(file),
                MembershipCandidate::MAX_BYTES,
            )?)
            .map_err(|_| "membership_candidate_decode")?;
            runtime
                .node_mut()
                .ingest_candidate(candidate)
                .map_err(|_| "membership_candidate_admission")?;
            json!({"event":"membership_candidate_received"})
        }
        Command::Candidate {
            block_file,
            payload_file,
            ..
        } => {
            let artifact = naome_chain::ArtifactBlock::from_canonical_bytes(&files::bytes(
                &base.join(block_file),
                naome_chain::ARTIFACT_BLOCK_BYTES,
            )?)
            .map_err(|_| "membership_artifact_decode")?;
            let payload = files::bytes(&base.join(payload_file), MAX_ARTIFACT_BYTES)?;
            let context = runtime
                .node()
                .machine()
                .map_err(|_| "membership_state")?
                .branch()
                .context();
            runtime
                .node_mut()
                .ingest_candidate(MembershipCandidate {
                    context,
                    artifact,
                    payload,
                })
                .map_err(|_| "membership_candidate_admission")?;
            json!({"event":"membership_candidate_received"})
        }
        Command::ExportRequest {
            request_id, file, ..
        } => {
            let request = runtime
                .node()
                .requests()
                .get(&super::super::config::hex32(&request_id)?)
                .ok_or("membership_unknown_request")?;
            write_new(&base.join(file), &request.to_bytes())?;
            json!({"event":"membership_request_exported", "request_id":request_id})
        }
        Command::ExportApproval {
            request_id, file, ..
        } => {
            let id = super::super::config::hex32(&request_id)?;
            let approval = runtime
                .node()
                .approval_messages()
                .into_iter()
                .find(|approval| approval.request == id && approval.organization == organization)
                .ok_or("membership_local_approval_missing")?;
            write_new(&base.join(file), &approval.to_bytes())?;
            json!({"event":"membership_approval_exported", "request_id":request_id})
        }
        Command::ExportProof { height, file, .. } => {
            let proof = runtime
                .node_mut()
                .finalized_proof(height)
                .map_err(|_| "membership_proof_read")?
                .ok_or("membership_proof_unavailable")?;
            write_new(&base.join(file), &proof.to_bytes())?;
            json!({"event":"membership_proof_exported", "height":height})
        }
        Command::ImportProof { file, .. } => {
            let proof = MembershipFinalityProof::from_bytes(&files::bytes(
                &base.join(file),
                MembershipFinalityProof::MAX_BYTES,
            )?)
            .map_err(|_| "membership_proof_decode")?;
            runtime
                .apply_event(MembershipMachineEvent::Finality(proof))
                .map_err(|_| "membership_proof_admission")?;
            json!({"event":"membership_proof_imported", "state":status(runtime)?})
        }
        Command::Shutdown { .. } => {
            stop = true;
            json!({"event":"membership_shutdown", "state":status(runtime)?})
        }
    };
    if changed_inbox || stop {
        save_inbox(runtime.node(), &base.join(&config.inbox_directory))
            .map_err(|_| "membership_inbox_persistence_failed")?;
    }
    Ok((result, stop))
}

fn approval_key(config: &Config, base: &Path) -> Result<SigningKey> {
    Ok(SigningKey::from_bytes(&*files::seed(
        &base.join(
            config
                .approval_seed_file
                .as_ref()
                .ok_or("membership_approval_key_required")?,
        ),
    )?))
}
fn member_json(member: &Member) -> Value {
    json!({"organization":hex(&member.organization), "consensus_key":hex(&member.consensus_key), "approval_key":hex(&member.approval_key), "network_key":hex(&member.network_key)})
}
