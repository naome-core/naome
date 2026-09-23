use super::{
    Result,
    control::{self, Request},
    files,
    node::decode_bytes,
    setup::NodeConfig,
};
use crate::archive::Manifest;
use naome_consensus::state::StateBranch;
use naome_ledger::LedgerState;
use serde_json::json;
use std::path::Path;

pub async fn run(args: &[String]) -> Result<()> {
    if args[0] == "verify" || args[0] == "inspect" {
        if (args[0] == "verify" && args.len() != 3) || (args[0] == "inspect" && args.len() != 5) {
            return Err("usage: verify GENESIS EXPORT_DIRECTORY; inspect GENESIS EXPORT_DIRECTORY SUBMISSION_ID OUTPUT_DIRECTORY".into());
        }
        let archive = crate::archive::replay(
            Path::new(&args[1]),
            Path::new(&args[2]),
            (args[0] == "inspect").then(|| args[3].as_str()),
        )?;
        let branch = archive.branch;
        let originals = archive.originals;
        let genesis = branch.state().genesis();
        if args[0] == "inspect" {
            let id = naome_ledger::OperationId::from_bytes(files::unhex(&args[3])?);
            let report = super::inspect::question(branch.state(), id)?;
            let q = branch.state().question(id).ok_or("question not found")?;
            let output = Path::new(&args[4]);
            files::directory(output)?;
            if let Some(naome_ledger::state::FamilyResult::Completed {
                normalization_receipt,
                ..
            }) = branch.state().families().get(&q.question().resolution_id())
            {
                let receipt = naome_ledger::receipt::NormalizationReceipt::decode_recorded(
                    normalization_receipt,
                    genesis,
                )?;
                let original = originals
                    .get(&receipt.original_hash)
                    .ok_or("winning original absent from replayed history")?;
                original.verify_signature(genesis, receipt.round, receipt.author)?;
                if original.original_hash() != receipt.original_hash {
                    return Err("winning original hash mismatch".into());
                }
                files::create_or_match(
                    &output.join("original.package"),
                    &original.package().encode()?,
                    false,
                )?;
                files::create_or_match(
                    &output.join("original.signed"),
                    &original.encode()?,
                    false,
                )?;
                files::create_or_match(
                    &output.join("normalized.package"),
                    &receipt.package.encode()?,
                    false,
                )?;
                files::create_or_match(
                    &output.join("normalization.receipt"),
                    normalization_receipt,
                    false,
                )?;
            }
            files::create_or_match(
                &output.join("report.json"),
                &serde_json::to_vec_pretty(&report)?,
                false,
            )?;
            println!("{report}");
            return Ok(());
        }
        let mut status = control::status(branch.state());
        status["verification"] = json!("independent full finality and mathematical replay");
        status["consensus_commitment"] = json!(files::hex(&branch.commitment()));
        println!("{status}");
        return Ok(());
    }
    if args.len() < 3 {
        return Err("usage: export CONFIG DIRECTORY; fetch-proof CONFIG PROOF_ID OUTPUT; receipt|question CONFIG ID; peer CONFIG VALIDATOR_INDEX on|off".into());
    }
    let config = NodeConfig::read(Path::new(&args[1]))?;
    match args[0].as_str() {
        "receipt" | "question" if args.len() == 3 => {
            let request = if args[0] == "receipt" {
                Request::Receipt {
                    id: args[2].clone(),
                }
            } else {
                Request::Question {
                    id: args[2].clone(),
                }
            };
            println!("{}", control::call(&config, request).await?);
        }
        "peer" if args.len() == 4 => {
            let enabled = match args[3].as_str() {
                "on" => true,
                "off" => false,
                _ => return Err("link state must be on or off".into()),
            };
            println!(
                "{}",
                control::call(
                    &config,
                    Request::SetPeer {
                        validator: args[2].parse()?,
                        enabled
                    }
                )
                .await?
            );
        }
        "fetch-proof-from" if args.len() == 5 => {
            let validator = args[2].parse()?;
            control::call(
                &config,
                Request::StartProofFetch {
                    validator,
                    id: args[3].clone(),
                },
            )
            .await?;
            let started = std::time::Instant::now();
            let response = loop {
                let response = control::call(
                    &config,
                    Request::ProofFetch {
                        validator,
                        id: args[3].clone(),
                    },
                )
                .await?;
                if response["status"] != "pending" {
                    break response;
                }
                if started.elapsed() > std::time::Duration::from_secs(40) {
                    return Err("network proof retrieval timed out".into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            };
            let bytes = decode_bytes(
                response["bytes"]
                    .as_str()
                    .ok_or("missing network proof bytes")?,
                config.genesis()?.profile().limits().certificate_bytes as usize,
            )?;
            files::create_or_match(Path::new(&args[4]), &bytes, false)?;
            let mut metadata = control::call(
                &config,
                Request::Proof {
                    id: args[3].clone(),
                },
            )
            .await?;
            metadata
                .as_object_mut()
                .ok_or("invalid proof metadata")?
                .remove("bytes");
            metadata["retrieval"] = json!("authenticated peer-to-peer network");
            metadata["source_validator"] = json!(validator);
            metadata["saved"] = json!(args[4]);
            println!("{metadata}");
        }
        "fetch-proof" if args.len() == 4 => {
            let response = control::call(
                &config,
                Request::Proof {
                    id: args[2].clone(),
                },
            )
            .await?;
            let bytes = decode_bytes(
                response["bytes"].as_str().ok_or("missing proof bytes")?,
                config.genesis()?.profile().limits().certificate_bytes as usize,
            )?;
            files::create_or_match(Path::new(&args[3]), &bytes, false)?;
            let mut report = response;
            report
                .as_object_mut()
                .ok_or("invalid proof response")?
                .remove("bytes");
            report["saved"] = json!(args[3]);
            println!("{report}");
        }
        "export" if args.len() == 3 => {
            let genesis = config.genesis()?;
            let status = control::call(&config, Request::Status {}).await?;
            let height = status["height"]
                .as_u64()
                .ok_or("missing finalized height")?;
            if height > genesis.profile().limits().run_records {
                return Err("node height exceeds genesis limit".into());
            }
            let root = Path::new(&args[2]);
            files::directory(root)?;
            let mut branch = StateBranch::from_genesis(LedgerState::new(genesis.clone()))?;
            for n in 1..=height {
                let response = control::call(&config, Request::History { height: n }).await?;
                let bytes = decode_bytes(
                    response["bytes"]
                        .as_str()
                        .ok_or("missing finalized bytes")?,
                    genesis.profile().limits().transport_frame_bytes as usize,
                )?;
                branch = branch
                    .decode_finality(&bytes, config.maximum_round)?
                    .into_branch();
                // Full records include already-finalized reveal material.
                // Keep archives private; publish only sanitized qualification reports.
                files::create(&root.join(format!("{n:08}.finality")), &bytes, true)?;
            }
            let manifest = Manifest {
                version: 1,
                genesis: files::hex(genesis.id().as_bytes()),
                head: files::hex(branch.state().head().as_bytes()),
                state: files::hex(branch.state().commitment().as_bytes()),
                height,
                maximum_round: config.maximum_round,
            };
            if status["head"] != manifest.head || status["state"] != manifest.state {
                return Err("independent export differs from initial finalized tip".into());
            }
            files::create(
                &root.join("manifest.json"),
                &serde_json::to_vec_pretty(&manifest)?,
                false,
            )?;
            files::create(&root.join("genesis.bin"), &genesis.encode(), false)?;
            println!(
                "{}",
                json!({"status":"independently_verified_export","height":height,"state":manifest.state,"directory":root})
            );
        }
        _ => return Err("invalid export or query arguments".into()),
    }
    Ok(())
}
