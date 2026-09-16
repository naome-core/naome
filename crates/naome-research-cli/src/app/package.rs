use super::{Result, files};
use naome_checker::{ArtifactState, check_normal_form_with_state};
use naome_proof::ProofCertificate;
use naome_research::{AccountId, library::ProofPackage, profile::Genesis};
use std::path::Path;

/// References are supplied before helpers; helpers before the root. Every input
/// certificate is actually checked, but selected-library admission is separate.
pub fn run(args: &[String]) -> Result<()> {
    if args.len() < 4 || !(args.len() - 4).is_multiple_of(2) {
        return Err("usage: package GENESIS ACCOUNT_KEY OUTPUT ROOT_SOURCE [--reference PROOF_FILE | --helper SOURCE_FILE]...".into());
    }
    let genesis = Genesis::decode(&files::read(Path::new(&args[0]), 16384, false)?)?;
    let key = files::key(Path::new(&args[1]), 1)?;
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    if genesis.account_key(author).is_none() {
        return Err("account is not registered in this genesis".into());
    }
    let mut context = ArtifactState::new();
    let mut new = Vec::new();
    let limits = genesis.profile().limits();
    if args.len() > 4 + 2 * (limits.new_helpers + limits.dependency_proofs) as usize {
        return Err("too many package inputs".into());
    }
    let mut reference_bytes = 0u64;
    for pair in args[4..].chunks_exact(2) {
        let bytes = if pair[0] == "--reference" {
            let bytes = files::read(
                Path::new(&pair[1]),
                limits.certificate_bytes as usize,
                false,
            )?;
            reference_bytes = reference_bytes
                .checked_add(bytes.len() as u64)
                .ok_or("dependency size overflow")?;
            if reference_bytes > limits.dependency_bytes {
                return Err("dependency byte limit".into());
            }
            bytes
        } else if pair[0] == "--helper" {
            let source = String::from_utf8(files::read(
                Path::new(&pair[1]),
                naome_authoring::AUTHORING_SOURCE_MAX_BYTES,
                false,
            )?)?;
            naome_authoring::compile_against_proof_context(&source, &context)?
                .canonical_proof_bytes()
                .to_vec()
        } else {
            return Err("expected --reference or --helper".into());
        };
        let checked = check_normal_form_with_state(
            ProofCertificate::from_canonical_bytes(&bytes)?.into_unchecked_normal_form(),
            &context,
        )?;
        if pair[0] == "--helper" {
            new.push((checked.proof_id(), bytes));
        }
        context.register_proof_for_verification(checked)?;
    }
    let source = String::from_utf8(files::read(
        Path::new(&args[3]),
        naome_authoring::AUTHORING_SOURCE_MAX_BYTES,
        false,
    )?)?;
    let root = naome_authoring::compile_against_proof_context(&source, &context)?;
    new.push((root.proof_id(), root.canonical_proof_bytes().to_vec()));
    let package = ProofPackage::new(author, root.proof_id(), new, genesis.profile())?;
    files::create_or_match(Path::new(&args[2]), &package.encode()?, false)?;
    println!(
        "{}",
        serde_json::json!({"status":"mathematically_checked_original","root":files::hex(root.proof_id().as_bytes()),"original_hash":files::hex(package.original_hash().as_bytes()),"publication":"requires finalized reveal and settlement"})
    );
    Ok(())
}

/// Offline checker invocation against explicit, dependency-ordered certificates.
pub fn check(args: &[String]) -> Result<()> {
    if args.len() < 2 {
        return Err("usage: check-proof GENESIS ROOT_PROOF [DEPENDENCY_PROOF...]".into());
    }
    let genesis = Genesis::decode(&files::read(Path::new(&args[0]), 16384, false)?)?;
    let limits = genesis.profile().limits();
    if args.len() - 2 > limits.dependency_proofs as usize {
        return Err("dependency proof limit".into());
    }
    let mut context = ArtifactState::new();
    let mut total = 0u64;
    for input in &args[2..] {
        let bytes = files::read(Path::new(input), limits.certificate_bytes as usize, false)?;
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or("dependency byte overflow")?;
        if total > limits.dependency_bytes {
            return Err("dependency byte limit".into());
        }
        let checked = check_normal_form_with_state(
            ProofCertificate::from_canonical_bytes(&bytes)?.into_unchecked_normal_form(),
            &context,
        )?;
        context.register_proof_for_verification(checked)?;
    }
    let bytes = files::read(
        Path::new(&args[1]),
        limits.certificate_bytes as usize,
        false,
    )?;
    let checked = check_normal_form_with_state(
        ProofCertificate::from_canonical_bytes(&bytes)?.into_unchecked_normal_form(),
        &context,
    )?;
    println!(
        "{}",
        serde_json::json!({"verification":"mathematical certificate checked offline","proof":files::hex(checked.proof_id().as_bytes()),"statement":files::hex(checked.statement_id().as_bytes()),"conclusion":checked.conclusion().to_source()})
    );
    Ok(())
}
