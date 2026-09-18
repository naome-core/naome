use super::{
    Result,
    control::{self, Request},
    files,
    setup::NodeConfig,
};
use naome_ledger::{
    AccountId, CommitmentId, QuestionId, SolutionRoundId,
    authentication::SignedOperation,
    library::ProofPackage,
    operations::{OperationBody, SignedOriginal},
    profile::Genesis,
    question::CompiledQuestion,
};
use serde_json::{Value, json};
use std::{
    io::{Cursor, Read},
    path::Path,
};
use zeroize::Zeroizing;

#[cfg(test)]
mod tests;

fn nonce(status: &Value, author: AccountId) -> Result<u64> {
    status["accounts"]
        .as_array()
        .and_then(|a| {
            a.iter()
                .find(|a| a["account"] == files::hex(author.as_bytes()))
        })
        .and_then(|a| a["next_nonce"].as_u64())
        .ok_or_else(|| "registered account nonce unavailable".into())
}
fn round(status: &Value, phase: &str) -> Result<SolutionRoundId> {
    if status["active"]["phase"] != phase {
        return Err(format!("active phase must be {phase}; inspect status before retrying").into());
    }
    Ok(SolutionRoundId::from_bytes(files::unhex(
        status["active"]["round"]
            .as_str()
            .ok_or("solution round unavailable")?,
    )?))
}
async fn send(config: &NodeConfig, operation: &SignedOperation) -> Result<()> {
    operation.verify(&config.genesis()?)?;
    let response = control::call(
        config,
        Request::Submit {
            bytes: files::hex(&operation.encode()),
        },
    )
    .await?;
    let mut result = json!({"operation":files::hex(operation.id().as_bytes()),"result":response,"notice":"transported actions are not finalized receipts or settlement"});
    if let OperationBody::Submit { question, .. } =
        OperationBody::decode(operation.payload(), &config.genesis()?)?
    {
        result["compiled_question"] = super::inspect::compiled_question(&question);
    }
    println!("{result}");
    Ok(())
}
async fn save_send(config: &NodeConfig, path: &str, operation: &SignedOperation) -> Result<()> {
    files::create_or_match(Path::new(path), &operation.encode(), true)?;
    send(config, operation).await
}
struct SecretBundle {
    round: SolutionRoundId,
    secret: Zeroizing<[u8; 32]>,
    original: SignedOriginal,
    commit: SignedOperation,
}
impl SecretBundle {
    fn encode(&self, genesis: &Genesis) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(b"NSSEC001");
        bytes.extend_from_slice(genesis.id().as_bytes());
        bytes.extend_from_slice(self.round.as_bytes());
        bytes.extend_from_slice(self.secret.as_ref());
        for part in [self.original.encode()?, self.commit.encode()] {
            bytes.extend_from_slice(&(part.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&part);
        }
        Ok(bytes)
    }
    fn read(path: &Path, genesis: &Genesis, author: AccountId) -> Result<Self> {
        let bytes = Zeroizing::new(files::read(
            path,
            genesis.profile().limits().package_bytes as usize + 4096,
            true,
        )?);
        let mut c = Cursor::new(bytes.as_slice());
        fn fixed<const N: usize>(c: &mut Cursor<&[u8]>) -> Result<[u8; N]> {
            let mut a = [0; N];
            c.read_exact(&mut a)?;
            Ok(a)
        }
        fn blob(c: &mut Cursor<&[u8]>, maximum: usize) -> Result<Vec<u8>> {
            let n = u32::from_be_bytes(fixed(c)?) as usize;
            if n > maximum {
                return Err("secret bundle field exceeds limit".into());
            }
            let mut a = vec![0; n];
            c.read_exact(&mut a)?;
            Ok(a)
        }
        if fixed::<8>(&mut c)? != *b"NSSEC001" || fixed::<32>(&mut c)? != *genesis.id().as_bytes() {
            return Err("secret bundle format or genesis mismatch".into());
        }
        let round = SolutionRoundId::from_bytes(fixed(&mut c)?);
        let secret = Zeroizing::new(fixed(&mut c)?);
        let original = SignedOriginal::decode(
            &blob(
                &mut c,
                genesis.profile().limits().package_bytes as usize + 1024,
            )?,
            genesis,
        )?;
        let commit = SignedOperation::decode(&blob(&mut c, 2048)?)?;
        if c.position() != bytes.len() as u64 {
            return Err("trailing secret bundle content".into());
        }
        original.verify(genesis, round, author)?;
        commit.verify(genesis)?;
        let expected =
            CommitmentId::for_original(genesis, round, author, original.original_hash(), &secret);
        if commit.author() != author
            || !matches!(OperationBody::decode(commit.payload(),genesis)?,OperationBody::Commit{round:r,commitment} if r==round && commitment==expected)
        {
            return Err("secret bundle commitment mismatch".into());
        }
        // Reusing a complete file after an uncertain earlier directory sync
        // must re-establish durable secret custody before resending the action.
        files::create_or_match(path, &bytes, true)?;
        Ok(Self {
            round,
            secret,
            original,
            commit,
        })
    }
}
pub async fn run(args: &[String]) -> Result<()> {
    let command = args[0].as_str();
    let expected = match command {
        "submit" => 6,
        "vote" => 5,
        "commit" => 6,
        "reveal" => 5,
        "send" => 3,
        _ => return Err("unknown action command".into()),
    };
    if args.len() != expected {
        return Err("usage: submit CONFIG KEY SOURCE PURPOSE ACTION; vote CONFIG KEY YES|NO ACTION; commit CONFIG KEY PACKAGE SECRET ACTION; reveal CONFIG KEY SECRET ACTION; send CONFIG ACTION".into());
    }
    let config = NodeConfig::read(Path::new(&args[1]))?;
    let genesis = config.genesis()?;
    if command == "send" {
        let op = SignedOperation::decode(&files::read(
            Path::new(&args[2]),
            genesis.profile().limits().record_bytes as usize,
            true,
        )?)?;
        return send(&config, &op).await;
    }
    let key = files::key(Path::new(&args[2]), 1)?;
    let author = AccountId::for_key(key.verifying_key().as_bytes());
    if command == "reveal" && Path::new(&args[4]).try_exists()? {
        let bundle = SecretBundle::read(Path::new(&args[3]), &genesis, author)?;
        let operation = SignedOperation::decode(&files::read(
            Path::new(&args[4]),
            genesis.profile().limits().record_bytes as usize,
            true,
        )?)?;
        operation.verify(&genesis)?;
        if operation.author() != author
            || !matches!(OperationBody::decode(operation.payload(),&genesis)?,OperationBody::Reveal{round,secret,original} if round==bundle.round && secret==*bundle.secret && original.encode()?==bundle.original.encode()?)
        {
            return Err("existing reveal does not match the retained secret and original".into());
        }
        return send(&config, &operation).await;
    }
    if command == "commit" && Path::new(&args[4]).try_exists()? {
        let bundle = SecretBundle::read(Path::new(&args[4]), &genesis, author)?;
        let package = ProofPackage::decode(
            &files::read(
                Path::new(&args[3]),
                genesis.profile().limits().package_bytes as usize,
                false,
            )?,
            genesis.profile(),
        )?;
        if package.encode()? != bundle.original.package().encode()? {
            return Err("existing secret belongs to a different original package".into());
        }
        return save_send(&config, &args[5], &bundle.commit).await;
    }
    let status = control::call(&config, Request::Status).await?;
    if status["genesis"] != files::hex(genesis.id().as_bytes()) {
        return Err("node and local genesis disagree".into());
    }
    let next = nonce(&status, author)?;
    let (body, output) = match command {
        "submit" => {
            let source = String::from_utf8(files::read(
                Path::new(&args[3]),
                genesis.profile().limits().question_source_bytes as usize,
                false,
            )?)?;
            (
                OperationBody::Submit {
                    purpose: args[4].clone(),
                    question: CompiledQuestion::compile(&source, genesis.profile())?,
                },
                &args[5],
            )
        }
        "vote" => {
            if status["active"]["phase"] != "Voting" {
                return Err("question is not in finalized VOTING phase".into());
            }
            let yes = match args[3].as_str() {
                "YES" => true,
                "NO" => false,
                _ => return Err("vote must be YES or NO".into()),
            };
            (
                OperationBody::Vote {
                    question: QuestionId::from_bytes(files::unhex(
                        status["active"]["question"]
                            .as_str()
                            .ok_or("question unavailable")?,
                    )?),
                    attempt: status["active"]["attempt"]
                        .as_u64()
                        .ok_or("attempt unavailable")?,
                    yes,
                },
                &args[4],
            )
        }
        "commit" => {
            let round = round(&status, "Commit")?;
            let secret = files::random()?;
            let package = ProofPackage::decode(
                &files::read(
                    Path::new(&args[3]),
                    genesis.profile().limits().package_bytes as usize,
                    false,
                )?,
                genesis.profile(),
            )?;
            let original = SignedOriginal::sign(&genesis, round, package, &key)?;
            let commitment = CommitmentId::for_original(
                &genesis,
                round,
                author,
                original.original_hash(),
                &secret,
            );
            let commit = OperationBody::Commit { round, commitment }.sign(&genesis, next, &key)?;
            let bundle = SecretBundle {
                round,
                secret,
                original,
                commit,
            };
            files::create(Path::new(&args[4]), &bundle.encode(&genesis)?, true)?;
            return save_send(&config, &args[5], &bundle.commit).await;
        }
        "reveal" => {
            let bundle = SecretBundle::read(Path::new(&args[3]), &genesis, author)?;
            if round(&status, "Reveal")? != bundle.round {
                return Err("retained secret belongs to a different solution round".into());
            }
            (
                OperationBody::Reveal {
                    round: bundle.round,
                    secret: *bundle.secret,
                    original: bundle.original,
                },
                &args[4],
            )
        }
        _ => return Err("unknown signed operation".into()),
    };
    let operation = body.sign(&genesis, next, &key)?;
    save_send(&config, output, &operation).await
}
