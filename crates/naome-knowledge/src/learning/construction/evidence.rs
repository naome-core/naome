//! Bounded local search evidence. It is not an accepted mathematical artifact.
use super::super::{
    definitions,
    proof::{self, Term},
};
use naome_foundation::Formula;
use naome_proof::ProofCertificate;

struct Evidence {
    certificate: Vec<u8>,
    lemmas: Vec<Vec<u8>>,
    definitions: Vec<definitions::Entry>,
}
fn decode(bytes: &[u8]) -> Result<Evidence, String> {
    let limits = crate::resources::limits();
    if bytes.len() < 4 || bytes.len() > limits.proof_bytes {
        return Err("construction evidence capacity".into());
    }
    let size = u32::from_le_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| "construction evidence extent")?,
    ) as usize;
    if size > limits.closure_bytes {
        return Err("construction decoded capacity".into());
    }
    let mut decoded = vec![0; size];
    let actual =
        lz4_flex::block::decompress_into(&bytes[4..], &mut decoded).map_err(|e| e.to_string())?;
    if actual != size {
        return Err("construction evidence extent".into());
    }
    let mut cursor = 0usize;
    fn number(bytes: &[u8], cursor: &mut usize) -> Result<usize, String> {
        let end = cursor
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or("construction evidence framing")?;
        let value = u32::from_le_bytes(
            bytes[*cursor..end]
                .try_into()
                .map_err(|_| "construction evidence width")?,
        ) as usize;
        *cursor = end;
        Ok(value)
    }
    fn field(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, String> {
        let length = number(bytes, cursor)?;
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or("construction evidence extent")?;
        let value = bytes[*cursor..end].to_vec();
        *cursor = end;
        Ok(value)
    }
    let certificate = field(&decoded, &mut cursor)?;
    let count = number(&decoded, &mut cursor)?;
    if count >= limits.closure_objects {
        return Err("construction lemma count".into());
    }
    let mut lemmas = Vec::with_capacity(count);
    for _ in 0..count {
        lemmas.push(field(&decoded, &mut cursor)?);
    }
    let definition_bytes = field(&decoded, &mut cursor)?;
    if definition_bytes.len() > 6 * definitions::BYTES + 1024 {
        return Err("construction definition framing capacity".into());
    }
    let definitions = serde_json::from_slice(&definition_bytes).map_err(|e| e.to_string())?;
    if cursor != decoded.len() {
        return Err("construction evidence trailing bytes".into());
    }
    let evidence = Evidence {
        certificate,
        lemmas,
        definitions,
    };
    if evidence.certificate.len() > limits.proof_bytes
        || evidence.lemmas.iter().any(|c| c.len() > limits.proof_bytes)
    {
        return Err("construction mathematical object capacity".into());
    }
    if evidence.lemmas.len() + evidence.definitions.len() >= limits.closure_objects {
        return Err("construction closure capacity".into());
    }
    Ok(evidence)
}
pub fn pack(proof: &proof::Verified) -> Result<Vec<u8>, String> {
    let evidence = Evidence {
        certificate: proof.certificate.to_canonical_bytes(),
        lemmas: proof
            .lemmas
            .iter()
            .map(ProofCertificate::to_canonical_bytes)
            .collect(),
        definitions: proof.definitions.clone(),
    };
    fn field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
        let length = u32::try_from(value.len()).map_err(|_| "construction evidence width")?;
        output.extend_from_slice(&length.to_le_bytes());
        output.extend_from_slice(value);
        Ok(())
    }
    let mut decoded = Vec::new();
    field(&mut decoded, &evidence.certificate)?;
    decoded.extend_from_slice(&(evidence.lemmas.len() as u32).to_le_bytes());
    for lemma in &evidence.lemmas {
        field(&mut decoded, lemma)?;
    }
    field(
        &mut decoded,
        &serde_json::to_vec(&evidence.definitions).map_err(|e| e.to_string())?,
    )?;
    if decoded.len() > crate::resources::limits().closure_bytes {
        return Err("construction decoded capacity".into());
    }
    let mut packed = (decoded.len() as u32).to_le_bytes().to_vec();
    packed.extend(lz4_flex::block::compress(&decoded));
    let _ = decode(&packed)?;
    Ok(packed)
}
pub fn compile(target: &Formula, bytes: &[u8]) -> Result<Term, String> {
    let evidence = decode(bytes)?;
    let term = Term::Native {
        certificate: ProofCertificate::from_canonical_bytes(&evidence.certificate)
            .map_err(|e| e.to_string())?,
        lemmas: evidence
            .lemmas
            .iter()
            .map(|b| ProofCertificate::from_canonical_bytes(b).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?,
        definitions: evidence.definitions,
        target: target.clone(),
    };
    if steps(bytes)? + selected(bytes)?.len() > crate::resources::limits().closure_steps {
        return Err("construction checker work capacity".into());
    }
    let checked = proof::verify(&term, target)?;
    if pack(&checked)? != bytes {
        return Err("construction evidence canonical binding".into());
    }
    Ok(term)
}
pub fn selected(bytes: &[u8]) -> Result<Vec<definitions::Entry>, String> {
    Ok(decode(bytes)?.definitions)
}
pub fn context(bytes: &[u8]) -> Result<naome_checker::ArtifactState, String> {
    let evidence = decode(bytes)?;
    let lemmas = evidence
        .lemmas
        .iter()
        .map(|b| ProofCertificate::from_canonical_bytes(b).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    proof::lemma_context(&evidence.definitions, &lemmas)
}
pub fn steps(bytes: &[u8]) -> Result<usize, String> {
    let evidence = decode(bytes)?;
    Ok(
        ProofCertificate::from_canonical_bytes(&evidence.certificate)
            .map_err(|e| e.to_string())?
            .steps()
            .len()
            + evidence
                .lemmas
                .iter()
                .map(|b| {
                    ProofCertificate::from_canonical_bytes(b)
                        .map(|c| c.steps().len())
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .sum::<usize>(),
    )
}
pub fn helpers(bytes: &[u8]) -> Result<Vec<String>, String> {
    let evidence = decode(bytes)?;
    let context = context(bytes)?;
    let certificate =
        ProofCertificate::from_canonical_bytes(&evidence.certificate).map_err(|e| e.to_string())?;
    let checked = naome_checker::normalize_and_check_with_state(certificate, &context)
        .map_err(|e| e.to_string())?;
    let target = checked.conclusion();
    let verified = proof::verify(&compile(target, bytes)?, target)?;
    let mut sources = verified
        .definitions
        .iter()
        .map(|e| e.source(&[]))
        .collect::<Result<Vec<_>, _>>()?;
    sources.extend(proof::lemma_sources(
        &verified.definitions,
        &verified.lemmas,
    )?);
    Ok(sources)
}
