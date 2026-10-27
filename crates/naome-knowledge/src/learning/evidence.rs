//! Bounded local search evidence. It is not an accepted mathematical artifact.
use super::{
    definitions,
    proof::{self, Term},
};
use naome_foundation::Formula;
use naome_proof::ProofCertificate;

pub(crate) struct Evidence {
    pub certificate: Vec<u8>,
    pub program: Option<super::program::Origin>,
    pub lemmas: Vec<Vec<u8>>,
    pub definitions: Vec<definitions::Entry>,
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Evidence, String> {
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
    let program =
        serde_json::from_slice(&field(&decoded, &mut cursor)?).map_err(|e| e.to_string())?;
    if cursor != decoded.len() {
        return Err("construction evidence trailing bytes".into());
    }
    let evidence = Evidence {
        program,
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
    pack_with_program(proof, None)
}
pub fn pack_with_program(
    proof: &proof::Verified,
    program: Option<super::program::Origin>,
) -> Result<Vec<u8>, String> {
    if let Some(origin) = &program {
        super::program::validate(origin, proof)?;
    }
    let evidence = Evidence {
        program,
        certificate: proof
            .certificate
            .clone()
            .into_unchecked_normal_form()
            .canonical_bytes()
            .to_vec(),
        lemmas: proof
            .lemmas
            .iter()
            .map(|certificate| {
                certificate
                    .clone()
                    .into_unchecked_normal_form()
                    .canonical_bytes()
                    .to_vec()
            })
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
    field(
        &mut decoded,
        &serde_json::to_vec(&evidence.program).map_err(|e| e.to_string())?,
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
    if pack_with_program(&checked, evidence.program)? != bytes {
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
    let checked =
        crate::learning::proof::check(certificate, &context).map_err(|e| e.to_string())?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packing_a_checked_non_normal_source_produces_the_unique_replay_packet() {
        let certificate = ProofCertificate::new(vec![
            naome_proof::ProofStep::ZfcAxiom(naome_foundation::ZfcAxiom::Foundation),
            naome_proof::ProofStep::ZfcAxiom(naome_foundation::ZfcAxiom::Pairing),
        ])
        .unwrap();
        let checked =
            proof::check(certificate.clone(), &naome_checker::ArtifactState::new()).unwrap();
        let verified = proof::Verified {
            certificate,
            lemmas: vec![],
            definitions: vec![],
            target: checked.conclusion().clone(),
            native_id: checked.proof_id(),
            payload_bytes: checked.normal_form().canonical_bytes().len(),
        };
        let packet = pack(&verified).unwrap();
        let restored = proof::verify(
            &compile(&verified.target, &packet).unwrap(),
            &verified.target,
        )
        .unwrap();
        assert_eq!(restored.native_id, verified.native_id);
        assert_eq!(restored.certificate.steps().len(), 1);
        assert_eq!(pack(&restored).unwrap(), packet);
    }
}
