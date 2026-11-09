//! Bounded local search evidence. It is not an accepted mathematical artifact.
use super::{
    definitions,
    proof::{self, Term},
};
use crate::outcome::EvidenceCode;
use naome_foundation::Formula;
use naome_proof::ProofCertificate;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EvidenceLimit {
    PacketBytes = 1,
    DecodedBytes = 2,
    DefinitionBytes = 3,
    ObjectBytes = 4,
    ClosureObjects = 5,
    LemmaCount = 6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Limit {
        resource: EvidenceLimit,
        actual: usize,
        maximum: usize,
    },
    Framing,
    Compression,
    Definitions,
}

impl Failure {
    fn limit(resource: EvidenceLimit, actual: usize, maximum: usize) -> Self {
        Self::Limit {
            resource,
            actual,
            maximum,
        }
    }

    pub(crate) fn code(self) -> EvidenceCode {
        match self {
            Self::Limit { .. } => EvidenceCode::Limit,
            Self::Framing => EvidenceCode::Framing,
            Self::Compression => EvidenceCode::Compression,
            Self::Definitions => EvidenceCode::Definitions,
        }
    }
}

impl serde::Serialize for Failure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut output = serializer.serialize_struct(
            "EvidenceFailure",
            if matches!(self, Self::Limit { .. }) {
                4
            } else {
                1
            },
        )?;
        output.serialize_field("code", &self.code())?;
        if let Self::Limit {
            resource,
            actual,
            maximum,
        } = *self
        {
            output.serialize_field("resource", &(resource as u8))?;
            output.serialize_field("actual", &actual)?;
            output.serialize_field("maximum", &maximum)?;
        }
        output.end()
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Limit {
                resource,
                actual,
                maximum,
                ..
            } => {
                write!(
                    formatter,
                    "evidence limit {resource:?}: {actual} > {maximum}"
                )
            }
            other => write!(formatter, "evidence {}", u32::from(other.code())),
        }
    }
}

impl From<Failure> for String {
    fn from(error: Failure) -> Self {
        error.to_string()
    }
}

pub(crate) struct Evidence {
    pub certificate: Vec<u8>,
    pub lemmas: Vec<Vec<u8>>,
    pub definitions: Vec<definitions::Entry>,
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Evidence, Failure> {
    let limits = crate::resources::limits();
    if bytes.len() < 4 {
        return Err(Failure::Framing);
    }
    if bytes.len() > limits.proof_bytes {
        return Err(Failure::limit(
            EvidenceLimit::PacketBytes,
            bytes.len(),
            limits.proof_bytes,
        ));
    }
    let size = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Failure::Framing)?) as usize;
    if size > limits.closure_bytes {
        return Err(Failure::limit(
            EvidenceLimit::DecodedBytes,
            size,
            limits.closure_bytes,
        ));
    }
    let mut decoded = vec![0; size];
    let actual = lz4_flex::block::decompress_into(&bytes[4..], &mut decoded)
        .map_err(|_| Failure::Compression)?;
    if actual != size {
        return Err(Failure::Framing);
    }
    let mut cursor = 0usize;
    fn number(bytes: &[u8], cursor: &mut usize) -> Result<usize, Failure> {
        let end = cursor
            .checked_add(4)
            .filter(|end| *end <= bytes.len())
            .ok_or(Failure::Framing)?;
        let value = u32::from_le_bytes(
            bytes[*cursor..end]
                .try_into()
                .map_err(|_| Failure::Framing)?,
        ) as usize;
        *cursor = end;
        Ok(value)
    }
    fn field(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, Failure> {
        let length = number(bytes, cursor)?;
        let end = cursor
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(Failure::Framing)?;
        let value = bytes[*cursor..end].to_vec();
        *cursor = end;
        Ok(value)
    }
    let certificate = field(&decoded, &mut cursor)?;
    let count = number(&decoded, &mut cursor)?;
    if count >= limits.closure_objects {
        return Err(Failure::limit(
            EvidenceLimit::LemmaCount,
            count,
            limits.closure_objects.saturating_sub(1),
        ));
    }
    let mut lemmas = Vec::with_capacity(count);
    for _ in 0..count {
        lemmas.push(field(&decoded, &mut cursor)?);
    }
    let definition_bytes = field(&decoded, &mut cursor)?;
    if definition_bytes.len() > 6 * definitions::BYTES + 1024 {
        return Err(Failure::limit(
            EvidenceLimit::DefinitionBytes,
            definition_bytes.len(),
            6 * definitions::BYTES + 1024,
        ));
    }
    let definitions =
        serde_json::from_slice(&definition_bytes).map_err(|_| Failure::Definitions)?;
    if cursor != decoded.len() {
        return Err(Failure::Framing);
    }
    let evidence = Evidence {
        certificate,
        lemmas,
        definitions,
    };
    if let Some(actual) = std::iter::once(&evidence.certificate)
        .chain(&evidence.lemmas)
        .map(Vec::len)
        .find(|&length| length > limits.proof_bytes)
    {
        return Err(Failure::limit(
            EvidenceLimit::ObjectBytes,
            actual,
            limits.proof_bytes,
        ));
    }
    let objects = evidence.lemmas.len() + evidence.definitions.len();
    if objects >= limits.closure_objects {
        return Err(Failure::limit(
            EvidenceLimit::ClosureObjects,
            objects,
            limits.closure_objects.saturating_sub(1),
        ));
    }
    Ok(evidence)
}
pub fn pack(proof: &proof::Verified) -> Result<Vec<u8>, Failure> {
    let evidence = Evidence {
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
    fn field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Failure> {
        let length = u32::try_from(value.len()).map_err(|_| Failure::Framing)?;
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
        &serde_json::to_vec(&evidence.definitions).map_err(|_| Failure::Definitions)?,
    )?;
    let maximum = crate::resources::limits().closure_bytes;
    if decoded.len() > maximum {
        return Err(Failure::limit(
            EvidenceLimit::DecodedBytes,
            decoded.len(),
            maximum,
        ));
    }
    let mut packed = (decoded.len() as u32).to_le_bytes().to_vec();
    packed.extend(lz4_flex::block::compress(&decoded));
    let _ = decode(&packed)?;
    Ok(packed)
}
pub fn checked(bytes: &[u8]) -> Result<proof::Verified, crate::Error> {
    let evidence = decode(bytes)?;
    let certificate = ProofCertificate::from_canonical_bytes(&evidence.certificate)
        .map_err(|e| crate::object::certificate_error(&evidence.certificate, e))?;
    let lemmas = evidence
        .lemmas
        .iter()
        .map(|b| {
            ProofCertificate::from_canonical_bytes(b)
                .map_err(|e| crate::object::certificate_error(b, e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let work = certificate.steps().len()
        + lemmas.iter().map(|c| c.steps().len()).sum::<usize>()
        + evidence.definitions.len();
    if work > crate::resources::limits().closure_steps {
        return Err(crate::ResearchFailure::EvidenceCheckerCapacity.into());
    }
    let checked = proof::verify_native(certificate, evidence.definitions, lemmas, None)?;
    if pack(&checked)? != bytes {
        return Err(crate::ResearchFailure::EvidenceCanonicalBinding.into());
    }
    Ok(checked)
}
pub fn compile(target: &Formula, bytes: &[u8]) -> Result<Term, crate::Error> {
    let checked = checked(bytes)?;
    if checked.target != *target {
        return Err(crate::ResearchFailure::EvidenceTargetBinding.into());
    }
    Ok(Term::Native {
        certificate: checked.certificate,
        lemmas: checked.lemmas,
        definitions: checked.definitions,
        target: checked.target,
    })
}
pub fn selected(bytes: &[u8]) -> Result<Vec<definitions::Entry>, crate::Error> {
    Ok(decode(bytes)?.definitions)
}
pub fn context(bytes: &[u8]) -> Result<naome_checker::ArtifactState, crate::Error> {
    let evidence = decode(bytes)?;
    let lemmas = evidence
        .lemmas
        .iter()
        .map(|b| {
            ProofCertificate::from_canonical_bytes(b)
                .map_err(|e| crate::object::certificate_error(b, e))
        })
        .collect::<Result<Vec<_>, _>>()?;
    proof::lemma_context(&evidence.definitions, &lemmas).map_err(Into::into)
}
pub fn steps(bytes: &[u8]) -> Result<usize, crate::Error> {
    let evidence = decode(bytes)?;
    Ok(
        ProofCertificate::from_canonical_bytes(&evidence.certificate)
            .map_err(|e| crate::object::certificate_error(&evidence.certificate, e))?
            .steps()
            .len()
            + evidence
                .lemmas
                .iter()
                .map(|b| {
                    ProofCertificate::from_canonical_bytes(b)
                        .map(|c| c.steps().len())
                        .map_err(|e| crate::object::certificate_error(b, e))
                })
                .collect::<Result<Vec<_>, _>>()?
                .iter()
                .sum::<usize>(),
    )
}
pub fn helpers(bytes: &[u8]) -> Result<Vec<String>, crate::Error> {
    let verified = checked(bytes)?;
    let mut sources = Vec::new();
    super::definitions::append_artifacts(&verified.definitions, &mut sources)?;
    for lemma in proof::lemma_sources(&verified.definitions, &verified.lemmas)? {
        if !sources.contains(&lemma) {
            sources.push(lemma);
        }
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_evidence_keeps_its_framing_code() {
        let error = checked(&[]).err().unwrap();
        assert_eq!(
            serde_json::to_value(error).unwrap()["code"],
            u32::from(crate::outcome::EvidenceCode::Framing)
        );
    }

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
