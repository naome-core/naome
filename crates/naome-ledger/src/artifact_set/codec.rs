use naome_proof::ArtifactId;

use super::{
    ArtifactPathStep, ArtifactSetProof, ArtifactSetProofError, ArtifactSetRoot, ArtifactTerminal,
    KEY_BITS,
};

const EMPTY_TERMINAL_TAG: u8 = 0x00;
const MEMBER_TERMINAL_TAG: u8 = 0x01;
const NON_MEMBER_TERMINAL_TAG: u8 = 0x02;
const ARTIFACT_ID_BYTES: usize = ArtifactId::BYTE_LENGTH;
const PATH_STEP_BYTES: usize = 1 + ArtifactSetRoot::BYTE_LENGTH;
const TERMINAL_TAG_BYTES: usize = 1;
const NON_MEMBER_PREFIX_BYTES: usize = TERMINAL_TAG_BYTES + ARTIFACT_ID_BYTES;

/// Maximum length of one canonical artifact-set proof.
///
/// A membership proof can authenticate all 256 key bits. A non-membership
/// proof can authenticate at most 255 bits because its terminal key must
/// differ from the query outside the authenticated branch positions.
pub const ARTIFACT_SET_PROOF_MAX_BYTES: usize = TERMINAL_TAG_BYTES + KEY_BITS * PATH_STEP_BYTES;

impl ArtifactSetProof {
    /// Encodes this proof in the canonical artifact-set wire format.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        debug_assert!(self.validate_shape().is_ok());

        let prefix_bytes = match self.terminal {
            ArtifactTerminal::Empty | ArtifactTerminal::Member => TERMINAL_TAG_BYTES,
            ArtifactTerminal::NonMember(_) => NON_MEMBER_PREFIX_BYTES,
        };
        let mut output = Vec::with_capacity(prefix_bytes + self.path.len() * PATH_STEP_BYTES);

        match self.terminal {
            ArtifactTerminal::Empty => output.push(EMPTY_TERMINAL_TAG),
            ArtifactTerminal::Member => output.push(MEMBER_TERMINAL_TAG),
            ArtifactTerminal::NonMember(artifact_id) => {
                output.push(NON_MEMBER_TERMINAL_TAG);
                output.extend_from_slice(artifact_id.as_bytes());
            }
        }
        for step in &self.path {
            output.push(step.bit);
            output.extend_from_slice(&step.sibling);
        }

        output
    }

    /// Decodes one complete canonical artifact-set proof.
    ///
    /// Decoding validates only the canonical structure. Call [`Self::verify`]
    /// with a trusted root and the queried [`ArtifactId`] before using the
    /// membership result.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ArtifactSetProofError> {
        if bytes.len() > ARTIFACT_SET_PROOF_MAX_BYTES {
            return Err(ArtifactSetProofError::InputTooLong {
                actual: bytes.len(),
                maximum: ARTIFACT_SET_PROOF_MAX_BYTES,
            });
        }

        let Some((&tag, remaining)) = bytes.split_first() else {
            return Err(ArtifactSetProofError::UnexpectedEnd);
        };

        let (terminal, path_bytes) = match tag {
            EMPTY_TERMINAL_TAG => {
                if !remaining.is_empty() {
                    return Err(ArtifactSetProofError::TrailingBytes {
                        remaining: remaining.len(),
                    });
                }
                (ArtifactTerminal::Empty, remaining)
            }
            MEMBER_TERMINAL_TAG => (ArtifactTerminal::Member, remaining),
            NON_MEMBER_TERMINAL_TAG => {
                if remaining.len() < ARTIFACT_ID_BYTES {
                    return Err(ArtifactSetProofError::UnexpectedEnd);
                }
                let (artifact_id, path) = remaining.split_at(ARTIFACT_ID_BYTES);
                let artifact_id = ArtifactId::from_bytes(
                    artifact_id
                        .try_into()
                        .expect("the checked terminal slice has exactly one artifact identity"),
                );
                (ArtifactTerminal::NonMember(artifact_id), path)
            }
            unknown => return Err(ArtifactSetProofError::UnknownTerminalTag(unknown)),
        };

        if path_bytes.len() % PATH_STEP_BYTES != 0 {
            return Err(ArtifactSetProofError::UnexpectedEnd);
        }
        let path_len = path_bytes.len() / PATH_STEP_BYTES;
        let mut path = Vec::with_capacity(path_len);
        for encoded_step in path_bytes.chunks_exact(PATH_STEP_BYTES) {
            path.push(ArtifactPathStep {
                bit: encoded_step[0],
                sibling: encoded_step[1..]
                    .try_into()
                    .expect("an artifact-set path step has exactly one sibling root"),
            });
        }

        let proof = Self {
            terminal,
            path: path.into_boxed_slice(),
        };
        proof.validate_shape()?;
        Ok(proof)
    }
}

#[cfg(test)]
mod tests;
