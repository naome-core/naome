use naome_proof::ProofId;

use super::{
    KEY_BITS, ProofPathStep, ProofSetProof, ProofSetProofError, ProofSetRoot, ProofTerminal,
};

const EMPTY_TERMINAL_TAG: u8 = 0x00;
const MEMBER_TERMINAL_TAG: u8 = 0x01;
const NON_MEMBER_TERMINAL_TAG: u8 = 0x02;
const PROOF_ID_BYTES: usize = ProofId::BYTE_LENGTH;
const PATH_STEP_BYTES: usize = 1 + ProofSetRoot::BYTE_LENGTH;
const TERMINAL_TAG_BYTES: usize = 1;
const NON_MEMBER_PREFIX_BYTES: usize = TERMINAL_TAG_BYTES + PROOF_ID_BYTES;

/// Maximum length of one canonical proof-set proof.
///
/// A membership proof can authenticate all 256 key bits. A non-membership
/// proof can authenticate at most 255 bits because its terminal key must
/// differ from the query outside the authenticated branch positions.
pub const PROOF_SET_PROOF_MAX_BYTES: usize = TERMINAL_TAG_BYTES + KEY_BITS * PATH_STEP_BYTES;

impl ProofSetProof {
    /// Encodes this proof in the canonical proof-set wire format.
    #[must_use]
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        debug_assert!(self.validate_shape().is_ok());

        let prefix_bytes = match self.terminal {
            ProofTerminal::Empty | ProofTerminal::Member => TERMINAL_TAG_BYTES,
            ProofTerminal::NonMember(_) => NON_MEMBER_PREFIX_BYTES,
        };
        let mut output = Vec::with_capacity(prefix_bytes + self.path.len() * PATH_STEP_BYTES);

        match self.terminal {
            ProofTerminal::Empty => output.push(EMPTY_TERMINAL_TAG),
            ProofTerminal::Member => output.push(MEMBER_TERMINAL_TAG),
            ProofTerminal::NonMember(proof_id) => {
                output.push(NON_MEMBER_TERMINAL_TAG);
                output.extend_from_slice(proof_id.as_bytes());
            }
        }
        for step in &self.path {
            output.push(step.bit);
            output.extend_from_slice(&step.sibling);
        }

        output
    }

    /// Decodes one complete canonical proof-set proof.
    ///
    /// Decoding validates only the canonical structure. Call [`Self::verify`]
    /// with a trusted root and the queried [`ProofId`] before using the
    /// membership result.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProofSetProofError> {
        if bytes.len() > PROOF_SET_PROOF_MAX_BYTES {
            return Err(ProofSetProofError::InputTooLong {
                actual: bytes.len(),
                maximum: PROOF_SET_PROOF_MAX_BYTES,
            });
        }

        let Some((&tag, remaining)) = bytes.split_first() else {
            return Err(ProofSetProofError::UnexpectedEnd);
        };

        let (terminal, path_bytes) = match tag {
            EMPTY_TERMINAL_TAG => {
                if !remaining.is_empty() {
                    return Err(ProofSetProofError::TrailingBytes {
                        remaining: remaining.len(),
                    });
                }
                (ProofTerminal::Empty, remaining)
            }
            MEMBER_TERMINAL_TAG => (ProofTerminal::Member, remaining),
            NON_MEMBER_TERMINAL_TAG => {
                if remaining.len() < PROOF_ID_BYTES {
                    return Err(ProofSetProofError::UnexpectedEnd);
                }
                let (proof_id, path) = remaining.split_at(PROOF_ID_BYTES);
                let proof_id = ProofId::from_bytes(
                    proof_id
                        .try_into()
                        .expect("the checked terminal slice has exactly one proof identity"),
                );
                (ProofTerminal::NonMember(proof_id), path)
            }
            unknown => return Err(ProofSetProofError::UnknownTerminalTag(unknown)),
        };

        if path_bytes.len() % PATH_STEP_BYTES != 0 {
            return Err(ProofSetProofError::UnexpectedEnd);
        }
        let path_len = path_bytes.len() / PATH_STEP_BYTES;
        let mut path = Vec::with_capacity(path_len);
        for encoded_step in path_bytes.chunks_exact(PATH_STEP_BYTES) {
            path.push(ProofPathStep {
                bit: encoded_step[0],
                sibling: encoded_step[1..]
                    .try_into()
                    .expect("a proof-set path step has exactly one sibling root"),
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
