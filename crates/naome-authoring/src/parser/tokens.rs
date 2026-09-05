//! Source tokens and strict identifier decoding.

use super::*;

impl<'source> Parser<'source> {
    pub(super) fn proof_id(&mut self) -> Result<ProofId, CompileError> {
        self.fixed_id_bytes("a 64-digit lowercase hexadecimal ProofId")
            .map(ProofId::from_bytes)
    }

    pub(super) fn definition_id(&mut self) -> Result<DefinitionId, CompileError> {
        self.fixed_id_bytes("a 64-digit lowercase hexadecimal DefinitionId")
            .map(DefinitionId::from_bytes)
    }

    fn fixed_id_bytes(&mut self, expected: &'static str) -> Result<[u8; 32], CompileError> {
        const HEX_LENGTH: usize = 64;
        self.skip_trivia();
        let quote_offset = self.offset;
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: quote_offset,
                expected,
            });
        }
        self.offset += 1;
        let offset = self.offset;
        let Some(encoded) = self.source.as_bytes().get(offset..offset + HEX_LENGTH) else {
            return Err(CompileError::Syntax { offset, expected });
        };
        let mut bytes = [0_u8; 32];
        for (index, (pair, byte)) in encoded.chunks_exact(2).zip(bytes.iter_mut()).enumerate() {
            let high_offset = offset + index * 2;
            let high_byte = pair[0];
            let Some(high) = lowercase_hex_nibble(high_byte) else {
                return Err(CompileError::Syntax {
                    offset: proof_id_error_offset(offset, high_offset, high_byte),
                    expected,
                });
            };
            let low_offset = high_offset + 1;
            let low_byte = pair[1];
            let Some(low) = lowercase_hex_nibble(low_byte) else {
                return Err(CompileError::Syntax {
                    offset: proof_id_error_offset(offset, low_offset, low_byte),
                    expected,
                });
            };
            *byte = (high << 4) | low;
        }
        self.offset += HEX_LENGTH;
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: self.offset,
                expected: "a closing quote after the ProofId",
            });
        }
        self.offset += 1;
        Ok(bytes)
    }

    pub(super) fn keyword(&mut self, expected: &'static str) -> Result<(), CompileError> {
        let offset = self.next_offset();
        let actual = self.name()?;
        if actual == expected {
            Ok(())
        } else {
            Err(CompileError::Syntax { offset, expected })
        }
    }

    pub(super) fn name(&mut self) -> Result<&'source str, CompileError> {
        self.skip_trivia();
        let start = self.offset;
        let mut characters = self.source[start..].char_indices();
        let Some((_, first)) = characters.next() else {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a name",
            });
        };
        if !first.is_ascii_alphabetic() && first != '_' {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a name",
            });
        }
        let mut end = start + first.len_utf8();
        for (relative, character) in characters {
            if !character.is_ascii_alphanumeric() && character != '_' {
                break;
            }
            end = start + relative + character.len_utf8();
        }
        self.offset = end;
        Ok(&self.source[start..end])
    }

    pub(super) fn string(&mut self, expected: &'static str) -> Result<&'source str, CompileError> {
        self.skip_trivia();
        let start = self.offset;
        if self.byte() != Some(b'"') {
            return Err(CompileError::Syntax {
                offset: start,
                expected,
            });
        }
        self.offset += 1;
        let content_start = self.offset;
        let Some(relative_end) = self.source[content_start..].find('"') else {
            return Err(CompileError::Syntax {
                offset: start,
                expected: "a closing quote",
            });
        };
        let content_end = content_start + relative_end;
        self.offset = content_end + 1;
        Ok(&self.source[content_start..content_end])
    }

    pub(super) fn punctuation(&mut self, expected: char) -> Result<(), CompileError> {
        self.skip_trivia();
        let offset = self.offset;
        if self.source[offset..].starts_with(expected) {
            self.offset += expected.len_utf8();
            Ok(())
        } else {
            Err(CompileError::Syntax {
                offset,
                expected: match expected {
                    ':' => "`:`",
                    '(' => "`(`",
                    ')' => "`)`",
                    '=' => "`=`",
                    ',' => "`,`",
                    '[' => "`[`",
                    _ => "punctuation",
                },
            })
        }
    }

    pub(super) fn end(&mut self) -> Result<(), CompileError> {
        self.skip_trivia();
        if self.offset == self.source.len() {
            Ok(())
        } else {
            Err(CompileError::Syntax {
                offset: self.offset,
                expected: "end of source",
            })
        }
    }

    pub(super) fn peek_word(&mut self, expected: &str) -> bool {
        self.skip_trivia();
        let remainder = &self.source[self.offset..];
        remainder.starts_with(expected)
            && remainder[expected.len()..]
                .chars()
                .next()
                .is_none_or(|character| !character.is_ascii_alphanumeric() && character != '_')
    }

    pub(super) fn call_end(&mut self) -> Result<(), CompileError> {
        self.skip_trivia();
        if self.byte() == Some(b',') {
            self.offset += 1;
        }
        self.punctuation(')')
    }

    pub(super) fn next_offset(&mut self) -> usize {
        self.skip_trivia();
        self.offset
    }

    pub(super) fn skip_trivia(&mut self) {
        loop {
            while matches!(self.byte(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                self.offset += 1;
            }
            if self.byte() != Some(b'#') {
                break;
            }
            self.offset += 1;
            while !matches!(self.byte(), None | Some(b'\n')) {
                self.offset += 1;
            }
        }
    }

    pub(super) fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }
}
