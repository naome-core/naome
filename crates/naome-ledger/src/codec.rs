use crate::LedgerError;
use sha2::{Digest, Sha256};

/// Fixed-width big-endian fields and u32-length-prefixed byte strings.
pub(crate) struct Writer {
    sink: Sink,
    length: u64,
}
enum Sink {
    Bytes(Vec<u8>),
    Count,
    Hash(Sha256),
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self {
            sink: Sink::Bytes(Vec::new()),
            length: 0,
        }
    }
    pub(crate) fn counting() -> Self {
        Self {
            sink: Sink::Count,
            length: 0,
        }
    }
    pub(crate) fn len(&self) -> u64 {
        self.length
    }
    pub(crate) fn hashing(domain: &[u8], field_length: u64) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(field_length.to_be_bytes());
        Self {
            sink: Sink::Hash(hash),
            length: 0,
        }
    }
    pub(crate) fn u8(&mut self, value: u8) {
        self.fixed(&[value]);
    }
    pub(crate) fn u16(&mut self, value: u16) {
        self.fixed(&value.to_be_bytes());
    }
    pub(crate) fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }
    pub(crate) fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }
    pub(crate) fn u128(&mut self, value: u128) {
        self.fixed(&value.to_be_bytes());
    }
    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.length = self
            .length
            .checked_add(value.len() as u64)
            .expect("bounded canonical state length");
        match &mut self.sink {
            Sink::Bytes(bytes) => bytes.extend_from_slice(value),
            Sink::Count => {}
            Sink::Hash(hash) => hash.update(value),
        }
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), LedgerError> {
        self.u32(u32::try_from(value.len()).map_err(|_| LedgerError::Limit("field bytes"))?);
        self.fixed(value);
        Ok(())
    }
    pub(crate) fn string(&mut self, value: &str) -> Result<(), LedgerError> {
        self.bytes(value.as_bytes())
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        match self.sink {
            Sink::Bytes(bytes) => bytes,
            _ => panic!("byte output requested from streaming writer"),
        }
    }
    pub(crate) fn finish_hash(self) -> [u8; 32] {
        match self.sink {
            Sink::Hash(hash) => hash.finalize().into(),
            _ => panic!("hash output requested from byte writer"),
        }
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, LedgerError> {
        if bytes.len() > maximum {
            return Err(LedgerError::Limit("encoded value"));
        }
        Ok(Self { bytes, offset: 0 })
    }
    pub(crate) fn take(&mut self, length: usize) -> Result<&'a [u8], LedgerError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(LedgerError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(LedgerError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], LedgerError> {
        self.take(N)?.try_into().map_err(|_| LedgerError::Truncated)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, LedgerError> {
        Ok(self.fixed::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, LedgerError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, LedgerError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, LedgerError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub(crate) fn u128(&mut self) -> Result<u128, LedgerError> {
        Ok(u128::from_be_bytes(self.fixed()?))
    }
    pub(crate) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], LedgerError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(LedgerError::Limit("field bytes"));
        }
        self.take(length)
    }
    pub(crate) fn string(&mut self, maximum: usize) -> Result<&'a str, LedgerError> {
        std::str::from_utf8(self.bytes(maximum)?).map_err(|_| LedgerError::Invalid("UTF-8"))
    }
    pub(crate) fn finish(self) -> Result<(), LedgerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(LedgerError::TrailingBytes)
        }
    }
}
