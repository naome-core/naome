use naome_ledger::LedgerError;

pub(super) struct Writer(Vec<u8>);
impl Writer {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }
    pub(super) fn fixed(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    pub(super) fn u16(&mut self, value: u16) {
        self.fixed(&value.to_be_bytes());
    }
    pub(super) fn u32(&mut self, value: u32) {
        self.fixed(&value.to_be_bytes());
    }
    pub(super) fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }
    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), LedgerError> {
        self.u32(u32::try_from(value.len()).map_err(|_| LedgerError::Limit("field bytes"))?);
        self.fixed(value);
        Ok(())
    }
    pub(super) fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, LedgerError> {
        if bytes.len() > maximum {
            return Err(LedgerError::Limit("encoded value"));
        }
        Ok(Self { bytes, offset: 0 })
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], LedgerError> {
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
    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], LedgerError> {
        self.take(N)?.try_into().map_err(|_| LedgerError::Truncated)
    }
    pub(super) fn u16(&mut self) -> Result<u16, LedgerError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, LedgerError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, LedgerError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub(super) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], LedgerError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(LedgerError::Limit("field bytes"));
        }
        self.take(length)
    }
    pub(super) fn finish(self) -> Result<(), LedgerError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(LedgerError::TrailingBytes)
        }
    }
}
