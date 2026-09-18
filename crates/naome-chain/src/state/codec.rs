use naome_ledger::ResearchError;

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
    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), ResearchError> {
        self.u32(u32::try_from(value.len()).map_err(|_| ResearchError::Limit("field bytes"))?);
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
    pub(super) fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, ResearchError> {
        if bytes.len() > maximum {
            return Err(ResearchError::Limit("encoded value"));
        }
        Ok(Self { bytes, offset: 0 })
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ResearchError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ResearchError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ResearchError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ResearchError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ResearchError::Truncated)
    }
    pub(super) fn u16(&mut self) -> Result<u16, ResearchError> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }
    pub(super) fn u32(&mut self) -> Result<u32, ResearchError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }
    pub(super) fn u64(&mut self) -> Result<u64, ResearchError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub(super) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], ResearchError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(ResearchError::Limit("field bytes"));
        }
        self.take(length)
    }
    pub(super) fn finish(self) -> Result<(), ResearchError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ResearchError::TrailingBytes)
        }
    }
}
