use super::{Result, StateConsensusError as Error};

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8], maximum: usize) -> Result<Self> {
        if bytes.len() > maximum {
            return Err(Error::Limit("wire bytes"));
        }
        Ok(Self { bytes, offset: 0 })
    }
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or(Error::Overflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::Invalid("truncated wire"))?;
        self.offset = end;
        Ok(bytes)
    }
    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Invalid("fixed field"))
    }
    pub(super) fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    pub(super) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub(super) fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = u32::from_be_bytes(self.fixed()?) as usize;
        if length > maximum {
            return Err(Error::Limit("wire field"));
        }
        self.take(length)
    }
    pub(super) fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(Error::Invalid("trailing wire"));
        }
        Ok(())
    }
}
pub(super) fn bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| Error::Limit("wire field"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}
