use super::StateStorageError as Error;

pub(super) fn bytes(out: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(value.len()).map_err(|_| Error::Limit("journal field"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
pub(super) struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(Error::Invalid("journal field overflow"))?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(Error::Invalid("truncated journal field"))?;
        self.offset = end;
        Ok(value)
    }
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::Invalid("fixed journal field"))
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }
    pub fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    pub fn bytes(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let len = u32::from_be_bytes(self.fixed()?) as usize;
        if len > maximum {
            return Err(Error::Limit("journal field"));
        }
        self.take(len)
    }
    pub fn finish(self) -> Result<(), Error> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(Error::Invalid("trailing journal bytes"))
        }
    }
}
