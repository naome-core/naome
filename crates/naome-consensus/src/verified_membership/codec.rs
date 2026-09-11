//! Bounded, exact binary framing for the organization-membership profile.

use super::MembershipError;

pub(super) struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], maximum: usize) -> Result<Self, MembershipError> {
        if bytes.len() > maximum {
            return Err(MembershipError::Limit);
        }
        Ok(Self { remaining: bytes })
    }

    pub fn take(&mut self, length: usize) -> Result<&'a [u8], MembershipError> {
        let (head, tail) = self
            .remaining
            .split_at_checked(length)
            .ok_or(MembershipError::Encoding)?;
        self.remaining = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], MembershipError> {
        self.take(N)?
            .try_into()
            .map_err(|_| MembershipError::Encoding)
    }

    pub fn byte(&mut self) -> Result<u8, MembershipError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u16(&mut self) -> Result<u16, MembershipError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u64(&mut self) -> Result<u64, MembershipError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, MembershipError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn finish(self) -> Result<(), MembershipError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(MembershipError::Encoding)
        }
    }
}
