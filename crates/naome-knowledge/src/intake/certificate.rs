//! One pre-allocation transport charge for every certificate in a closure.
use crate::{Envelope, Error};

pub(in crate::intake) fn resources(object: &Envelope) -> Result<(usize, usize), Error> {
    if object.proof.len() > 2 * crate::resources::limits().proof_bytes
        || !object.proof.len().is_multiple_of(2)
    {
        return Err(Error::InputLimit("staged certificate byte capacity"));
    }
    let header = crate::unhex(
        object
            .proof
            .get(..8)
            .ok_or("truncated certificate header")?,
    )?;
    let steps = u32::from_be_bytes(header.try_into().map_err(|_| "certificate header")?) as usize;
    if steps == 0 {
        return Err(Error::InputLimit("empty certificate"));
    }
    Ok((object.proof.len() / 2, steps))
}
