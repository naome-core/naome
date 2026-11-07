//! One pre-allocation transport charge for every certificate in a closure.
use crate::{Envelope, Error};

/// Cumulative certificate work for one entire unpublished closure. Program
/// streams have their own bounded working sets, but share the member ceiling.
#[derive(Clone, Copy, Default)]
pub(in crate::intake) struct Usage {
    count: usize,
    bytes: usize,
    steps: usize,
}
impl Usage {
    pub(in crate::intake) fn add(self, object: &Envelope) -> Result<Self, Error> {
        let (bytes, steps) = resources(object)?;
        let next = Self {
            count: self
                .count
                .checked_add(1)
                .ok_or(Error::InputLimit("staged closure object overflow"))?,
            bytes: self
                .bytes
                .checked_add(bytes)
                .ok_or(Error::InputLimit("staged closure byte overflow"))?,
            steps: self
                .steps
                .checked_add(steps)
                .ok_or(Error::InputLimit("staged closure step overflow"))?,
        };
        let limits = crate::resources::limits();
        if next.steps > limits.closure_steps {
            return Err(Error::InputLimit("staged closure step work limit"));
        }
        if next.count > limits.closure_objects
            || next.bytes > limits.closure_bytes
            || next
                .count
                .checked_mul(naome_checker::CHECKER_MAX_FORMULA_WORK_BYTES)
                .is_none_or(|bytes| bytes > limits.closure_work_bytes)
        {
            return Err(Error::InputLimit("staged closure resource capacity"));
        }
        Ok(next)
    }
    #[cfg(test)]
    pub(in crate::intake) fn steps(&self) -> usize {
        self.steps
    }
}

pub(in crate::intake) fn resources(object: &Envelope) -> Result<(usize, usize), Error> {
    if object.payload.len() > 2 * crate::resources::limits().proof_bytes
        || !object.payload.len().is_multiple_of(2)
    {
        return Err(Error::InputLimit("staged certificate byte capacity"));
    }
    let tag = object.payload.get(..2).ok_or("truncated artifact header")?;
    let steps = match tag {
        "00" => {
            let header = crate::unhex(
                object
                    .payload
                    .get(2..10)
                    .ok_or("truncated certificate header")?,
            )?;
            let steps =
                u32::from_be_bytes(header.try_into().map_err(|_| "certificate header")?) as usize;
            if steps == 0 {
                return Err(Error::InputLimit("empty certificate"));
            }
            steps
        }
        "01" => 1,
        _ => return Err("unknown artifact payload".into()),
    };
    Ok((object.payload.len() / 2, steps))
}
