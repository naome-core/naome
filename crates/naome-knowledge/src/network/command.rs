//! Count JSON tree allocations before constructing a command's retained value.
use super::{QueuedCommand, Value};
use crate::resources::json::allocation_bound;
use crate::{
    Error,
    resources::{COMMAND_PARSE_OVERHEAD, MemoryLease},
};
use std::sync::Arc;

impl QueuedCommand {
    pub(super) fn parse(&self) -> Result<(Value, Arc<MemoryLease>), Error> {
        let budget = crate::resources::limits()
            .command_parse_budget()
            .ok_or(Error::InputLimit("CLI JSON allocation budget overflow"))?;
        let bytes = {
            // The streaming pass retains only serde_json's string scratch space.
            let _scratch = MemoryLease::acquire_control(
                self.bytes
                    .len()
                    .saturating_mul(2)
                    .saturating_add(COMMAND_PARSE_OVERHEAD),
            )?;
            allocation_bound(&self.bytes, budget)?
        };
        let memory = MemoryLease::acquire_control(bytes)?;
        let value = serde_json::from_slice(&self.bytes)
            .map_err(|error| Error::InvalidInput(error.to_string()))?;
        Ok((value, memory))
    }
}

#[cfg(test)]
mod tests;
