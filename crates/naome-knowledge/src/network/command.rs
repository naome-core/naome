//! Count JSON tree allocations before constructing a command's retained value.
use super::{QueuedCommand, Value};
use crate::{
    Error,
    resources::{COMMAND_PARSE_OVERHEAD, MemoryLease},
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{fmt, sync::Arc};

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

struct Budget {
    charged: usize,
    limit: usize,
    exceeded: bool,
}
impl Budget {
    fn charge<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        // Dispatch may retain input fields while cloning request metadata and
        // formatting its response. Keep that ownership inside the same lease.
        match bytes
            .checked_mul(8)
            .and_then(|bytes| self.charged.checked_add(bytes))
        {
            Some(total) if total <= self.limit => {
                self.charged = total;
                Ok(())
            }
            _ => {
                self.exceeded = true;
                Err(E::custom("CLI JSON allocation limit"))
            }
        }
    }
    fn string<E: de::Error>(&mut self, text: &str) -> Result<(), E> {
        self.charge(text.len().saturating_mul(2).saturating_add(64))
    }
}
fn allocation_bound(bytes: &[u8], limit: usize) -> Result<usize, Error> {
    let mut budget = Budget {
        charged: COMMAND_PARSE_OVERHEAD,
        limit,
        exceeded: false,
    };
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let result = Count(&mut budget)
        .deserialize(&mut decoder)
        .and_then(|()| decoder.end());
    if budget.exceeded || budget.charged > limit {
        return Err(Error::InputLimit("CLI JSON allocation limit"));
    }
    result.map_err(|error| Error::InvalidInput(error.to_string()))?;
    Ok(budget.charged)
}

struct Count<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for Count<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Count<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        self.0.string(text)
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<(), S::Error> {
        while sequence.next_element_seed(Count(&mut *self.0))?.is_some() {
            // Covers vector growth, each Value, and allocator overhead.
            self.0.charge(256)?;
        }
        Ok(())
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        while map.next_key_seed(Key(&mut *self.0))?.is_some() {
            // Even one entry may allocate a whole sparse B-tree node.
            self.0.charge(1024)?;
            map.next_value_seed(Count(&mut *self.0))?;
        }
        Ok(())
    }
}
struct Key<'a>(&'a mut Budget);
impl<'de> DeserializeSeed<'de> for Key<'_> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for Key<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object key")
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        self.0.string(text)
    }
}

#[cfg(test)]
mod tests;
