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
            let _scratch = MemoryLease::acquire(
                self.bytes
                    .len()
                    .saturating_mul(2)
                    .saturating_add(COMMAND_PARSE_OVERHEAD),
            )?;
            allocation_bound(&self.bytes, budget)?
        };
        let memory = MemoryLease::acquire(bytes)?;
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
mod tests {
    use super::*;
    #[test]
    fn sparse_maps_are_charged_for_nodes_and_rejected_before_tree_allocation() {
        let source = format!("{}0{}", "{\"\":".repeat(100), "}".repeat(100));
        // Measured with the pinned Rust/serde_json allocator: this shape retains
        // 63,200 bytes, although its entire source is only 501 bytes.
        let bound = allocation_bound(source.as_bytes(), usize::MAX).unwrap();
        assert!(bound >= 63_200);
        assert_eq!(
            allocation_bound(source.as_bytes(), 63_199),
            Err(Error::InputLimit("CLI JSON allocation limit"))
        );
        let command = QueuedCommand::from_value(serde_json::from_str(&source).unwrap());
        let (parsed, memory) = command.parse().unwrap();
        assert_eq!(parsed, serde_json::from_str::<Value>(&source).unwrap());
        drop(memory);
    }
    #[test]
    fn maximum_escaped_sources_remain_supported_and_syntax_stays_strict() {
        let value = serde_json::json!({"command":"produce","source":"\u{1}".repeat(crate::resources::limits().producer_bytes),"request":"escaped"});
        let command = QueuedCommand::from_value(value.clone());
        assert!(command.bytes.len() < crate::resources::limits().command_bytes);
        let (parsed, _memory) = command.parse().unwrap();
        assert_eq!(parsed, value);
        for bytes in [b"{} {}".as_slice(), b"{\"a\":", b"[1,]", b"NaN"] {
            assert!(matches!(
                allocation_bound(bytes, usize::MAX),
                Err(Error::InvalidInput(_))
            ));
        }
    }
}
