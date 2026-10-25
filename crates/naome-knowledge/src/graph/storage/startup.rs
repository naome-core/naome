//! Coalesce startup writes in the existing bounded raw-byte cache.
//! Every restart still begins empty and rechecks the canonical corpus.
use super::*;

impl CheckedStorage {
    pub(in crate::graph) fn begin_startup_page(&self) -> Result<(), String> {
        self.require_live()?;
        self.adapt_cache()?;
        self.begin_write_phase()?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| "checked cache lock poisoned")?;
        if cache.buffering.is_some() || !cache.pending.is_empty() || cache.closed {
            return Err("startup page already buffered or closed".into());
        }
        cache.buffering = Some(self.generation);
        Ok(())
    }

    pub(in crate::graph) fn finish_startup_page(
        &self,
        context: &DiskArtifactState,
    ) -> Result<(), String> {
        let result = (|| {
            self.adapt_cache()?;
            // This generation is still private to Graph::open. A previously
            // materialized subtree cannot contain a buffered descendant.
            context
                .visit_pending_records(|address| {
                    let mut cache = self
                        .cache
                        .lock()
                        .map_err(|_| ContextError::Storage("checked cache lock poisoned".into()))?;
                    if cache.buffering != Some(self.generation) {
                        return Err(ContextError::Storage("startup generation changed".into()));
                    }
                    let Some(entry) = cache.entries.get_mut(&address) else {
                        return Ok(false);
                    };
                    if matches!(entry.state, EntryState::Buffered | EntryState::Reachable) {
                        entry.state = EntryState::Reachable;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })
                .map_err(|e| e.to_string())?;
            #[cfg(test)]
            tests::at_stage(tests::Cut::Mark)?;
            {
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|_| "checked cache lock poisoned")?;
                self.flush_buffered(&mut cache, true)
                    .map_err(|e| e.to_string())?;
                cache.buffering = None;
                cache.trim(crate::resources::adaptive::cache(
                    crate::resources::active_limits().checked_cache_bytes,
                ));
            }
            #[cfg(test)]
            tests::at_stage(tests::Cut::Commit)?;
            self.finish_write_phase()
        })();
        if let Err(error) = &result {
            // No roots escape this startup generation. Its OFF journal cannot
            // recover a partial flush; the next open discards it and replays.
            *self.halt.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
        result
    }

    pub(super) fn buffer_write(
        &self,
        cache: &mut Cache,
        address: [u8; 32],
        bytes: &[u8],
    ) -> Result<bool, ContextError> {
        let Some(generation) = cache.buffering else {
            return if cache.pending.is_empty() {
                Ok(false)
            } else {
                Err(ContextError::Storage(
                    "buffered records have no startup owner".into(),
                ))
            };
        };
        if generation != self.generation || cache.closed {
            return Err(ContextError::Storage(
                "startup buffer generation differs or closed".into(),
            ));
        }
        let charge = bytes
            .len()
            .checked_add(CACHE_ENTRY_BYTES)
            .ok_or(ContextError::Limit)?;
        let limit = crate::resources::adaptive::cache(
            crate::resources::active_limits().checked_cache_bytes,
        );
        cache.trim(limit);
        if cache.charged > limit {
            self.flush_buffered(cache, false)?;
            cache.trim(limit);
        }
        if let Some(entry) = cache.entries.get(&address)
            && (entry.state == EntryState::Persisted(self.generation)
                || !matches!(entry.state, EntryState::Persisted(_)))
        {
            if entry.bytes != bytes {
                return Err(ContextError::Corrupt);
            }
            cache.touch(address);
            return Ok(true);
        }
        if charge > limit {
            // A directly persisted parent must not retain buffered children.
            self.flush_buffered(cache, false)?;
            cache.trim(limit);
            return Ok(false);
        }
        cache.trim(limit - charge);
        if cache.charged > limit - charge && !cache.pending.is_empty() {
            self.flush_buffered(cache, false)?;
            cache.trim(limit - charge);
        }
        if cache.charged > limit - charge {
            return Ok(false);
        }
        // The allocation uses its exact requested capacity. Cache accounting
        // charges that capacity plus the existing per-entry metadata allowance.
        let bytes = bytes.to_vec();
        let charge = bytes
            .capacity()
            .checked_add(CACHE_ENTRY_BYTES)
            .ok_or(ContextError::Limit)?;
        if charge > limit || cache.charged > limit - charge {
            self.flush_buffered(cache, false)?;
            cache.trim(limit);
            return Ok(false);
        }
        if let Some(old) = cache.entries.remove(&address) {
            cache.recency.remove(&old.clock);
            cache.charged -= old.bytes.capacity() + CACHE_ENTRY_BYTES;
        }
        cache.charged += charge;
        cache.pending.insert(address);
        cache.entries.insert(
            address,
            CacheEntry {
                bytes,
                state: EntryState::Buffered,
                clock: 0,
            },
        );
        Ok(true)
    }

    // Startup has exclusive custody: no view or mirror is published yet.
    // All other storage paths release SQL before acquiring the raw cache.
    pub(super) fn flush_buffered(
        &self,
        cache: &mut Cache,
        selected_only: bool,
    ) -> Result<(), ContextError> {
        if cache.pending.is_empty() {
            return Ok(());
        }
        if cache.buffering != Some(self.generation) {
            return Err(ContextError::Storage(
                "buffered startup generation differs".into(),
            ));
        }
        if cache
            .clock
            .checked_add(cache.pending.len() as u64)
            .is_none()
        {
            cache.reset_clock();
        }
        let connection_guard = self
            .connection
            .lock()
            .map_err(|_| ContextError::Storage("checked index lock poisoned".into()))?;
        let connection = connection_guard.open().map_err(ContextError::Storage)?;
        // Buffered entries use this address set instead of an LRU position,
        // within the same per-entry charge. Never scan historical cache rows.
        let mut pending = std::mem::take(&mut cache.pending);
        while let Some(address) = pending.pop_first() {
            let result = (|| {
                let entry = cache
                    .entries
                    .get_mut(&address)
                    .ok_or(ContextError::Corrupt)?;
                if matches!(entry.state, EntryState::Persisted(_)) {
                    return Err(ContextError::Corrupt);
                }
                if selected_only && entry.state == EntryState::Buffered {
                    let entry = cache.entries.remove(&address).expect("buffered record");
                    cache.charged -= entry.bytes.capacity() + CACHE_ENTRY_BYTES;
                } else {
                    persist_record(connection, self.generation, address, &entry.bytes)?;
                    #[cfg(test)]
                    tests::at_stage(tests::Cut::Flush).map_err(ContextError::Storage)?;
                    entry.state = EntryState::Persisted(self.generation);
                    cache.clock += 1;
                    entry.clock = cache.clock;
                    cache.recency.insert(cache.clock, address);
                }
                Ok(())
            })();
            if let Err(error) = result {
                pending.insert(address);
                cache.pending = pending;
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
