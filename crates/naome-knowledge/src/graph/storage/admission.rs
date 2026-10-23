//! One proof's disposable index writes, isolated from every other writer.
//! Canonical persistence remains outside both disposable SQL transactions.

use super::{CheckedStorage, WriteRoute};
use std::{cell::Cell, marker::PhantomData, rc::Rc, sync::MutexGuard, thread::ThreadId};

pub(in crate::graph) struct AdmissionPhase<'a> {
    source: &'a CheckedStorage,
    target: Option<std::sync::Arc<CheckedStorage>>,
    epoch: Option<u64>,
    owner: ThreadId,
    published: Cell<bool>,
    _thread_bound: PhantomData<Rc<()>>,
}

pub(in crate::graph) struct AdmissionGuards<'a> {
    source: MutexGuard<'a, WriteRoute>,
    target: Option<MutexGuard<'a, WriteRoute>>,
}

impl CheckedStorage {
    pub(in crate::graph) fn admission_phase(&self) -> Result<AdmissionPhase<'_>, String> {
        // Install the abort guard before any fallible phase setup. In
        // particular, a poisoned gate must still close its exact databases.
        let mut phase = AdmissionPhase {
            source: self,
            target: None,
            epoch: None,
            owner: std::thread::current().id(),
            published: Cell::new(false),
            _thread_bound: PhantomData,
        };
        let mut source = self.write_gate()?;
        self.require_live()?;
        phase.epoch = Some(source.epoch);
        phase.target = source.mirror.clone();
        let mut target = phase
            .target
            .as_ref()
            .map(|target| target.write_gate())
            .transpose()?;
        if source.phase_owner.is_some()
            || target
                .as_ref()
                .is_some_and(|target| target.phase_owner.is_some() || target.mirror.is_some())
        {
            return Err("checked admission phase already owned".into());
        }
        source.phase_owner = Some(phase.owner);
        if let Some(target) = &mut target {
            target.phase_owner = Some(phase.owner);
        }
        // Actual per-row writes reacquire these gates on this same thread.
        // Foreign writers and copy attach/detach wait without holding SQL/cache.
        drop(target);
        drop(source);
        #[cfg(test)]
        tests::prepare_failure(self, phase.target.as_deref());
        self.begin_write_phase()
            .map_err(|error| format!("checked admission source BEGIN: {error}"))?;
        if let Some(target) = &phase.target {
            target
                .begin_write_phase()
                .map_err(|error| format!("checked admission mirror BEGIN: {error}"))?;
        }
        Ok(phase)
    }

    pub(super) fn require_live(&self) -> Result<(), String> {
        match &*self.halt.lock().map_err(|_| "checked halt lock poisoned")? {
            Some(error) => Err(format!("checked owner halted: {error}")),
            None => Ok(()),
        }
    }

    fn close_admission_connection(&self) {
        // Taking the connection makes every later SQL access fail closed even
        // while old snapshots still retain this generation's Arc.
        let mut slot = self
            .connection
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(connection) = slot.0.take() {
            match connection.close() {
                Ok(()) => slot.1 = None,
                Err((connection, error)) => {
                    // Preserve the actual native close refusal and its handle.
                    // open() refuses the quarantined slot, and cleanup must not
                    // be reported complete merely because close was attempted.
                    let message = format!("checked admission close unresolved: {error}");
                    slot.0 = Some(connection);
                    slot.1 = Some(message.clone());
                    let mut halt = self.halt.lock().unwrap_or_else(|error| error.into_inner());
                    match &mut *halt {
                        Some(primary) => {
                            primary.push_str("; ");
                            primary.push_str(&message);
                        }
                        None => *halt = Some(message),
                    }
                }
            }
        }
    }
}

impl AdmissionPhase<'_> {
    pub(in crate::graph) fn finish(
        &self,
        current: &CheckedStorage,
    ) -> Result<AdmissionGuards<'_>, String> {
        let source = self.source.write_gate()?;
        let target = self
            .target
            .as_ref()
            .map(|target| target.write_gate())
            .transpose()?;
        self.source.require_live()?;
        let epoch = self.epoch.ok_or("checked admission has no source epoch")?;
        let route_matches = match &self.target {
            Some(target) => source.matches(epoch, target),
            None => source.epoch == epoch && source.mirror.is_none(),
        };
        if !std::ptr::eq(self.source, current)
            || !route_matches
            || source.phase_owner != Some(self.owner)
            || target.as_ref().is_some_and(|target| {
                target.phase_owner != Some(self.owner) || target.mirror.is_some()
            })
        {
            return Err("checked admission generation, epoch or phase owner changed".into());
        }
        if let Some(target) = &self.target {
            target
                .finish_write_phase()
                .map_err(|error| format!("checked admission mirror COMMIT: {error}"))?;
        }
        self.source
            .finish_write_phase()
            .map_err(|error| format!("checked admission source COMMIT: {error}"))?;
        self.source.require_live()?;
        #[cfg(test)]
        tests::before_canonical(self.source, self.target.as_deref());
        // Keep both gates through the canonical transaction and infallible
        // publication. No reader or writer can make this an open SQL phase.
        Ok(AdmissionGuards { source, target })
    }

    /// Disposable writes have already committed, while the canonical SQL
    /// transaction has confirmed rollback for a revoked publication. They are
    /// unreachable immutable nodes; releasing the phase does not publish roots.
    pub(in crate::graph) fn discarded(&self, guards: &mut AdmissionGuards<'_>) {
        self.published(guards);
    }

    pub(in crate::graph) fn published(&self, guards: &mut AdmissionGuards<'_>) {
        // Called only after canonical success and the fixed root/scalar moves.
        // No lock acquisition, SQL operation, allocation or error remains.
        guards.source.phase_owner = None;
        if let Some(target) = &mut guards.target {
            target.phase_owner = None;
        }
        self.published.set(true);
        self.source.write_ready.notify_all();
        if let Some(target) = &self.target {
            target.write_ready.notify_all();
        }
    }
}

impl Drop for AdmissionPhase<'_> {
    fn drop(&mut self) {
        if self.published.get() {
            return;
        }
        {
            let mut halt = self
                .source
                .halt
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            halt.get_or_insert_with(|| "checked admission aborted before publication".into());
        }
        // Recover poisoned gates only for fatal disposal, never continued use.
        // Source -> target is also the normal immutable-write lock order.
        let mut source = self
            .source
            .write_gate
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let target = if self.epoch.is_some() {
            self.target.clone()
        } else {
            source.mirror.clone()
        };
        let mut target_gate = target.as_ref().map(|target| {
            target
                .write_gate
                .lock()
                .unwrap_or_else(|error| error.into_inner())
        });
        if self.epoch.is_none()
            || self.target.as_ref().is_some_and(|target| {
                self.epoch
                    .is_some_and(|epoch| source.matches(epoch, target))
            })
        {
            source.mirror = None;
        }
        // journal_mode=OFF has no recoverable rollback guarantee. Close both
        // disposable databases instead; startup replays the unchanged catalog.
        self.source.close_admission_connection();
        if let Some(target) = &target {
            target.close_admission_connection();
        }
        *self
            .source
            .cache
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = super::Cache {
            closed: true,
            ..super::Cache::default()
        };
        source.phase_owner = None;
        if let Some(target) = &mut target_gate {
            target.phase_owner = None;
        }
        self.source.write_ready.notify_all();
        if let Some(target) = &target {
            target.write_ready.notify_all();
        }
    }
}

#[cfg(test)]
pub(super) fn test_insert_state(generation: u64, autocommit: bool) {
    tests::insert_state(generation, autocommit);
}

#[cfg(test)]
mod tests;
