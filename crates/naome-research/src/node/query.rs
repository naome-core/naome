//! Bounded queries and streamed semantic replay with no external effects.

use super::{
    Checkpoint, Config, Node, WindowLedger,
    budget::Phase,
    engine::Operation,
    model::WorkingState,
    store::{Store, index_key},
};
use crate::{
    journal::write_new,
    state::{Id, hex},
};
use serde_json::{Value, json};
use std::path::Path;

impl Node {
    pub fn status(&self, lifecycle: &str) -> Result<Value, String> {
        let phase = |phase| {
            let bucket = self.state.bucket(phase);
            let allocation = self.config.budgets.allowance(phase);
            json!({"window":bucket.window,"allocation":allocation.amount,"period":allocation.period,
                "spent":bucket.used,"remaining":allocation.amount.saturating_sub(bucket.used),
                "overrun":bucket.used.saturating_sub(allocation.amount)})
        };
        Ok(
            json!({"version":2,"lifecycle":lifecycle,"profile":hex(&self.profile.id()),"checkpoint":self.checkpoint(),
            "questions":self.state.questions,"unreviewed":self.state.unreviewed,"pending_blocks":self.state.pending,
            "finalized_blocks":self.state.finalized,"local_credit":self.credit(self.profile.coordinator)?,
            "attempts_admitted":self.state.attempts,"unresolved_reservation":self.state.in_flight,
            "response_pending_recovery":self.state.received,"accounting_unknown":self.state.usage_unknown,
            "budgets":{"discovery_attempts":phase(Phase::Discover),"evaluation_attempts":phase(Phase::Evaluate),"research_reported_tokens":phase(Phase::Solve)},
            "greatest_observed_clock":self.state.clock,"active_lease_target":self.state.target,
            "provider":{"route":if self.config.provider.responses.is_some(){"public_responses_siwc"}else{"legacy_native_codex"},
                "account_id":self.config.provider.responses.as_ref().map(|c|&c.account_id),"model":self.config.provider.model,
                "manage_usage":self.config.provider.responses.as_ref().map(|_|crate::chatgpt::USAGE_SETTINGS),"credential_status":"not_read_by_offline_status"},
            "active_leases":self.state.leases.iter().map(|lease|hex(&lease.question)).collect::<Vec<_>>(),
            "evidence":"Local serialized checked proof possession and configured local credit; no public finality, issuance, scientific usefulness or measured work claim"}),
        )
    }
    pub fn window_ledger(&self, phase: Phase, start: i64) -> Result<Option<WindowLedger>, String> {
        self.store.get(index_key("window", &(phase, start)))
    }

    /// Reconstruct every selected transition in a fresh store, one record at a
    /// time. Completeness is claimed only against a supplied external checkpoint.
    /// The source remains exclusively locked during the entire replay.
    pub fn replay(
        config: Config,
        destination: &Path,
        expected: Option<(Id, u64)>,
    ) -> Result<Value, String> {
        if !destination.is_absolute() || destination.exists() {
            return Err("replay requires a new absolute destination directory".into());
        }
        let source = Node::open(config.clone())?;
        let selected: Checkpoint = source.checkpoint().clone();
        if let Some((head, count)) = expected
            && (head != selected.head || count != selected.count)
        {
            return Err("source differs from independent expected checkpoint".into());
        }
        let initial = source.store.initial()?;
        let state: WorkingState =
            serde_json::from_value(initial.state).map_err(|e| e.to_string())?;
        state.coherent()?;
        let mut destination_config = config;
        destination_config.directory = destination.into();
        let store = Store::create(destination, source.profile.id(), &source.key, &state)?;
        write_new(&destination.join("profile.json"), &source.profile)?;
        super::index::sync_directory(destination)?;
        let mut replay = Node {
            config: destination_config,
            profile: source.profile.clone(),
            key: source.key.clone(),
            state,
            store,
        };
        for ordinal in 0..selected.count {
            let record = source.store.record(ordinal)?;
            if record.body.previous != replay.checkpoint().head
                || record.body.previous_root != replay.checkpoint().root
            {
                return Err("replay selected hash chain mismatch".into());
            }
            let operation: Operation =
                serde_json::from_value(record.body.operation.clone()).map_err(|e| e.to_string())?;
            let (next, changes) = replay.derive(&operation)?;
            if changes != record.body.changes
                || serde_json::to_value(&next).map_err(|e| e.to_string())? != record.body.state
            {
                return Err("replay semantic effects mismatch".into());
            }
            replay.commit(operation, next, changes)?;
            if replay.checkpoint().head != record.id()
                || replay.checkpoint().root != record.body.root
            {
                return Err("replay canonical record/index mismatch".into());
            }
        }
        if replay.checkpoint() != &selected {
            return Err("replay final checkpoint mismatch".into());
        }
        Ok(
            json!({"version":2,"records_verified":selected.count,"head":hex(&selected.head),"root":hex(&selected.root),
            "independent_checkpoint_verified":expected.is_some(),"prefix_only":expected.is_none(),"destination":destination,
            "provider_turns":0,"clock_effects":0,"report":replay.status("replayed")?}),
        )
    }
}
