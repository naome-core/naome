use super::*;
use journal::{Account, Disk, Journal};
use libp2p::futures::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Instant,
};

fn lanes() -> [usize; 4] {
    crate::resources::limits().workers
}

#[derive(Clone)]
pub(crate) struct Recovery {
    pub next_cursor: u64,
    pub archive_end: u64,
    pub records: Vec<Record>,
}

pub(crate) struct Service {
    thread: Option<JoinHandle<()>>,
    error: Arc<Mutex<Option<String>>>,
    halt: Option<oneshot::Sender<()>>,
    stopped: Option<oneshot::Receiver<Result<(), String>>>,
}

impl Service {
    pub(crate) fn open(
        directory: &Path,
        settings: Settings,
        cursor: u64,
    ) -> Result<(Self, Client, Recovery), String> {
        settings.validate()?;
        let (disk, journal) = Disk::open(directory, settings, cursor)?;
        let recovery = Recovery {
            next_cursor: journal.next_cursor,
            archive_end: journal.next_id,
            records: journal
                .records
                .values()
                .filter(|r| !r.acknowledged)
                .cloned()
                .collect(),
        };
        let (sender, receiver) = mpsc::channel(crate::resources::limits().job_commands);
        let client = Client { sender };
        let (halt, stop) = oneshot::channel();
        let (receipt, stopped) = oneshot::channel();
        let error = Arc::new(Mutex::new(None));
        let report = error.clone();
        let thread = std::thread::Builder::new()
            .name("naome-research-jobs".into())
            .spawn(move || {
                let result = (|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|e| e.to_string())?;
                    let (events, progress) =
                        mpsc::channel(crate::resources::limits().provider_events);
                    runtime.block_on(
                        Owner::new(disk, journal, settings).run(receiver, stop, events, progress),
                    )
                })();
                if let Err(failure) = &result {
                    *report.lock().unwrap_or_else(|e| e.into_inner()) = Some(failure.clone());
                }
                let _ = receipt.send(result);
            })
            .map_err(|e| e.to_string())?;
        Ok((
            Self {
                thread: Some(thread),
                error,
                halt: Some(halt),
                stopped: Some(stopped),
            },
            client,
            recovery,
        ))
    }

    pub(crate) fn error(&self) -> Option<String> {
        self.error.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) async fn shutdown(&mut self) -> Result<(), String> {
        self.begin_shutdown()?;
        let result = match self.stopped.take() {
            Some(receiver) => receiver
                .await
                .unwrap_or_else(|_| Err("research stop receipt unavailable".into())),
            None => self.error().map_or(Ok(()), Err),
        };
        let mut joined = Ok(());
        if let Some(thread) = self.thread.take() {
            joined = thread
                .join()
                .map_err(|_| "research owner thread panicked".to_owned());
        }
        result.and(joined)
    }

    pub(crate) fn begin_shutdown(&mut self) -> Result<(), String> {
        if let Some(halt) = self.halt.take() {
            let _ = halt.send(());
        }
        Ok(())
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.begin_shutdown();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            *self.error.lock().unwrap_or_else(|e| e.into_inner()) =
                Some("research owner thread panicked".into());
        }
    }
}

struct Running {
    cancel: Option<oneshot::Sender<()>>,
    clock: Instant,
}

struct Owner {
    disk: Disk,
    journal: Journal,
    settings: Settings,
    waiters: BTreeMap<u64, Vec<oneshot::Sender<Completion>>>,
    clocks: BTreeMap<u64, Instant>,
    running: BTreeMap<u64, Running>,
    tasks: FuturesUnordered<BoxFuture<'static, (u64, process::Outcome)>>,
    next_lane: usize,
    recovery_skip: std::collections::BTreeSet<u64>,
    flushed: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reservation {
    Granted,
    Exhausted,
}

impl Owner {
    fn new(disk: Disk, journal: Journal, settings: Settings) -> Self {
        let recovery_skip = journal.records.keys().copied().collect();
        Self {
            disk,
            journal,
            recovery_skip,
            settings,
            waiters: BTreeMap::new(),
            clocks: BTreeMap::new(),
            running: BTreeMap::new(),
            tasks: FuturesUnordered::new(),
            next_lane: 0,
            flushed: Instant::now(),
        }
    }

    async fn run(
        mut self,
        commands: mpsc::Receiver<Command>,
        halt: oneshot::Receiver<()>,
        events: mpsc::Sender<process::Event>,
        progress: mpsc::Receiver<process::Event>,
    ) -> Result<(), String> {
        let result = std::panic::AssertUnwindSafe(self.drive(commands, halt, events, progress))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| {
                Err("research driver panicked; pending effects require reconciliation".into())
            });
        let cleanup = self.stop_all().await;

        combine_outcomes(result, cleanup)
    }

    async fn drive(
        &mut self,
        mut commands: mpsc::Receiver<Command>,
        mut halt: oneshot::Receiver<()>,
        events: mpsc::Sender<process::Event>,
        mut progress: mpsc::Receiver<process::Event>,
    ) -> Result<(), String> {
        let mut tick = tokio::time::interval(crate::resources::limits().job_tick_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _=&mut halt=>break,
                command=commands.recv()=>match command {
                    Some(Command::Submit(input,binding,reply))=>self.submit(input,binding,reply)?,
                    Some(Command::Recover{after,before,reply})=>{
                        let page=self.disk.recovery_page(after,before,&self.recovery_skip)?;
                        let _=reply.send(Ok(page));
                    },
                    Some(Command::Acknowledge(id))=>{
                        if id==0{continue;}
                        if !self.journal.records.contains_key(&id){self.disk.acknowledge(&self.journal,id)?;continue;}
                        if id!=0 {
                            let Some(record)=self.journal.records.get_mut(&id) else {
                                if id<self.journal.next_id {continue;}
                                return Err("unknown research acknowledgement".into());
                            };
                            if !record.state.terminal() { return Err("acknowledged research job is still running".into()); }
                            record.acknowledged=true;
                            self.compact();
                            self.save()?;
                        }
                    },
                    Some(Command::Discard(input,binding))=>{
                        if let Some(record)=self.disk.request(&input,&binding,self.settings.for_input(&input))?
                            && !self.journal.records.contains_key(&record.id)&&record.state.terminal(){self.disk.acknowledge(&self.journal,record.id)?;}
                        let ids=self.journal.records.values().filter(|r|r.input==input && r.binding==binding
                            && !r.acknowledged && r.state!=State::InDoubt).map(|r|r.id).collect::<Vec<_>>();
                        for id in ids {
                            let waiters=self.waiters.get_mut(&id);
                            if let Some(waiters)=waiters {waiters.retain(|reply|!reply.is_closed());}
                            if self.waiters.get(&id).is_none_or(|w|w.is_empty()) {
                                if let Some(running)=self.running.get_mut(&id)
                                    && let Some(cancel)=running.cancel.take(){let _=cancel.send(());}
                                let record=self.journal.records.get_mut(&id).expect("owned discarded job");
                                if !record.state.terminal(){record.state=State::Cancelled;record.result=None;}
                                if !self.running.contains_key(&id){record.acknowledged=true;}
                            }
                        }
                        self.compact();self.save()?;
                    },
                    None=>break,
                },
                event=progress.recv()=>if let Some(event)=event {
                    match event {
                        process::Event::Reserve{id,next,reply}=>{
                            if self.journal.records.get(&id).is_some_and(|r|matches!(r.state,State::Cancelled|State::Expired)) {
                                let _=reply.send(Err("research job cancelled or expired".into()));continue;
                            }
                            match self.reserve(id,next) {
                                Ok(Reservation::Granted)=>{let _=reply.send(Ok(()));},
                                Ok(Reservation::Exhausted)=>{let _=reply.send(Err("research work budget exhausted".into()));},
                                Err(error)=>{let _=reply.send(Err(error.clone()));return Err(error);},
                            }
                        },
                        process::Event::Progress{id,checkpoint,reply}=>{
                            if self.journal.records.get(&id).is_some_and(|r|matches!(r.state,State::Cancelled|State::Expired)) {
                                let _=reply.send(Err("research job cancelled or expired".into()));continue;
                            }
                            let result=(||{
                                self.charge(id)?;
                                let record=self.journal.records.get_mut(&id).ok_or("unknown provider progress")?;
                                if record.state!=State::Running{return Err("research checkpoint cancelled".into());}
                                if checkpoint!=record.checkpoint+1 || checkpoint>record.reserved_units {
                                    return Err("provider checkpoint differs from its durable reservation".into());
                                }
                                record.checkpoint=checkpoint;
                                self.save()
                            })();
                            let failure=result.as_ref().err().cloned();
                            let _=reply.send(result);
                            if let Some(error)=failure{return Err(error);}
                        },
                    }
                },
                completion=self.tasks.next(),if !self.tasks.is_empty()=>if let Some((id,outcome))=completion {
                    self.complete(id,outcome)?;
                },
                _=tick.tick()=>self.reconcile()?,
            }
            self.schedule(&events)?;
        }
        Ok(())
    }

    fn complete(&mut self, id: u64, outcome: process::Outcome) -> Result<(), String> {
        if outcome.state == State::InDoubt {
            // The completed task has already left tasks. Retain uncertainty
            // before any clock or disk operation can fail and lose its outcome.
            let record = self
                .journal
                .records
                .get_mut(&id)
                .ok_or("unknown provider completion")?;
            record.state = State::InDoubt;
            record.acknowledged = false;
            record.result = None;
            record.failure = outcome
                .result
                .as_ref()
                .err()
                .map(|error| failure_detail(error));
            let accounting = self.charge(id);
            self.running.remove(&id);
            self.clocks.remove(&id);
            // Persist this fail-closed disposition with the existing observed
            // clock even after rollback. This grants no new time or work.
            let retained = self.retain_uncertainty();
            return combine_outcomes(
                Err("provider cleanup or effects require reconciliation".into()),
                combine_outcomes(accounting, retained),
            );
        }
        self.charge(id)?;
        let expired = allowance_expired(&self.journal, id)?;
        let record = self
            .journal
            .records
            .get_mut(&id)
            .ok_or("unknown provider completion")?;
        if !record.state.terminal() {
            record.state = if expired {
                State::Expired
            } else {
                outcome.state
            };
            match outcome.result {
                Ok(output) if !expired => record.result = Some(output),
                Ok(_) => record.result = None,
                Err(error) => record.failure = Some(failure_detail(&error)),
            }
        }
        if self
            .waiters
            .get(&id)
            .is_none_or(|w| w.iter().all(|w| w.is_closed()))
            && record.state.terminal()
        {
            record.acknowledged = true;
        }
        let uncertain = record.state == State::InDoubt;
        // Keep the completing job protected from terminal-history compaction
        // until its persisted outcome can be delivered, even if abandoned.
        self.save()?;
        self.running.remove(&id);
        self.clocks.remove(&id);
        self.deliver(id);
        if uncertain {
            return Err("provider cleanup or effects require reconciliation".into());
        }
        Ok(())
    }

    fn save(&mut self) -> Result<(), String> {
        let now = wall_ms()?;
        if now < self.journal.observed_ms {
            return Err("research clock moved backwards; no fresh allowance".into());
        }
        self.journal.observed_ms = now;
        self.journal.remember_holds()?;
        if !self.compact_bytes(0)? {
            return Err("research reserved result byte capacity".into());
        }
        self.journal.validate_delta(self.settings)?;
        self.disk.save(&mut self.journal)?;
        self.flushed = Instant::now();
        Ok(())
    }

    fn retain_uncertainty(&mut self) -> Result<(), String> {
        // Preserve the clock already used for accounting without consulting a
        // rolled-back wall clock. This persistence path only retains a hold.
        self.journal.observed_ms = self.journal.observed_ms.max(
            self.journal
                .records
                .values()
                .map(|record| record.accounted_ms)
                .max()
                .unwrap_or(0),
        );
        self.journal.remember_holds()?;
        self.journal.validate_delta(self.settings)?;
        self.disk.save(&mut self.journal)
    }

    fn submit(
        &mut self,
        input: Input,
        binding: Binding,
        reply: oneshot::Sender<Completion>,
    ) -> Result<(), String> {
        if reply.is_closed() {
            return Ok(());
        }
        let account_key = input.account_key();
        let original_account = if matches!(input, Input::Find { .. }) {
            None
        } else if let Some(account) = self.journal.accounts.get(&account_key) {
            Some(account.clone())
        } else {
            self.disk.account(&account_key)?
        };
        let settings = original_account.as_ref().map_or_else(
            || self.settings.for_input(&input),
            |account| account.settings,
        );
        if self
            .journal
            .records
            .values()
            .any(|r| r.input == input && r.state == State::InDoubt)
        {
            reject_state(
                reply,
                binding,
                State::InDoubt,
                "research in-flight effects require reconciliation",
            );
            return Ok(());
        }
        if let Some(record) = self
            .journal
            .records
            .values()
            .find(|r| {
                r.input == input
                    && r.binding == binding
                    && !r.acknowledged
                    && r.configuration == identity(&settings)
            })
            .cloned()
        {
            let waiters = self.waiters.entry(record.id).or_default();
            waiters.retain(|reply| !reply.is_closed());
            if waiters.len() >= crate::resources::limits().waiters_per_job {
                reject(reply, binding, "research duplicate waiter capacity");
            } else {
                waiters.push(reply);
                self.clocks.entry(record.id).or_insert_with(Instant::now);
                if record.state.terminal() {
                    self.deliver(record.id);
                }
            }
            return Ok(());
        }
        if let Some(record) = self.disk.request(&input, &binding, settings)? {
            if record.state.terminal() || record.state == State::InDoubt {
                let completion = completion(&record);
                let _ = reply.send(completion);
                return Ok(());
            }
            return Err("nonterminal research job is absent from its resident working set".into());
        }
        if let Err(error) = crate::resources::require_disk_space(
            self.disk.directory(),
            u64::try_from(output_reservation(&input)).map_err(|_| "job disk reservation width")?,
        ) {
            reject(reply, binding, &error.to_string());
            return Ok(());
        }
        self.compact();
        let input_bytes = serde_json::to_vec(&(&input, &binding, settings))
            .map_err(|e| e.to_string())?
            .len();
        let reservation = output_reservation(&input)
            .checked_add(input_bytes + 4096)
            .ok_or("research byte reservation overflow")?;
        if !self.compact_bytes(reservation)? {
            reject(reply, binding, "research result byte reservation capacity");
            return Ok(());
        }
        let queued = self
            .journal
            .records
            .values()
            .filter(|r| {
                matches!(r.state, State::Queued | State::Running | State::Suspended)
                    && r.input.lane() == input.lane()
            })
            .count();
        if self.journal.records.len() >= crate::resources::limits().resident_jobs
            || queued >= crate::resources::limits().queued_jobs_per_role + lanes()[input.lane()]
        {
            reject(reply, binding, "research role queue capacity");
            return Ok(());
        }
        let now = wall_ms()?;
        if now < self.journal.observed_ms {
            return Err("research clock rollback".into());
        }
        let mut created_ms = now;
        let mut expires_ms = now
            .checked_add(settings.limits.horizon_ms)
            .ok_or("research horizon overflow")?;
        let mut spent_ms = 0;
        let mut reserved_units = 0;
        if let Input::Find { cursor } = input {
            if cursor < self.journal.next_cursor {
                reject(reply, binding, "research finding cursor already consumed");
                return Ok(());
            }
            self.journal.next_cursor = cursor
                .checked_add(1)
                .ok_or("research finding cursor exhausted")?;
        } else if let Some(account) = original_account {
            if account.held.is_some() {
                reject_state(
                    reply,
                    binding,
                    State::InDoubt,
                    "research original effects require reconciliation",
                );
                return Ok(());
            }
            created_ms = account.created_ms;
            expires_ms = account.expires_ms;
            spent_ms = account.spent_ms;
            reserved_units = account.reserved_units;
            if now >= expires_ms
                || spent_ms >= settings.limits.horizon_ms
                || reserved_units >= settings.limits.work_units
            {
                reject_state(
                    reply,
                    binding,
                    State::Expired,
                    "research original obligation allowance exhausted",
                );
                return Ok(());
            }
            self.journal.accounts.insert(account_key.clone(), account);
        } else {
            self.journal.accounts.insert(
                account_key,
                Account {
                    settings,
                    created_ms,
                    expires_ms,
                    spent_ms,
                    reserved_units,
                    held: None,
                },
            );
        }
        let id = self.journal.next_id;
        self.journal.next_id = id.checked_add(1).ok_or("research job identity exhausted")?;
        self.journal.records.insert(
            id,
            Record {
                id,
                input: input.clone(),
                binding: binding.clone(),
                provider: super::provider::DEFAULT_PROVIDER.into(),
                configuration: identity(&settings),
                settings,
                created_ms,
                expires_ms,
                accounted_ms: now,
                spent_ms,
                reserved_units,
                checkpoint: 0,
                state: State::Queued,
                result: None,
                acknowledged: false,
                failure: None,
            },
        );
        self.waiters.insert(id, vec![reply]);
        self.clocks.insert(id, Instant::now());
        self.save()?;
        crate::network::emit(
            serde_json::json!({"event":"research_created","job":id,"lane":input.lane(),"expires_ms":expires_ms}),
        );
        Ok(())
    }

    fn charge(&mut self, id: u64) -> Result<(), String> {
        let now = wall_ms()?;
        if now < self.journal.observed_ms {
            return Err("research clock rollback".into());
        }
        let clock = if let Some(running) = self.running.get_mut(&id) {
            &mut running.clock
        } else {
            self.clocks.entry(id).or_insert_with(Instant::now)
        };
        let instant = Instant::now();
        let elapsed: u64 = instant
            .saturating_duration_since(*clock)
            .as_nanos()
            .div_ceil(1_000_000)
            .try_into()
            .map_err(|_| "research elapsed overflow")?;
        *clock = instant;
        let record = self
            .journal
            .records
            .get_mut(&id)
            .ok_or("research accounting record absent")?;
        record.spent_ms = record.spent_ms.saturating_add(elapsed);
        record.accounted_ms = now;
        self.journal.total_spent_ms = self.journal.total_spent_ms.saturating_add(elapsed);
        if let Some(account) = self.journal.accounts.get_mut(&record.input.account_key()) {
            account.spent_ms = account.spent_ms.saturating_add(elapsed);
        }
        Ok(())
    }

    fn reserve(&mut self, id: u64, next: u32) -> Result<Reservation, String> {
        self.charge(id)?;
        let now = wall_ms()?;
        let record = self
            .journal
            .records
            .get_mut(&id)
            .ok_or("research reservation record absent")?;
        if record.state != State::Running || next != record.checkpoint + 1 {
            return Err("research reservation lifecycle differs".into());
        }
        let account_exhausted = self
            .journal
            .accounts
            .get(&record.input.account_key())
            .is_some_and(|a| {
                a.spent_ms >= a.settings.limits.horizon_ms
                    || a.reserved_units >= a.settings.limits.work_units
            });
        if account_exhausted
            || now >= record.expires_ms
            || record.spent_ms >= record.settings.limits.horizon_ms
            || record.reserved_units >= record.settings.limits.work_units
        {
            record.state = State::Expired;
            record.result = None;
            self.save()?;
            return Ok(Reservation::Exhausted);
        }
        record.reserved_units += 1;
        if let Some(account) = self.journal.accounts.get_mut(&record.input.account_key()) {
            account.reserved_units += 1;
        }
        self.journal.total_reserved_units = self.journal.total_reserved_units.saturating_add(1);
        self.save()?;
        Ok(Reservation::Granted)
    }

    fn schedule(&mut self, events: &mpsc::Sender<process::Event>) -> Result<(), String> {
        for offset in 0..lanes().len() {
            let lane = (self.next_lane + offset) % lanes().len();
            let active = self
                .running
                .keys()
                .filter(|id| self.journal.records[id].input.lane() == lane)
                .count();
            if active >= lanes()[lane] {
                continue;
            }
            let ready = self
                .journal
                .records
                .values()
                .filter(|r| {
                    r.input.lane() == lane
                        && matches!(r.state, State::Queued | State::Suspended)
                        && self
                            .waiters
                            .get(&r.id)
                            .is_some_and(|w| w.iter().any(|w| !w.is_closed()))
                })
                .map(|r| r.id)
                .take(lanes()[lane] - active)
                .collect::<Vec<_>>();
            for id in ready {
                let Some(slot) = self.disk.slot(lane)? else {
                    continue;
                };
                self.charge(id)?;
                let now = wall_ms()?;
                let record = self
                    .journal
                    .records
                    .get_mut(&id)
                    .ok_or("queued research job absent")?;
                let mut remaining_ms = record.expires_ms.saturating_sub(now).min(
                    record
                        .settings
                        .limits
                        .horizon_ms
                        .saturating_sub(record.spent_ms),
                );
                let mut units_exhausted =
                    record.reserved_units >= record.settings.limits.work_units;
                if let Some(account) = self.journal.accounts.get(&record.input.account_key()) {
                    remaining_ms = remaining_ms.min(
                        account
                            .settings
                            .limits
                            .horizon_ms
                            .saturating_sub(account.spent_ms),
                    );
                    units_exhausted |= account.reserved_units >= account.settings.limits.work_units;
                }
                let finalizing = super::provider::complete(record, record.checkpoint)
                    && record.settings.recovery == RecoveryPolicy::DeterministicCheckpoint;
                if remaining_ms == 0 || units_exhausted && !finalizing {
                    record.state = State::Expired;
                    self.save()?;
                    self.deliver(id);
                    continue;
                }
                record.state = State::Running;
                let source = record.clone();
                self.save()?;
                let (cancel, receiver) = oneshot::channel();
                let events = events.clone();
                self.running.insert(
                    id,
                    Running {
                        cancel: Some(cancel),
                        clock: Instant::now(),
                    },
                );
                self.tasks.push(Box::pin(async move {
                    let outcome = std::panic::AssertUnwindSafe(process::run(
                        source,
                        remaining_ms,
                        events,
                        receiver,
                        slot,
                    ))
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| process::Outcome {
                        state: State::InDoubt,
                        result: Err(
                            "provider task panicked; cleanup requires reconciliation".into()
                        ),
                    });
                    (id, outcome)
                }));
            }
        }
        self.next_lane = (self.next_lane + 1) % lanes().len();
        Ok(())
    }

    fn reconcile(&mut self) -> Result<(), String> {
        let now = wall_ms()?;
        if now < self.journal.observed_ms {
            return Err("research clock rollback".into());
        }
        let ids = self
            .journal
            .records
            .values()
            .filter(|r| !r.state.terminal() && r.state != State::InDoubt)
            .map(|r| r.id)
            .collect::<Vec<_>>();
        let mut changed = false;
        for id in ids {
            if self.waiters.contains_key(&id) {
                self.charge(id)?;
                changed = true;
            }
            let cancelled = self
                .waiters
                .get(&id)
                .is_some_and(|w| w.iter().all(|w| w.is_closed()));
            let record = self
                .journal
                .records
                .get_mut(&id)
                .expect("research reconciliation identity");
            let expired =
                now >= record.expires_ms || record.spent_ms >= record.settings.limits.horizon_ms;
            if cancelled || expired {
                record.state = if expired {
                    State::Expired
                } else {
                    State::Cancelled
                };
                record.result = None;
                if let Some(running) = self.running.get_mut(&id)
                    && let Some(cancel) = running.cancel.take()
                {
                    let _ = cancel.send(());
                }
                self.clocks.remove(&id);
                changed = true;
                if !self.running.contains_key(&id) {
                    if cancelled {
                        self.journal
                            .records
                            .get_mut(&id)
                            .expect("cancelled job")
                            .acknowledged = true;
                    }
                    self.deliver(id);
                }
            }
        }
        if changed && self.flushed.elapsed() >= crate::resources::limits().job_flush_interval {
            self.save()?;
        }
        Ok(())
    }

    fn deliver(&mut self, id: u64) {
        let record = &self.journal.records[&id];
        if !record.state.terminal() {
            return;
        }
        let completion = completion(record);
        crate::network::emit(serde_json::json!({"event":"research_finished","job":id,
            "state":format!("{:?}",completion.state),"spent_ms":completion.spent_ms,
            "reserved_units":completion.reserved_units}));
        if let Some(waiters) = self.waiters.remove(&id) {
            for waiter in waiters {
                let _ = waiter.send(completion.clone());
            }
        }
    }

    fn compact(&mut self) {
        let terminal = self
            .journal
            .records
            .values()
            .filter(|r| {
                (r.state.terminal() || r.state == State::InDoubt)
                    && !self.running.contains_key(&r.id)
            })
            .map(|r| r.id)
            .collect::<Vec<_>>();
        let remove = terminal
            .len()
            .saturating_sub(crate::resources::limits().terminal_job_page);
        for id in terminal
            .into_iter()
            .filter(|id| !self.journal.records.changed(id))
            .take(remove)
            .collect::<Vec<_>>()
        {
            self.journal.records.remove(&id);
            self.journal.retired_jobs = self
                .journal
                .retired_jobs
                .checked_add(1)
                .expect("bounded monotonic record sequence");
        }
    }

    fn compact_bytes(&mut self, additional: usize) -> Result<bool, String> {
        self.compact();
        let future = self
            .journal
            .records
            .values()
            .filter(|r| matches!(r.state, State::Queued | State::Running | State::Suspended))
            .try_fold(additional, |sum, r| {
                sum.checked_add(output_reservation(&r.input))
            })
            .ok_or("research result reservation overflow")?;
        loop {
            let encoded = self.journal.encoded_active_len()?;
            if encoded
                .checked_add(future)
                .is_some_and(|bytes| bytes + 256 <= crate::resources::limits().active_job_bytes)
            {
                return Ok(true);
            }
            let oldest = self
                .journal
                .records
                .values()
                .find(|r| {
                    (r.state.terminal() || r.state == State::InDoubt)
                        && !self.running.contains_key(&r.id)
                        && !self.journal.records.changed(&r.id)
                })
                .map(|r| r.id);
            let Some(id) = oldest else {
                return Ok(false);
            };
            self.journal.records.remove(&id);
            self.journal.retired_jobs = self.journal.retired_jobs.saturating_add(1);
        }
    }

    async fn stop_all(&mut self) -> Result<(), String> {
        let mut failure = None;
        let ids = self.running.keys().copied().collect::<Vec<_>>();
        for id in ids {
            if let Err(error) = self.charge(id) {
                failure = Some(append_failure(failure.take(), &error));
            }
            let record = self
                .journal
                .records
                .get_mut(&id)
                .expect("owned running research record");
            if !record.state.terminal() && record.state != State::InDoubt {
                record.state = if record.settings.recovery == RecoveryPolicy::HoldInFlight {
                    State::InDoubt
                } else {
                    State::Suspended
                };
            }
        }
        let saved = self.save();
        if let Err(error) = saved {
            failure = Some(append_failure(failure.take(), &error));
        }
        for (id, running) in std::mem::take(&mut self.running) {
            self.clocks.insert(id, running.clock);
            if let Some(cancel) = running.cancel {
                let _ = cancel.send(());
            }
        }
        while let Some((id, outcome)) = self.tasks.next().await {
            if let Err(error) = self.charge(id) {
                failure = Some(append_failure(failure.take(), &error));
            }
            if outcome.state == State::InDoubt {
                let record = self
                    .journal
                    .records
                    .get_mut(&id)
                    .expect("owned cleanup job");
                record.state = State::InDoubt;
                record.acknowledged = false;
                record.result = None;
                record.failure = outcome.result.err().map(|error| failure_detail(&error));
                failure = Some(append_failure(
                    failure.take(),
                    "provider cleanup is unconfirmed",
                ));
            } else if let Ok(output) = outcome.result {
                let record = self
                    .journal
                    .records
                    .get_mut(&id)
                    .expect("owned finalizing job");
                if record.state == State::Suspended {
                    let exhausted = match allowance_expired(&self.journal, id) {
                        Ok(expired) => expired,
                        Err(error) => {
                            failure = Some(append_failure(failure.take(), &error));
                            true
                        }
                    };
                    let record = self
                        .journal
                        .records
                        .get_mut(&id)
                        .expect("owned finalizing job");
                    record.state = if exhausted {
                        State::Expired
                    } else {
                        State::Complete
                    };
                    record.result = (!exhausted).then_some(output);
                }
            }
            self.clocks.remove(&id);
        }
        self.waiters.clear();
        if let Err(error) = self.save() {
            failure = Some(append_failure(failure.take(), &error));
            if self
                .journal
                .records
                .values()
                .any(|record| record.state == State::InDoubt)
                && let Err(error) = self.retain_uncertainty()
            {
                failure = Some(append_failure(failure.take(), &error));
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

fn reject(reply: oneshot::Sender<Completion>, binding: Binding, error: &str) {
    reject_state(reply, binding, State::Failed, error);
}

fn reject_state(reply: oneshot::Sender<Completion>, binding: Binding, state: State, error: &str) {
    let _ = reply.send(Completion {
        id: 0,
        binding,
        spent_ms: 0,
        reserved_units: 0,
        state,
        result: Err(error.into()),
    });
}

fn failure_detail(error: &str) -> String {
    error
        .char_indices()
        .take_while(|(index, ch)| {
            index + ch.len_utf8() <= crate::resources::limits().failure_detail_bytes
        })
        .map(|(_, ch)| ch)
        .collect()
}

fn output_reservation(input: &Input) -> usize {
    match input {
        Input::Solve { .. } => 6 * crate::resources::limits().closure_bytes + 1024,
        Input::Find { .. } => 6 * naome_authoring::QUESTION_SOURCE_MAX_BYTES + 128,
        Input::Interest { .. } => 64,
    }
}
fn allowance_expired(journal: &Journal, id: u64) -> Result<bool, String> {
    let record = journal
        .records
        .get(&id)
        .ok_or("completion research identity absent")?;
    Ok(wall_ms()? >= record.expires_ms
        || record.spent_ms >= record.settings.limits.horizon_ms
        || journal
            .accounts
            .get(&record.input.account_key())
            .is_some_and(|a| a.spent_ms >= a.settings.limits.horizon_ms))
}
fn append_failure(previous: Option<String>, next: &str) -> String {
    previous.map_or_else(|| next.to_owned(), |old| format!("{old}; cleanup: {next}"))
}
fn completion(record: &Record) -> Completion {
    Completion {
        id: record.id,
        binding: record.binding.clone(),
        spent_ms: record.spent_ms,
        reserved_units: record.reserved_units,
        state: record.state,
        result: record
            .result
            .clone()
            .ok_or_else(|| format!("research job {:?}", record.state)),
    }
}

fn combine_outcomes(result: Result<(), String>, cleanup: Result<(), String>) -> Result<(), String> {
    match (result, cleanup) {
        (Err(primary), Err(cleanup)) => Err(format!(
            "cleanup failed: {cleanup}; primary failure: {primary}"
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests;
