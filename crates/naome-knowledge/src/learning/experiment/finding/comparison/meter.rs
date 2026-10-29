//! One unchanged allowance includes common inputs and every attempted update.
use super::*;
const CPU: u64 = 180_000_000;
const WALL: u64 = 240_000_000;
const IO: u64 = 2 * 1024 * 1024 * 1024;

pub(super) struct Meter {
    cpu: u64,
    wall: Instant,
    checking: proof::CheckingWork,
    common_cpu: u64,
    common_wall: u64,
    common_bytes: u64,
    restore_bytes: u64,
    checkpoint_reads: u64,
    archive_bytes: u64,
    archive_operations: u64,
}
impl Meter {
    pub(super) fn start() -> Result<Self, String> {
        Ok(Self {
            cpu: meta::cpu_micros()?,
            wall: Instant::now(),
            checking: proof::checking_work(),
            common_cpu: 0,
            common_wall: 0,
            common_bytes: 0,
            restore_bytes: 0,
            checkpoint_reads: 0,
            archive_bytes: 0,
            archive_operations: 0,
        })
    }
    pub(super) fn common(&mut self, source: &Value, restore: &Value) -> Result<(), String> {
        let get = |value: &Value, key: &str| {
            value[key]
                .as_u64()
                .ok_or_else(|| format!("missing measured cost {key}"))
        };
        self.common_cpu = get(source, "cpu_micros")?;
        self.common_wall = get(source, "wall_micros")?;
        self.common_bytes = get(source, "model_io_bytes")?
            .checked_add(get(source, "archive_written_bytes")?)
            .ok_or("common input cost overflow")?;
        self.restore_bytes = get(restore, "source_read_bytes")?;
        Ok(())
    }
    pub(super) fn write(&mut self, path: &Path, value: &impl Serialize) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        std::fs::write(path, &bytes).map_err(|e| e.to_string())?;
        self.archive_bytes += bytes.len() as u64;
        self.archive_operations += 1;
        Ok(())
    }
    pub(super) fn restore_failure(&self) -> Value {
        json!({"physical_cpu_micros":meta::cpu_micros().ok().map(|now|now.saturating_sub(self.cpu)),"physical_wall_micros":self.wall.elapsed().as_micros(),"restore_completed":false,"source_io_bytes":null,"note":"Incomplete source validation supplies no model or training permission. Whole-process timing and original source artifacts remain separate."})
    }
    pub(super) fn export(
        &mut self,
        path: &Path,
        model: &Checkpoint,
        store: &MemoryStore,
    ) -> Result<(), String> {
        export_model(path, model, store);
        for file in std::fs::read_dir(path).map_err(|e| e.to_string())? {
            self.archive_bytes += file
                .map_err(|e| e.to_string())?
                .metadata()
                .map_err(|e| e.to_string())?
                .len();
            self.archive_operations += 1;
        }
        Ok(())
    }
    pub(super) fn checkpoint(
        &mut self,
        path: &Path,
        state: &mut State,
        io: &mut sources::history::Io<'_>,
    ) -> Result<(), String> {
        let cost = persistence::export(path, state, &mut io.store)?;
        self.archive_bytes += cost.bytes;
        self.archive_operations += cost.operations;
        let (restored, store, cost) = persistence::import(path)?;
        self.restore_bytes += cost.bytes;
        self.checkpoint_reads += cost.operations;
        if digest(&restored) != digest(state) {
            return Err("reopened complete learning state differs".into());
        }
        *state = restored;
        io.store.inner = store;
        Ok(())
    }
    fn totals(&self, io: &sources::history::Io<'_>) -> Result<(u64, u64, u64), String> {
        Ok((
            self.common_cpu + meta::cpu_micros()?.saturating_sub(self.cpu),
            self.common_wall + self.wall.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
            self.common_bytes
                + self.restore_bytes
                + io.source_bytes
                + io.source_written_bytes
                + io.store.bytes
                + self.archive_bytes,
        ))
    }
    pub(super) fn check(&self, io: &sources::history::Io<'_>) -> Result<(), String> {
        let (cpu, wall, bytes) = self.totals(io)?;
        let peak = crate::resources::feedback::Meter::start()
            .finish(0, true)
            .peak_rss_bytes
            .ok_or("experiment lacks its memory observation")?;
        if cpu > CPU || wall > WALL || bytes > IO || peak > model::REQUIREMENTS.work_bytes as u64 {
            return Err(format!(
                "experiment exhausted its original allowance: cpu={cpu}, wall={wall}, io={bytes}, peak_rss={peak}"
            ));
        }
        Ok(())
    }
    pub(super) fn report(&self, io: &sources::history::Io<'_>) -> Value {
        let (cpu, wall, bytes) = self.totals(io).unwrap();
        let checking = proof::checking_work();
        json!({"charged_cpu_micros":cpu,"charged_wall_micros":wall,"charged_io_bytes":bytes,"common_cpu_micros":self.common_cpu,"common_wall_micros":self.common_wall,"common_io_bytes":self.common_bytes,"physical_arm_cpu_micros":cpu-self.common_cpu,"physical_arm_wall_micros":wall-self.common_wall,"source_restore_bytes":self.restore_bytes,"checkpoint_read_operations":self.checkpoint_reads,"history_source_bytes":io.source_bytes,"history_source_reads":io.source_reads,"history_written_bytes":io.source_written_bytes,"model_io_bytes":io.store.bytes,"model_io_operations":io.store.operations,"archive_written_bytes":self.archive_bytes,"archive_writes":self.archive_operations,"checker_calls":checking.calls-self.checking.calls,"checker_steps":checking.steps-self.checking.steps,"peak_rss_bytes":crate::resources::feedback::Meter::start().finish(0,true).peak_rss_bytes,"checker_scope":"Instrumented native proof checking; all other preparation and checking CPU is included in physical cost."})
    }
}

#[test]
fn shared_preparation_cannot_receive_an_additional_arm_allowance() {
    let directory = Directory::new();
    // Transport-only fixture: this test performs no search or optimizer work.
    let frozen = sources::Frozen {
        initial: State::fresh(),
        store: MemoryStore::default(),
        epochs: Vec::new(),
        episodes: Vec::new(),
        ledgers: Vec::new(),
        cost: Value::Null,
    };
    let io = sources::history::Io::new(&frozen, &directory.0);
    let mut meter = Meter::start().unwrap();
    meter.common(&json!({"cpu_micros":CPU+1,"wall_micros":0,"model_io_bytes":0,"archive_written_bytes":0}), &json!({"source_read_bytes":0})).unwrap();
    assert!(meter.check(&io).unwrap_err().contains("original allowance"));
    assert!(meter.report(&io)["charged_cpu_micros"].as_u64().unwrap() > CPU);
    meter
        .common(
            &json!({"cpu_micros":0,"wall_micros":0,"model_io_bytes":IO,"archive_written_bytes":1}),
            &json!({"source_read_bytes":2}),
        )
        .unwrap();
    assert_eq!(meter.report(&io)["charged_io_bytes"], IO + 3);
    assert!(meter.check(&io).is_err());
}
