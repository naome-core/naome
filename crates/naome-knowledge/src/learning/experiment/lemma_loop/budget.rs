use super::*;
pub(super) const EXPANSIONS: usize = 512;
pub(super) const SLICE: usize = 128;
const CPU_MICROS: u64 = 2_500_000;
const WALL_MICROS: u64 = 5_000_000;
const CHECKER_CALLS: u64 = 10_000;
const CHECKER_STEPS: u64 = 2_000_000;
const IO_BYTES: u64 = 8_000_000;
const IO_OPERATIONS: u64 = 512;
pub(super) fn limits() -> Value {
    json!({"search_expansions":EXPANSIONS,"cpu_micros":CPU_MICROS,"wall_micros":WALL_MICROS,"checker_calls":CHECKER_CALLS,"submitted_checker_steps":CHECKER_STEPS,"model_io_bytes":IO_BYTES,"model_io_operations":IO_OPERATIONS})
}
pub(super) struct Meter {
    wall: Instant,
    cpu: u64,
    checking: proof::CheckingWork,
    expansions: usize,
    debit: Value,
}
impl Meter {
    pub(super) fn new() -> Self {
        Self::debited(Value::Null)
    }
    pub(super) fn debited(debit: Value) -> Self {
        Self {
            wall: Instant::now(),
            cpu: meta::cpu_micros().unwrap(),
            checking: proof::checking_work(),
            expansions: debit["search_expansions"].as_u64().unwrap_or(0) as usize,
            debit,
        }
    }
    pub(super) fn charge(&mut self, expansions: usize) {
        self.expansions += expansions;
    }
    fn total(&self, key: &str, current: u64) -> u64 {
        self.debit[key]
            .as_u64()
            .unwrap_or(0)
            .saturating_add(current)
    }
    pub(super) fn remaining(&self) -> usize {
        EXPANSIONS.saturating_sub(self.expansions)
    }
    pub(super) fn within(&self, io: &Store) -> bool {
        let checking = proof::checking_work();
        self.expansions <= EXPANSIONS
            && self.total(
                "cpu_micros",
                meta::cpu_micros().unwrap().saturating_sub(self.cpu),
            ) <= CPU_MICROS
            && self.total("wall_micros", self.wall.elapsed().as_micros() as u64) <= WALL_MICROS
            && self.total(
                "checker_calls",
                checking.calls.saturating_sub(self.checking.calls),
            ) <= CHECKER_CALLS
            && self.total(
                "submitted_checker_steps",
                checking.steps.saturating_sub(self.checking.steps),
            ) <= CHECKER_STEPS
            && self.total("model_read_bytes", io.read_bytes)
                + self.total("model_written_bytes", io.written_bytes)
                <= IO_BYTES
            && self.total("model_reads", io.reads) + self.total("model_writes", io.writes)
                <= IO_OPERATIONS
    }
    pub(super) fn receipt(&self, io: &Store) -> Value {
        let checking = proof::checking_work();
        json!({"search_expansions":self.expansions,"cpu_micros":self.total("cpu_micros",meta::cpu_micros().unwrap().saturating_sub(self.cpu)),"wall_micros":self.total("wall_micros",self.wall.elapsed().as_micros() as u64),"checker_calls":self.total("checker_calls",checking.calls.saturating_sub(self.checking.calls)),"submitted_checker_steps":self.total("submitted_checker_steps",checking.steps.saturating_sub(self.checking.steps)),"model_read_bytes":self.total("model_read_bytes",io.read_bytes),"model_written_bytes":self.total("model_written_bytes",io.written_bytes),"model_reads":self.total("model_reads",io.reads),"model_writes":self.total("model_writes",io.writes),"within_budget":self.within(io)})
    }
}

#[test]
fn a_counterfactual_cannot_refill_the_original_expansion_or_io_allowance() {
    let mut meter = Meter::debited(json!({"search_expansions":500,"model_read_bytes":8_000_000}));
    assert_eq!(meter.remaining(), 12);
    meter.charge(12);
    let mut io = Store::default();
    assert!(meter.within(&io));
    io.read_bytes = 1;
    assert!(!meter.within(&io));
    assert_eq!(meter.receipt(&io)["model_read_bytes"], 8_000_001);
    assert_eq!(meter.remaining(), 0);
}
