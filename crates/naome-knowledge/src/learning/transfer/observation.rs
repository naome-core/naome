//! Bounded test-only capture of actual native qualification outcomes.
//! It performs no extra search and never supplies training labels or gates.
use super::{Evaluation, Outcome};
use std::cell::RefCell;

thread_local! {
    static ROWS: RefCell<Option<Vec<serde_json::Value>>> = const { RefCell::new(None) };
}
struct Guard;
impl Drop for Guard {
    fn drop(&mut self) {
        ROWS.with(|r| {
            r.borrow_mut().take();
        });
    }
}
pub(in crate::learning) fn capture<T>(
    operation: impl FnOnce() -> T,
) -> (T, Vec<serde_json::Value>) {
    ROWS.with(|r| {
        let mut rows = r.borrow_mut();
        assert!(rows.is_none(), "native qualification capture is not nested");
        *rows = Some(Vec::new());
    });
    let _guard = Guard;
    let value = operation();
    let rows = ROWS.with(|r| r.borrow_mut().take().unwrap());
    (value, rows)
}
pub(super) fn record(source: &str, evaluation: &Evaluation) -> Result<(), String> {
    ROWS.with(|r| {
        let mut rows = r.borrow_mut();
        let Some(rows) = rows.as_mut() else {
            return Ok(());
        };
        if rows.len() >= (crate::learning::EVALUATIONS as usize + super::CASES) {
            return Err("native qualification observation capacity".into());
        }
        let outcome = |o: &Outcome| {
            serde_json::json!({"solved":o.solved,"diagnostic":o.diagnostic,
            "proof_id":o.proof_id,"micros":o.micros})
        };
        rows.push(
            serde_json::json!({"question":source,"before":outcome(&evaluation.before),
            "after":outcome(&evaluation.after)}),
        );
        Ok(())
    })
}
