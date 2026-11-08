//! Scoped research comparator; production always uses structural coverage.
use std::cell::Cell;
thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(true) };
}
pub(super) fn enabled() -> bool {
    ENABLED.get()
}
struct Restore(bool);
impl Drop for Restore {
    fn drop(&mut self) {
        ENABLED.set(self.0);
    }
}
pub(in crate::learning) fn with<T>(enabled: bool, operation: impl FnOnce() -> T) -> T {
    let _restore = Restore(ENABLED.replace(enabled));
    operation()
}
