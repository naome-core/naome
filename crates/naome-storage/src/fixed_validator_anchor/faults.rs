//! One-shot operation errors for exact anchor paths on the current test thread.

use std::cell::RefCell;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    CreateTemporary,
    WriteTemporary,
    SyncTemporary,
    Rename,
    SyncReplacementDirectory,
    StabilizeFile,
    StabilizeDirectory,
}

pub(crate) const REPLACEMENT_OPERATIONS: [Operation; 5] = [
    Operation::CreateTemporary,
    Operation::WriteTemporary,
    Operation::SyncTemporary,
    Operation::Rename,
    Operation::SyncReplacementDirectory,
];

thread_local! {
    static ACTIVE: RefCell<Option<(PathBuf, Operation, bool)>> = const { RefCell::new(None) };
}

// The guard must remain on the thread whose injection it owns.
pub(crate) struct Injection(PhantomData<Rc<()>>);

pub(crate) fn inject(path: &Path, operation: Operation) -> Injection {
    ACTIVE.with_borrow_mut(|active| {
        assert!(active.is_none(), "nested anchor fault injection");
        *active = Some((path.to_path_buf(), operation, false));
    });
    Injection(PhantomData)
}

impl Injection {
    pub(crate) fn assert_fired(&self) {
        ACTIVE.with_borrow(|active| {
            assert!(
                active.as_ref().unwrap().2,
                "anchor operation was not reached"
            );
        });
    }
}

impl Drop for Injection {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|active| *active = None);
    }
}

pub(super) fn check(path: &Path, operation: Operation) -> io::Result<()> {
    ACTIVE.with_borrow_mut(|active| {
        if let Some((target, selected, fired)) = active
            && target == path
            && *selected == operation
            && !*fired
        {
            *fired = true;
            return Err(io::Error::other(format!(
                "injected anchor operation failure: {operation:?}"
            )));
        }
        Ok(())
    })
}
