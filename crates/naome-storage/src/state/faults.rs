//! Exact-path, thread-local, one-shot anchor failures for durability tests.
use std::{
    cell::RefCell,
    io,
    marker::PhantomData,
    path::{Path, PathBuf},
    rc::Rc,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Point {
    Create,
    Write,
    Sync,
    Rename,
    DirectorySync,
}
pub(super) const POINTS: [Point; 5] = [
    Point::Create,
    Point::Write,
    Point::Sync,
    Point::Rename,
    Point::DirectorySync,
];
thread_local! { static ACTIVE: RefCell<Option<(PathBuf,Point,bool)>> = const {RefCell::new(None)}; }
pub(super) struct Guard(PhantomData<Rc<()>>);
pub(super) fn inject(path: &Path, point: Point) -> Guard {
    ACTIVE.with_borrow_mut(|active| {
        assert!(active.is_none());
        *active = Some((path.to_owned(), point, false));
    });
    Guard(PhantomData)
}
impl Guard {
    pub(super) fn assert_fired(&self) {
        ACTIVE.with_borrow(|a| assert!(a.as_ref().unwrap().2));
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|a| *a = None);
    }
}
pub(super) fn check(path: &Path, point: Point) -> io::Result<()> {
    ACTIVE.with_borrow_mut(|active| {
        if let Some((p, expected, fired)) = active
            && p == path
            && *expected == point
            && !*fired
        {
            *fired = true;
            return Err(io::Error::other(format!(
                "injected research anchor {point:?}"
            )));
        }
        Ok(())
    })
}
