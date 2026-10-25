use super::*;

impl ProgramBudget {
    // Tests of local input staging can freeze this owner independently of the
    // global computation gate, as happens in library nodes without Control.
    pub(crate) fn fixed_for_test(snapshot: Snapshot) -> Self {
        Self {
            snapshot: Some(snapshot),
            next: Instant::now() + crate::resources::limits().profile_poll_interval,
            governor: adaptive::Governor::default(),
        }
    }
}
