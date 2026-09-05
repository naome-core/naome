//! Checked arithmetic shared by separately owned inbox budgets.

pub(super) enum BudgetExceeded {
    EntriesOverflow,
    BytesOverflow,
    Capacity { entries: usize, bytes: u64 },
}

pub(super) fn checked_totals(
    current_entries: usize,
    current_bytes: u64,
    inserted_bytes: u64,
    maximum_entries: usize,
    maximum_bytes: u64,
) -> Result<(usize, u64), BudgetExceeded> {
    let entries = current_entries
        .checked_add(1)
        .ok_or(BudgetExceeded::EntriesOverflow)?;
    let bytes = current_bytes
        .checked_add(inserted_bytes)
        .ok_or(BudgetExceeded::BytesOverflow)?;
    if entries > maximum_entries || bytes > maximum_bytes {
        return Err(BudgetExceeded::Capacity { entries, bytes });
    }
    Ok((entries, bytes))
}
