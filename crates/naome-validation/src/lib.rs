//! Pre-release block-validation orchestration for the NAOME protocol.
//!
//! The current pipeline is deliberately type-agnostic because NAOME does not
//! define a block model yet. Its only registered check is an initial scaffold
//! that accepts every candidate. A successful result therefore confirms only
//! that all checks currently registered in this crate have run successfully;
//! it does not yet establish mathematical or consensus validity.

mod checks;

use std::error::Error;
use std::fmt;

/// A block that passed every currently registered validation check.
///
/// This wrapper can only be constructed through [`validate_block`].
#[derive(Debug)]
#[must_use]
pub struct ValidatedBlock<B> {
    block: B,
}

impl<B> ValidatedBlock<B> {
    /// Returns the validated block candidate.
    #[must_use]
    pub fn block(&self) -> &B {
        &self.block
    }

    /// Consumes the validation result and returns the block candidate.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.block
    }
}

/// A failure produced by a registered block-validation check.
///
/// The initial scaffold check cannot fail, so this enum has no variants yet.
/// It is non-exhaustive so concrete check failures can be added incrementally.
#[derive(Debug)]
#[non_exhaustive]
pub enum BlockValidationError {}

impl fmt::Display for BlockValidationError {
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

impl Error for BlockValidationError {}

/// Runs every registered check and returns the candidate as validated.
///
/// Checks run in their declared order. Validation stops at the first failure,
/// and a [`ValidatedBlock`] is constructed only after every check succeeds.
pub fn validate_block<B>(block: B) -> Result<ValidatedBlock<B>, BlockValidationError> {
    for check in checks::all() {
        check(&block)?;
    }

    Ok(ValidatedBlock { block })
}

#[cfg(test)]
mod tests {
    use super::validate_block;

    #[derive(Debug, PartialEq, Eq)]
    struct Candidate {
        value: u8,
    }

    #[test]
    fn validate_block_returns_the_candidate_after_all_checks_succeed() {
        let candidate = Candidate { value: 7 };

        let validated = validate_block(candidate).expect("the scaffold check always succeeds");

        assert_eq!(validated.block(), &Candidate { value: 7 });
        assert_eq!(validated.into_inner(), Candidate { value: 7 });
    }
}
