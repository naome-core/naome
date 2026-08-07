use crate::BlockValidationError;

pub(super) type BlockCheck<B> = fn(&B) -> Result<(), BlockValidationError>;

pub(super) fn all<B>() -> [BlockCheck<B>; 1] {
    [initial_scaffold::<B>]
}

fn initial_scaffold<B>(_block: &B) -> Result<(), BlockValidationError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{all, initial_scaffold};

    #[test]
    fn initial_scaffold_accepts_every_block() {
        assert!(initial_scaffold(&()).is_ok());
        assert!(initial_scaffold(&"arbitrary candidate").is_ok());
    }

    #[test]
    fn initial_pipeline_contains_only_the_scaffold_check() {
        assert_eq!(all::<()>().len(), 1);
    }
}
