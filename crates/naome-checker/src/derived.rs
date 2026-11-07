//! Shared Hilbert schemas for derived rules.
pub(crate) enum Term {
    A,
    B,
    Not(usize),
    Implies(usize, usize),
}
pub(crate) enum Step {
    K(usize, usize),
    S(usize, usize, usize),
    C(usize, usize),
    Mp(usize, usize),
}
pub(crate) struct Schema {
    pub(crate) terms: &'static [Term],
    pub(crate) steps: &'static [Step],
}
use Step::*;
use Term::*;
mod commutation;

pub(crate) use commutation::COMMUTATION;
