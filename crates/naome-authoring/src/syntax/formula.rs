//! Shared recursive formula grammar. Builders own their representations,
//! allocation preflights, diagnostics and explicitly supported extensions.
use naome_foundation::FreeVariable;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operator {
    Equal,
    Member,
    Unequal,
    Not,
    Implies,
    All,
    Exists,
    And,
    Or,
    Iff,
}
impl Operator {
    pub(crate) fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "eq" => Self::Equal,
            "mem" => Self::Member,
            "ne" => Self::Unequal,
            "not" => Self::Not,
            "imp" => Self::Implies,
            "all" => Self::All,
            "ex" => Self::Exists,
            "and" => Self::And,
            "or" => Self::Or,
            "iff" => Self::Iff,
            _ => return None,
        })
    }
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Equal => "eq",
            Self::Member => "mem",
            Self::Unequal => "ne",
            Self::Not => "not",
            Self::Implies => "imp",
            Self::All => "all",
            Self::Exists => "ex",
            Self::And => "and",
            Self::Or => "or",
            Self::Iff => "iff",
        }
    }
}
pub(crate) enum Start<'a, F> {
    Value(F),
    Call { name: &'a str, offset: usize },
}

pub(crate) trait FormulaBuilder<'a> {
    type Parsed;
    type Error;
    type Mode: Copy;
    fn start(
        &mut self,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<Start<'a, Self::Parsed>, Self::Error>;
    fn atom(
        &mut self,
        op: Operator,
        offset: usize,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<Self::Parsed, Self::Error>;
    fn binders(&mut self, offset: usize) -> Result<Vec<FreeVariable>, Self::Error>;
    fn quantified_depth(
        &mut self,
        op: Operator,
        count: usize,
        offset: usize,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<usize, Self::Error>;
    fn quantified(
        &mut self,
        op: Operator,
        variables: Vec<FreeVariable>,
        body: Self::Parsed,
        offset: usize,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<Self::Parsed, Self::Error>;
    fn negated(
        &mut self,
        body: Self::Parsed,
        offset: usize,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<Self::Parsed, Self::Error>;
    fn binary(
        &mut self,
        op: Operator,
        children: [Self::Parsed; 2],
        offset: usize,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<Self::Parsed, Self::Error>;
    fn extension(
        &mut self,
        name: &'a str,
        offset: usize,
        depth: usize,
        mode: Self::Mode,
    ) -> Result<Self::Parsed, Self::Error>;
    fn comma(&mut self) -> Result<(), Self::Error>;
    fn finish(&mut self, parsed: Self::Parsed, depth: usize) -> Result<Self::Parsed, Self::Error>;
}

pub(crate) fn parse<'a, B: FormulaBuilder<'a>>(
    builder: &mut B,
    depth: usize,
    mode: B::Mode,
) -> Result<B::Parsed, B::Error> {
    let (name, offset) = match builder.start(depth, mode)? {
        Start::Value(value) => return Ok(value),
        Start::Call { name, offset } => (name, offset),
    };
    let parsed = match Operator::parse(name) {
        Some(op @ (Operator::Equal | Operator::Member | Operator::Unequal)) => {
            builder.atom(op, offset, depth, mode)?
        }
        Some(op @ (Operator::All | Operator::Exists)) => {
            let variables = builder.binders(offset)?;
            builder.comma()?;
            let child_depth = builder.quantified_depth(op, variables.len(), offset, depth, mode)?;
            let body = parse(builder, child_depth, mode)?;
            builder.quantified(op, variables, body, offset, depth, mode)?
        }
        Some(Operator::Not) => {
            let body = parse(builder, depth + 1, mode)?;
            builder.negated(body, offset, depth, mode)?
        }
        Some(op @ (Operator::Implies | Operator::And | Operator::Or | Operator::Iff)) => {
            let left = parse(builder, depth + 1, mode)?;
            builder.comma()?;
            let right = parse(builder, depth + 1, mode)?;
            builder.binary(op, [left, right], offset, depth, mode)?
        }
        None => builder.extension(name, offset, depth, mode)?,
    };
    builder.finish(parsed, depth)
}
