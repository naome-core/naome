//! Test-only named-variable semantics and an independent canonical interpreter.
//! Finite relational structures exercise first-order logic, not the ZFC axioms.

use naome_foundation::{Formula, FreeVariable};

#[derive(Clone, Debug)]
pub enum Named {
    Equal(u8, u8),
    Member(u8, u8),
    Not(Box<Self>),
    Implies(Box<Self>, Box<Self>),
    All(u8, Box<Self>),
}

impl Named {
    pub fn lower(&self) -> Formula {
        let v = |id| FreeVariable::new(u32::from(id));
        match self {
            Self::Equal(a, b) => Formula::equal(v(*a), v(*b)),
            Self::Member(a, b) => Formula::member(v(*a), v(*b)),
            Self::Not(a) => Formula::negate(a.lower()),
            Self::Implies(a, b) => Formula::implies(a.lower(), b.lower()),
            Self::All(v, body) => Formula::for_all(FreeVariable::new(u32::from(*v)), body.lower()),
        }
    }

    pub fn evaluate(&self, model: Model, environment: [usize; 8]) -> bool {
        match self {
            Self::Equal(a, b) => environment[*a as usize] == environment[*b as usize],
            Self::Member(a, b) => model.member(environment[*a as usize], environment[*b as usize]),
            Self::Not(a) => !a.evaluate(model, environment),
            Self::Implies(a, b) => {
                !a.evaluate(model, environment) || b.evaluate(model, environment)
            }
            Self::All(variable, body) => (0..model.domain).all(|value| {
                let mut nested = environment;
                nested[*variable as usize] = value;
                body.evaluate(model, nested)
            }),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Model {
    pub domain: usize,
    pub membership: u16,
}

impl Model {
    fn member(self, left: usize, right: usize) -> bool {
        self.membership & (1 << (left * self.domain + right)) != 0
    }
}

#[derive(Debug)]
pub enum Variable {
    Free(usize),
    Bound(usize),
}

#[derive(Debug)]
pub enum Primitive {
    Equal(Variable, Variable),
    Member(Variable, Variable),
    Not(Box<Self>),
    Implies(Box<Self>, Box<Self>),
    All(Box<Self>),
}

impl Primitive {
    pub fn from_formula(formula: &Formula) -> Self {
        let bytes = formula.encode_canonical().unwrap();
        fn variable(bytes: &[u8], offset: &mut usize) -> Variable {
            let tag = bytes[*offset];
            let id =
                u32::from_be_bytes(bytes[*offset + 1..*offset + 5].try_into().unwrap()) as usize;
            *offset += 5;
            match tag {
                0 => Variable::Free(id),
                1 => Variable::Bound(id),
                _ => panic!("variable tag"),
            }
        }
        fn parse(bytes: &[u8], offset: &mut usize) -> Primitive {
            let tag = bytes[*offset];
            *offset += 1;
            match tag {
                0 => Primitive::Equal(variable(bytes, offset), variable(bytes, offset)),
                1 => Primitive::Member(variable(bytes, offset), variable(bytes, offset)),
                2 => Primitive::Not(Box::new(parse(bytes, offset))),
                3 => Primitive::Implies(
                    Box::new(parse(bytes, offset)),
                    Box::new(parse(bytes, offset)),
                ),
                4 => Primitive::All(Box::new(parse(bytes, offset))),
                _ => panic!("formula tag"),
            }
        }
        let mut offset = 0;
        let result = parse(&bytes, &mut offset);
        assert_eq!(offset, bytes.len());
        result
    }

    pub fn evaluate(&self, model: Model, free: [usize; 8]) -> bool {
        fn value(variable: &Variable, free: &[usize; 8], bound: &[usize]) -> usize {
            match *variable {
                Variable::Free(id) => free[id],
                Variable::Bound(index) => bound[bound.len() - 1 - index],
            }
        }
        fn evaluate(
            formula: &Primitive,
            model: Model,
            free: &[usize; 8],
            bound: &mut Vec<usize>,
        ) -> bool {
            match formula {
                Primitive::Equal(a, b) => value(a, free, bound) == value(b, free, bound),
                Primitive::Member(a, b) => {
                    model.member(value(a, free, bound), value(b, free, bound))
                }
                Primitive::Not(body) => !evaluate(body, model, free, bound),
                Primitive::Implies(a, b) => {
                    !evaluate(a, model, free, bound) || evaluate(b, model, free, bound)
                }
                Primitive::All(body) => (0..model.domain).all(|value| {
                    bound.push(value);
                    let result = evaluate(body, model, free, bound);
                    bound.pop();
                    result
                }),
            }
        }
        evaluate(self, model, &free, &mut Vec::new())
    }
}

pub fn generate(seed: u64, depth: usize) -> Named {
    fn next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state >> 24
    }
    fn node(state: &mut u64, depth: usize) -> Named {
        let kind = next(state) % if depth == 0 { 2 } else { 5 };
        let left = (next(state) % 4) as u8;
        match kind {
            0 => Named::Equal(left, (next(state) % 4) as u8),
            1 => Named::Member(left, (next(state) % 4) as u8),
            2 => Named::Not(Box::new(node(state, depth - 1))),
            3 => Named::Implies(
                Box::new(node(state, depth - 1)),
                Box::new(node(state, depth - 1)),
            ),
            _ => Named::All(left, Box::new(node(state, depth - 1))),
        }
    }
    node(&mut seed.wrapping_add(0x4e414f4d45), depth)
}

pub fn worlds(mut inspect: impl FnMut(Model, [usize; 8])) {
    for domain in [2, 3] {
        let relations: Vec<_> = if domain == 2 {
            (0..16).collect()
        } else {
            vec![0, 1, 3, 85, 170, 273, 510, 511]
        };
        for membership in relations {
            for assignment in 0..32 {
                let free = std::array::from_fn(|variable| match variable {
                    0..=3 => (assignment >> variable) % domain,
                    7 => (assignment >> 4) % domain,
                    _ => 0,
                });
                inspect(Model { domain, membership }, free);
            }
        }
    }
}
