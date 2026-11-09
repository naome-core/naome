//! The canonical instruction encoding. Each opcode fixes its operand layout.
//! Record boundaries can therefore be recovered directly from a byte stream.
use super::{
    ACTION_PREMISES, Axiom, Command, RECORD_BYTES, SCOPE_ACTIONS, SCOPE_ASSUMPTIONS, ScopedAction,
};
use naome_foundation::graph::{Node, Variable};

pub(super) fn put_integer(out: &mut Vec<u8>, mut value: u64) {
    while value >= 128 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub(super) struct Reader<'a>(pub(super) &'a [u8]);

impl Reader<'_> {
    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let (bytes, rest) = self
            .0
            .split_at_checked(N)
            .ok_or("truncated program input")?;
        self.0 = rest;
        Ok(bytes.try_into().expect("fixed field width"))
    }

    pub(super) fn integer(&mut self) -> Result<u64, String> {
        let mut value = 0;
        for shift in (0..64).step_by(7) {
            let [byte] = self.fixed()?;
            let part = u64::from(byte & 0x7f);
            if shift == 63 && byte > 1 {
                return Err("program integer overflow".into());
            }
            value |= part << shift;
            if byte < 128 {
                if shift != 0 && part == 0 {
                    return Err("noncanonical program integer".into());
                }
                return Ok(value);
            }
        }
        Err("program integer overflow".into())
    }

    fn term(&mut self) -> Result<u32, String> {
        u32::try_from(self.integer()?).map_err(|_| "program term width".into())
    }

    fn variable(&mut self) -> Result<Variable, String> {
        let encoded = self.integer()?;
        if encoded & 1 == 0 {
            u32::try_from(encoded >> 1)
                .map(Variable::Free)
                .map_err(|_| "free term width".into())
        } else {
            Ok(Variable::Bound(encoded >> 1))
        }
    }

    fn arguments(&mut self) -> Result<Vec<u32>, String> {
        let count = self.integer()?;
        if count > u64::from(crate::DEFINITION_MAX_GRAPH_ARITY) {
            return Err("program definition argument capacity".into());
        }
        (0..count).map(|_| self.term()).collect()
    }

    fn count(&mut self, limit: usize) -> Result<usize, String> {
        let count = self.integer()?;
        if count > limit as u64 {
            return Err("scoped program operand capacity".into());
        }
        Ok(count as usize)
    }

    fn axiom(&mut self) -> Result<Axiom, String> {
        Ok(match self.fixed::<1>()?[0] {
            0 => Axiom::Extensionality,
            1 => Axiom::Pairing,
            2 => Axiom::Union,
            3 => Axiom::PowerSet,
            4 => Axiom::Infinity,
            5 => Axiom::Foundation,
            6 => Axiom::Choice,
            _ => return Err("program axiom tag".into()),
        })
    }
}

fn put_count(out: &mut Vec<u8>, count: usize, limit: usize) -> Result<(), String> {
    if count > limit {
        return Err("scoped program operand capacity".into());
    }
    put_integer(out, count as u64);
    Ok(())
}

fn write_scope(
    out: &mut Vec<u8>,
    assumptions: &[u64],
    actions: &[ScopedAction],
    result: u32,
) -> Result<(), String> {
    if assumptions.is_empty() {
        return Err("deduction requires an assumption".into());
    }
    put_count(out, assumptions.len(), SCOPE_ASSUMPTIONS)?;
    for &assumption in assumptions {
        put_integer(out, assumption);
    }
    put_count(out, actions.len(), SCOPE_ACTIONS)?;
    for action in actions {
        match action {
            ScopedAction::Instantiate {
                universal,
                replacement,
                premises,
            } => {
                out.push(0);
                put_integer(out, u64::from(*universal));
                put_integer(out, u64::from(*replacement));
                put_count(out, premises.len(), ACTION_PREMISES)?;
                for &premise in premises {
                    put_integer(out, u64::from(premise));
                }
            }
            ScopedAction::Conjoin { left, right } => {
                out.push(1);
                put_integer(out, u64::from(*left));
                put_integer(out, u64::from(*right));
            }
        }
    }
    put_integer(out, u64::from(result));
    Ok(())
}

fn read_scope(input: &mut Reader<'_>) -> Result<Command, String> {
    let count = input.count(SCOPE_ASSUMPTIONS)?;
    if count == 0 {
        return Err("deduction requires an assumption".into());
    }
    let assumptions = (0..count)
        .map(|_| input.integer())
        .collect::<Result<_, _>>()?;
    let count = input.count(SCOPE_ACTIONS)?;
    let mut actions = Vec::with_capacity(count);
    for _ in 0..count {
        actions.push(match input.fixed::<1>()?[0] {
            0 => {
                let universal = input.term()?;
                let replacement = input.term()?;
                let count = input.count(ACTION_PREMISES)?;
                let premises = (0..count).map(|_| input.term()).collect::<Result<_, _>>()?;
                ScopedAction::Instantiate {
                    universal,
                    replacement,
                    premises,
                }
            }
            1 => ScopedAction::Conjoin {
                left: input.term()?,
                right: input.term()?,
            },
            _ => return Err("unknown scoped program opcode".into()),
        });
    }
    Ok(Command::Deduce {
        assumptions,
        actions,
        result: input.term()?,
    })
}

fn axiom_tag(axiom: Axiom) -> u8 {
    match axiom {
        Axiom::Extensionality => 0,
        Axiom::Pairing => 1,
        Axiom::Union => 2,
        Axiom::PowerSet => 3,
        Axiom::Infinity => 4,
        Axiom::Foundation => 5,
        Axiom::Choice => 6,
    }
}

fn put_variable(out: &mut Vec<u8>, variable: Variable) -> Result<(), String> {
    let encoded = match variable {
        Variable::Free(id) => u64::from(id) * 2,
        Variable::Bound(index) => index.checked_mul(2).ok_or("program binder width")? | 1,
    };
    put_integer(out, encoded);
    Ok(())
}

pub(super) fn write_command(command: &Command, out: &mut Vec<u8>) -> Result<(), String> {
    match command {
        Command::Graph { node } => match *node {
            Node::Equal(a, b) | Node::Member(a, b) => {
                out.push(u8::from(matches!(node, Node::Member(..))));
                put_variable(out, a)?;
                put_variable(out, b)?;
            }
            Node::Not(child) | Node::ForAll(child) => {
                out.push(if matches!(node, Node::Not(_)) { 2 } else { 4 });
                put_integer(out, child);
            }
            Node::Implies(a, b) => {
                out.push(3);
                put_integer(out, a);
                put_integer(out, b);
            }
        },
        Command::DefinedRelation {
            definition_id,
            arguments,
        }
        | Command::AuthoredRelation {
            definition_id,
            arguments,
            ..
        } => {
            let authored = if let Command::AuthoredRelation { body, .. } = command {
                Some(*body)
            } else {
                None
            };
            out.push(if authored.is_some() { 0x1e } else { 0x05 });
            out.extend_from_slice(definition_id);
            if arguments.len() > crate::DEFINITION_MAX_GRAPH_ARITY as usize {
                return Err("program definition argument capacity".into());
            }
            put_integer(out, arguments.len() as u64);
            for &argument in arguments {
                put_integer(out, u64::from(argument));
            }
            if let Some(body) = authored {
                put_integer(out, body);
            }
        }
        Command::Equal { left, right } => {
            out.push(0x06);
            put_integer(out, u64::from(*left));
            put_integer(out, u64::from(*right));
        }
        Command::Member { element, set } => {
            out.push(0x07);
            put_integer(out, u64::from(*element));
            put_integer(out, u64::from(*set));
        }
        Command::Not { formula } => {
            out.push(0x08);
            put_integer(out, *formula);
        }
        Command::Implies {
            antecedent,
            consequent,
        } => {
            out.push(0x09);
            put_integer(out, *antecedent);
            put_integer(out, *consequent);
        }
        Command::ForAll { variable, body } => {
            out.push(0x0a);
            put_integer(out, u64::from(*variable));
            put_integer(out, *body);
        }
        Command::Substitute { from, to, body } => {
            out.push(0x0b);
            put_integer(out, u64::from(*from));
            put_integer(out, u64::from(*to));
            put_integer(out, *body);
        }
        Command::Simplification {
            antecedent,
            consequent,
        } => {
            out.push(0x0c);
            put_integer(out, *antecedent);
            put_integer(out, *consequent);
        }
        Command::Frege {
            first,
            second,
            third,
        } => {
            out.push(0x0d);
            put_integer(out, *first);
            put_integer(out, *second);
            put_integer(out, *third);
        }
        Command::Contraposition {
            antecedent,
            consequent,
        } => {
            out.push(0x0e);
            put_integer(out, *antecedent);
            put_integer(out, *consequent);
        }
        Command::Distribution {
            variable,
            antecedent,
            consequent,
        } => {
            out.push(0x0f);
            put_integer(out, u64::from(*variable));
            put_integer(out, *antecedent);
            put_integer(out, *consequent);
        }
        Command::Vacuous { formula } => {
            out.push(0x10);
            put_integer(out, *formula);
        }
        Command::Instantiation {
            variable,
            replacement,
            body,
        } => {
            out.push(0x11);
            put_integer(out, u64::from(*variable));
            put_integer(out, u64::from(*replacement));
            put_integer(out, *body);
        }
        Command::Instantiate {
            premise,
            replacement,
        } => {
            out.push(0x13);
            put_integer(out, *premise);
            put_integer(out, u64::from(*replacement));
        }
        Command::Deduce {
            assumptions,
            actions,
            result,
        } => {
            out.push(0x12);
            write_scope(out, assumptions, actions, *result)?;
        }
        Command::Reflexivity { variable } => {
            out.push(0x14);
            put_integer(out, u64::from(*variable));
        }
        Command::Substitution { from, to, body } => {
            out.push(0x15);
            put_integer(out, u64::from(*from));
            put_integer(out, u64::from(*to));
            put_integer(out, *body);
        }
        Command::Axiom { axiom } => {
            out.push(0x16);
            out.push(axiom_tag(*axiom));
        }
        Command::ProofReference { proof_id } => {
            out.push(0x17);
            out.extend_from_slice(proof_id);
        }
        Command::Separation {
            predicate,
            element,
            source,
            result,
        } => {
            out.push(0x18);
            put_integer(out, *predicate);
            put_integer(out, u64::from(*element));
            put_integer(out, u64::from(*source));
            put_integer(out, u64::from(*result));
        }
        Command::Replacement {
            predicate,
            input,
            output,
            witness,
            source,
            result,
        } => {
            out.push(0x19);
            put_integer(out, *predicate);
            put_integer(out, u64::from(*input));
            put_integer(out, u64::from(*output));
            put_integer(out, u64::from(*witness));
            put_integer(out, u64::from(*source));
            put_integer(out, u64::from(*result));
        }
        Command::ModusPonens {
            premise,
            implication,
        } => {
            out.push(0x1a);
            put_integer(out, *premise);
            put_integer(out, *implication);
        }
        Command::Generalization { premise, variable } => {
            out.push(0x1b);
            put_integer(out, *premise);
            put_integer(out, u64::from(*variable));
        }
        Command::Alias { input } => {
            out.push(0x1c);
            put_integer(out, *input);
        }
        Command::Seal { proof } => {
            out.push(0x1d);
            put_integer(out, *proof);
        }
    }
    Ok(())
}

pub(super) fn read_command(input: &mut Reader<'_>) -> Result<Command, String> {
    Ok(match input.fixed::<1>()?[0] {
        0 => Command::Graph {
            node: Node::Equal(input.variable()?, input.variable()?),
        },
        1 => Command::Graph {
            node: Node::Member(input.variable()?, input.variable()?),
        },
        2 => Command::Graph {
            node: Node::Not(input.integer()?),
        },
        3 => Command::Graph {
            node: Node::Implies(input.integer()?, input.integer()?),
        },
        4 => Command::Graph {
            node: Node::ForAll(input.integer()?),
        },
        0x05 => Command::DefinedRelation {
            definition_id: input.fixed()?,
            arguments: input.arguments()?,
        },
        0x06 => Command::Equal {
            left: input.term()?,
            right: input.term()?,
        },
        0x07 => Command::Member {
            element: input.term()?,
            set: input.term()?,
        },
        0x08 => Command::Not {
            formula: input.integer()?,
        },
        0x09 => Command::Implies {
            antecedent: input.integer()?,
            consequent: input.integer()?,
        },
        0x0a => Command::ForAll {
            variable: input.term()?,
            body: input.integer()?,
        },
        0x0b => Command::Substitute {
            from: input.term()?,
            to: input.term()?,
            body: input.integer()?,
        },
        0x0c => Command::Simplification {
            antecedent: input.integer()?,
            consequent: input.integer()?,
        },
        0x0d => Command::Frege {
            first: input.integer()?,
            second: input.integer()?,
            third: input.integer()?,
        },
        0x0e => Command::Contraposition {
            antecedent: input.integer()?,
            consequent: input.integer()?,
        },
        0x0f => Command::Distribution {
            variable: input.term()?,
            antecedent: input.integer()?,
            consequent: input.integer()?,
        },
        0x10 => Command::Vacuous {
            formula: input.integer()?,
        },
        0x11 => Command::Instantiation {
            variable: input.term()?,
            replacement: input.term()?,
            body: input.integer()?,
        },
        0x12 => read_scope(input)?,
        0x13 => Command::Instantiate {
            premise: input.integer()?,
            replacement: input.term()?,
        },
        0x14 => Command::Reflexivity {
            variable: input.term()?,
        },
        0x15 => Command::Substitution {
            from: input.term()?,
            to: input.term()?,
            body: input.integer()?,
        },
        0x16 => Command::Axiom {
            axiom: input.axiom()?,
        },
        0x17 => Command::ProofReference {
            proof_id: input.fixed()?,
        },
        0x18 => Command::Separation {
            predicate: input.integer()?,
            element: input.term()?,
            source: input.term()?,
            result: input.term()?,
        },
        0x19 => Command::Replacement {
            predicate: input.integer()?,
            input: input.term()?,
            output: input.term()?,
            witness: input.term()?,
            source: input.term()?,
            result: input.term()?,
        },
        0x1a => Command::ModusPonens {
            premise: input.integer()?,
            implication: input.integer()?,
        },
        0x1b => Command::Generalization {
            premise: input.integer()?,
            variable: input.term()?,
        },
        0x1c => Command::Alias {
            input: input.integer()?,
        },
        0x1d => Command::Seal {
            proof: input.integer()?,
        },
        0x1e => Command::AuthoredRelation {
            definition_id: input.fixed()?,
            arguments: input.arguments()?,
            body: input.integer()?,
        },
        _ => return Err("unknown program opcode".into()),
    })
}

pub fn encode_command(command: &Command) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    write_command(command, &mut bytes)?;
    if bytes.len() > RECORD_BYTES {
        return Err("program command byte capacity".into());
    }
    Ok(bytes)
}

pub fn decode_command(bytes: &[u8]) -> Result<Command, String> {
    if bytes.len() > RECORD_BYTES {
        return Err("program command byte capacity".into());
    }
    let mut input = Reader(bytes);
    let command = read_command(&mut input)?;
    if !input.0.is_empty() {
        return Err("trailing program command bytes".into());
    }
    Ok(command)
}
