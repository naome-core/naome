//! Provider records are durable candidates, never checked graph membership.
use naome_proof::program::{Command, encode_records};

/// A controlled provider exercises the production stream with a deep checked
/// intermediate and a small selected conclusion. It is not a general solver.
pub(super) fn mock_group(
    unit: u32,
    units: u32,
    outcome: super::MockOutcome,
) -> Result<Vec<Command>, crate::Error> {
    if unit == 0 || unit > units {
        return Err(crate::ResearchFailure::MockProgramUnit.into());
    }
    let start = u64::from(unit - 1) * 128;
    let mut commands = Vec::with_capacity(128);
    for position in start..start + 128 {
        commands.push(if position == 0 {
            use naome_foundation::graph::{Node, Variable};
            Command::Graph {
                node: Node::Equal(Variable::Free(0), Variable::Free(0)),
            }
        } else if position == 1 {
            Command::Separation {
                predicate: 0,
                element: 0,
                source: 1,
                result: 2,
            }
        } else if unit == units && position == start + 127 {
            Command::Seal {
                proof: match outcome {
                    super::MockOutcome::Malformed => 0,
                    super::MockOutcome::WrongTarget => position - 1,
                    _ => 1,
                },
            }
        } else {
            Command::Generalization {
                premise: position - 1,
                variable: 1,
            }
        });
    }
    encode_records(&commands)?;
    Ok(commands)
}
