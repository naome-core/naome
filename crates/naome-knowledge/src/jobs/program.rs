//! Provider records are durable candidates, never checked graph membership.
use naome_proof::program::{CHUNK_BYTES, CHUNK_RECORDS, Command, RECORD_BYTES};

pub(super) fn validate_group(records: &[Command]) -> Result<(), String> {
    if records.is_empty() || records.len() > CHUNK_RECORDS {
        return Err("provider program group capacity".into());
    }
    for command in records {
        if serde_json::to_vec(command)
            .map_err(|e| e.to_string())?
            .len()
            > RECORD_BYTES
        {
            return Err("provider program record capacity".into());
        }
    }
    if serde_json::to_vec(records)
        .map_err(|e| e.to_string())?
        .len()
        > CHUNK_BYTES
    {
        return Err("provider program group byte capacity".into());
    }
    Ok(())
}

/// A controlled provider exercises the production stream with a deep checked
/// intermediate and a small selected conclusion. It is not a general solver.
pub(super) fn mock_group(
    unit: u32,
    units: u32,
    outcome: super::MockOutcome,
) -> Result<Vec<Command>, String> {
    if unit == 0 || unit > units {
        return Err("invalid mock program unit".into());
    }
    let start = u64::from(unit - 1) * 128;
    let mut commands = Vec::with_capacity(128);
    for position in start..start + 128 {
        commands.push(if position == 0 {
            Command::Equal { left: 0, right: 0 }
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
    validate_group(&commands)?;
    Ok(commands)
}
