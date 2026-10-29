//! Bind operational experience before it can affect durable finder learning.
use super::*;
use crate::learning::experience::{ExperienceSummary, TerminalEvidence};

#[cfg(test)]
pub(super) mod tests;

pub(super) fn completion<'a>(
    question: &CompiledQuestion,
    completion: &'a jobs::Completion,
    outcome: Outcome,
) -> Result<Option<&'a ExperienceSummary>, String> {
    let Some(summary) = &completion.experience else {
        return Ok(None);
    };
    summary.validate()?;
    if summary.job != completion.id
        || summary.question != crate::hex(question.resolution_id())
        || completion.model_checkpoint.as_deref() != Some(summary.checkpoint.as_str())
        || summary.policy != crate::learning::input_specification()
        || summary.request_binding != crate::learning::digest(&completion.binding)
        || !matches!(summary.origin, crate::learning::Origin::Local)
        || summary.spent_ms != completion.spent_ms
        || summary.reserved_units != completion.reserved_units
    {
        return Err("finder experience differs from its completed job".into());
    }
    let expected_outcome = match (completion.state, &completion.result) {
        (
            jobs::State::Complete,
            Ok(jobs::Output::Native {
                solution,
                terminal,
                frontier,
                ..
            }),
        ) => {
            terminal.validate(solution.as_ref())?;
            if summary.terminal != **terminal
                || summary.trace.checked_trajectory
                    != solution.as_ref().map(|s| crate::learning::digest(&s.tree))
                || summary.trace.observed_branches != frontier.as_ref().map(crate::learning::digest)
            {
                return Err("finder experience differs from its native result".into());
            }
            if solution.is_some() {
                Outcome::Candidate
            } else {
                Outcome::NoCandidate
            }
        }
        (jobs::State::Failed, _) if summary.terminal == TerminalEvidence::TechnicalFailure => {
            Outcome::Failed
        }
        (jobs::State::Cancelled, _) if summary.terminal == TerminalEvidence::Interrupted => {
            Outcome::Failed
        }
        (jobs::State::Expired, _) if summary.terminal == TerminalEvidence::Interrupted => {
            Outcome::Expired
        }
        (jobs::State::InDoubt, _) if summary.terminal == TerminalEvidence::Interrupted => {
            Outcome::InDoubt
        }
        _ => return Err("finder experience lacks its terminal job state".into()),
    };
    if outcome != expected_outcome {
        return Err("finder outcome differs from its native experience".into());
    }
    Ok(Some(summary))
}

pub(super) fn record(question: &CompiledQuestion, record: &Record) -> Result<(), String> {
    if let Some(summary) = &record.experience {
        summary.validate()?;
        if summary.job != record.last_job
            || summary.question != crate::hex(question.resolution_id())
            || record.model_checkpoint.as_deref() != Some(summary.checkpoint.as_str())
            || summary.spent_ms > record.spent_ms
            || summary.reserved_units != record.last_units
        {
            return Err("stored finder experience differs from its observation".into());
        }
    }
    Ok(())
}
