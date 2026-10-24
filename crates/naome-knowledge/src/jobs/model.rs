//! Budgeted job execution using the owner's single shared decision access.
use super::*;
use crate::decision::runtime::{Access, Failure};

pub(super) async fn run(
    record: Record,
    remaining_ms: u64,
    events: mpsc::Sender<process::Event>,
    cancel: oneshot::Receiver<()>,
    access: Access,
    slot: Option<std::fs::File>,
) -> process::Outcome {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(remaining_ms);
    let result = execute(&record, deadline, events, cancel, access, slot).await;
    match result {
        Ok(distribution) => process::Outcome {
            state: State::Complete,
            result: Ok(Output::Decision(distribution)),
        },
        Err(Failure::Cancelled) => process::Outcome {
            state: State::Cancelled,
            result: Err("decision cancelled".into()),
        },
        Err(Failure::TimedOut) => process::Outcome {
            state: State::Expired,
            result: Err("decision deadline expired".into()),
        },
        Err(Failure::Failed(error)) => process::Outcome {
            state: State::Failed,
            result: Err(error),
        },
        Err(Failure::Uncertain(error)) => process::Outcome {
            state: State::InDoubt,
            result: Err(error),
        },
    }
}

async fn execute(
    record: &Record,
    deadline: tokio::time::Instant,
    events: mpsc::Sender<process::Event>,
    cancel: oneshot::Receiver<()>,
    access: Access,
    slot: Option<std::fs::File>,
) -> Result<crate::decision::Distribution, Failure> {
    let Input::Interest {
        question,
        assessment,
        ..
    } = &record.input
    else {
        return Err("decision job input differs".into());
    };
    let question =
        naome_authoring::CompiledQuestion::compile(question).map_err(|e| e.to_string())?;
    let request = assessment.request(&question);
    let (reply, receipt) = oneshot::channel();
    events
        .send(process::Event::Reserve {
            id: record.id,
            next: 1,
            reply,
        })
        .await
        .map_err(|_| "decision reservation owner stopped")?;
    receipt
        .await
        .map_err(|_| "decision reservation receipt absent")??;
    access
        .infer(request, &assessment.model, slot, cancel, deadline)
        .await
}
