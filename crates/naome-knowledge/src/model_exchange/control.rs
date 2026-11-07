use super::Profile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ffi::OsString;
use tokio::sync::{mpsc, oneshot};

#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Status,
    Share,
    Unshare,
    Audit,
    Peer {
        peer: String,
    },
    Compare {
        peer: String,
        expected: Option<String>,
    },
    Extend,
    Offer {
        peer: String,
        comparison: String,
    },
    Adopt {
        comparison: String,
    },
    Rollback {
        expected: String,
    },
    Cancel,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) profile: Profile,
    pub(crate) action: Action,
}

pub(crate) type Response = Result<Value, String>;
pub(crate) type Command = (Request, oneshot::Sender<Response>);
pub(crate) type Sender = mpsc::Sender<Command>;

pub(crate) fn parse(arguments: &[OsString]) -> Option<Result<Request, String>> {
    let arguments = if arguments.first().is_some_and(|arg| arg == "--json") {
        &arguments[1..]
    } else {
        arguments
    };
    if arguments.first().is_none_or(|arg| arg != "models") {
        return None;
    }
    Some(parse_model(&arguments[1..]))
}

fn parse_model(arguments: &[OsString]) -> Result<Request, String> {
    let args = arguments
        .iter()
        .map(|arg| arg.to_str().ok_or("invalid model command text"))
        .collect::<Result<Vec<_>, _>>()?;
    let [action, profile, rest @ ..] = args.as_slice() else {
        return Err("usage: naome models <action> <solver|finder> [arguments]".into());
    };
    let action = match (*action, rest) {
        ("status", []) => Action::Status,
        ("share", []) => Action::Share,
        ("unshare", []) => Action::Unshare,
        ("audit", []) => Action::Audit,
        ("peer", [peer]) => Action::Peer {
            peer: (*peer).into(),
        },
        ("compare", [peer]) => Action::Compare {
            peer: (*peer).into(),
            expected: None,
        },
        ("compare", [peer, expected]) => Action::Compare {
            peer: (*peer).into(),
            expected: Some((*expected).into()),
        },
        ("extend", []) => Action::Extend,
        ("offer", [peer, comparison]) => Action::Offer {
            peer: (*peer).into(),
            comparison: (*comparison).into(),
        },
        ("adopt", [comparison]) => Action::Adopt {
            comparison: (*comparison).into(),
        },
        ("rollback", [expected]) => Action::Rollback {
            expected: (*expected).into(),
        },
        ("cancel", []) => Action::Cancel,
        _ => return Err("invalid model command or arguments (see naome --help)".into()),
    };
    Ok(Request {
        profile: profile.parse()?,
        action,
    })
}
