use crate::{Action, Reference, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[derive(Default, Serialize)]
struct Request<'a> {
    op: &'a str,
    target: &'a str,
    value: &'a str,
    state: usize,
    action: u8,
    source: &'a str,
    name: &'a str,
    index: usize,
    declaration: &'a str,
    dependencies: &'a [String],
    references: &'a [String],
    #[serde(rename = "describeActions")]
    describe_actions: bool,
    kernel: Option<&'a Value>,
    names: &'a [(String, String)],
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Signature {
    pub conclusion: String,
    pub premises: Vec<String>,
    pub conclusion_symbols: Vec<String>,
    pub premise_symbols: Vec<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct View {
    pub state: usize,
    pub pending: usize,
    pub target: String,
    pub head: String,
    pub locals: Vec<String>,
    pub local_signatures: Vec<Signature>,
    pub target_symbols: Vec<String>,
    pub reference_signatures: Vec<Signature>,
}

#[derive(Debug)]
pub(crate) struct Rejection(pub String);

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Rejection {}

#[derive(Deserialize)]
struct Reply {
    accepted: bool,
    error: String,
    view: View,
    axioms: Vec<String>,
    symbols: Vec<String>,
    kernel: Value,
    dependencies: Vec<String>,
}

pub(crate) struct Checked {
    pub axioms: Vec<String>,
    pub symbols: Vec<String>,
}

impl From<Reply> for Checked {
    fn from(reply: Reply) -> Self {
        Self {
            axioms: reply.axioms,
            symbols: reply.symbols,
        }
    }
}

impl Reply {
    fn require(self) -> Result<Self> {
        if self.accepted {
            Ok(self)
        } else {
            Err(Rejection(self.error).into())
        }
    }
}

pub(crate) enum Step {
    Accepted(View),
    Rejected(String),
}

pub(crate) struct Lean {
    child: Child,
    input: BufWriter<ChildStdin>,
    output: BufReader<ChildStdout>,
    checker_calls: usize,
}

fn project() -> Result<PathBuf> {
    let project = match std::env::var_os("NAOME_LEAN_PROJECT") {
        Some(path) => PathBuf::from(path),
        None => {
            let binary = std::env::current_exe()?;
            let installed = binary.with_file_name("lean-proof");
            let shared = binary
                .parent()
                .and_then(Path::parent)
                .map(|prefix| prefix.join("share/naome/lean-proof"))
                .filter(|path| path.is_dir());
            if installed.is_dir() {
                installed
            } else if let Some(shared) = shared {
                shared
            } else {
                Path::new(option_env!("CARGO_MANIFEST_DIR").unwrap_or(".")).to_owned()
            }
        }
    };
    for (file, expected) in [
        (
            "lean-toolchain",
            include_bytes!("../lean-toolchain").as_slice(),
        ),
        (
            "lakefile.toml",
            include_bytes!("../lakefile.toml").as_slice(),
        ),
        (
            "lake-manifest.json",
            include_bytes!("../lake-manifest.json").as_slice(),
        ),
        (
            "lean/Bridge.lean",
            include_bytes!("../lean/Bridge.lean").as_slice(),
        ),
    ] {
        let path = project.join(file);
        let actual = std::fs::read(&path).map_err(|error| {
            format!(
                "cannot read {}: {error}. Set NAOME_LEAN_PROJECT to the installed proof project",
                path.display()
            )
        })?;
        if actual != expected {
            return Err(format!(
                "Lean project file differs from the pinned source: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(project)
}

impl Lean {
    pub fn spawn() -> Result<Self> {
        let project = project()?;
        let lake = std::env::var_os("NAOME_LEAN_LAKE").unwrap_or_else(|| "lake".into());
        let mut child = Command::new(lake)
            .args(["env", "lean", "--run", "lean/Bridge.lean"])
            .current_dir(project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("cannot start Lean via Lake: {error}"))?;
        let input = BufWriter::new(child.stdin.take().expect("piped Lean input"));
        let output = BufReader::new(child.stdout.take().expect("piped Lean output"));
        let mut session = Self {
            child,
            input,
            output,
            checker_calls: 0,
        };
        let mut ready = String::new();
        session.output.read_line(&mut ready)?;
        let pinned = include_str!("../lean-toolchain").trim();
        let version = pinned
            .rsplit(':')
            .next()
            .unwrap_or(pinned)
            .trim_start_matches('v');
        if ready.trim_end() != format!("naome-lean {version}") {
            return Err(format!(
                "expected Lean {version}; bridge reported {:?}",
                ready.trim_end()
            )
            .into());
        }
        Ok(session)
    }

    pub(crate) fn checker_calls(&self) -> usize {
        self.checker_calls
    }

    fn request(&mut self, request: Request<'_>) -> Result<Reply> {
        serde_json::to_writer(&mut self.input, &request)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        if matches!(request.op, "step" | "finish" | "define" | "importKernel") {
            self.checker_calls = self
                .checker_calls
                .checked_add(1)
                .ok_or("Lean checker call count overflow")?;
        }
        let mut response = String::new();
        if self.output.read_line(&mut response)? == 0 {
            return Err("Lean bridge stopped before answering".into());
        }
        serde_json::from_str(&response)
            .map_err(|error| format!("invalid Lean bridge reply: {error}: {response}").into())
    }

    pub fn start(&mut self, target: &str) -> Result<View> {
        self.start_search(target, &[], false)
    }

    pub fn start_search(
        &mut self,
        target: &str,
        references: &[String],
        describe_actions: bool,
    ) -> Result<View> {
        Ok(self
            .request(Request {
                op: "start",
                target,
                references,
                describe_actions,
                ..Request::default()
            })?
            .require()?
            .view)
    }

    pub fn step(&mut self, state: usize, action: &Action) -> Result<Step> {
        self.search_step(state, action, false)
    }

    pub fn search_step(
        &mut self,
        state: usize,
        action: &Action,
        describe_actions: bool,
    ) -> Result<Step> {
        action.validate()?;
        let mut request = Request {
            op: "step",
            describe_actions,
            state,
            action: action.id,
            ..Request::default()
        };
        let archived_name;
        match &action.argument {
            Some(Reference::Local(index)) => {
                request.source = "local";
                request.index = *index;
            }
            Some(Reference::Declaration(name)) => {
                request.source = "declaration";
                request.name = name;
            }
            Some(Reference::Archived(id)) => {
                archived_name = id.lean_name();
                request.source = "declaration";
                request.name = &archived_name;
            }
            Some(Reference::Catalog(_)) => return Err("unbound active catalog reference".into()),
            None => {}
        }
        let reply = self.request(request)?;
        if reply.accepted {
            Ok(Step::Accepted(reply.view))
        } else {
            Ok(Step::Rejected(reply.error))
        }
    }

    pub fn finish(
        &mut self,
        state: usize,
        declaration: &str,
        dependencies: &[String],
    ) -> Result<Checked> {
        Ok(self
            .request(Request {
                op: "finish",
                state,
                declaration,
                dependencies,
                ..Request::default()
            })?
            .require()?
            .into())
    }

    pub fn finish_candidate(
        &mut self,
        state: usize,
        declaration: &str,
        dependencies: &[String],
    ) -> Result<Option<Checked>> {
        let reply = self.request(Request {
            op: "finish",
            state,
            declaration,
            dependencies,
            ..Request::default()
        })?;
        Ok(reply.accepted.then(|| reply.into()))
    }

    pub fn define(
        &mut self,
        target: &str,
        value: &str,
        declaration: &str,
        dependencies: &[String],
    ) -> Result<Checked> {
        Ok(self
            .request(Request {
                op: "define",
                target,
                value,
                declaration,
                dependencies,
                ..Request::default()
            })?
            .require()?
            .into())
    }

    pub(crate) fn export_kernel(
        &mut self,
        declaration: &str,
        names: &[(String, String)],
    ) -> Result<(Value, Vec<String>)> {
        let reply = self
            .request(Request {
                op: "exportKernel",
                declaration,
                names,
                ..Request::default()
            })?
            .require()?;
        Ok((reply.kernel, reply.dependencies))
    }

    pub(crate) fn import_kernel(
        &mut self,
        declaration: &str,
        dependencies: &[String],
        kernel: &Value,
    ) -> Result<(Checked, String)> {
        let mut reply = self
            .request(Request {
                op: "importKernel",
                declaration,
                dependencies,
                kernel: Some(kernel),
                ..Request::default()
            })?
            .require()?;
        let target = std::mem::take(&mut reply.view.target);
        Ok((reply.into(), target))
    }
}

impl Drop for Lean {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
