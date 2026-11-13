use crate::archive::QuestionType;
use crate::{Action, Reference, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
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
    question: Option<QuestionType>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeIdentity {
    version: String,
    source: String,
}

pub(crate) struct Checked {
    pub axioms: Vec<String>,
    pub symbols: Vec<String>,
    pub question: Option<QuestionType>,
}

impl From<Reply> for Checked {
    fn from(reply: Reply) -> Self {
        Self {
            axioms: reply.axioms,
            symbols: reply.symbols,
            question: reply.question,
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
        let binary = project.join(".lake/build/bin/naome-lean-bridge");
        if !binary.is_file() {
            return Err(format!(
                "Lean bridge is missing at {}. Run `lake build naome-lean-bridge` in {}",
                binary.display(),
                project.display()
            )
            .into());
        }
        let environment = Command::new(lake)
            .args([
                "env",
                "sh",
                "-c",
                "printf '%s\\0%s' \"$LEAN_SYSROOT\" \"$LEAN_PATH\"",
            ])
            .current_dir(&project)
            .output()
            .map_err(|error| format!("cannot read the Lean environment via Lake: {error}"))?;
        if !environment.status.success() {
            return Err(format!(
                "Lake did not supply the Lean environment: {}",
                String::from_utf8_lossy(&environment.stderr)
            )
            .into());
        }
        let settings = std::str::from_utf8(&environment.stdout)?;
        let (sysroot, search_path) = settings.split_once('\0').unwrap_or_default();
        if sysroot.is_empty() || search_path.is_empty() || search_path.contains('\0') {
            return Err("Lake did not supply a complete Lean environment".into());
        }
        let executable = binary.canonicalize()?;
        let mut child = Command::new(executable)
            .env("LEAN_SYSROOT", sysroot)
            .env("LEAN_PATH", search_path)
            .current_dir(&project)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("cannot start the compiled Lean bridge: {error}"))?;
        let input = BufWriter::new(child.stdin.take().expect("piped Lean input"));
        let output = BufReader::new(child.stdout.take().expect("piped Lean output"));
        let mut session = Self {
            child,
            input,
            output,
            checker_calls: 0,
        };
        let mut ready = String::new();
        session
            .output
            .by_ref()
            .take((include_bytes!("../lean/Bridge.lean").len() * 6 + 1024) as u64)
            .read_line(&mut ready)?;
        let identity: BridgeIdentity = serde_json::from_str(&ready)
            .map_err(|error| format!("invalid compiled Lean bridge identity: {error}"))?;
        let pinned = include_str!("../lean-toolchain").trim();
        let version = pinned
            .rsplit(':')
            .next()
            .unwrap_or(pinned)
            .trim_start_matches('v');
        if identity.version != version || identity.source != include_str!("../lean/Bridge.lean") {
            return Err(format!(
                "compiled bridge differs from the pinned Lean {version} source. Run `lake build naome-lean-bridge` in {}",
                project.display()
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

    pub(crate) fn question(
        &mut self,
        target: &str,
        dependencies: &[String],
        term: Option<&Value>,
    ) -> Result<QuestionType> {
        self.request(Request {
            op: "question",
            target,
            dependencies,
            kernel: term,
            ..Request::default()
        })?
        .require()?
        .question
        .ok_or_else(|| "Lean did not return a checked question type".into())
    }
}

impl Drop for Lean {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
