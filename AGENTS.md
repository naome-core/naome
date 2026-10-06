# Codex repository instructions

## Language defaults

Write chat replies, progress updates and questions in German by default. Write
durable outputs in English, including Space content, visual labels, code,
comments, documentation, work records, commit messages and PR content. Keep
each artifact consistent; preserve quotations, archived sources, fixed bytes
and established identifiers. An explicit language request for the task takes
precedence.

## Documentation and task routing

Maintain NAOME documentation, whitepapers, research, decisions, evidence and work
tracking in the [NAOME Space](https://chatgpt.com/space/page_6abd15f8b06c8191849e7d5b25f0550e).
Use `$naome-space`, read its [Agent operating guide](https://chatgpt.com/space/page_b7369d115b688191a1f45fda42b1c8fb)
and the relevant domain Pages, and update affected records within the authorized
scope. Keep code, executable experiments, fixtures, licenses and this bootstrap
in Git; build, test and runtime operation must not require cloud access.
Follow the guide's **Choose the format for the reader** rule: use editable
documents, sheets, presentations or visuals when they make the task clearer,
with one authoritative source and explicit provenance for derived artifacts.

Originating chats coordinate substantial repository work with
`$main-task-coordinator`; dispatched workers use `$implementation-task-worker`
and do not redispatch the same assignment. A direct request to work in the
current chat takes precedence. Completion reports authorize only the read-only
next-work assessment, not another implementation scope or PR.

## Guarded pull-request automation

The user grants standing authorization for pull requests created by Codex in
`naome-core/naome` to:

- mark a finalized draft ready for review; and
- enable squash auto-merge once the gate below passes, whether required CI is
  pending or successful.

Codex does not need another per-PR confirmation for those two operations when
all conditions below are satisfied. This is the default completion path for
every PR Codex creates during an active user-requested task, including requests
to implement, open, or publish a PR. Unless the user explicitly asks to keep
the PR as a draft, requests review before merge, or rules out merging, Codex
should mark the finalized draft ready and arm squash auto-merge as soon as the
gate below passes. The standing authorization does not allow an
unbounded PR loop, a new product scope, direct merging, admin or ruleset bypass,
force-pushes, changing repository protections, or marking ready, arming
auto-merge, or merging any PR Codex did not create.

Before marking a draft ready or arming auto-merge, verify live that:

- the agreed scope and PR description are complete and no material decision is
  missing;
- the remote PR head exactly matches the locally reviewed and tested commit,
  the worktree is clean, and no further push is planned;
- the PR is currently mergeable and its base commit is recorded;
- all required approvals and Code Owner approvals are satisfied, with no
  changes-requested reviews, unresolved review threads, or unanswered material
  PR comments;
- every required status-check context is present and is successful, pending,
  or in progress, with no required failure, cancellation, timeout, or skip;
- the live base-branch rules enforce the expected checks and review-thread
  resolution without a bypass; and
- repository auto-merge is enabled.

Only required CI may remain pending. After marking a draft ready, repeat the
live head, base, mergeability, feedback, protection, and check gate before
arming. Use squash auto-merge with expected-head protection. Once armed, treat
the head as immutable and supervise the PR until it merges. Poll the exact head
and base commits, required checks, mergeability, reviews, review threads,
material PR comments, and auto-merge state.

Disable auto-merge before any push, or whenever the head, base, protection
rules, mergeability, review or comment state, or required-check set changes.
Also disable it if a required check fails, cancels, times out, is skipped,
disappears, changes source, or remains pending when supervision must pause; then
repeat the full gate. Do not leave auto-merge armed when the task pauses or
ends. If disarming cannot be confirmed, report that unresolved safety condition
immediately. Never use an admin or bypass merge.

After GitHub merges, verify that the merged PR head is the armed commit, all
required checks succeeded, the merge commit is reachable from `origin/main`,
and the merged patch matches the gated feature patch. Report local checks, CI,
and runtime or multi-node evidence separately. Do not begin another scope merely
because this PR merged; continue only as far as the active user request says.

## Rust validation and CI

The maintained core is mathematical proof, definition and question checking and
authoring, plus the economy-free `naome-knowledge` gossip node. The former
blockchain runtime and deployment harnesses are retired.

Use the Rust version pinned in `rust-toolchain.toml`. CI runs the complete
workspace in both `test` and `release` profiles on Linux x86_64 and macOS ARM64.
These are the current supported targets. Windows is not a current distribution
target; Windows CI and platform-specific test maintenance are not required.
Shared portable code and upstream vendor platform code may remain where used
by the supported targets. Each profile builds all targets before executing tests:

```sh
cargo test --workspace --profile test --all-targets --all-features --locked --no-run
cargo test --workspace --profile test --all-targets --all-features --locked --no-fail-fast
```

Use `--profile release` in both commands for release validation. The `test`
profile optimizes Ed25519/Curve25519 and both SHA-2 versions at
level 2 while retaining debug assertions and overflow checks. Other workspace
packages retain their default test optimization level; `dev` and `release`
settings are unchanged. For CI timing comparisons, set `CARGO_INCREMENTAL=0`
and record compilation and execution separately.

Focused gossip process tests must select `naome-knowledge` and use the same
profile, features and targets for compilation and execution. Use the matching
`cargo test --no-run` barrier before a filtered test command; plain `cargo build`
uses the different `dev` profile.

Both platform checks require their complete two-profile matrix;
`Rust CI` requires both platform checks and `Rust quality`.
Cache hits still run every Cargo build and test command. Cache writes occur only after
successful pushes to `main`, with keys covering the runner, profile, toolchain,
manifests, lockfile, and build/workflow configuration.
