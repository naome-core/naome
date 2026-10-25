# Codex repository instructions

## Language defaults

Write chat replies, progress updates and questions in German by default. Write
durable outputs in English, including visual labels, code,
comments, documentation, work records, commit messages and PR content. Keep
each artifact consistent; preserve quotations, archived sources, fixed bytes
and established identifiers. An explicit language request for the task takes
precedence.

## Documentation and work

Work in the current chat by default. Use the current source, supplied artifacts,
and existing local documentation. Return review findings in chat unless a saved
report is requested. Keep build, test, and runtime operation independent of cloud
documentation or project-management services.

Use additional worker chats, subagents, external records, native Goals, Factory
admission, or effort tracking only when explicitly requested. Existing installed
controls, resource limits, active ownership, and the pull-request rules below
remain binding. A completed review or PR does not authorize a successor scope.

## Pre-release compatibility

NAOME is pre-release software. Implement and test the current formats and APIs.
Do not add migrations, compatibility fallbacks, legacy adapters, deprecated APIs,
or tests dedicated to obsolete formats or behavior unless the user explicitly
requests migration or legacy support for the task. Remove obsolete paths within
the requested scope; do not preserve them speculatively. Keep current-format
validation, corruption detection, and crash-recovery guarantees.

## Authorized pull-request delivery and squash merging

For an explicitly requested implementation in `naome-core/naome`, the user
provides standing authorization to create and update the task's pull request,
mark a finalized draft ready, and squash-merge it after the live gate below
passes. No additional confirmation is needed to push, publish, mark ready,
squash-merge, or enable squash auto-merge within that agreed scope. This is the
default completion path unless the user asks to keep a draft, requests review
before merge, or rules out merging.

This authorization covers PRs the agent creates and PRs explicitly assigned to
it for delivery. It does not authorize a successor task, an unbounded PR loop,
force-pushes, direct pushes to `main`, admin or ruleset bypass, or changes to
repository protections.

Before marking ready, merging, or enabling auto-merge, verify live that:

- the agreed scope and PR description are complete;
- the remote head exactly matches the locally reviewed and tested commit,
  the worktree is clean, and no further push is planned;
- the PR is mergeable and its current base commit is recorded;
- required approvals and Code Owner approvals are satisfied, with no
  changes-requested reviews, unresolved review threads, or unanswered material
  PR comments;
- every required check is present from its expected source; all must succeed
  for an immediate squash merge, while only required CI may remain pending
  or in progress when enabling auto-merge; and
- the live base rules enforce the expected checks and review-thread resolution
  without a bypass.

Use the normal squash merge API with expected-head protection. Alternatively,
use squash auto-merge when the repository supports it; repository auto-merge
need not be enabled for an immediate squash merge. Repeat the full live gate
between marking ready and merging or arming auto-merge.

After arming auto-merge, keep the head immutable and supervise it until merge.
Disable auto-merge before any push or whenever the head, base, protection,
mergeability, feedback, required-check set or check source changes. Also disable
it when a required check fails, cancels, times out, is skipped or disappears,
or when supervision must pause. Do not leave auto-merge armed when the task
pauses or ends; report immediately if disarming cannot be confirmed.

After merge, verify the merged head, successful required PR checks, reachability
of the merge commit from `origin/main`, and equivalence of the merged feature
patch. Record the post-merge `CI` and `Full Cargo CI` run links and current status,
separately from MR checks and local validation. Ordinary PR delivery tasks must
not wait for the complete main pipeline or full Cargo matrix to finish before
completing. Report pending or unavailable post-merge results as unverified;
successful MR checks do not establish full Cargo qualification. A failed
post-merge run remains a main regression. A merge does not authorize another scope.

### Scheduled main-pipeline repair

The separately authorized scheduled monitor checks `main` hourly and owns
post-merge pipeline follow-up. It autonomously diagnoses actionable `CI` and
`Full Cargo CI` failures, implements focused fixes, publishes repair PRs, and
squash-merges them only after the same live gate above passes. This recurring
repair scope is explicitly authorized; ordinary delivery tasks retain their
bounded scope.

Resume existing repairs and respect active ownership instead of creating
duplicate PRs. Preserve unrelated work and use a clean isolated worktree when
needed. Fix causes without weakening assertions, coverage, required checks,
repository protections, or existing resource limits. Retry an unchanged commit
only with evidence of a transient failure; a passing retry is not a code fix.

For each repair, verify merge reachability and patch equivalence, then follow
the merged main commit through successful `CI` and the complete `Full Cargo CI`
matrix on both supported platforms in both profiles. The monitor continues this
verification across scheduled runs; the ordinary-task completion rule above
does not waive its recovery checks. If `main` advances, distinguish the repair
commit's results from the latest head's results. Report meaningful failures,
repairs, verified recovery, or actionable blockers; remain quiet while the
observed state is unchanged or healthy. Missing access, required human approval,
or unavailable resources must be reported as blockers without bypassing the gate.

## Rust validation and CI

The maintained core is mathematical proof, definition and question checking and
authoring, plus the economy-free `naome-knowledge` gossip node. The former
blockchain runtime and deployment harnesses are retired.

Use the Rust version pinned in `rust-toolchain.toml`. Linux x86_64 and macOS
ARM64 are the supported targets. Windows is not a current distribution target;
Windows CI and platform-specific test maintenance are not required. Portable
shared code and upstream vendor platform code may remain where used.

### Merge-blocking checks

`CI` runs on pull requests, merge groups, and pushes to `main`. Both supported
platforms build the Bazel `//:mr_build` targets and run `//:mr_tests`, in the
ordinary product configuration, including Clippy over product and selected test
targets. `Rust quality` checks CI
contracts, formatting, documentation, and documentation tests. The existing
required contexts remain `Rust quality`, `Rust platform (Linux x86_64)`,
`Rust platform (macOS ARM64)`, and `Rust CI`.

Keep the MR suite focused on fast deterministic regressions. Long network,
discovery, recovery, and resource-stress scenarios belong to the full Cargo
matrix. The `system-tests` feature gates large-history and load regressions;
`--all-features` enables them in every full Cargo profile. Test grouping must be
explicit; do not remove assertions or weaken
system-test guarantees to shorten the MR path.

Bazel executes locally and uses only a local disk cache and existing GitHub
Actions caching. Use standard `ubuntu-24.04` and `macos-15` runners. Do not add
remote execution, hosted build services, paid runners, or additional accounts
without explicit authorization. Cargo manifests and `Cargo.lock` remain the
Rust dependency authority. Bazel's Rust pin must match `rust-toolchain.toml`.

### Full Cargo verification

`Full Cargo CI` runs after every push to `main`, without cancelling previous
main runs. It can also be dispatched manually; dispatching `CI` with
`full_cargo=true` runs the same full matrix before a merge when needed. The
full matrix is deliberately outside the MR merge gate.

Every platform runs the complete workspace in both `test` and `release`
profiles, including the long system tests. Each profile builds all targets
before executing tests:

```sh
cargo test --workspace --profile test --all-targets --all-features --locked --no-run
cargo test --workspace --profile test --all-targets --all-features --locked --no-fail-fast
```

Use `--profile release` in both commands for release validation. Retain the
ordinary product configuration checks without developer tools, the all-feature
binary restoration, macOS multicast preflight, and discovery evidence capture
in `.github/workflows/rust-tests.yml`. Documentation tests remain explicit;
`--all-targets` does not run them.

The `test` profile optimizes Ed25519/Curve25519 and both SHA-2 versions at
level 2 while retaining debug assertions and overflow checks. Other workspace
packages retain their default test optimization level; `dev` and `release`
settings are unchanged. For comparisons, set `CARGO_INCREMENTAL=0` and record
compilation and execution separately.

Focused gossip process tests must select `naome-knowledge` and use the same
profile, features and targets for compilation and execution. Use the matching
`cargo test --no-run` barrier before a filtered command; plain `cargo build`
uses the different `dev` profile. Keep process-fixture serialization intact.

Only explicit success satisfies a required result job; failures, cancellations,
and skipped or missing required dependencies must fail it. Cache hits never
replace the full Cargo build or test commands. Cache writes occur only after
successful pushes to `main`; cache service failures must not mask test failures.
