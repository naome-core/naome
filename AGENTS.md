# Codex repository instructions

## Guarded pull-request automation

The user grants standing authorization for pull requests created by Codex in
`naome-core/naome` to:

- mark a finalized draft ready for review; and
- enable squash auto-merge while required CI is pending.

Codex does not need another per-PR confirmation for those two operations when
all conditions below are satisfied. This authorization applies only within an
active user-requested task that explicitly includes completing that PR. A
request only to implement, open, or publish a PR does not authorize marking it
ready or arming auto-merge. The standing authorization does not allow an
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
