# Operator research supervisor

`tools/research_supervisor.py` runs an explicit, finite list of already supplied
questions and checked proof sources against an existing v6 node. It supervises
saved CLI actions, finalized receipts, phase changes, results, and independent
archive replay. The ledger still chooses the single active attempt, checks
proofs, settles rewards, and decides when the finite record run ends. The
supervisor never opens validator signing custody, creates keys, changes consensus
rules, or infers a research agenda.

## Prepare an operator plan

Create the run and start the validators as in [operations.md](operations.md).
Use absolute paths. Keep the plan, account keys, and the supervisor directory
private. The nodes and account keys must already be configured; the questions,
purpose text, solution sources, and helper sources must already be supplied by
operators. A `reference` is an already finalized library ProofId; the runner
fetches and checks its certificate before package construction. It does not
create a proof. The fixture below illustrates two successive questions. Replace
these paths with the paths of your run and approved inputs.

```json
{
  "version": 1,
  "genesis": "/private/run/genesis.bin",
  "node": "/private/run/node-0/node.json",
  "questions": [
    {
      "label": "A",
      "source": "/absolute/repo/examples/state-workflow/question-a.nao",
      "purpose": "Operator supplied reusable reflexivity question",
      "author_key": "/private/run/accounts/account-4.key",
      "solution": "/absolute/repo/examples/state-workflow/solution-a.nao",
      "helpers": ["/absolute/repo/examples/state-workflow/helper-h.nao"],
      "references": [],
      "votes": [
        {"node": "/private/run/node-0/node.json", "owner_key": "/private/run/accounts/account-0.key", "policy": "YES"},
        {"node": "/private/run/node-1/node.json", "owner_key": "/private/run/accounts/account-1.key", "policy": "YES"},
        {"node": "/private/run/node-2/node.json", "owner_key": "/private/run/accounts/account-2.key", "policy": "YES"}
      ]
    },
    {
      "label": "B",
      "source": "/absolute/repo/examples/state-workflow/question-b.nao",
      "purpose": "Operator supplied question citing H",
      "author_key": "/private/run/accounts/account-5.key",
      "solution": "/absolute/repo/examples/state-workflow/solution-b-original.nao",
      "helpers": ["/absolute/repo/examples/state-workflow/helper-h-duplicate.nao"],
      "references": ["c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73"],
      "votes": [
        {"node": "/private/run/node-0/node.json", "owner_key": "/private/run/accounts/account-0.key", "policy": "YES"},
        {"node": "/private/run/node-1/node.json", "owner_key": "/private/run/accounts/account-1.key", "policy": "YES"},
        {"node": "/private/run/node-2/node.json", "owner_key": "/private/run/accounts/account-2.key", "policy": "YES"}
      ]
    }
  ]
}
```

Each vote requires an explicit owner policy: `YES`, `NO`, or `agent`. `agent`
requires an absolute `provider` executable and may include an absolute
`provider_config` JSON path. It calls the existing bounded local agenda
adapter only for that configured owner. Manual ballots use the plan's common
node intake after the owner key is checked against its configured node; the
signature still belongs to that owner. A `REVIEW` response stops the runner
for operator action without signing a vote. The owner may use `naome vote`
with the matching `LABEL-vote-N.action` path in the private directory, then
restart the runner to reconcile that exact action. Model output never supplies a
proof or consensus authority. A manual `YES` or `NO` is an operator's policy,
not an inference made by the runner. Review the question identities and the
vote policies before starting; the plan is intentionally not editable in place.

## Run and supervise

Build with Rust 1.97.1 from `rust-toolchain.toml`. Confirm that both `cargo
--version` and `rustc --version` resolve to 1.97.1; placing only a pinned Cargo
binary on `PATH` can still invoke a different compiler. Then run from the
repository root, substituting absolute paths:

```sh
cargo build -p naome-cli -p naome-validator -p naome-verifier --bins --profile release --locked
umask 077
python3 -B tools/research_supervisor.py /private/operator-plan.json \
  /private/operator-state --bin "$PWD/target/release/naome" \
  --verifier "$PWD/target/release/naome-verifier"
```

Keep the validator processes running separately. Run this command under a
process manager with restart on failure and a restart delay, or restart it
manually after resolving its private `last-error.txt`. Send SIGTERM to stop
this operator process; the validators continue independently. Reuse the same
plan and private state directory to resume. Only one operator process can hold
the directory lock. `supervisor.json` records plan, input, executable, and
action-file digests, operation IDs, final receipts, question results, and
verified archive paths. The signed
actions, original packages, and commitment secrets remain in mode-0700 private
storage. Preserve the entire directory across restarts and backups. Do not
restore old validator signing seeds or delete custody anchors. If
`supervisor.json` is missing while private actions remain, preserve the
directory for recovery; the runner refuses to initialize over it.

The runner sends a saved action again if its receipt is still unfinalized or
local intake defers it. A restart checks the action file before creating any
new signed operation and reconciles prior final receipts and archive replay.
It waits for the finalized phase of its own submission,
and starts the next question only after the preceding question has reached a
terminal status. After each result, it exports selected history and invokes
`naome-verifier verify` for full offline replay. The output archives contain
original reveal material and must stay private. The runner exits cleanly when
the plan finishes, the run terminates, or ordinary record headroom is gone.
If a submitted action has no final receipt when terminal capacity is reached,
it records that receipt status and stops without creating another action.
A rejected action, changed input, custody mismatch, invalid proof, or unresolved
operator review stops with a visible error for investigation.

## One-host process scenario

After building the three binaries, run:

```sh
python3 -B devnet/research_supervisor_scenario.py \
  --bin-dir "$PWD/target/release" --directory /private/operator-scenario
```

Choose a fresh mode-0700 directory. The scenario uses four independent local
validator processes with the explicitly accelerated `short-test` timing
profile (15-second vote, 45-second commit, 45-second reveal), two real checked
results, helper H reuse and citation, termination and restart of the operator
process after the first result, recovery of a signed-action crash gap, and
independent archive export/replay from all
four nodes. It writes a private `scenario-report.json`. This is one-host
process evidence, not physical multi-machine acceptance or a real-time Lab or
research-profile run.

## Remaining operator and protocol work

Operators still provision and maintain validators, choose and supply questions,
proofs, and vote policies, handle `REVIEW` or rejected actions, monitor private
storage and node availability, and decide whether an expired or unresolved
question should be reintroduced in a later plan. The finite terminal record
has no renewal rule here. A continuation needs a separate agreement on who can
authorize a successor genesis or epoch, how finalized state and proof identity
carry forward, how old and new validator authority overlap, and how signing
custody and late archive verification work across that boundary. Until then,
stop at terminal capacity and retain the complete run.
