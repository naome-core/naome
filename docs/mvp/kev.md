# Local Kev agenda voting

Kev assesses whether a question fits the operator's research profile. A local
policy returns YES, NO or REVIEW; REVIEW never signs a ballot. The model has no
proof-validity authority and does not change consensus voting weight.

## Setup and worker controls

Requires macOS on Apple Silicon, at least 16 GiB physical RAM, Python 3.9+, and
[`uv`](https://docs.astral.sh/uv/) on PATH. Allow 15 GiB free disk space for a fresh
installation and enough free memory for approximately 8.5 GB of model allocation.
From the repository root:

```sh
python3 tools/agenda_agent_kev.py setup
python3 tools/agenda_agent_kev.py start
python3 tools/agenda_agent_kev.py status
python3 tools/agenda_agent_kev.py stop
```

Setup downloads pinned Kev-4B weights, source and locked Python dependencies into
ignored `.local/kev`. It reports progress and saves details in private `setup.log`.
Rerun after an interruption to resume; a completed installation is verified and
reused. Setup does not load the model. No account or API key is needed.

`start` allows up to 180 seconds for loading; `check` is its compatibility alias.
`status` inspects without loading. `stop` cancels loading or releases the model,
confirming process ownership has ended within ten seconds or reporting failure.
Ctrl-C and termination clean up processes started by that command. The model
also exits after five idle minutes. Add `--json` for scripts or an optional
runtime directory; start/status/stop also accept a private configuration file.

Inference is offline and automatically starts the worker when needed. Prewarm
with `start` before a time-sensitive vote: automatic startup plus inference has
only 50 seconds. Busy, invalid, oversized or late requests produce no vote and
are not silently retried. Status and stop remain available during model loading.
Inspect private `worker.log` after a failure; stop/start after changing runtime
code. Changed installed model files require setup in a fresh directory.

## Review, vote and replay

During Voting, use the [operations runbook](operations.md) variables `BIN`, `C0`
and `RUN`, after setting the node's research profile:

```sh
"$BIN" agent-review "$C0" "$RUN/accounts/account-0.key" \
  "$RUN/kev-review-0.json" "$PWD/tools/agenda_agent_kev.py" \
  --provider-config "$PWD/.local/kev/kev.json"

"$BIN" agent-vote "$C0" "$RUN/accounts/account-0.key" \
  "$RUN/kev-vote-0.bin" "$RUN/kev-review-0.json" \
  "$PWD/tools/agenda_agent_kev.py" \
  --provider-config "$PWD/.local/kev/kev.json"
```

Review retains structured probabilities, policy/model versions and a decision
without signing. Vote reuses that result without another inference and rechecks
the current attempt and deadline. REVIEW remains terminal; the operator can
instead vote manually. Changing the profile or configuration after reservation
fails closed and does not reset the shared attempt budget. Never delete budget
files to retry an uncertain call.

The provisional policy checks gates in order: context or purpose alignment below
8,000 basis points yields REVIEW; then explicit exclusion at least 8,000 yields
NO, and exclusion above 2,000 yields REVIEW. Only after those gates pass does the
70% relevance / 30% usefulness score yield YES at 7,500 or above, NO at 2,500 or
below, or REVIEW between them.
These are local policy thresholds, not calibrated correctness probabilities.
Weights and thresholds live in private `kev.json`; compare a candidate policy
without inference or signing using:

```sh
python3 tools/agenda_agent_kev.py replay \
  "$RUN/kev-review-0.json" /absolute/path/private-candidate-kev.json
```

Keep configurations, request snapshots and reports private: they include research
preferences. The model receives public question context and preferences, never
account keys. It rejects branches over 2,048 tokens without truncation. Model and
context versions must match for replay; changed model weights or prompts need a fresh
evaluation. Known arithmetic and instruction-handling errors remain.

## Repeatable validation

The [verification summary](verification.md#local-kev-voting-prototype) records
local results and their limits. Keep generated reports under ignored `.local/kev`.
Run the offline regressions and the actual four-validator integration check with:

```sh
python3 -m unittest discover -s tools/tests -v
python3 tools/kev_mvp_smoke.py --binary target/release/naome \
  --validator target/release/naome-validator \
  --verifier target/release/naome-verifier \
  --config "$PWD/.local/kev/kev.json" --scenario require-yes
```
