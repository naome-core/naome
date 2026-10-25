# Matched question prefilter comparison

Run the fixed workloads against two exact Git revisions:

```sh
python3 tools/benchmarks/prefilter.py \
  --base <baseline-commit> --candidate <candidate-commit> \
  --target-dir /tmp/naome-prefilter-target --output /tmp/naome-prefilter-results
```

The runner archives each revision into a temporary source directory, overlays
identical test-only measurement files and mathematical fixtures, and builds both
with the pinned toolchain, `release`, the lockfile and `CARGO_INCREMENTAL=0`.
Compilation is recorded separately. Benchmark executables are copied before
building the other revision. Seven process rounds alternate revision order;
there are no concurrent benchmark processes. Source and fixture hashes, raw
samples, build logs, process peak RSS and CPU usage are retained in `raw.json`
and the revision-specific output directories.

The checker workloads contain 24 elementary equivalences, 24 distinct controls,
eight short-answer cases with 64–192 decoy implications and the same 512-operation
budget, eight unanswered queries in an empty registry, eight unanswered queries
with 32 unrelated registered questions, and eight elementary known answers.
Each checker workload repeats its cases 16 times per process. State construction
is outside the assessment interval; request and snapshot binding are inside.
Generated answer certificates are independently rechecked outside that interval.
Production regressions separately check both generated equivalence certificates,
disk-backed indexes, copy, recovery, limits and the actual node admission path.

The node-owner workloads perform 4,096 assessments each: one repeated question,
eight alternating questions, and eight alternating inputs with forced fresh
evaluation. They count actual checker computations as well as elapsed time.
The fresh case represents the mandatory recomputation used at admission; cached
read-only decisions never replace this check. The cache is cold at the start of
each workload, so timing includes its initial misses.

These are synthetic, bounded local workloads. Report extra recognized cases and
avoided computations separately from latency. Include regressions, medians and
the observed range. Process peak RSS includes fixture setup and the test runner;
it is not a measurement of cache allocation or a sustained node memory plateau.
The comparison does not measure human-labelled question quality, distributed
throughput, provider inference, saved research-job runtime or production traffic.
