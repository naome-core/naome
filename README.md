# Research Evidence Protocol

The `naome-protocol` Rust crate and its `rep` CLI preserve scientific evidence, inspect the warrant for a claim, and revisit it after a correction. The separate `naome-network` crate supplies the `rep-node` binary for replication among configured peers. Release 0.1.0 implements the bootstrap formats and a local research profile for [A Research Evidence Protocol for Autonomous Science](research-evidence-protocol.pdf). The [editable paper](research-evidence-protocol.tex) describes the wider protocol and its independent validation criteria.

## Try the calibration case

Install Rust and a C compiler for bundled SQLite. Build from the locked dependency set. The trial needs a new directory or one with no previous trial files.

```sh
cargo build --locked --release
rep=./target/release/rep
"$rep" trial /tmp/rep-trial > /tmp/rep-trial-summary.json
"$rep" suite /tmp/rep-trial/conformance > /tmp/rep-trial-submission.json
"$rep" grade /tmp/rep-trial/conformance/answers.json /tmp/rep-trial-submission.json
```

The trial creates two SQLite archives, a separate disclosure archive, six portable exchange files, 24 queries and a separate answer key. Each query names a claim, its arguments, a policy and a resource budget. The suite opens a fresh database for each packet. The reference fixture includes public synthetic laboratory credentials. A new installation establishes its own trust roots.

| Evidence available | Planned threshold and band scores | Physical threshold and band claims |
| --- | --- | --- |
| Original calibration | Both pass | Both supported |
| Accepted 80 µm correction | Both fail | Both refuted |
| Accepted 80 µm and 10 µm alternatives | Fail under one, pass under the other | Both contested |
| Certified corrected hull alone | Both fail | Both unresolved |

The summary identifies the original and migrated records, dated inventories, corrected receipts, both notices and learning dependencies. To inspect a receipt directly, use `rep --db /tmp/rep-trial/west.sqlite show HEAD ID` with an inventory containing that receipt. `rep --help` lists the available commands. Global `--format a` and `--format b` select the native output encoding.

## Replicate a released inventory

Build both binaries with `cargo build --workspace --locked`. Run `rep-node --directory A init` once for each custodian. This creates its private transport key and `archive.sqlite` and prints the stable peer ID. Supply a JSON configuration with the local listen address and each counterparty's independently obtained peer ID and TCP address. For example, A's configuration for a connection to B has this shape.

```json
{
  "listen": "/ip4/127.0.0.1/tcp/41001",
  "peers": [
    {"id": "<B peer ID from init>", "address": "/ip4/127.0.0.1/tcp/41002"}
  ]
}
```

Run `rep-node --directory A run A/node.json`. Use `rep --db A/archive.sqlite` for ordinary deposit, import, assessment and snapshot operations. Release a selected inventory using `rep-node --directory A publish HEAD`. Publication authorises all members of this configured custody group, including downstream mirrors, to see the membership and receive every readable member under its existing access descriptor. Use a separate disclosure inventory for a narrower audience. A complete mirror serves the same head when the publisher is offline. `rep-node --directory B heads` lists complete releases on B.

Peers use signed GossipSub on `naome-rep-releases-v2` to announce a head. Connected peers reconcile their release catalogs on connection and every four seconds. A receiver fetches the manifest by its hash and requests each object by head and content ID on `/naome/rep/archive/2`. Upgrade the configured peers together to exchange on version 2. An upgraded node can serve an existing version 1 archive directly.

Responses have a four-byte big-endian length followed by a one-byte tag. Tags 0 and 1 indicate unavailable and busy. Tags 2 and 3 carry the JSON catalog and manifest. Tags 4 and 5 carry the exact stored record bytes for formats A and B. Tag 6 carries the 32-byte SHA-256 digest of the REP blob access descriptor followed by the exact blob bytes. Requests, catalogs and manifests use JSON. The file bundle format remains portable JSON.

The receiver verifies the requested content identity and canonical record bytes. For a record the access reference comes from the hashed envelope. For a blob the payload ID covers the bytes and the authenticated custodian supplies the separate access reference. The receiver requires the descriptor in the inventory, verifies its bytes and read permission, and rejects conflicts with existing local custody metadata. For a first-seen blob the reference has the authority of the sending custodian. Noise authenticates the channel, while the blob hash authenticates the payload. A single SQLite transaction admits the full release after these checks and cryptographic verification of research-profile attestations. A local withdrawal removes affected heads from the serving catalog and keeps their historical membership for review. An interrupted transfer restarts from its manifest.

A node's optional `review` configuration is a local current-standing training request in the same JSON form as `rep train`. It pins the recipient's policy, baseline label inventory, feature cutoff and examples. On startup and on a changed catalog, the evaluator considers the union of the baseline and all previously admitted release memberships. A local review record links the evaluated horizon, extraction manifest and withheld labels with their reasons. The node emits their IDs in its JSON log. Historical assessments stay addressable. The operator controls publication of any locally derived review.

The transport retains the static-peer path from NAOME commit `9c368e6a`, including Ed25519 peer identity, Noise over TCP, Yamux, signed gossip, bounded request/response, peer allowlisting, redial and rate accounting. The vendored TCP crate includes the macOS occupied-port-reuse fix and its regression test. The REP network uses direct IP/TCP for configured peers. Public discovery, multicast, circuit relays, hole punching and the proof/work-offer protocols have no role in this configuration. B is an archive mirror with its own stored copy.

The exchange supports up to 16 configured peers and 64 released heads per node. Each head has up to 512 members, 1 MiB per member and 16 MiB total. The receiver stages one transfer at a time. Use REP chunk descriptors for larger individual payloads and select inventories that fit the release budget. The transfer request timeout is 10 seconds, with a 90-second lifetime for a head. Per-peer request quotas and stream and connection ceilings also apply.

Run the local process trial with the command below. The optional directory must be new and have an existing parent. It retains the three databases, configurations, node logs and `result.json`. With the variable unset, Cargo runs the test in a temporary directory.

```sh
REP_TRIAL_DIRECTORY="$PWD/trial-evidence" cargo test -p naome-network --locked --test replication
```

### Measured object sizes

The three-process calibration trial fetched gauge A for `bar-7 / transition-1`, with positions `[10000, 10260]` µm. The archive column counts the original SQLite BLOB for the object on C. It excludes SQLite overhead, referenced objects and indexes. The response column counts successful application-codec writes from B to its negotiated stream. It includes the four-byte length and excludes the request, discovery, Noise, Yamux, and TCP/IP overhead.

| Reading and transport | Stored object | Object response |
| --- | ---: | ---: |
| Legacy reading and JSON/hex response, measured on `faf37db` | 255 B | 691 B |
| Same original reading over the binary response | 255 B | 260 B |
| Paired measurement profile in CBOR over the binary response | 180 B | 185 B |

The baseline trial used the previous writer with a trace after writing the length and JSON bytes. The current trial records successful object writes with `"trace_object_frames": true` in the node configurations. The retained `result.json` and B's `events.jsonl` identify the measured objects and frame lengths. Blob frames include a further 32 bytes for the separate access reference.

## Create and query an archive

The JSON document interface provides a convenient way to author a research record. Its ordered links have a role, target content identifier and optional qualifier. Strings in scientific fields are literals. The typed links carry machine-traversable dependencies.

An occurrence with exactly the fields `gauge`, `positions`, `mode`, `event`, `unit` and `source` and the types in the [paired measurement profile](kits/measurement-profile-v1.txt) uses that content-addressed profile. With format A, `put` writes the typed array directly as canonical CBOR. Both representation profiles resolve to the same named fields for assessment. Existing records preserve their exact bytes, content identifiers, and detached attestations. A newly encoded reading has its own identifier and requires its own attestation where policy calls for one.

```sh
mkdir -p /tmp/rep-example
cat > /tmp/rep-example/question.json <<'JSON'
{"kind":"question","subject":"bar-7","scope":"transition-1","fields":{"purpose":"measure axial displacement","target":"change between the two registered windows"},"inputs":[]}
JSON
"$rep" --db /tmp/rep-example/archive.sqlite put /tmp/rep-example/question.json
"$rep" --db /tmp/rep-example/archive.sqlite snapshot laboratory
```

Use the printed inventory identifier as `HEAD`. Use the first identifier as `ID`. The commands print structured JSON. Scientific refutation and an inconclusive assessment are successful query executions.

| Operation | CLI and result |
| --- | --- |
| Deposit and resolve | `blob` stores exact bytes, `wire` imports a canonical envelope, and `put` authors a research document. `resolve` verifies bytes against the requested identity. `capture` and `recover` stream chunked payloads and check positions, total length and the whole-payload digest. |
| Discover and explain | `discover HEAD --kind question` returns a bounded page with its source, excluded count and continuation. `explain HEAD ID` returns candidate arguments and contrary notices, the dependency closure and the unsearched frontier. |
| Assess and attest | `assess HEAD query.json` evaluates the pinned arguments and deposits a receipt. `keygen`, `sign` and `verify` create or check detached Ed25519 attestations on the original identifier, scope, role and authorisation context. |
| Exchange | `export HEAD packet.json` writes an inventory and its permitted objects. `import packet.json` verifies and reconciles it atomically. Large inventories can be exchanged in pages with `export --limit N` and `--after ID` using the returned continuation. Each import retains the same inventory head. Earlier heads remain addressable. `migrate HEAD ISSUER` creates native records and an inventory mapping. `mapping HEAD ID` checks each pair against both original byte streams. |
| Correct and disclose | Deposit a notice and its attestation, then seal a new inventory. `impact HEAD NOTICE` finds dependent records within the declared horizon. `project HEAD RECEIPT KEY packet.json` replays a measurement and exports a signed scoring hull from a clean archive. It retains provenance for the disclosure in the producing archive. |
| Learn and reassess | `label` derives a target or check label from a receipt, optionally conditioned on one correction. `train` replays the source receipts and emits a dated extraction manifest with withheld-example reasons. `adopt` checks a registered paired-count trial and records the decision, use range, evidence and rollback reference. |
| Investigate | `value` evaluates the finite-world expected reduction in decision loss. `select` ranks observational plans under a stated objective and per-unit ceilings and records the alternatives. `resource`, `reserve`, `readback` and `revoke` manage a durable execution budget. `execute` runs the built-in payload verification operation under an authorised plan and seals the result. |

`tests/conformance.rs` contains complete, executable examples of a registered computational attempt, signed test exemptions, training extraction and a scoped adoption decision. The source-bound query and receipt transcripts retain their original identifiers during migration. A new assessment can cite its predecessor through a native `previous-receipt` edge.

## Training requests

`rep train request.json` uses a recipient-admitted `policy` ID, a `feature_cutoff` inventory and a `label_head` inventory. Examples contain ordered `features`, a `label` ID and a `partition` name. The manifest always groups by claim identity. Supply relevant dependency roles in `independent_roles`, such as `patient`, `specimen` or `manuscript`. The extractor rejects crossings along those roles and exact repeated examples. Verified format mappings can be listed in `mappings`.

- **Provenance.** An argument declares an `origin`. A detached `data-origin` attestation identifies the authorised classifier. `rep label HEAD RECEIPT ORIGIN` checks the requested origin and binds the admitted signatures. The extractor checks them again under the requested policy. For prospective use, set `forecast_plan`. Each argument then requires a signed `release` occurrence that pins the same plan and feature inventory and attests to concealment. The `reading`, `outcome` and `outcome-input` roles mark known outcomes for the cutoff check.
- **Labels after corrections.** The default `standing: "current"` checks the pinned query against the requested label head and withholds an affected label until reassessment. Set `standing: "historical"` for an as-of extraction. A historical manifest still requires currently valid use permission.
- **Project grants.** An access descriptor can include `"training": {"project": "methods-study", "not_before": 0, "expires": 1900000000}` alongside `"purposes": ["read", "train"]`. Enter that project as `project` in the request. Times are Unix seconds with exclusive expiry. Plain `export --purpose train` applies access filters and omits scoped data. Use the extraction manifest to select eligible examples. The local operator is responsible for supplying the authorised project.
- **Typed targets.** For a `training-target` claim, use the `typed-outcome` argument and link the signed occurrence through `outcome`. The occurrence and claim share a `target-profile` link to a `profile` record with scope `training-target-1`. The occurrence provides a structured `target`. The `outcome` signing role attests to it. Use `binary: false` to keep exact quantities, interpreted intervals, right-censored endpoints, referenced text variants or explicit missing values. The typed fixture in `tests/conformance.rs` gives complete records for the three disciplines and their exchange.

The training interface consumes authored evidence records. Discipline-specific importers can map native files to these records and bind their source bytes. The current release exercises this boundary with synthetic datasets.

## Trust and custody

The local operator controls database files, policy selection, authoritative source inventories, release of signatures and access to the CLI. Use an independently obtained kit digest and an independently approved policy and key for a scientific decision. An imported policy is a proposal until the recipient admits it. Protect the SQLite files and signing seeds at the operating-system boundary.

A read or training purpose applies separately to every object. A whole-inventory exchange discloses membership, including identifiers for omitted payloads. Use it between parties authorised to see that inventory. A hull projection creates a new inventory for a recipient entitled only to the projection. Withdrawal leaves a local tombstone and blocks payload restoration through re-import. Other custodians control copies previously received.

A full query scans the specified notice inventory and reports exhaustion or unavailable warrants. A current-standing query additionally names an evaluation time and checks the authority inventories and maximum age in its policy. A migration records an issuer name. A separately verified attestation binds that assertion to a credential. The exposure witness, calibration laboratory, readback witness and trial controller each have a distinct evidential role. Hardware interlocks, external access brokers and key custody belong to the deployment. An ambiguous physical reservation persists across restart until an authorised witness reconciles it.

## Bootstrap and verification

The repository ships the canonical [format A kit](kits/A.json), [format B kit](kits/B.json) and [research profile](kits/research-profile.txt). Each kit includes grammar, decoding rules, resource registry and six cases covering canonical representation, identity, rejection, missing interpretation and exhaustion. A receiver can compare a package with its previously obtained digest using `rep kit FILE SHA256`. `capabilities` identifies the built-in versions and their digests.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --workspace --locked --release --all-features
cargo package -p naome-protocol --locked --allow-dirty
```

The tests cover the paper's known wire digests, arithmetic, restricted evidence, rival notices, profile translation, proof scope, source dependence, survey coverage, crash recovery, learning cutoffs, permission propagation and release entry points. The public suite can grade submissions from other implementations. Both native paths in this release share one Rust evaluator. Independent implementation trials, blinded comparisons with the two proposed baselines and prospective instrument trials remain empirical work.
