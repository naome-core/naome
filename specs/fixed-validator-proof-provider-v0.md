# Fixed-Validator Proof Provider V0

## Scope and authority

`SEC-003-003` connects the existing Unix validator process to the independently
verifying [archive](fixed-validator-archive-v0.md). An explicitly enabled
validator serves the first complete finality envelope and matching artifact
payload already retained at an exact requested height. It continues to own its
sole driver, signer and independently anchored journals. Archive requests do
not cause proposal creation, voting, finalization or signer acknowledgement.

This is one provider-to-archive capability. It does not add a proof wire format,
head discovery, source selection, vote assembly, continuous following, retries,
general artifact/block serving, recovery, pruning or dynamic validators. It
does not complete general full-node conformance or close `SEC-003`, `SYNC-001`,
`SYNC-002` or `SYNC-004`.

## Explicit process configuration

The existing validator `[network]` table accepts one optional boolean:

```toml
serve_finality_proofs = true
```

Absent or `false` preserves the previous process behavior: complete-proof
requests are transferred through the runtime and discarded by the process's
ordinary diagnostic path. There is no unavailable response from disabled
service. Non-boolean values and duplicate fields are configuration errors
before authority provisioning. This option does not alter create/open mode,
seed requirements, public context, fixed set, limits or address validation.

When enabled, the process responds to complete-proof requests from any peer
in its existing explicit static peer configuration. It uses the same Noise
identity, sessions and shared resource limits. No second response allowlist,
listener or peer-role classification is introduced. `publication_targets`
remains an independent explicit subset: an archive peer can be connected for
proof requests while omitted from consensus proposal/vote publication.
Configured peer identity grants transport access, not consensus membership or
proof validity. The archive still selects its source explicitly and verifies
every complete response against its own public context and selected parent.

## Restricted selected-proof reading

Storage seals `SelectedFinalityProofHistoryV0` to the independently anchored
finality journal. Its single lookup accepts an exact context and height and
returns only a borrowed first-retained finality record. It checks operational
health before answering any address, including a foreign context, zero height
or missing height. Healthy absent addresses return no proof. Halted or poisoned
owners return their existing journal error. The projection creates no owned
snapshot, writes no file and performs no signing operation.

The driver exposes that trait through `selected_finality_proof_history`.
It does not expose the concrete journal: even immutable journal methods can
issue signer-height and signer-stop acknowledgement capabilities, which are
absent from this projection. The borrow prevents consuming driver work while
it is held; neither the scope nor an acknowledgement capability escapes.

The existing journal network responder delegates to
`respond_finality_proof_from_selected_history`. Closed-channel rejection and
shared application-rate admission precede selected-history access. Operational
health precedes foreign-context or missing-height unavailability. Proof length
validation and shared response-custody reservation precede allocation and
copying. The existing framing, exact bytes, eight physical pending requests,
per-peer request retention and incoming/outgoing response budget are unchanged.
No transport receipt establishes remote verification or anchored commit.

## Runtime and process lifetime

The runtime's explicit `respond_finality_proof_from_selected_history` checks
that a driver survives before borrowing its reader. An unavailable driver
returns `DriverUnavailable` with the original inbound request; it consumes no
channel, rate admission, history read or response allocation. Once delegated,
the lower response operation retains its existing consuming error semantics.

The response call does not poll the runtime, observe a timer, step the driver,
drain an inbox, change pending input, or alter command/publication custody. It
does not inspect or acknowledge peer consensus messages. Ordinary scheduling
continues after the call, with existing local-publication admission and exact
due-timer precedence. A response queued during publication backpressure does
not release that backpressure. Shared streams have no new reserved capacity,
fairness or production timing guarantee.

Only the opted-in process dispatches returned `InboundFinalityProof` events to
this adapter. `proof_response_queued` reports the requested peer and height;
it means queued transport output, including an unavailable response, and does
not mean delivered or accepted. `proof_response_failed` reports a bounded
reason. Ordinary channel/rate, response-retention or copy-allocation failures
end that response and allow normal processing to continue without retry.
Driver absence, a journal health error or an unsupported future response error
ends the owning process through its existing fatal teardown path.

Other fatal runtime or command outcomes already end the process before a
later request can be served. Strict restart classifies both journal/anchor
pairs before runtime ownership or listening. Terminal, pending or mismatched
restart states do not start this provider. A ready strict reopen can serve its
retained first proofs without the original proposal input files. This option
restores no pending request, publication, archive sync intent or outbox.

## Evidence and limits

The cross-process corpus uses four equal-weight validator executables. They
author and exchange ordinary proposals and votes, each reaching finality at
two successive heights. An archive excluded from their publication targets
fetches one selected provider's complete proofs, independently verifies and
anchors each height, and does not advance without an explicit sync command.
The producer's artifact input files are removed before serving. Quiescent
provider finality and vote authority images remain unchanged by requests.
After strict provider and archive reopen, a fresh archive obtains H1 from
the validator and H2 from the archive relay; retained envelope/payload bytes,
values and selected ancestry agree with the selected provider's history.

Separate process cases exercise omitted/false opt-in, unavailable and foreign
requests, terminal sibling halt and disabled provider startup after strict
halted reopen. The adversarial sibling fixture is signed by the parent test
process and is not attributed to the honest producer. Runtime vectors check
pending publication allocations and delivery states, queued input custody,
exact expired timers and loss-of-driver refunds. Storage and transport vectors
check first-evidence retention, real anchor-operation poisoning, terminal halt,
and channel/rate admission before unhealthy-history access.

The cross-binary test locates `naome-validator` beside Cargo's verifier binary.
A missing binary fails the test. Existence alone does not establish freshness:
focused validation must build both executables with matching profile, features
and target before selecting both packages for tests, for example:

```sh
cargo build -p naome-validator -p naome-verifier --bins --all-features --locked
cargo test -p naome-validator -p naome-verifier --all-targets --all-features --locked validator_provider
```

Use `--release` on both commands for release evidence. Workspace test gates
select both packages. No test invokes Cargo recursively or skips the provider.
These are finite local/CI process and ownership vectors, not deployment,
exhaustive crash/power-loss, general safety/liveness, throughput, fairness or
full-node conformance evidence. The archive's unmeasured real 120-second
whole-command expiry remains unmeasured by this provider corpus.
