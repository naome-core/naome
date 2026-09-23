# Trusted research MVP verification

The current authority-period implementation uses canonical `state-v5` history through
`naome`, `naome-validator`, and `naome-verifier`. The checked artifact DAG is the
proof-library component of that complete state. The historical
[qualification report](evidence/final-integration.json) records source identities,
commands, output hashes, the real-agent lab, and CI for `state-v1`. The mappings
below identify executable test sources; a source pointer is not a passing run.
Every recorded run establishes evidence only for its named snapshot.

The older lab and CI reports below qualify only their named historical snapshots.
They do not qualify the current authority-period implementation. There is one
supported prerelease model; fresh genesis and stores are required for it.

## Authority-period qualification

The canonical implementation seals every record using outgoing agreement,
three incoming READY signatures and three outgoing TERMINAL signatures. The
same selected authority drives consensus, time reports, service accounting,
transport and replay. Research attempts retain their frozen owner electorate.
Four stable slots retain their quorum weight through unavailability; admission
consumes the oldest eligible claim only when its successor is sealed.

The 23 September 2026 qualification passed on clean implementation commit
`1554fcac6d39dcbf9eba4c43c4767e078856cf51`. The [local qualification record](evidence/handoff-final-local.json)
contains the source fingerprint, commands, elapsed times, output hashes,
architecture review and paper checks. Documentation and evidence added after
that run do not change the qualified implementation fingerprint.

| Evidence | Current result |
|---|---|
| Complete local workspace | Rust 1.97.1, `CARGO_INCREMENTAL=0`; 639 tests in `test` and 639 in `release`, zero failures. Each complete all-target, all-feature, locked execution followed its own complete `--no-run` build barrier. Profiles ran sequentially. |
| Local timing | Test compilation 3.134 s and execution 494.290 s; release compilation 14.424 s and execution 441.244 s. |
| Quality | Formatting, Clippy and rustdoc with warnings denied, workspace doctest command, 32 devnet Python tests and 54 Kev Python tests passed. |
| Platform CI | [Run 35905106571](https://github.com/naome-core/naome/actions/runs/35905106571) passed both profiles on Linux x86_64, macOS ARM64 and Windows x86_64, plus quality, devnet and all aggregate gates on the named commit. |
| Earned installation | The process scenario registers a new account, verifies its paid proof and claim, installs its prepared candidate, requires its signature in a later ordinary quorum with only two bootstrap signers online, verifies the future service payment, cold-restarts peers and independently replays four distinct stores. |
| Delayed native network | [Four-process report](evidence/handoff-final-native.json): 15 matching heights in 98.565 s with 50 ms delay in each direction, timed isolation with surviving-quorum progress, catch-up, SIGKILL, graceful restart, four replays and corrupt-export rejection. |
| Portable bundles | [CI rehearsal](evidence/handoff-final-pilot.json): relocated private bundles, real proof/helper settlement with one node offline, catch-up, cold reopen and four agreeing archive replays; all nine checks passed. |
| Independent review | Selected authority, seal binding, signer custody, recovery, transport retention and priority, obsolete paths, operating commands and process evidence were reviewed; substantive findings were fixed and no blocking findings remained. |
| Whitepaper | The updated source, diagrams and generated 20-page English PDF passed structural checks and manual rendered-page inspection. Hashes are retained in the qualification record. |

The [final Docker report](evidence/handoff-final-ci.json) reached 102 matching
canonical heights in 34 attempts in **483.476 seconds**, compared with
**1103.819 seconds** in the [baseline](evidence/handoff-baseline-ci.json):
**2.283 times faster**. Both runs used the GitHub-hosted Ubuntu 24.04
x86_64 runner class with the same container CPU/memory limits. The image changed
from `20260907.300.1` to `20260920.314.1`. The authorized timing
profile changed from 15-second to 1-second voting windows, all committed in
genesis and completed under certified time (510 versus 34 required seconds).
The profile, proxy and observation changes are part of this observed end-to-end
result; their individual contributions are not apportioned, and this is not a
protocol throughput claim. Separate signed-time tests preserve every complete
Lab, research, short-test and CI phase boundary.

The final Docker run retained 50 ms bidirectional delay, alternating authenticated
owners, the timed partition with surviving-quorum progress and catch-up, active
signer SIGKILL and graceful restarts, post-restart progress, bounded resources,
four independent archive replays, 32 rejected malformed ingress attempts and
corrupted-export rejection. The CI job separately recorded 95 s for the release
build barrier, 154 s for the publication/recovery scenario, 73 s for the portable
rehearsal and 16 s for image packaging. Those steps are outside the Docker
qualification measurement. Observation and certified-window counters overlap
the attempt phases and must not be added to them.

These results accept MVP-36 through MVP-38 and AB-08 through AB-10 under the
explicit accelerated authority-period qualification. A new real-agent Lab run,
physical multi-machine acceptance and the complete seven-day research run remain
separate and unqualified. Operational handoff requires operator attestation that
external secret backups and regeneration seeds are destroyed; the implementation
retires managed local signing capability. Finite run and journal limits remain.

## Historical retirement-order qualification

The v4 genesis and profile are incompatible with v3. The new genesis field is an
exact four-validator-ID permutation selected through a required setup JSON plan;
`profile-info` exposes it. Ledger tests cover missing, duplicate and foreign IDs,
order identity, strict wire decoding and stable state replay. CLI setup tests
cover rejection before provisioning. The 22 September 2026 local check used
Rust 1.97.1 and `CARGO_INCREMENTAL=0`: both complete workspace profiles passed
585 tests with zero failures, each after its own
`--workspace --all-targets --all-features --locked --no-run` build barrier.
Formatting, Clippy with warnings denied, rustdoc with warnings denied,
doctests, 54 Kev Python tests, and 18 devnet Python tests passed. Release
binaries passed a one-host four-process relocated-bundle rehearsal through 12
heights, with offline catch-up, cold reopen, and four agreeing independent
archive replays. The tested `fb21c8e` tree is identical to the rebased v4
implementation `d91675a`. Platform CI, physical multi-machine qualification,
and the long research-window profile remain unverified for v4. At that v4
snapshot, the order had no effect on live authority.

## Historical join-intent qualification

The 22 September 2026 local v3 check on the merged v2 base used Rust 1.97.1 and
`CARGO_INCREMENTAL=0`. Both complete workspace profiles (`test` and `release`)
passed 583 tests with zero failures, each after its own
`--workspace --all-targets --all-features --locked --no-run` build barrier.
Formatting, Clippy with warnings denied, rustdoc with warnings denied, and
doctests passed. All 54 Kev and 18 devnet Python tests passed. The seven local
process scenarios include a four-validator join-intent case that passed in
35.46 s. Component tests cover
claim binding, candidate key possession, role and endpoint collisions, nonce
conflicts, replay, and direct rejection of candidate research votes, consensus
signing and votes, proposals, time reports, and transport identity. The
qualified implementation and test source is
`e236914`.
The [v3 CI run 35784893448](https://github.com/naome-core/naome/actions/runs/35784893448)
passed all required platform and quality checks, plus Devnet qualification, on
head `754bec4`; squash merge `92353ca` has the same feature tree. Physical
multi-machine qualification and the long research-window profile have not
run. The v3 four-process run used the accelerated short-test profile, so
Lab-profile extension acceptance remains pending. At that v3 snapshot, a join
intent neither activated a validator nor consumed its eligibility claim; activation was deferred to the handoff milestone.

## Historical account-admission qualification

The original 22 September 2026 local v2 check passed 564 tests per profile.
After integration with Kev, the merged v2 head `b5f0207` passed both complete
Rust 1.97.1 workspace profiles with 572 tests each, their separate
`--all-targets --all-features --locked --no-run` build barriers, formatting,
Clippy with warnings denied, rustdoc with warnings denied, doctests, and 54 Kev
Python tests. [CI run 35781130410](https://github.com/naome-core/naome/actions/runs/35781130410)
passed all six platform test/release jobs, quality, devnet, and the required
aggregate checks on that exact head. The squash merge `68e9f7d` has the same
feature tree. The seven local process scenarios include a fresh
researcher creating a key, registering with zero balance, earning a proof reward,
independently verifying its archive, and surviving all four validators' cold
restart. Registry exhaustion, fixed voting authority, protected intake, original
and citation rewards, and journal replay have separate component coverage below.
Physical multi-machine acceptance remains separate.

## Historical state-v1 qualification

| Evidence | Source and result |
|---|---|
| Implementation | `0bae7b0e61c576f9fc1edf2f465da90602a9645e`, the source qualified by the successful CI run below. |
| Complete local workspace | Rust 1.97.1 with `CARGO_INCREMENTAL=0`; separate build barriers and complete all-target/all-feature/locked executions; 533 tests passed in each of the test and release profiles. Commands and output hashes are in the qualification report. |
| Quality | Formatting, Clippy with warnings denied, documentation with warnings denied, and the workspace doctest command passed. The final crates define zero doctests. |
| Platform CI | [Run 35465126870](https://github.com/naome-core/naome/actions/runs/35465126870) on `0bae7b0`: all six Linux x86_64, macOS ARM64, and Windows x86_64 test/release jobs, quality, devnet, and aggregate gates passed. |
| CI devnet | [Public Docker report](evidence/final-integration-ci-devnet.json): all four validators independently replayed 102 matching complete records on the same clean `0bae7b0` source, with 50 ms traffic delay, isolation/healing, SIGKILL, graceful restart, and corrupt-export rejection. This is accelerated control-record qualification, not 102 proof publications. |
| Real lab | [Public lab report](evidence/final-integration-lab.json): passed in 1,665.669 seconds with real 300/120/120-second windows, actual bounded agenda review, reversed reveals, missing earlier reveal, helper retrieval while its original provider was offline, citation payment, no retrospective payment, 2:2 partition/healing, four-node cold restart, and independent replay. |
| Lab provenance | The lab ran clean source `7e43f2bc3c5e967b2a2f3aad54496c61eb064be2`. The later code change only gates two Unix test helpers. Rebuilt main executable hashes match the lab; the qualification report retains the source-manifest and binary hashes. |
| Independent review | Read-only architecture and source/log/binary/evidence review was clear for that integration. It did not perform an independent Cargo run. |

The lab produced exactly three paid completions and three passive claims, with
3,000,000,000 atoms across balances and reserve. Claims activate no voting rights.
Component checks, injected storage faults, accelerated process tests, platform CI,
and the real-window lab establish different properties. Graceful shutdown is not
an abrupt settlement crash; the storage fault suite covers that boundary.

The evidence is bounded to trusted fixed membership and four local processes.
Finite consensus-round and journal limits remain. Two-machine operation and the
seven-day profile are still unqualified; these results do not establish public
permissionless-network security. Keys, secrets, raw histories and provider
diagnostics remain private. Public reports include the intentionally published
fixture profile and actual agent decision and reason.

## Pilot preparation

The next pilot's [local preparation evidence](evidence/pilot-local.json), dated
20 September 2026, records an exact file manifest for the changes after
`6cdab88`. Both complete Rust profiles passed 535 tests with separate build
barriers; formatting, Clippy, rustdoc and the doctest command passed. All 18
devnet/Python tests passed. A release-binary rehearsal moved four private bundles,
settled one real proof and helper with one validator offline, restored it,
cold-restarted all four, and independently replayed 12 matching records. It also
rejected duplicate node exports, corrupt archive bytes, missing anchors and
simulation controls. The run took 36.979 seconds with compact short-test limits
and manual votes; cleanup completed.

The [pilot runbook](pilot.md) defines deployment and collection on real machines.
The rehearsal is one-host evidence. Standard-limit network execution, a new
real-agent or LAB-window run, Docker and CI for this patch, physical machine
independence, and the seven-day profile were not run. The revised 19-page
[paper](whitepaper-en.pdf) passed structural checks and rendered-page visual
review; that document review does not qualify the proposed public network.

## Local Kev voting prototype

Local validation on 2026-09-22 used an Apple M4 with 16 GiB RAM. Rust 1.97.1
passed 543 tests in each of the test and release profiles, plus formatting,
Clippy, rustdoc and doctests. After the Python-only lifecycle changes, all 54
offline tests passed; Rust sources were unchanged from that validation.

Actual model loading cancellation, termination cleanup, restart and process
reuse passed. Existing installation reuse was exercised directly; fresh-download
interruption and resumption used fixtures. Real Kev reviews produced unsigned
REVIEW and finalized YES/NO ballots. The final four-validator smoke reused
assessments without extra inference and replayed four archives to the same head.
This is one-machine evidence, not separate-machine or full research-lifecycle
acceptance. No CI or publication result is claimed.

The frozen benchmark scored 37/48 baseline questions across 60 calls including
repeat/order probes. A confident wrong answer to `17 mod 5` illustrates why this
is not a dependable mathematical authority. Scores and policy thresholds remain
uncalibrated. The benchmark script and question set are local research artifacts
under ignored `.local/kev/research/`; reports are under `.local/kev/evidence/`.
See the [Kev runbook](kev.md) for repeatable software and integration checks.

## Executable evidence locations

| Label | Source and scope |
|---|---|
| Profile | [Profile/genesis tests](../../crates/naome-ledger/src/profile/tests.rs) |
| Account admission | [Registration, capacity and authority](../../crates/naome-chain/src/state/tests/admission.rs), [protected intake](../../crates/naome-runtime/src/state/tests/intake_priority.rs), [four-process registration, reward and restart](../../crates/naome-cli/tests/cases/admission.rs) |
| Join intent | [Canonical intent and key possession](../../crates/naome-ledger/src/operations/join_intent/tests.rs), [claim and state admission](../../crates/naome-ledger/src/state/tests.rs), [candidate consensus exclusion](../../crates/naome-consensus/src/state/tests.rs), [candidate transport exclusion](../../crates/naome-network/src/transport/state_exchange/tests.rs), [CLI action custody](../../crates/naome-cli/src/app/actions/tests.rs), [four-process prepare, replay and restart](../../crates/naome-cli/tests/cases/admission.rs); an intent alone grants no authority, while the sealed handoff activates its selected claimant |
| Questions | [Question compilation tests](../../crates/naome-ledger/src/question/tests.rs) |
| State | [Canonical state transitions](../../crates/naome-chain/src/state/tests.rs), [wire/replay vectors](../../crates/naome-chain/src/state/tests/golden.rs), [default queue boundary](../../crates/naome-chain/src/state/tests/queue_boundary.rs), [all-sixteen-author reservation](../../crates/naome-chain/src/state/tests/capacity_sixteen.rs) |
| Library | [Mathematical normalization/reuse tests](../../crates/naome-ledger/src/library/tests.rs), [workload qualification](../../crates/naome-ledger/src/library/tests/qualification.rs), [older-depth boundary](../../crates/naome-ledger/src/library/tests/depth_boundary.rs) |
| Accounting | [Exact monetary distribution](../../crates/naome-ledger/src/accounting/tests.rs) |
| Receipts | [Settlement inspection and canonical receipt tests](../../crates/naome-chain/src/state/receipt_tests.rs) |
| Authentication/time | [Action authentication](../../crates/naome-ledger/src/authentication/tests.rs), [signed time](../../crates/naome-ledger/src/time/tests.rs) |
| Consensus/node | [Consensus kernel](../../crates/naome-consensus/src/state/tests.rs), [node recovery](../../crates/naome-node/src/state/tests.rs) |
| Safety model | [Bounded explorer and mutation controls](../../crates/naome-node/src/state/safety_model/model.rs), [real signer/reopen replay](../../crates/naome-node/src/state/safety_model/replay.rs), [weighted arithmetic oracle](../../crates/naome-consensus/src/weight_oracle.rs) |
| Storage | [State history/signer/settlement recovery](../../crates/naome-storage/src/state/tests.rs), [journal I/O faults](../../crates/naome-storage/src/state/log_tests.rs) |
| Transport/runtime | [Network exchange](../../crates/naome-network/src/transport/state_exchange/tests.rs), [exact frame limits](../../crates/naome-network/src/transport/state_exchange/tests/boundary.rs), [peer isolation and lifecycle](../../crates/naome-network/src/transport/state_exchange/tests/lifecycle.rs), [wire protocol](../../crates/naome-protocol/src/state_exchange/tests.rs), [runtime intake](../../crates/naome-runtime/src/state/tests.rs) |
| CLI | [Agent](../../crates/naome-cli/src/app/agent/tests.rs), [durable actions](../../crates/naome-cli/src/app/actions/tests.rs), [private files](../../crates/naome-cli/src/app/files/tests.rs), [setup/local profile](../../crates/naome-cli/src/app/setup/tests.rs) |
| Process | [four_process_state_recovery_partition_and_independent_replay](../../crates/naome-cli/tests/state_process.rs): accelerated independent processes |
| LAB | [state_lab_acceptance.py](../../tools/state_lab_acceptance.py): real windows, actual provider, separate four-process state; report required |

## Requirement mapping

Names below identify concrete test functions within those sources. LAB references
identify runner actions and fields in the recorded acceptance report.

| Requirement | Executable evidence and scope |
|---|---|
| MVP-01 | Profile: `genesis_identity_binds_all_configuration_and_keys`, `rejects_duplicate_keys_roles_and_owners`, strict codec tests. Network: `state_noise_peer_with_wrong_genesis_never_delivers_application_payload`. LAB: `independent_process_custody` and immutable profile. |
| MVP-02 | Process test and LAB start four executables with separate configured histories, anchors, signer stores and keys. LAB records custody and agreement. |
| MVP-03 | State: `complete_a_h_b_c_workflow_preserves_attribution_citation_and_once_only_issuance`; Consensus: `verified_control_record_finality_binds_full_state_and_preserves_empty_library`; LAB compares complete state/accounts/claims/library. |
| MVP-04 | Consensus control-record test above; Storage: `complete_control_history_reopens_and_observer_uses_same_full_state`; Process finalizes an unapproved question without a proof. |
| MVP-05 | State: `canonical_wire_and_identifier_vectors`, `streaming_state_commitment_matches_materialized_canonical_bytes`; Profile and Protocol golden vectors; Process/LAB observer agreement. Target-platform agreement also requires completed CI. |
| MVP-06 | Questions: `rejects_free_variables_assumptions_imports_and_bad_syntax`, `profile_smaller_bounds_are_enforced_for_both_targets`, canonical/orientation tests. Receipts: `rendered_closed_targets_round_trip_without_changing_canonical_formula`. CLI `compile-question` and submission preview are exercised through operating procedures/LAB submission. |
| MVP-07 | State: `actual_queue_limit_and_exact_expiry_preserve_state_on_rejection`, `default_queue_accepts_32_in_finalized_order_and_rejects_33_without_mutation`; Runtime: `queue_receipt_is_not_finality_and_duplicate_identity_is_idempotent`. |
| MVP-08 | State A/H/B/C workflow; Library: `real_a_group_then_b_refutation_preserves_h_attribution_and_known_c`; LAB `helper_normalization_citation_known`. |
| MVP-09 | State: `complete_real_proof_settlement_and_replay_are_atomic`, `minimum_66_record_run_protects_active_slots_and_settles_timely_reveal_after_pause`; Library: `stale_library_parent_prevents_whole_publication_without_mutation`. |
| MVP-10 | CLI: `changing_local_agenda_profile_cannot_change_genesis_or_reinitialize_history`; LAB `actual_agent_review` with provider hash and actual question. Fake-provider tests do not supply the actual-agent evidence. |
| MVP-11 | CLI: `fake_provider_accepts_only_bounded_complete_decisions`, `changed_or_expired_voting_context_never_creates_a_signed_action`, timeout/process cleanup and durable budget tests. State vote/nonce tests prevent replacement of finalized votes. Manual fallback is an operator CLI path. |
| MVP-12 | State helper `open_and_approve` asserts three early YES votes leave phase Voting; `absence_never_counts_yes_and_expiry_never_means_refutation` rejects two YES. Consensus: `two_votes_never_finalize_and_duplicate_signers_never_add_weight`. Chain `every_timing_profile_preserves_complete_certified_phase_windows` checks exact full voting, commitment and reveal deadlines for Lab, research, short-test and ci-test using signed time certificates and canonical record replay. LAB phase/deadline observations. |
| MVP-13 | Time: `lower_median_and_parent_time_are_exact`, `distinct_registered_quorum_and_context_required`; State: `phase_start_deadline_and_nonce_rejections_leave_parent_unchanged`, `reveal_at_exact_deadline_and_wrong_original_author_are_rejected`. Process partition demonstrates no finality from local timers alone. |
| MVP-14 | CLI: `commit_secret_precedes_transmission_and_missing_action_or_lost_ack_reuses_exact_intent`; private file no-overwrite/durability helpers. LAB creates retained commitments before transmission. |
| MVP-15 | CLI: `retained_reveal_after_lost_ack_resends_without_open_phase_or_new_nonce`, `mismatched_private_bundle_author_genesis_secret_or_retained_reveal_never_transmits`; State exact-deadline/author rejection; Storage actual settlement recovery. |
| MVP-16 | State: `commitment_order_wins_even_when_reveals_arrive_in_reverse_order`, `invalid_or_missing_earlier_reveal_does_not_block_later_eligible_commitment`. LAB `AB02_reverse_reveal` and `AB02_missing_earlier`. |
| MVP-17 | Library: `invalid_unused_original_and_noncanonical_original_are_not_repaired`, `cycles_unknown_dependencies_wrong_target_and_known_roots_fail`; A/H/B actual checker fixtures; LAB `check-proof` for downloaded normalized certificates. |
| MVP-18 | Library: `different_new_certificates_of_same_statement_include_root_collision`, `same_derivation_original_alias_is_verified_then_removed_before_publication`. |
| MVP-19 | Library: `parent_selection_orders_height_operation_then_raw_proof_id`, `duplicate_helper_substitution_prunes_its_only_dependency_and_recomputes_root`; LAB B substitution and unchanged H provenance/payment. |
| MVP-20 | Library duplicate substitution/pruning test above, `cycles_unknown_dependencies_wrong_target_and_known_roots_fail`; Receipts: `receipt_reads_actual_settlements_and_rejects_truncation_and_reward_mutations`; LAB offline inspection. |
| MVP-21 | State atomic A/H/B/C workflow; Accounting: `arithmetic_failure_keeps_all_balances_unchanged`; Storage: `actual_settlement_anchor_failures_never_expose_partial_proofs_rewards_or_claims` and actual crash-image test. |
| MVP-22 | State: `absence_never_counts_yes_and_expiry_never_means_refutation`, `signed_old_attempt_reveal_never_resolves_new_attempt`, minimum-66 capacity/pending-settlement test. |
| MVP-23 | Process and LAB `fetch-proof-from` use another authenticated peer with node 0 stopped; B actually references H and credits its original recipient. |
| MVP-24 | Library: `older_ancestors_are_checked_but_only_first_boundary_proof_is_cited`, `repeated_boundary_paths_count_once_and_new_helpers_are_not_citations`, pruning test; LAB B payment inspection. |
| MVP-25 | Accounting: `no_citations_preserves_exact_supply`, `division_precedes_shared_recipient_aggregation`, `duplicate_or_unknown_recipients_cannot_gain_payments`; State A/H/B/C account assertions. |
| MVP-26 | Accounting exact distribution/overflow tests; Consensus: `finality_evidence_subset_and_consensus_round_do_not_change_value_or_successor`; LAB total accounts plus reserve equals three billion atoms after three completions. |
| MVP-27 | Receipts tests; Process export/verify; LAB question queries, inspection outputs, network download and independent `check-proof` of A/B/D roots with dependencies. |
| MVP-28 | CLI tests and complete Process/LAB command paths. [Operating guide](operations.md) distinguishes transported, finalized and settled states. |
| MVP-29 | Authentication: `every_wire_byte_is_bound_or_strictly_rejected`, `exact_action_roundtrip_and_roles`; State old-attempt and nonce tests; CLI exact commitment/reveal/agent retry tests; Runtime duplicate receipt test. |
| MVP-30 | Node: `cold_restart_resends_identical_completed_precommit_and_retains_record`, `all_validators_restart_after_prevoting_and_recover_the_durable_proposal`, `asymmetric_nil_quorum_delivery_recovers_after_full_cold_restart`; Storage: `proposal_and_both_votes_replay_for_exact_resend_until_round_changes`; Process/LAB returning-node catch-up. |
| MVP-31 | Storage: `actual_settlement_journal_crash_images_recover_only_old_complete_or_halted_state`, actual anchor-fault test, `signing_anchor_faults_never_publish_and_preparation_faults_never_use_key`; journal scripted I/O faults. These are explicit crash/fault experiments, separate from graceful process restart. |
| MVP-32 | Node: `absent_proposer_advances_by_nil_quorums_then_three_nodes_finalize_and_fourth_catches_up`, `clean_two_two_partition_does_not_consume_round_budget_and_heals`, `asymmetric_nil_quorum_delivery_recovers_after_full_cold_restart`; Process/LAB three live validators, 2:2 partition, restored links and convergence. |
| MVP-33 | State queue/capacity tests, `minimum_run_reserves_all_sixteen_authors_through_delayed_atomic_settlement`, and `multiple_reveals_share_budget_before_any_additional_checker_call`; Library count/byte/step/depth tests; Transport exact bounds/retention; Storage: `exhausted_signing_bytes_or_frames_never_use_key_and_pending_intent_recovers`. |
| MVP-34 | Library `qualification_actual_4096_steps_and_near_64k_certificate`, `qualification_17_used_nodes_near_compact_and_default_package_bounds`, `qualification_64_verified_older_citations_and_65th_reject_before_checker`, `qualification_near_2mib_older_closure_sixteen_authenticated_candidates`; exact queue/depth/frame tests; minimum 65/66-record state tests; LAB resource/timing report. Preserve measured output from both pinned profiles. |
| MVP-35 | Storage observer/full cold replay, `historical_conflicting_finality_is_verified_and_persistently_halts`; journal complete-corruption rejection; Process/LAB independent replay and corrupted export rejection. |
| MVP-36 | Account-admission State `registration_is_zero_starting_nonce_bound_and_idempotent_without_validator_rights`, `full_registry_preserves_existing_research_and_rejects_new_keys_atomically`, `registration_cannot_ride_on_reserved_progress_or_automatic_opening`; Process `new_researcher_registers_proves_receives_reward_and_survives_replay_and_restart`. The current combined run is recorded above; historical v2/v3 runs remain separately identified. |
| MVP-37 | Join-intent format `exact_join_intent_roundtrip_and_context_bound_key_possession`, `all_join_intent_bytes_are_bound_or_rejected`, `possession_roles_and_claim_fields_cannot_be_exchanged`; State `only_earlier_paid_claim_author_can_finalize_an_intent`, `author_can_replace_current_intent_without_gaining_authority`, `another_pending_intent_reserves_its_keys_and_endpoint`; CLI `join_intent_requires_own_claim_and_saves_a_pending_action_for_send`, `join_keys_are_private_role_specific_and_never_overwritten`; Process researcher flow. An intent remains preparatory until the separately tested sealed installation. |
| MVP-38 | Ledger `selected_claim_handoff_replaces_oldest_slot_and_retires_old_keys`, `attempt_opening_at_handoff_freezes_outgoing_owners_for_later_ballots`; Consensus [handoff seal and stable-slot tests](../../crates/naome-consensus/src/state/tests/handoff.rs); Storage READY/TERMINAL fault, period custody and candidate retry tests; Runtime [rotation and recovery](../../crates/naome-runtime/src/state/tests/handoff_lifecycle.rs); Process earned-owner quorum signature, future service payment and restart. Current run evidence is recorded above. |

## Acceptance scenario mapping

| Scenario | Required combined evidence |
|---|---|
| AB-01 | LAB independent startup, zero-balance A author, actual profile/agent invocation, three owner YES votes, real voting window; CLI profile isolation and State full-window tests supplement the run. |
| AB-02 | LAB reverse reveal ordering with distinct checked A roots and earlier winner; separate D attempt with missing earlier reveal and later winner. State tests additionally cover invalid earlier reveal. |
| AB-03 | LAB A is PROVED and publishes the used H/root; State A/H/B/C test checks no separate helper completion/claim. |
| AB-04 | LAB original provider stopped; network H retrieval from a different validator; distinct author B is REFUTED; duplicate H substituted; provenance retained and positive citation payment checked. |
| AB-05 | LAB C ends KnownUnpaid without completion payment; State A/H/B/C verifies unchanged issuance/claim count. |
| AB-06 | Component negative matrix: unapproved/expired attempt and late/old reveal (State); wrong target/invalid original/new duplicate (Library); mutated final effects/receipt (State/Receipts); chain/signature/role mutation (Authentication/Transport); queue/operation/package/work overload (State/Library/Transport). These are not all injected over the LAB network. |
| AB-07 | Actual settlement journal/anchor fault tests, including crash images; Process/LAB one node unavailable, partition, reconnect, catch-up, all-node cold start and independent complete-state replay; exact issuance and claim counts. |
| AB-08 | The current Process researcher flow creates and registers a new account, checks its zero starting balance, completes an approved proof, verifies its reward and earned claim, exports independently replayable history and cold-restarts the participating nodes. Account admission and registry-capacity negatives remain separate component tests. |
| AB-09 | The Process researcher flow records an earned join intent before activation; format, Ledger, Consensus and transport tests reject foreign or absent claims, conflicting nonce, stale or reused keys, endpoint collisions, bad possession proofs and premature authority. A current intent can replace its advertised pair while preserving its claim and queue order. |
| AB-10 | The extended Process researcher flow installs an earned claimant, decodes a later ordinary quorum to verify its selected signature, checks the next service payment, exports independently verifiable history and cold-restarts peers. Consensus and Storage tests cover conflicting seals, old-key rejection, READY/TERMINAL crash boundaries, failed preparation, candidate retry and retired custody. Runtime tests cover no-join rotation, vacant slots and owner-authenticated recovery; Ledger tests preserve frozen ballots. |

## Measurement and reporting boundaries

The qualifier measures real checked certificates and reachable work. Near-byte
limits are reported as the actual byte counts, not rounded up to an exact cap.
The many-candidate qualifier authenticates envelopes and accumulates one shared
verification budget; it does not claim that those candidates were admitted and
finalized together in a maximum-size record. Exact transport-frame tests qualify
bounded envelope parsing and custody, not the validity of arbitrary payload
bytes. The older-depth and queue tests use actual default capacities before
rejecting the next item.

Retain the `MVP34` measurement lines with machine/toolchain/profile information.
Component elapsed time, build time, process elapsed time, disk reservation floor
and observed disk use are different measurements. No throughput guarantee follows
from them. A compact local LAB run does not claim default-limit end-to-end network
throughput or multi-machine performance.

Reports identify the exact source snapshot that was measured. Earlier successful
runs do not qualify later code changes. Local checks, CI, lab execution, and
multi-machine qualification remain separate evidence.
