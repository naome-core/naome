# Trusted research MVP verification map

The state-v1 architecture integration is in progress. The evidence below remains
tied to its recorded commits and does not qualify the new format or establish
that the remaining parallel authority paths have been removed. Fresh complete
workspace, platform CI, and real-window lab evidence are required for integration
acceptance.

This records historical MVP baseline acceptance for the 35 requirements and seven acceptance
scenarios in [requirements.md](requirements.md), within the authorized trusted,
bounded four-process local simulation. Component checks, storage faults, actual
lab execution, complete workspace qualification, and platform CI are separate
evidence. The [lab report](evidence/lab-acceptance.json) records three real-window
attempts in 1,677.630 seconds; the [workspace report](evidence/workspace-qualification.json)
records the complete pinned test and release builds and executions.

Component tests establish specific rule and recovery behavior. The accelerated
process test establishes interaction among four separate executables, stores and
keys. The lab runner adds actual 300/120/120-second windows and a real agent.
Storage fault injection supplies settlement crash-boundary evidence; graceful
process shutdown is not an abrupt settlement crash. Local four-process evidence
does not establish operation on two machines. The seven-day research profile
remains separate later qualification.

The [chain ownership milestone](evidence/chain-ownership.json) passed all platform
CI gates at `73e1156`. The [main executable milestone](evidence/main-executables.json)
records direct validator execution, portable verifier replay, and process-level
crash, conflict and corrupt-start checks. These do not qualify the still-pending
retirement of V0 authority or replace the final real-window lab.
The [canonical devnet milestone](evidence/canonical-devnet.json) replaces the
artifact-chain qualification harness and records delayed state traffic, fault
recovery and independent replay through the main executables. Its evidence and
qualification states are recorded separately. Its 100-record Docker CI and
102-record native run passed; the same overall CI run failed a retired V0
supervisor process test and is not recorded as green.
The [executable retirement milestone](evidence/executable-retirement.json) removes
the V0 validator/verifier implementations and records canonical custody, bounded
control/output, signal, and portable replay replacements. Both local process
profiles and a fresh delayed native devnet smoke passed. All platform, quality,
and devnet gates passed in [CI run 35458531522](https://github.com/naome-core/naome/actions/runs/35458531522)
at `a1d03c9`. Remaining V0 library APIs and the final real-window lab are still open.

The [proof-library integration milestone](evidence/library-integration.json) puts
the checked artifact DAG inside atomic proof publication and replaces the V0
journal authoring adapter with the sealed finalized full-history interface.
All mathematical fixture identities and state replay vectors are retained.
Both complete local workspace profiles passed 1,572 tests, and a fresh delayed
12-record native devnet passed. Its first CI run found Windows authoring snapshot reads of an actively locked
lockfile; the following transport milestone corrects that test portability issue.
Remaining V0 library retirement and the final real-window lab are still open.

The [sole transport milestone](evidence/transport-retirement.json) removes the
V0 runtime, wire messages, acquisition, store serving, and disabled exchanges.
The canonical frame and state rules are unchanged. Shared authentication,
connection/stream limits, exact correlation, and custody remain covered by
canonical tests; fresh local and CI evidence is recorded separately.

The [canonical authority milestone](evidence/authority-retirement.json) removes
V0 artifact blocks, separate consensus branches and journals, candidate/payload
stores, and the old node coordinator. Canonical state rules, replay, crash-fault,
process and transport coverage remain. A new canonical safety model uses the
actual timeout/catch-up rules and replays its witnesses through anchored honest
signers and cold restart; separate tests check every four-unit quorum subset and
shared full-width weight arithmetic. Cross-process tests cover history/signer
owners and their independent anchors. The ledger retains the proof/set malformed
decoder campaign. Neutral API/on-disk naming and final real-window qualification
remain outstanding; this milestone does not establish public-network security.

## Recorded qualification

| Evidence | Source and result |
|---|---|
| Real lab windows | [Public report](evidence/lab-acceptance.json): passed in 1,677.630 seconds with four distinct local validators, actual Codex review, three 300/120/120-second attempts, reversed reveals, missing earlier reveal, authenticated helper retrieval with its original provider offline, positive citation payment, known-unpaid question, 2:2 partition, all-node cold restart, full offline replay, proof checks, and corrupt-export rejection. |
| Exact lab source and binary | Clean commit `25238b8bec56baf12070ee87945268e5752837bf`, release binary SHA-256 `b225465d6a26d1ba5709f1a71d209d6c313fc7530e0fc82b4bb82ca34b9c47ae`. The report records the 551-file source-manifest hash, runner hash, provider hash, and exact configuration. Research CLI, library, consensus, storage, network, and runtime production source is unchanged through `e2cb26b9fc78e3e6c13dbdb7ce1b9242a2e7dd59`; later production changes concern the separate V0 validator supervisor. |
| Independent lab replay | The recorded `25238b8` release executable replayed the completed archive offline, matched every final-state field, checked downloaded proofs, and rejected a corrupted export. |
| Complete local workspace | [Qualification report](evidence/workspace-qualification.json): Rust 1.97.1; separate full build barriers followed by all-target, all-feature, locked workspace executions, with 1,729 tests passed in each of the test and release profiles. The report records exact commands and output hashes. |
| Documentation and quality | [Qualification report](evidence/workspace-qualification.json): 23 doctests passed; formatting, Clippy, and documentation checks passed. These checks are recorded separately from process and lab evidence. |
| Implementation platform CI | [Run 35047169827](https://github.com/naome-core/naome/actions/runs/35047169827) on `e2cb26b9fc78e3e6c13dbdb7ce1b9242a2e7dd59`: all six Linux x86_64, macOS ARM64, and Windows x86_64 test/release jobs passed, together with quality, devnet, and required aggregate gates. |
| Accelerated processes | On `25238b8`, the four-process scenario passed in test (102.15 seconds) and release (99.76 seconds); both complete final-source workspace profiles also include this scenario. Every intended vote, commitment, and reveal requires a finalized receipt. |
| Actual mathematical workloads | [Test measurements](evidence/qualification-test.json) and [release measurements](evidence/qualification-release.json): six measurements, four qualification tests, and 77 research tests per profile, tied to `c0bfaf2`, exact commands and output hashes. Mathematical and research-state production code is unchanged since that measured snapshot. |
| Existing network qualification | [100-height local devnet report](evidence/devnet-local-100.json): 50 ms delay in each direction, outage/healing, process restarts, malformed offers, and independent replay. This report preserves its earlier source snapshot and binary hashes; the implementation CI above separately qualifies devnet on `e2cb26b`. |

The lab issued exactly 3,000,000,000 atoms across account balances and reserve,
recorded three passive eligibility claims, and reached the same complete state
commitment on all four validators and the independent observer. It did not
activate voting rights. Raw histories, archives, keys, commitment secrets and
provider diagnostics remain private. The public report includes the intentionally
published fixture profile and the actual agent decision and reason.

Independent subagents reviewed mathematical normalization and attribution,
protocol/state behavior, durable custody/replay, runtime integration, and the
acceptance map. Material findings were fixed: bounded future-evidence retention,
authentication before historical replay, bounded proof-fetch result retention,
durable exact retries and agent budgets, explicit lock release, retransmission
of preceding-round votes after asymmetric quorum delivery, capped growth of
research consensus retry timeouts, retention of fetched V0 finality during
publication backpressure, and preservation of the supervisor's selected sync
peer while local custody is busy. These bounded recovery changes received
independent source review and focused regression coverage, followed by complete
workspace and platform qualification. The fresh lab exercises the research retry
changes; the separate V0 supervisor correction is covered by its process and CI
qualification.

Regression tests and actual process runs validate their recorded snapshots within
the trusted, bounded profile. Finite consensus-round and journal limits remain;
this evidence does not establish recovery from arbitrary delay schedules or
permissionless-network security.

## Executable evidence locations

| Label | Source and scope |
|---|---|
| Profile | [Profile/genesis tests](../../crates/naome-ledger/src/profile/tests.rs) |
| Questions | [Question compilation tests](../../crates/naome-ledger/src/question/tests.rs) |
| State | [Research state transitions](../../crates/naome-chain/src/state/tests.rs), [wire/replay vectors](../../crates/naome-chain/src/state/tests/golden.rs), [default queue boundary](../../crates/naome-chain/src/state/tests/queue_boundary.rs), [all-sixteen-author reservation](../../crates/naome-chain/src/state/tests/capacity_sixteen.rs) |
| Library | [Mathematical normalization/reuse tests](../../crates/naome-ledger/src/library/tests.rs), [workload qualification](../../crates/naome-ledger/src/library/tests/qualification.rs), [older-depth boundary](../../crates/naome-ledger/src/library/tests/depth_boundary.rs) |
| Accounting | [Exact monetary distribution](../../crates/naome-ledger/src/accounting/tests.rs) |
| Receipts | [Settlement inspection and canonical receipt tests](../../crates/naome-chain/src/state/receipt_tests.rs) |
| Authentication/time | [Action authentication](../../crates/naome-ledger/src/authentication/tests.rs), [signed time](../../crates/naome-ledger/src/time/tests.rs) |
| Consensus/node | [Consensus kernel](../../crates/naome-consensus/src/state/tests.rs), [node recovery](../../crates/naome-node/src/state/tests.rs) |
| Storage | [Research history/signer/settlement recovery](../../crates/naome-storage/src/state/tests.rs), [journal I/O faults](../../crates/naome-storage/src/state/log_tests.rs) |
| Transport/runtime | [Network exchange](../../crates/naome-network/src/transport/state_exchange/tests.rs), [exact frame limits](../../crates/naome-network/src/transport/state_exchange/tests/boundary.rs), [peer isolation and lifecycle](../../crates/naome-network/src/transport/state_exchange/tests/lifecycle.rs), [wire protocol](../../crates/naome-protocol/src/state_exchange/tests.rs), [runtime intake](../../crates/naome-runtime/src/state/tests.rs) |
| CLI | [Agent](../../crates/naome-cli/src/app/agent/tests.rs), [durable actions](../../crates/naome-cli/src/app/actions/tests.rs), [private files](../../crates/naome-cli/src/app/files/tests.rs), [setup/local profile](../../crates/naome-cli/src/app/setup/tests.rs) |
| Process | [four_process_research_recovery_partition_and_independent_replay](../../crates/naome-cli/tests/research_process.rs): accelerated independent processes |
| LAB | [research_lab_acceptance.py](../../tools/research_lab_acceptance.py): real windows, actual provider, separate four-process state; report required |

## Requirement mapping

Names below identify concrete test functions within those sources. LAB references
identify runner actions and fields in the recorded acceptance report.

| Requirement | Executable evidence and scope |
|---|---|
| MVP-01 | Profile: `genesis_identity_binds_all_configuration_and_keys`, `rejects_duplicate_keys_roles_and_owners`, strict codec tests. Network: `research_noise_peer_with_wrong_genesis_never_delivers_application_payload`. LAB: `independent_process_custody` and immutable profile. |
| MVP-02 | Process test and LAB start four executables with separate configured histories, anchors, signer stores and keys. LAB records custody and agreement. |
| MVP-03 | State: `complete_a_h_b_c_workflow_preserves_attribution_citation_and_once_only_issuance`; Consensus: `verified_control_record_finality_binds_full_state_and_preserves_empty_library`; LAB compares complete state/accounts/claims/library. |
| MVP-04 | Consensus control-record test above; Storage: `complete_control_history_reopens_and_observer_uses_same_full_state`; Process finalizes an unapproved question without a proof. |
| MVP-05 | State: `complete_v1_wire_and_identifier_vectors`, `streaming_state_commitment_matches_materialized_canonical_bytes`; Profile and Protocol golden vectors; Process/LAB observer agreement. Target-platform agreement also requires completed CI. |
| MVP-06 | Questions: `rejects_free_variables_assumptions_imports_and_bad_syntax`, `profile_smaller_bounds_are_enforced_for_both_targets`, canonical/orientation tests. Receipts: `rendered_closed_targets_round_trip_without_changing_canonical_formula`. CLI `compile-question` and submission preview are exercised through operating procedures/LAB submission. |
| MVP-07 | State: `actual_queue_limit_and_exact_expiry_preserve_state_on_rejection`, `default_queue_accepts_32_in_finalized_order_and_rejects_33_without_mutation`; Runtime: `queue_receipt_is_not_finality_and_duplicate_identity_is_idempotent`. |
| MVP-08 | State A/H/B/C workflow; Library: `real_a_group_then_b_refutation_preserves_h_attribution_and_known_c`; LAB `helper_normalization_citation_known`. |
| MVP-09 | State: `complete_real_proof_settlement_and_replay_are_atomic`, `minimum_66_record_run_protects_active_slots_and_settles_timely_reveal_after_pause`; Library: `stale_library_parent_prevents_whole_publication_without_mutation`. |
| MVP-10 | CLI: `changing_local_agenda_profile_cannot_change_genesis_or_reinitialize_history`; LAB `actual_agent_review` with provider hash and actual question. Fake-provider tests do not supply the actual-agent evidence. |
| MVP-11 | CLI: `fake_provider_accepts_only_bounded_complete_decisions`, `changed_or_expired_voting_context_never_creates_a_signed_action`, timeout/process cleanup and durable budget tests. State vote/nonce tests prevent replacement of finalized votes. Manual fallback is an operator CLI path. |
| MVP-12 | State helper `open_and_approve` asserts three early YES votes leave phase Voting; `absence_never_counts_yes_and_expiry_never_means_refutation` rejects two YES. Consensus: `two_votes_never_finalize_and_duplicate_signers_never_add_weight`. LAB phase/deadline observations. |
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

The linked reports identify the pinned workspace builds and executions, required
Linux/macOS/Windows CI, accelerated process evidence, actual LAB report, actual-agent
provenance, and fault-injection evidence separately. The implementation CI link
identifies the tested source. The final handoff records the exact documentation commit and its successful
run of the same CI workflow.
