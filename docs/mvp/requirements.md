# NAOME trusted MVP: requirements, rules, and acceptance

The trusted MVP baseline adopts rules R1–R11 and their parameters. Acceptance
uses four independent local validator processes with separate keys and durable
stores, including simulated partitions and failures. A real two-machine run
remains later qualification. The accompanying [English whitepaper](whitepaper-en.pdf),
revised 23 September 2026, distinguishes the implemented trusted MVP from the
broader public-network proposal. The [pilot runbook](pilot.md) defines the next
separate-machine qualification and its evidence requirements.

**Goal:** Four stable validator slots jointly operate a small research network with openly registered researchers and claim-backed handoff between trusted operators. Researchers supply formal questions and proof material; validators select tasks, check proofs or refutations, publish reusable results, and record the same rewards on every machine. They use the command line to operate the system.

This is the implementation and acceptance contract: 38 requirements, ten
acceptance scenarios, five implementation stages, and rules R1–R11. The first
35 requirements and seven scenarios were accepted for the historical `state-v1`
trusted, bounded local simulation. The current `state-v5` authority-period model
replaces the earlier prerelease models and requires its own acceptance.
[Verification evidence](verification.md) separates component
checks, storage faults, process and lab execution, and cross-platform CI, with
the source snapshot for each result.

The canonical state path finalizes complete records binding phases, proof groups,
rewards, earned eligibility claims, and sealed validator handoffs. [Component ownership](../../specs/ownership.md)
indexes the mathematical libraries, authoring, consensus, authenticated period
network, storage, runtime, executables, and qualification tooling.

Navigation: [Checklist](#checklist) · [Acceptance scenarios](#acceptance) · [Implementation stages](#implementation) · [Rules and parameters](#rules) · [Research status and remaining work](#r11).

## 1. Scope and Limits

The trusted participant group, “Survival of the first,” and command-line interface use the following MVP rules. These rules do not adopt a public-network protocol. Their precise meaning is defined in [rules R1–R11](#rules); the acceptance cases make their effects testable.

| Area | Scope |
|---|---|
| Validators | Four stable, equally weighted slots; three votes form a quorum. Sealed handoff changes slot owners and rotates both period keys. An unavailable slot remains in the denominator. |
| Users | Research accounts supplied in genesis or admitted by signed self-registration; no starting balance is required. A paid author may record one claim-backed validator join intent, which grants no authority. |
| Research operation | One active question throughout its attempt until settlement; other questions wait. Multiple authors may work on the active question simultaneously. Current authority-period acceptance uses explicit accelerated profiles; separate signed-time tests cover all Lab and research phase boundaries. Actual full-window runs are recorded separately. |
| Results | An actual proof **or** an actual refutation of the approved target. An unsuccessful attempt remains unresolved. |
| Proof groups | One root and a bounded set of helper proofs that are actually used; reuse of older proofs with their original attribution. |
| Authorship | One author for all new proofs in a package; that author is also their payment recipient. |
| Rewards | One Test-NAO per first research completion, a positive citation pool when eligible citations exist, and exact whole atoms. |
| Membership | A finalized paid claim and authenticated intent enter bounded ordered admission. Only a sealed transition consumes the claim and activates its owner. |
| Operation | Independent processes and data stores on macOS/Linux; two configured endpoints per owner, fresh period identities, operator-supplied recovery endpoints, shared genesis, restart, and authenticated catch-up. |
| Interface | A CLI with readable messages and machine-readable output; no graphical interface is required. |

Initial acceptance does not include identity-flooding resistance, automatic endpoint discovery, market value or redemption of the test currency, transfers, reserve spending, joint authorship, recipient delegation, standalone publication of definitions, live protocol upgrades, general mathematical equivalence detection, or an autonomous solver for arbitrary research questions. Agent-assisted **selection** of questions is part of the MVP. Existing notation expansion and mathematical checking capabilities are reused.

<a id="checklist"></a>

## 2. Startup and Shared State

- [x] **MVP-01 – Reproducible startup.** A shared genesis describes the four validators, accounts, peer mappings, Foundation, protocol version, parameters, and initially empty research library. Different genesis configurations or parameters are detected when establishing connections or starting the protocol. Private keys are not included in the shared genesis.
- [x] **MVP-02 – Independent validator operation.** Four independent validator processes run with separate keys and data directories under the user-authorized local network simulation. A single-process state-machine simulation or four views of the same database do not satisfy acceptance. Execution on at least two actual machines is separately deferred qualification.
- [x] **MVP-03 – Complete consensus state.** Finality binds questions, votes, phases, commitments, reveals, proofs, authors, completions, eligibility claims, balances, and the reserve. Additional local status alongside an unchanged artifact chain is insufficient.
- [x] **MVP-04 – Records without proofs.** Votes, phase transitions, and other control operations can be finalized even when no new research result is available.
- [x] **MVP-05 – Determinism.** The same genesis and finalized history produce identical identifiers and the same complete state commitment on all target systems. The local clock, AI output, and order of arrival do not change any decision during replay.

## 3. Questions, Research Profiles, and Voting

- [x] **MVP-06 – Submit a question.** A registered user can submit a purpose and a `.nao` proof obligation. Before voting, the compiler displays both exact targets and the question and family identifiers. Free variables, unknown assumptions, disallowed references, and exceeded limits are rejected with understandable explanations.
- [x] **MVP-07 – Bounded queue.** Finalized receipts determine queue order. Each family has at most one waiting or active attempt. Admission, rejection due to overload, and subsequent opening are distinct visible states.
- [x] **MVP-08 – Known answers.** At the actual opening, both exact targets are checked. An already published, unpaid helper proof results in `KNOWN_UNPAID`; a paid completion remains `COMPLETED`. Neither case creates a new reward or eligibility claim.
- [x] **MVP-09 – One active attempt.** The proof library remains unchanged during voting, solution work, and pending settlement. No alternative path may select proofs, definitions, or imported states. The next attempt begins in a later record, only after a finalized closure.
- [x] **MVP-10 – Research profile and actual agent review.** Each operator can edit their local research profile. A bounded agent invocation assesses at least one actual question against that profile and returns a structured agenda assessment. A configured policy can produce YES/NO or retain an uncertain assessment without voting; a prose reason is optional. An adapter authorized by the operator signs a decisive result; secrets remain local. Simulated responses are only testing tools.
- [x] **MVP-11 – Agent review failure.** Missing, invalid, or late output produces no vote. The operator may vote manually before the deadline; an already finalized vote is not overwritten. AI text affects neither proof validity nor deterministic replay.
- [x] **MVP-12 – Full voting window.** All four votes in the attempt's frozen electorate remain in the denominator through handoffs; three YES votes approve, two do not. The first valid vote from each frozen owner counts. The window closes only once its deadline has been reached, even if a quorum is reached early.
- [x] **MVP-13 – Shared time.** Signed time reports, monotonic record time, and separate phases determine deadlines. Operations exactly at a deadline are late. Without finality, no local timer changes canonical status.

## 4. Solutions, Priority, and Proof Admission

- [x] **MVP-14 – Durable commitment.** Before sending, the CLI stores the signed original, secret, and commitment. The finalized receipt reserves the later reveal. Restarting and resending do not create a second claim.
- [x] **MVP-15 – Protected reveal.** A reveal is permitted only after finalized closure of the commitment phase. Chain, attempt, author, original hash, and deadline must match. All necessary bytes are available on the confirming validators and can be durably recovered.
- [x] **MVP-16 – “Survival of the first.”** Among valid, timely reveals, the earliest eligible commitment receipt wins. Earlier arrival on the network or faster checking does not establish priority. A missing or invalid earlier reveal does not block a valid later candidate.
- [x] **MVP-17 – Actual mathematical checking.** The existing checker verifies the original and the normalized final form, including required dependencies. The conclusion matches exactly one approved target. A counterexample without a certificate, an AI judgment, or a proof only of “Q or not Q” is insufficient.
- [x] **MVP-18 – Unambiguous helper proofs.** Different new certificates for the same exact statement within one package are rejected, as is a root/helper-proof collision. Only byte-identical nodes with identical attribution may be merged.
- [x] **MVP-19 – Reuse.** A matching older proof replaces a duplicate helper proof according to the specified earliest eligible admission. Its author and recipient attribution is preserved. A shorter reconstruction does not displace it.
- [x] **MVP-20 – Pruning and receipt.** Helper proofs and citations that are no longer used are removed. The final graph remains acyclic and fully valid. A reproducible normalization receipt connects the signed original to the final identifiers and the specific parent state.
- [x] **MVP-21 – Once-only atomic completion.** All new proofs, the PROVED/REFUTED outcome, the family completion, exactly one passive eligibility claim, and all monetary entries are finalized together. If an error occurs, no part is published or paid.
- [x] **MVP-22 – Expiry and retry.** Without a timely valid reveal, the result is `UNRESOLVED`, with no payment or helper-proof publication. A new attempt requires new approval and new identifiers. Timely valid reveals remain protected until their pending settlement.

## 5. Citations, Test Balances, and Library Access

- [x] **MVP-23 – Actual later citation.** A subsequent, different research completion retrieves a previously published proof from the network and demonstrably uses it. The original recipient receives a positive citation payment.
- [x] **MVP-24 – Correct citation boundary.** Count the distinct first older proofs along the paths actually used from the normalized root. Repeated paths count once; new proofs in the same record, removed citations, and ancestors beyond this boundary receive no share.
- [x] **MVP-25 – Exact distribution.** When citations exist, 0.60 Test-NAO is credited to the solution author and a total of 0.10 to the eligible proofs; without citations, the author receives 0.70. Another 0.20 is divided equally among the four outgoing slot owners at settlement, including unavailable slots, and 0.10 goes to the reserve. Remaining atoms follow [R7](#r7).
- [x] **MVP-26 – Supply conservation.** With zero starting balances, after N paid completions: the sum of all balances, including the reserve, equals N × 1,000,000,000 atoms. No floating-point arithmetic, overflow, duplicate entries, or distributions that depend on which validators signed.
- [x] **MVP-27 – Usable library.** Users can look up and export the question, outcome, original, normalized proof group, actual conclusion, author, citations, reward, and eligibility claim. A local checking command independently verifies downloaded certificates; displaying hashes alone does not count as proof checking.

## 6. Operation, Restart, and Failure Behavior

- [x] **MVP-28 – Reliable CLI.** Setup, startup, shutdown, profile editing, submission, voting, commitment, reveal, status queries, catch-up, export, and checking work without manual database changes. Messages distinguish transported, finalized, mathematically valid, and settled. Command syntax will be specified during implementation.
- [x] **MVP-29 – Authentication and replay protection.** Actions are bound to genesis, version, role, author, and nonce or attempt, as applicable. Actions claiming another author, other chains, modified packages, and old attempts are rejected. Resending exactly the same action returns the same receipt without applying its effect again.
- [x] **MVP-30 – Restart and catch-up.** After a process crash, stored signed messages are resent without producing conflicting new signatures. A returning validator downloads and verifies the complete research history and reaches the same state.
- [x] **MVP-31 – Storage failures.** Interruptions before and after journal/anchor steps result in the old state, the complete new state, or an explicitly halted recovery case. Partial proof groups, lost acknowledged reveals, and duplicate rewards are not permitted.
- [x] **MVP-32 – Outages and partitions.** Progress is demonstrated with three reachable validators. During a 2:2 partition, neither half finalizes new completions. After reconnection, all four converge. A machine failure affecting two processes is accordingly treated as quorum loss.
- [x] **MVP-33 – Hard work limits.** The queue, commitments, package sizes, formula work, helper proofs, reference paths, and transport buffers have deterministic limits. Overload results in rejection with an explanation. Already reserved reveals retain their capacity. The finite run limit stops new attempts in time; its record reservation protects already active attempts through settlement.
- [x] **MVP-34 – Qualify the limits.** The proposed starting values are measured against the actual example proofs, target machines, and delays. Minimum and maximum cases and exhausted capacity are part of acceptance. This plan claims no throughput or storage performance has already been measured.
- [x] **MVP-35 – Complete verification.** An observer without signing keys replays the finalized history and compares all research and monetary state, not only artifacts. Corrupt complete data or conflicting verified finality produces a visible halt.
- [x] **MVP-36 – Bounded research self-registration.** A new researcher can create a key, sign `Register` with nonce 1 and zero starting balance, then submit with nonce 2, publish a checked result, and receive its reward. Registration grants no validator authority. Exact retries retain the original receipt; reused validator keys, over-cap registrations, and registrations consuming protected attempt capacity are rejected without changing state. All four validators, a cold restart, and independent replay agree on the account registry. Current v5 accelerated process and CI acceptance is recorded in [verification](verification.md); a new full real-agent Lab run remains separate.
- [x] **MVP-37 – Claim-backed join intent.** After a paid completion is sealed, its signing author can finalize a current intent bound to that exact family and completion ordinal, fresh candidate consensus and transport keys with separate possession proofs, and a canonical endpoint. The intent and receipt survive replay and restart. A foreign author, absent claim, conflicting same-nonce intent, reused role key, bad proof, wrong genesis, or conflicting nonce changes no state. This preparation grants no validator, time-reporting, transport, proposer, reward-share, or voting authority and does not consume the claim. A later sealed transition performs admission and activation.

- [x] **MVP-38 – Sealed validator handoff.** An eligible claimant replaces the oldest selected unit through the agreed record, incoming READY and outgoing TERMINAL quorums. All four stable slots, frozen research ballots, service rewards, proposer priorities, transport identities, signer custody, restart and independent replay follow the same selected history. Old keys lose authority, missing offers retain the denominator, and failed preparation cannot activate a successor. Qualification is recorded separately from implementation.

The [authority-period contract](../../specs/authority-periods.md) specifies the current canonical implementation.

<a id="acceptance"></a>

## 7. Required Acceptance Scenarios for the Proposed Scope

- [x] **AB-01 – Startup and actual selection.** Four separate validators start; a research participant with no initial balance submits question A. At least one actual profile/agent invocation is executed with traceable evidence. Three valid YES votes result in approval only when the window ends.
- [x] **AB-02 – Competition.** Two authors commit different valid solutions. The author with the later commitment reveals first; the earlier author wins if their reveal is also valid and timely. In a separate run, the later author wins when the earlier reveal is missing or invalid.
- [x] **AB-03 – Proof group.** A is completed as PROVED; at least one new helper proof H that is actually used is published together with the root. H receives no separate initial reward or eligibility claim.
- [x] **AB-04 – Reuse and refutation.** A research account different from the account of H's author resolves a different question B as REFUTED. Its actually checked refutation certificate uses H. A submitted duplicate of H is replaced with the stored version. H is retrieved from another node while its original provider is unreachable and a quorum of three remains available. H's original author receives the positive citation payment.
- [x] **AB-05 – No retroactive reward.** A waiting question C, whose exact target H already answers, ends as `KNOWN_UNPAID` at opening. No new NAO or eligibility claim is created.
- [x] **AB-06 – Negative paths.** An unapproved question, wrong target, invalid original, invalid final form, late reveal, duplicate package, other chain, old attempt, disallowed new duplicates, invalid signature, and overload are handled according to the rules. An unsuccessful attempt is never presented as a refutation.
- [x] **AB-07 – Interruption and independent verification.** A crash around settlement, one failed instance, a 2:2 partition, recovery of connectivity, and a complete cold start are checked. All four state commitments and the independent verification agree; N paid families have exactly N issuances and N passive eligibility claims.
- [x] **AB-08 – New researcher admission.** In four independent local validator processes, a researcher absent from genesis creates a key, registers without a balance, submits a question, publishes a checked solution, receives the author reward, and remains in identical replayed state after all validators cold-restart. Component cases reject unregistered actions, validator-role keys, exhausted registry capacity, and registration that would consume protected attempt capacity. Current v5 accelerated process and CI acceptance is recorded in [verification](verification.md); a new full real-agent Lab run remains separate.
- [x] **AB-09 – Earned join intent without authority.** A registered researcher earns a checked paid completion and later finalizes its join intent in a separate record. Four validators and an independent archive replay agree on the intent, receipt, claim, and unchanged four-owner authority. Tests reject a foreign or absent claim, a conflicting same-nonce intent, key/endpoint collisions, invalid possession proofs, wrong genesis and nonce, and any candidate attempt to vote or sign consensus or time reports. A later signed revision replaces the current keys and endpoint without changing the claim or four-owner authority.

The mathematical example certificates must be verified with the actual checker before the integration test. That H can actually be used for B's refutation target is a requirement for the fixtures; the abstract rule model does not establish it. The original state-v1 acceptance used the Lab profile. Current authority-period acceptance uses the explicitly selected accelerated process and CI profiles, with separate signed-time boundary tests for the complete Lab and research windows. A new full real-agent Lab run and a complete seven-day research run remain separate qualifications.

<a id="implementation"></a>

- [x] **AB-10 – Earned validator installation and retirement.** A paid author finalizes an intent, prepares a candidate process, is installed in the oldest stable slot, signs a later ordinary record with its selected keys, and receives the corresponding future service share. Verify no-join rotation, an unavailable slot, frozen ongoing ballots, preparation conflicts, old-key rejection, fault-injected preparation, READY, TERMINAL, sealing, retirement and activation/restart boundaries, catch-up, and four independent replays.

## 8. Order of Subsequent Implementation

| Stage | Coherent work package | Complete when… |
|---|---|---|
| 1 | Profile, formats, and actual example proofs | The [rule draft](#rules) has executable encoding vectors and actual certificates for AB-03/04; all limits are specified in machine-readable form. |
| 2 | Research state and atomic local transitions | Questions, phases, priority, normalization, and monetary entries satisfy the local positive and negative acceptance cases. |
| 3 | Consensus, durable storage, and catch-up | Actual validators jointly finalize the complete state, which is independently replayed; control-only records work. |
| 4 | CLI, signed intake, and agent integration | Genesis and newly registered users can complete the entire workflow without manual data changes. |
| 5 | Acceptance in the authorized local network simulation and operating instructions | AB-01 through AB-10 and the appropriate repository checks pass with traceable evidence; real multi-machine qualification is listed separately as deferred. |

The existing mathematical core libraries, transport components, and operational components are reused. Proposal/finality formats, research state, and their replay require substantial extensions. Existing fee arithmetic and selection of the candidate with the lowest ID must not be adopted as the new reward or priority rule without checking them. This code review belongs to the preparatory research status described below.

A subsequent implementation uses Rust `1.97.1` and the repository checks with separate build and test phases in `test` and `release`. CI, local tests, and actual runs across multiple machines are reported separately. For running validator processes, the MVP follows the existing Unix operation paths; a successful Windows build is not evidence of Windows runtime operation. This checklist does not authorize an automatic chain of pull requests.

<a id="rules"></a>

## 9. Draft rules and concrete parameters

The following rules make the preceding requirements concrete for the proposed MVP profile. The distinction between user decisions and R&D recommendations in section 1 applies to every rule. These simplifications claim neither fair public admission, secure distribution of authority, nor economically optimal rewards.

<a id="r1"></a>

### R1. A separate, immutable test configuration

The current protocol is `state-v5`, with one supported prerelease implementation and data model. Incompatible earlier development genesis and state formats are rejected; fresh development genesis and fixtures replace them. Four stable slots retain an equal denominator of four. Both consensus and research approval require three votes, including when a slot is unavailable.

Genesis fixes the Foundation, checker, bootstrap owners and period keys, explicit bootstrap retirement order, initial research accounts, endpoints, timing, limits and reward rules. A finalized record contains a parent-bound handoff plan and commits its successor authority. Three outgoing consensus votes agree that record; three incoming READY signatures and three outgoing TERMINAL signatures seal it before selected history or ordinary incoming signing advances. The oldest eligible queued claimant replaces at most one oldest unit. If that claimant has no exact-parent offer, the same owners rotate keys and preserve its queue position and expiry. Missing incumbent offers leave vacant slots. Proposer arithmetic uses stable slot identifiers across rotations.

Research attempts freeze their four-owner electorate when opened. Current period authorities sign consensus and time reports; the outgoing service snapshot receives a completion's validator allocation. Registration and an intent alone grant neither ordinary consensus signing nor research votes. Candidate transport has bounded handoff/history access while awaiting selection. Account keys stay separate from the fresh consensus and transport keys, which rotate at each finalized height. Genesis and its parameters remain immutable during the finite run.

A new test genesis starts a new test run with its own identifier. It is explicitly displayed as such; it does not repair or overwrite any earlier history. Existing histories and key states remain traceable. Normal restarts use the same genesis and the same durable state.

<a id="r2"></a>

### R2. One active question protects approved obligations

A bounded FIFO queue orders questions by their finalized receipt `(height, operation index)`. Each family has at most one queued or active attempt. Rejection before finalized admission grants no queue position. The queue deadline is the certified time of the admission record plus the queue duration fixed in the profile. When the record time is greater than or equal to this deadline, the entry expires before any possible opening. Redelivery extends nothing; after expiry, resubmission requires a new action and receives a new position.

Globally, exactly one attempt is active, from the opening of its voting window until finalized completion or final unresolved expiry. This includes pending settlement after a timely reveal. Only settlement of this attempt publishes new proofs. Standalone proof/definition admission, library imports, and other publication paths are excluded. Control records may continue during this time.

The next question opens only if the **parent state** already contains no active attempt and the full attempt reservation is available. The supervisor initiates this system operation automatically; the proposer cannot choose an arbitrary later question. The at most 32 entries are checked in receipt order: expired and known questions receive their status, and at most the first remaining eligible question opens. Its formal targets are checked again against the selected library. If a valid selected proof of either exact target exists, a paid opening is not permitted:

- Already paid families remain `COMPLETED`.
- A known target proof that has not received a separate completion payment produces `KNOWN_UNPAID`, without retrospective payment or an eligibility claim. The actual stored proof provenance is displayed.

Both states prevent a later paid reopening of that family. The check concerns the exact normalized targets; it does not claim to recognize every logically equivalent statement. A helper proof may still earn citation rewards through use in a **different** new completion.

At opening, the entire library selected at that time is fixed as the permitted reference context. Its set of proofs remains unchanged throughout the attempt. No other publication can therefore retrospectively make an already approved task “already known.” This serialization reduces throughput, but removes the otherwise unresolved MVP conflict between an unpaid helper proof, a later question, and an already protected opportunity to earn a reward.

<a id="r3"></a>

### R3. Targets and identities remain separate

The existing Foundation compiler expands permitted notation and normalizes variables. A question contains a closed formula Q; after expansion, only leading negations are removed. The remaining core R and the parity of the negations determine the exact targets R and ¬R and their presentation as PROVED or REFUTED. Expiry never means REFUTED.

`StatementId`, `ProofId`, `DerivationId`, and typed `ArtifactId` retain their existing mathematical meaning. `ResolutionId` binds the Foundation and canonical core R. Opposite formulations and leading double negations do not open a second paid family completion. Titles, recipients, or software labels do not reset the family's history.

A submitted proposal binds its purpose, formal source, and author identifier. At actual opening, `QuestionId` additionally binds both exact targets, orientation, Foundation/checker, library root, and all applicable limits/policies. A family's attempt number increases with each actual new opening. An arbitrary user-chosen number cannot create a new attempt.

The previously undefined commitment “round” is replaced in this MVP by `SolutionRoundId`:

`H(role-specific domain, GenesisId, QuestionId, attempt number, ApprovalRecordId)`.

This identifies the solution round of a specific approval. The identifier is created and installed only at the later COMMIT start, using the identifier of the approval record that has already been finalized by then. The approval record therefore does not need to hash its own identifier as part of its state. Consensus round, height, and restart are different concepts. Protocol-change cycles remain outside this finite profile; authority periods and their keys change only through the sealed handoff path.

<a id="r4"></a>

### R4. Complete phases with unambiguous deadline boundaries

Every record contains time reports from at least three distinct selected period validators. The reports sign genesis, parent identifier, height, TIME role, and integer UTC seconds with keys from the exact outgoing snapshot. Record time is the maximum of parent time and the lower median of the included reports. With four reports, this is the second value in ascending order; with three, it is also the second. Certificates are canonically ordered by validator identifier; an incorrect context or duplicate signers makes them invalid. Operators keep their clocks synchronized; the error bound below is an operating assumption, not cryptographic proof of the time.

Due closures are evaluated before user operations. Votes, commitments, and reveals may belong only to the still-open phase of the parent state. Queuing additional questions is independent of phase and remains possible within available capacity. A phase-bound operation therefore cannot use its own approval or the start of its reveal phase at the same height. Every start/closure decision must be finalized before the next record builds on it.

| Parent phase | Deterministic outcome |
|---|---|
| No active attempt | If sufficient completion capacity is available, the next record processes the FIFO queue under R2 and opens the first remaining eligible question; `VOTING`, deadline = record time + voting window. If opening capacity is exhausted, the mandatory run termination in R10 applies instead. |
| `VOTING`, time < deadline | Admit the first valid YES/NO vote from each owner. An early quorum does not close the window. |
| `VOTING`, time ≥ deadline | Three or four YES → `APPROVED_WAIT`; otherwise `NOT_APPROVED` and release of the active slot. No vote at this height counts retroactively. |
| `APPROVED_WAIT` | The next record starts `COMMIT`; its time + commitment duration defines the new deadline. Commitments are allowed only in later records. |
| `COMMIT`, time < deadline | At most one commitment per research account; ordered by finalized receipt. |
| `COMMIT`, time ≥ deadline | `COMMIT_CLOSED_WAIT`; the commitment list is closed. |
| `COMMIT_CLOSED_WAIT` | The next record starts `REVEAL`; its time + reveal duration defines the new deadline. Reveals are allowed only in later records. |
| `REVEAL`, time < deadline | Admit complete, matching, valid reveals. |
| `REVEAL`, time ≥ deadline | `SETTLEMENT_PENDING`; no further reveals and no release of the active slot. |
| `SETTLEMENT_PENDING` | The next valid record settles the first eligible winner or produces `UNRESOLVED` if there is no valid reveal. Only then is the slot free. |

A reveal is timely only if the **certified time of its finalized admission record is strictly before** the reveal deadline. The real time at which that record is ultimately finalized is not an additional replay criterion. Network receipt or local verification shortly before the deadline is also insufficient. Missing bytes are not recorded as a successful reveal. An already finalized valid reveal must not expire merely because its later settlement is waiting for quorum or recovery.

A halt finalizes no local time events. When operation resumes, an already running window may have expired. The following window, however, begins only with its own finalized start record and receives its full nominal duration. Retained consensus proposals keep their original time certificate; replay does not use the current local clock.

<a id="r5"></a>

### R5. Authentication, commitments, and priority

An MVP account has a public key supplied in genesis or admitted by a signed `Register` action. Registration is open to a fresh account key, requires possession of that key, and consumes nonce 1; its first subsequent action uses nonce 2. Genesis accounts retain initial nonce 1. Registration creates zero balance and grants no validator, consensus, or transport authority. Existing consensus and transport keys cannot be reused as research keys. At most 256 research accounts, including genesis accounts, can exist in a run. A full registry rejects new keys without evicting existing accounts or stopping their research; this finite cap provides no identity-flooding resistance or fairness guarantee. Exact retries return the original receipt. No fee, invitation, identity oracle, or NAO prepayment is required.

Registration uses unreserved record capacity. A record admitting a new account cannot also open or progress an active attempt, including automatic phase transitions. Rejection changes no account, balance, nonce, receipt, or reserved budget. Terminal runs admit no new accounts. All new proofs in a submission belong to the signing author; their payment recipient is that same account. Joint authorship, naming other authors for new proofs, and different recipients are rejected. Existing referenced proofs retain their stored account assignments.

The canonical original package contains the root, helper certificates, dependency edges, and unambiguous authorship of the new material. Its hash binds unchanged bytes. A commitment binds genesis, version, `SolutionRoundId`, author, policy, original hash, and 32 cryptographically random secret bytes. The account signs the commitment operation. The reveal supplies the secret and the complete signed original with matching context. At most one valid reveal may be finalized per commitment; a second reveal with a new nonce is rejected. Identical redelivery returns only the existing receipt. Before publication, the CLI stores the secret and original bytes durably and locally; it can resend the same action after a restart.

An earned eligibility claim remains passive. A `JoinIntent` action signed by its registered author may refer only to a claim already present in the sealed parent; its family and original completion ordinal must match. The candidate consensus and transport keys separately prove possession over the genesis, author, nonce, claim, both keys, and canonical endpoint. Candidate keys must be distinct and must not reuse registered account keys, current or historical period keys, or other pending intent keys. An endpoint must be canonical and must not collide with either the outgoing or proposed successor validator roster, or another intent. Historical endpoints may be reused after both live rosters release them; historical keys remain forbidden. At most one current intent is recorded per claim. An exact retry returns its original receipt; a later signed action with the next nonce may replace the current intent while earlier receipts remain historical. The intent enters a queue of at most 32 claims ordered by paid completion ordinal and family identifier. Its first finalized admission receipt and expiry are retained across revisions. The queue lifetime uses the immutable profile queue duration. Expired, stale, or consumed entries are rejected or removed deterministically. The oldest unready claimant is not skipped: no-join key rotation preserves its place until expiry. Only a sealed record consumes its claim and grants the selected slot.

Every user action has a nonce used monotonically by the account holder and a content identifier. A nonce value that has never been applied must equal the exact next expected value. Invalid actions consume no nonce. Identical already finalized actions return the existing receipt; different content under a consumed nonce is rejected. Subsequent actions prepared offline wait for their predecessors. Additional domain rules prevent second votes per owner/voting attempt and second commitments per author/solution round.

After finalized reveal closure, the smallest commitment coordinate pair `(admission height, operation index)` wins among valid timely reveals. The receipt binds its content. This does not establish who first discovered the result outside the network; the rank is a recorded submission priority. A missing or invalid reveal skips that candidate, not verification of other authors. PROVED and REFUTED compete for the same one-time completion.

<a id="r6"></a>

### R6. “Survival of the first” in the library

An already selected proof of the same exact canonical statement is reused if the Foundation, assumptions, approved context, and resource rules match. Matching uses `StatementId` **and** exact conclusion-formula bytes; `ResolutionId` or arbitrary mathematical equivalence is insufficient. Among multiple eligible parent proofs, the minimum `(admission height, operation index, ProofId in byte order)` applies. The library stores this original attribution permanently. A later, shorter proof does not displace it.

The fresh MVP prevents new multiple selections of the same exact statement at admission. Old V0 histories with different rules are not silently imported. For multiple proofs of different statements within the same atomic publication, ProofId provides the reproducible final sorting criterion; this does not establish priority among different authors of the same statement.

Within an original package, after merging exactly byte-identical certificate nodes with identical attribution, the following rule applies: **Two different new certificates of the same exact statement make the package invalid.** This also applies to a root/helper-proof collision. There is therefore no need to invent an artificial temporal first author among new duplicates submitted together.

Every original certificate must be valid, including parts removed later. After permitted substitution of new duplicate helper proofs with parent proofs, parts no longer reachable from the root are removed, the graph is topologically canonicalized, and affected identifiers are recomputed. The final version, including all required dependencies, is verified again. Older proofs are not recursively rewritten; a new helper proof cannot designate another new helper proof as an “older replacement.” Both restrictions and the final acyclicity check prevent circular substitution.

The normalization receipt contains, in a fixed order: version, genesis, recorded outgoing service authority, solution round, commitment coordinate/identifier, original hash, current parent-state commitment, policy identifier, sorted substitution map, final package with identifiers, and stored attributions. It is bound by the finalized record. Original signatures remain on the original bytes; no author signature over rewritten bytes is claimed.

Even when the set of proofs is unchanged, control records can change the settlement parent state. An old normalization receipt therefore cannot simply be reused: it is reproduced against the exact new parent state. Commitment rank and approved conditions remain unchanged.

<a id="r7"></a>

### R7. Citation pool and exact balance entries

A paid completion issues exactly `1,000,000,000` atoms = 1 **Test-NAO**. The 200,000,000 operating atoms are distributed as 50,000,000 to each of the four outgoing authority-unit owners, regardless of which three or four actually certify. Another 100,000,000 goes to the reserve. The remaining 700,000,000 forms the research allocation.

The eligible citation set is derived from the **final** graph: traverse from the root through new helper proofs; stop each path at the first proof selected in the sealed parent state. Each distinct ProofId counts once. Required older ancestors are still loaded for validity verification, but receive no automatic share beyond this payment boundary. Proofs newly published in this record earn no citation reward in this record. Removed references do not count. Self-citations are permitted.

For n eligible proofs:

- n = 0: no citation pool; 700,000,000 atoms to the solution author.
- n > 0: 600,000,000 to the solution author and P = 100,000,000 to the eligible older proofs.
- Sort eligible ProofIds in ascending raw-byte order. `q = P div n`, `r = P mod n`. The first r IDs receive q + 1, and the rest receive q. Only then aggregate amounts with the same stored recipient.

For three IDs, this yields 33,333,334 / 33,333,333 / 33,333,333 citation atoms. Duplicate references multiply nothing. There is no burned remainder and no additional pool per helper proof. Multiple distinct eligible proofs by the same author may produce multiple shares; the MVP does not claim to prevent artificial citation chains. The 0.10 NAO amount is a simple positive **test parameter**, not an empirically established fair valuation of research.

Account balances, reserve, and total are maintained as whole nonnegative atoms. Explicitly bounded u128 values with checked arithmetic are recommended for the MVP; overflow rejects the entire candidate. This bounds the growing natural-number monetary values proposed in the full design without introducing floating-point rounding or wraparound. Every settlement preserves `balances + reserve = 1,000,000,000 × number of paid families`. The test token is not redeemable; transfers and reserve spending are deliberately absent.

The winning author receives exactly one passive, nontransferable eligibility claim with the original completion number. Helper proofs, citations, balances, and redelivery create no additional claims or active votes.

<a id="r8"></a>

### R8. New records and unambiguous encoding

The canonical `StateRecord` format binds zero or multiple new artifacts together with authenticated operations and the complete resulting state. The former single-artifact `ConsensusValueV0`/`ArtifactBlock` authority is removed. No research result may exist solely in an unconfirmed side database. The existing consensus, transport, and storage paths must actually verify, sign, transmit, select, and replay this format.

The binding record content includes genesis/profile, height, parent identifier, complete previous-state commitment, time certificate, ordered user operations, deterministically derived phase/settlement results, and the complete successor-state commitment. Signature evidence is separate from the content it identifies; the choice of a sufficient subset of signatures must not change that content's identity or payout.

Implementation will use the existing strict binary-encoding style: role-specific hash/signature domains, unambiguous lengths, fixed field order, canonical integers, explicit tags, and rejection of unknown variants, duplicate entries, and trailing bytes. Sets are sorted by their defined raw-byte identifiers; actual operation sequences retain their bound order. JSON serves CLI output, not unchecked consensus identity. Complete tags, decoders, and golden vectors belong to implementation step 1; the meanings fixed here must not be reinterpreted during that work.

Mathematical artifact identifiers remain reusable. A complete research-state commitment additionally covers questions, attempts, phases, receipts, nonces, original attributions, known/unpaid and paid families, eligibility claims, join intents, accounts, the monetary reserve, and queues. Remaining record/byte budgets and the still-reserved active completion capacity are separate state fields, also stored canonically and replayed; they are not the monetary reserve. An artifact Merkle tree alone is insufficient.

<a id="r9"></a>

### R9. Durability and the limits of simplified security

Candidates are evaluated completely on temporary state. Only a valid finalized record may make all effects visible together. The authoritative journal contains all finalized inputs and proof bytes required for recovery. Separate search indexes and views are reproducible derivatives of it, not another source of truth. The existing anchor/journal principles are extended to the new complete state.

A confirmed reveal requires durable, available bytes, not merely a hash or transport receipt. A crash after durable storage but before the response is resolved through identity and replay. An uncertain write situation stops the affected path until verified recovery. Incorrectly decoded complete journal frames, anchor mismatches, or verified conflicting finality are not automatically “repaired.”

Each owner durably anchors its fresh period key offer before advertising it. Incoming READY binds the exact agreed predecessor and successor. After an incoming quorum, the outgoing signer anchors TERMINAL, writes STOP, drops its signing key, closes old transport sessions and deletes locally controlled secret files before releasing TERMINAL evidence. Crash recovery reuses saved evidence and never regenerates missing anchored keys. Only fully sealed selected history activates an incoming signer. A selected terminal run deletes its staged incoming keys without activating them.

This is a local custody guarantee under an honest operator assumption. External backups, copied seeds, hostile host memory and simultaneous malicious rollback of all anchors are outside the guarantee. Operators must not restore retired signing capabilities. Lost quorum never lowers the denominator or installs unverified validators. Recovery uses a fresh owner-authorized transport and configured reachable endpoints; it confers history access only and does not revive a retired key.

<a id="r10"></a>

### R10. Concrete starting values and their qualification

The following values are fully specified **starting proposals**, not yet measured performance limits. They are bound in genesis. Choosing different values before the first start produces a different profile; an active attempt does not change them. A later change in the MVP occurs only through an explicitly separate new test run.

| Parameter | Proposal |
|---|---|
| Active attempts | 1, including pending settlement |
| Queued questions | 32 in total; at most 1 per ResolutionId |
| Research accounts | At most 16 initial accounts; at most 256 total after self-registration |
| Join intents | At most 32 queued claims, one current intent per claim; original admission and expiry survive revisions. Historical receipts remain bounded by the finite run. |
| Commitments | At most 16 per attempt, and at most 1 per account and attempt |
| Formal question | 16 KiB of source; both expanded targets limited to 1,024 nodes and depth 32 each |
| Proof group | At most 16 new helper proofs plus the root; original and final version limited to 256 KiB each |
| Individual certificate | At most 64 KiB and 4,096 steps; all stricter existing checker limits also apply |
| Older dependencies | At most 64 distinct required proofs in the full verification dependency closure, totaling at most 2 MiB; depth at most 32 |
| Citation recipient basis | At most 64 distinct eligible ProofIds, bounded by the dependency-closure limit |
| User operations / record | At most 16; at most one settlement group; original proofs are not embedded repeatedly as copies in the same message |
| Complete research record | At most 1 MiB, including required new packages, operations, and supporting evidence; transport units receive corresponding limits checked before allocation |
| Verification work | The existing formula-work limit per checker call remains in place; the number and input bytes of all calls, DAG traversal, and normalization must additionally be bounded in advance |
| Running archive | An MVP run has at most 8,192 records; check a conservative full archive/reveal reservation derived from these upper bounds before starting, with no automatic deletion of confirmed history |
| Completion capacity reserve | Before opening, reserve 64 record slots, including opening, together with the maximum frame bytes; additionally, from genesis, 1 slot within the run limit is reserved exclusively for final run termination |
| Clock error | Operator target of at most 2 seconds; if a breach is detectable, issue no new time reports and display a status error |
| Research profile | Voting 604,800 s, commitment 86,400 s, reveal 86,400 s, queue deadline interval 2,592,000 s |
| Lab profile | Voting 300 s, commitment 120 s, reveal 120 s, queue deadline interval 1,800 s |
| Agent review | At most 2 inference attempts per question/attempt, 60 s per call, and 4 bounded tool calls; failure → no automatic vote |

The reservation accounts for all of the up to 16 possible reveals, original and final verification, and their complete older verification dependency closure. When a commitment is admitted, the promised slot is actually reserved. A small final result does not excuse an oversized original. A record that bundles too many otherwise valid operations is invalid; the operations may be admitted in suitable later records before the deadline.

The supervisor responds to events and deadlines: new valid actions, due phases, and pending settlement trigger proposals. It does not create periodic empty records merely to increase the height. Consensus retries at an undecided height consume no new finalized-record slot. Already due system operations take priority; a proposal cannot evade a required closure or settlement through arbitrary empty operations.

Even with only one of these domain actions per record, 43 slots suffice for opening, four votes, voting closure, COMMIT start, 16 commitments, commitment closure, REVEAL start, 16 reveals, reveal closure, and settlement. The reserve of 64 slots additionally provides room for bounded system work; its actual use is checked against the profile. A finalized record consumes at most one reserved slot if it performs such outstanding active domain actions or a required phase transition. Unproductive empty operations, pure retries, extra time ticks, and unrelated queue and expiry work must not consume the remaining reserve. Queue expiries are included at the start of the next permitted record; separate expiry records require unreserved capacity.

If less than the opening reserve is available in an inactive parent state, the next record must perform final run termination. After due queue expiries, the remaining queued questions are closed with `CAPACITY_END`; this record contains no new user actions. The terminal slot separately reserved from genesis must never be used for ordinary work or an attempt. The terminal state rejects further submissions and records and remains readable. An active attempt, however, retains its completion slots until a valid result or final unresolved expiry, including after a temporary loss of quorum. Reaching the capacity limit therefore does not terminate an already protected active attempt.

For later qualification, data storage, final wire overheads, active buffers, and test machines must be compatible. Before starting, required storage is calculated conservatively from the profile and archive limit; declining free space causes a visible local operating fault rather than loss of confirmed data. It does not change a record's deterministic validity. Whether a record consumes reserved capacity follows solely from its valid domain operations and mandatory transitions together with the canonical remaining budget, not from a claim by the proposer. Archive frames alone are bounded by 8,192 × 1 MiB, totaling 8 GiB; indexes, signing journals, protocol evidence, and a safety margin are additional. This is a finite MVP run, not an indefinitely running production network. The run limit must not cut off an already protected settlement.

The original state-v1 acceptance used the Lab profile; its shorter voting window was an explicit deviation from the whitepaper's seven-day window. Current authority-period process and Docker acceptance use explicit accelerated profiles committed in genesis. Separate signed-time tests replay all timing profiles at their exact voting, commitment and reveal boundaries. An accelerated run and these boundary tests do not establish a complete real-time Lab or seven-day research run on the current implementation; those remain separate qualifications.

<a id="r11"></a>

### R11. Sources and remaining implementation work

The current implementation includes bounded self-registration, ordered claim-backed admission, per-height key rotation, READY/TERMINAL sealing and local signing-capability retirement. Current acceptance remains tied to the exact source and checks in [verification.md](verification.md). The broader public-network proposal, independent-machine qualification, automatic endpoint discovery, customer submission APIs, and indefinite operation remain separate work. Proof discovery and generation belong to `naome-agent`; core starts with supplied `.nao` material.

During the preparatory research, the rules were checked against the whitepaper, actual code paths, and three separate specialist reviews. The static code review identified reusable foundations and missing integration. Isolated rule models examined distribution, duplicate/parent selection, and commitment priority; a lifecycle model examined deadline boundaries, serial opening, unpaid known helper proofs, and atomic model states. Those individual reports and scripts are not part of this starting package.

The preparatory models used abstract identity and validity values. They were not actual mathematical checks, signature tests, on-disk crash tests, or a running network, and did not establish the record reservation in R10. The subsequent Rust implementation adds those mechanisms and executable component, storage-fault, and process checks. Their completed acceptance evidence is mapped in [verification.md](verification.md); implementation, component checks, actual lab execution, and whole-workspace qualification remain distinct evidence.

The separation of a deterministic state machine from consensus and the prohibition of external side effects during replay are also described in the official [CometBFT application requirements](https://raw.githubusercontent.com/cometbft/cometbft/main/spec/abci/abci%2B%2B_app_requirements.md). This is an architectural comparison, not a recommendation to replace the existing consensus system. [RFC 8949, section 4.2](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2) shows why deterministic serialization requires explicit rules; CBOR is not selected here as an additional dependency. The [SQLite documentation on atomic commit](https://www.sqlite.org/atomiccommit.html) explains all-or-nothing behavior and the necessary storage assumptions; merely trusting users does not replace these properties. Nor does this establish a decision to migrate to SQLite.

Historical acceptance of the trusted, bounded local `state-v1` MVP applies only
to its recorded source snapshot. Later prerelease slices have separately recorded
evidence. The current `state-v5` milestone requires its own complete workspace,
process, custody, replay and platform CI qualification, documented in the
[verification record](verification.md). The user-authorized four-process local
simulation is the network acceptance target; a real multi-machine run and the
long research-window profile remain separate later qualifications. Removing the
trusted operating assumptions reopens the corresponding protocol questions.
