# NAOME
# A Public Network for Formal Research

[META] Whitepaper · Draft v0.2 · 28 September 2026 · Public-network target and bounded v7

[ABSTRACT] NAOME aims to coordinate formal research on an open-ended public network: participants submit questions and checkable proofs, while a shared history preserves attribution and prevents duplicate settlement. The current state-v7 prototype uses four to 32 validator units, owner-approved questions, earliest valid commitment completion, earned-validator claims, one active attempt and finite Test-NAO accounting. Its four starting units may all be founder-controlled. A proposed non-mining successor investigates finite active validator committees with open, objective, Sybil-resistant entry and rotation, alongside parallel research questions under Proof of Useful Work: each question has its own first-solver prize, while proof length orders results ready together across questions. Citation eligibility would follow the accepted parent chain, not a library frozen at question opening. Canonical valid disclosure sets first-solver priority; batching, authority, admission, rewards and migration rules remain undecided. Every full node must check consensus-relevant proofs and bounded resource use. Public safety, physical capacity and independence are unqualified.

## 1. Purpose and scope

NAOME coordinates three decisions in shared mathematical research: which questions receive resources, which answers satisfy their formal obligations, and which history assigns the resulting rights. The agenda directs finite attention, checking and storage capacity. The public library preserves checked results for later use. Current v7 agreement establishes submission order, completed question families, payments and validator membership; a public committee would need independently specified entry, authority and continuation rules.

[FIG:system]

[CAPTION] This diagram shows the current v7 research lifecycle; a public committee proposal would need new authority rules while retaining formal checking. Continuing records repeat this path. An accepted result enters the library and creates payment and an author claim; a separate handoff may change the electorate. The current terminal seal can select one linked successor run; open-ended continuation remains a proposed public-network property.

This paper sets out an intended permissionless, open-ended public network while identifying the current bounded state-v7 implementation. The companion variable-roster paper is a historical fresh-v6 discussion copy; current rules are in the v7 authority-period specification and profile. Question-specific policies and definition publication discussed here are proposals, not active v7 inputs. The 32-unit active ceiling is a testnet limit, not a lifetime participation policy or physical 32-host qualification. Seven-day live operation, physical multi-machine acceptance and public-network operation remain unverified.

NAOME's research path can span many sealed records. An unapproved or expired attempt produces no paid result. A solution author's join request is optional and grants no voting weight until a separate handoff is sealed.

A proposal combines a readable purpose with an exact mathematical task. Validator owners judge whether to authorize it; contributors seek a proof of an approved conclusion under the declared Foundation, or formal rulebook. Approval expresses a research preference, while checking establishes derivability. The shared history records both without treating either as evidence for the other.

Under current v7 rules, a paid completion credits the bounded profile's Test-NAO accounts and creates a nontransferable eligibility claim for its authenticated solution author. This claim provides a possible route to validation; holdings confer no voting weight.

The current v7 profile uses a sealed four-to-32-unit electorate and a linked terminal successor; it does not reinterpret an existing v5 chain in place. Material public-network decisions and the non-mining committee candidate are collected in Sections 9.3 and 9.4. Applicable rules and bounds must be fixed before the affected question is approved. Safety and service also depend on the distribution, exposure and availability of authority; mathematical checking does not establish those conditions.

## 2. Network model and research lifecycle

### 2.1. Participants, records and rights

A <i>question author</i> proposes a task through a registered research account. A <i>solution author</i> authenticates a submitted bundle containing the solution and its helper proofs. In v7, a <i>validator</i> checks records and participates in agreement; its <i>owner</i> controls the associated authority. Each installed unit has a distinct owner account ID, though one person may control several accounts. A local <i>agent</i> assists its owner in reviewing research questions. A proposed public committee and independent verifying full nodes have distinct roles, described in Section 9.4.

The current installed electorate begins with four equal voting units in genesis and may grow through sealed handoffs to <i>N ≤ 32</i>. Its owners authorize research and membership handoffs. Section 7 describes how qualifying authors may add a unit until the limit is reached, then request replacement of the oldest unit. The founder may control all four starting units. Separate account IDs and keys do not establish independent control, and no present rule prevents founder censorship or quorum control.

In the bounded profile, the solution author is also the recipient for all new proofs in a submission. Each reusable proof block records authenticated <i>proof authorship</i> and payment attribution; eligible later use may generate a citation payment to its recorded beneficiary. A broader network design could permit a separate <i>research-payment recipient</i> or several authors, but their authorization rules remain open. A <i>record proposer</i> packages operations for agreement and acquires no authorship merely by including them.

<i>NAO</i> is the proposed accounting unit; one NAO equals one billion indivisible atoms. The bounded implementation uses Test-NAO with no market value or redemption promise. Registering an account, proposing a question, committing, disclosing and receiving a reward require no mandatory prepayment. Admission and reservations bound the shared processing these activities can consume.

The history consists of ordered <i>consensus records</i>, or blockchain blocks, at successive <i>heights</i>. A <i>seal</i> authorizes an agreed record's successor. The selected sealed parent provides the historical state against which a proposed successor's use of older proofs is evaluated.

A <i>proof block</i> is an independently addressable library object containing a proof and its references. Several may enter through one consensus record, without separate consensus steps or heights. Agreement may use several <i>rounds</i> at one height. A research <i>attempt</i> includes voting and, if approved, a solution phase, potentially spanning many records and membership changes. It is distinct from an agreement round; voting duration and the number of installed units are independent parameters.

### 2.2. From a question to a settled result

In the proposed public network, any pseudonymous key holder should be able to seek research admission without a human-identity test or manual selection. That does not make keys unique people or grant validator authority. In the current finite run, a researcher with a registered account submits a readable purpose and an exact formal question. The question enters a bounded queue; when the one active attempt slot is free, a sealed record opens a vote on its fixed terms. More than two thirds of the opening electorate's full weight must approve before a separate solution phase begins. The research profile specifies a seven-day vote; Section 4.3 distinguishes that rule from current runtime evidence.

Contributors commit to concealed proof bundles before disclosing them. The earliest eligible receipt with a valid disclosure wins across the approved outcomes. Acceptance checks the original submission, applies permitted reuse and pruning, and checks the final proof. Sections 4 and 5 explain this path.

For example, three of four owners may approve a question, after which a contributor commits and later discloses a checked refutation. Settlement records REFUTED, publishes the root and used helpers, credits Test-NAO and gives the solution author one eligibility claim. A later proof may cite that result with its attribution intact. The author may separately request a validator slot while the claim remains eligible; the claim itself has no vote.

## 3. Formal questions and proof objects

### 3.1. The mathematical obligation

A v7 question's <i>.nao</i> source contains <i>foundation = "naome:zfc"</i> and one closed <i>statement = Q</i>, with optional <i>success = "resolve"</i>. A closed statement has no free variables. The source cannot set assumptions, definitions, reference permissions, substitution rules or resource bounds; those would require broader public-network rules. Its formal obligation must compile before voting begins; a solution need not accompany the proposal. Owners judge whether the readable purpose matches the formal statement. Compilation checks syntax and profile bounds, not the fidelity or scientific value of the translation.

The Foundation <i>naome:zfc</i> consists of classical first-order logic with equality over sets, ZFC axioms, and the Separation and Replacement schemas. A certificate supplies axiom or schema instances, inference steps and checked references. Verification establishes derivability under this rulebook. The interpretation of that result relies on sound checking and a consistent Foundation. Unapproved assumptions are forbidden.

Approval covers both possible outcomes. A certificate must prove one of two exact conclusions determined before voting. A counterexample qualifies only when a checked certificate establishes the refutation target with the required domain and assumptions. Failure to find a proof leaves the question unresolved. A proof of the disjunction <i>Q or not-Q</i> alone selects neither outcome. Some statements have neither a proof nor a refutation in the chosen Foundation.

### 3.2. Question families and resolution identity

A question and its negation concern the same resolution for settlement purposes. Before voting, notation is expanded and only leading negations are removed from <i>Q</i>, leaving a canonical core <i>R</i> and their parity. The approved conclusions are exactly <i>R</i> and <i>¬R</i>. For even parity, these mean PROVED and REFUTED respectively; odd parity reverses the labels. This convention uses classical double-negation equivalence.

The permanent <i>ResolutionId</i> identifies the Foundation and canonical core. Opposite wording and additional leading double negations therefore share one completion key. The contextual <i>QuestionId</i> binds the exact orientation, approved targets and checking conditions. Different presentations can share a family-wide settlement identity, but the rule does not identify every logically equivalent formulation.

[FIG:graph]

[CAPTION] The library records the conclusion actually proved. Reversing the question's wording preserves its ResolutionId and cannot create another completion.

The library admits one selected solution of either target for a resolution family. Settlement, rather than validation alone, completes that family permanently. Another solution or author cannot create a second paid completion or eligibility claim. Repackaging an existing proof adds no proof block. Section 9.2 specifies the treatment of later questions already answered by unpaid helpers.

After refutation, the rejected claim is not entered as a theorem. If certificates for both targets were finalized during an open attempt, their recorded submissions remain available for inspection, but only the selected result settles the family. A second settlement is prohibited; the bounded profile has no general post-completion conflict-admission workflow.

### 3.3. Certificates, helpers and definitions

A bundle contains a root certificate for the approved question and helper certificates for their own closed statements. Surviving helpers become reusable proof blocks when the group settles; internal inference steps are not separate publications. Appendix B specifies publication and attribution.

The authoring compiler can check conservative definitions offline. Relations abbreviate primitive graphs; a function with one or more inputs requires a selected proof that its expanded graph gives exactly one output for every input. The v7 ledger does not publish definitions or admit their references in questions or settlement certificates; a broader network needs a definition-publication rule. Recursion, zero-input relations or functions, and standalone constants are excluded from the offline authoring form.

Helpers developed after approval may be used by later certificates in the normalized group without becoming older proofs for payment. Appendices A and B define their identities, admission and attribution.

## 4. Research authorization and submission

### 4.1. Admission and reserved capacity

Anyone may submit a question with its purpose and exact terms. Admission checks formalization and byte limits and reserves capacity; it does not imply approval. Finalized receipts establish queue position. Raw arrival at a peer carries no position guarantee.

The bounded profile admits one active research attempt from opening through settlement or expiry; other questions wait. Increasing <i>N</i> changes the number of voters, not this capacity or the amount of proof checking per result. The proposed public design with <i>C</i> simultaneous attempts needs separate reservation, closure, review and delivery bounds for each question and an aggregate bound across all active questions. Queue waiting adds to the voting window, which guarantees neither a ballot from every owner nor fair admission under flooding.

Reservations cover voting and the bounded solution phase, including work on the original submission. For a frozen electorate of <i>N</i> and at most <i>K</i> commitments, the active-record reserve is at least max(64, <i>N</i> + 2<i>K</i> + 7), allowing each owner to vote in a separate record. A fresh genesis needs that reserve plus a terminal record; later growth may end question intake if too few records remain. Appendix E.1 specifies queue order, expiry, retries, family uniqueness, capacity reuse and join service.

### 4.2. Owner judgment and agent review

Each validator node maintains an owner-defined, editable <i>Research Profile</i> describing its research interests. The current local agent assesses the exact question and supplied bounded context; it does not independently retrieve library material. Its assessment may be YES, NO or REVIEW. Owner policy can authorize a decisive signed ballot; REVIEW yields no ballot. Bounded read-only retrieval is a possible broader design rule. This is a judgment about the proposed use of resources, including whether the formal task reflects its stated purpose.

[FIG:agenda]

[CAPTION] The Research Profile guides local review. The owner authorizes the ballot, whose weight comes from the opening snapshot; the agent's recommendation establishes no mathematical conclusion.

The bounded profile has one active question for review. Agent inference time and supplied context are bounded; failure, uncertainty or exhaustion produces no ballot. A broader concurrent design would need deadline ordering and separate review-work budgets. Submitted text and any future retrieved material are untrusted input, separate from owner instructions. A valid signature establishes authorization; it does not establish the quality of the judgment or demonstrate that an AI was used.

### 4.3. The frozen seven-day vote

A sealed opening freezes the proposal and electorate for the seven-day vote. Let <i>W</i> be its full combined weight, <i>Y</i> the recorded YES weight, <i>T</i> the certified opening time and <i>D</i> the deadline:

[EQ] D = T + 604,800 seconds; approval requires 3Y &gt; 2W.

With five opening units, four YES approve; with 32, 22 YES approve. The result authorizes research resources and says nothing about the statement's truth.

Current process qualification uses accelerated windows and separate signed-time boundary tests, not a complete seven-day live run. Appendix C.1 gives ballot admission, deadline and closure rules; C.2 defines certified time.

The frozen snapshot preserves a stable electorate even if membership changes during review. Former owners can therefore influence attempts opened during their membership, using research authority protected through closure. A halt can consume part of the voting interval, as discussed in Section 8.3.

### 4.4. Commitment, disclosure and selection

Approval permits a bounded solution phase with separate commitment, disclosure and expiry rules. A contributor authenticates a commitment to the complete original submission. Its finalized receipt reserves disclosure and checking capacity. Appendix B.1 specifies the committed contents and authorization.

The author discloses only after commitment closure has been sealed. After disclosure closure, the earliest eligible valid receipt wins in canonical order across both approved outcomes. A missing or invalid disclosure receives nothing. This order identifies the successful authenticated submission; it does not establish who first discovered the mathematics. Approval, commitment closure and settlement occur across the required sealed phases and cannot be combined into one unsealed record.

[FIG:delivery]

[CAPTION] Sealed closures separate commitment from disclosure and selection. Settlement follows only after the selected submission passes acceptance.

An unresolved solution phase expires without recording a refutation, issuing money or eligibility, or independently publishing its helpers. Timely valid disclosures remain eligible for later settlement under the parent-dependent checks in Appendix B.3.

## 5. Proof acceptance and publication

Acceptance connects an authenticated submission to a reusable public result. Both the original bundle and its final form must validate. The fixed v7 rule replaces exact duplicate helpers with admissible older proofs and removes material no longer used by the root; a question cannot change that rule. Appendix B specifies the exact matching, pruning, authorization and validation rules.

[FIG:helpers]

[CAPTION] Original validation, authorized reuse and final validation lead to publication of the used proof group. A failed acceptance check rejects the group as a whole.

A normalization receipt makes the transformation reproducible while preserving the original signatures. This allows reuse without assigning the submitter another author's work. A changed settlement parent requires renewed checks under Appendix B.3.

Settlement atomically publishes the selected root and surviving helpers, permanently completes the approved resolution family, creates the solution author's eligibility claim and records research and citation allocations. The proof blocks remain independently reusable without copying the original bundle. Additional helpers do not create additional paid completions or initial eligibility claims.

Other valid bounded-profile records may carry research and control operations without issuing Test-NAO. Transfers and reserve spending require future rules. Appendix B.5 defines the publication boundary and the once-only reward conditions.

## 6. Rewards and accounting

### 6.1. The completion budget and its recipients

Each paid research completion credits exactly one Test-NAO in the bounded profile, equally for proof and refutation: 0.20 funds validator service, 0.10 enters the reserve, and 0.70 funds the solution author and a citation pool of <i>P</i>. The author receives 0.70 minus <i>P</i>. Each completion has one pool within this budget; helper admission adds no issuance. These accounting units have no established market value.

Section 9.2 gives the immutable bounded profile's citation terms and identifies open allocation choices for a broader network. The prototype's terms apply to every question opened under that profile.

[FIG:payments]

[CAPTION] The one-Test-NAO completion budget includes the citation pool P. Account credits and the solution author's eligibility claim are separate rights.

### 6.2. Citation eligibility follows final use

Citation eligibility follows actual use in the final proof. Its <i>direct bundle boundary</i> consists of the first older proofs reached along dependency paths, where older means selected in the sealed parent before the entire record. Direct describes this boundary, which may lie beyond several helpers, rather than a fixed number of reference edges.

[FIG:citation]

[CAPTION] Traversal stops at the first selected parent proof on each path. Checking may continue beyond this payment boundary to establish validity.

Only eligible boundary proofs may share <i>P</i>. Appendix B.4 specifies traversal, deduplication, replacement attribution and exclusions. Newly published proofs may qualify through use in later paid completions.

Actual dependency checking establishes use, not scientific necessity; it does not prevent a contributor from constructing avoidable dependencies. A bounded pool limits the amount available for distribution but does not alone establish a fair allocation. Citation counts and NAO ownership create no additional voting units.

### 6.3. Conservation and the cost of operation

Service distribution is independent of which sufficient signature subset certifies the record. The 0.20 Test-NAO service pool is divided across all installed outgoing units as whole atoms: each receives the integer quotient, and remainder atoms follow canonical slot order. A successor installed in that record does not receive an outgoing share. The bounded profile starts with zero monetary balances and uses checked, bounded integer accounting. For <i>F</i> finalized paid completions, it conserves:

[EQ] S = 10<super>9</super>F atoms;<br/>account balances + reserve = S.

The bounded run limits actual issuance through its finite record budget. A broader public network has no specified lifetime supply cap. Resource bounds limit admitted work, while approved questions may finish at different times or in clusters. Validators can authorize easy tasks; the approval rule alone provides no economic scarcity or measure of scientific value.

An empty reserve does not invalidate control transitions. Review, agreement, storage and delivery still need resources during periods without paid completions. Operators need separate funding before the first discovery. The bounded profile has no reserve-spending operation; sustainable public service and reserve use require defined rules and real resources.

## 7. Validator membership

### 7.1. Bounded growth and contribution-ordered replacement

The v7 electorate starts with four installed, equal-weight units in genesis and may grow to <i>32</i>. Each record uses one finite snapshot with <i>4 ≤ N ≤ 32</i>; there is no undefined or unbounded set of voters for that record. A slot keeps its identity when its occupant or keys change. Each unit has an owner account and an immutable age: a genesis retirement rank for a bootstrap unit or the original paid-completion ordinal for an earned unit. Installed units have distinct owner account IDs. That is not a per-person cap or an independent-identity assertion.

A winning author may voluntarily request admission using the completion's nontransferable claim, independently of payment. An authenticated join intent binds the exact claim, owner, candidate consensus and transport keys, and a literal network endpoint; both candidate keys prove possession. It grants no weight. A later, exact-parent admission offer must match that finalized intent and the oldest eligible claim in the bounded queue. The claim must be unused and newer than the oldest installed unit. A revised intent retains its first queue position and expiry.

At most one claim is installed in one sealed transition. While <i>N &lt; 32</i>, that claim creates one new stable slot, so the next snapshot has <i>N + 1</i> units. At <i>N = 32</i>, it replaces the oldest installed unit in its existing slot; the size remains 32. All continuing units rotate keys. A missing rotation offer leaves that unit vacant, but it stays in the denominator. An absent candidate offer makes a no-join rotation and leaves the claim queued until expiry or later selection.

[FIG:membership]

[CAPTION] A sealed handoff can add one earned unit to a four-unit roster, making five. At the 32-unit ceiling, the same claim rule replaces the oldest unit. The outgoing and incoming quorum thresholds are calculated separately.

The ordinal does not change with delayed joining, retry, key rotation or re-registration. An installed claim is permanently consumed, including after retirement. An unused claim becomes stale when the oldest installed boundary passes it. Intent expiry is a separate bounded service rule. The permanent research archive continues to grow.

Every height rotates active consensus and transport keys through at least <i>q(N) = floor(2N/3) + 1</i> owner-authorized offers. Activation requires a previously sealed completion, author consent, agreement under the outgoing snapshot, incoming READY and outgoing TERMINAL. New weight cannot authorize its own installation. Section 8 and Appendix D describe the seal and the availability consequences of a vacant unit.

Genesis supplies the initial allocation, retirement order, capacity and join-service limits. The founder may hold all four starting units. This initial authority is adopted trust, with no independence assumption. The membership rule describes later growth and replacement; it does not establish that either the initial allocation or subsequent acquisition of claims is fair.

### 7.2. Distribution of authority

A founder controlling the four initial units can form a quorum, censor questions or joins, and halt the service. The one-third exposure assumption below is not met against a malicious founder; the current system provides no takeover resistance in that case. Formal checking limits which certificates may settle a task. It does not establish the independence of authors or equal costs of acquiring eligibility. Incumbents influence the research agenda and may favor specialties, approve easy distinct targets, fragment work, buy solutions or censor questions and join requests. Owners' agents may share errors or respond to malicious descriptions. Authors can stockpile solutions or bank unused eligibility claims while the participation boundary is stationary.

Adding or replacing one unit changes a coalition's share and may cross the one-third safety boundary. Growth can dilute incumbents, but repeated earned admissions can also concentrate control in one operator using distinct accounts. Its active share can differ substantially from its lifetime contribution share. Contribution ordering prevents re-dating; it supplies no lower bound on the cost of acquiring control. Safety therefore requires the explicit concentration and exposure assumption in Section 8.3, alongside the membership rule.

A proposed public committee would need objective, Sybil-resistant entry and
rotation, not one vote per key or per research proof. This is a successor
question, not a v7 handoff variant. It needs separately defined authority,
continuation and migration rules; the current earned-validator bootstrap
remains a v7 mechanism until a reviewed transition selects otherwise.

## 8. Agreement, security and operation

### 8.1. Agreement on the shared state

A selected parent at height <i>h-1</i> contains authority <i>S<sub>h</sub></i>
for record <i>h</i>. The record applies an ordered, bounded sequence of
operations and one exact handoff plan to that parent. All operations are
evaluated on provisional state; any failure rejects the entire candidate. The
record commits to its predecessor, height, configuration, certified time,
operations, plan and complete resulting state. This includes artifacts,
questions, ballots, commitments, completions, claims, accounts, funded
balances, reserves, queues and the next authority snapshot. A sufficient
signature subset certifies the record without changing its identity.

At least <i>q(N<sub>out</sub>)</i> distinct current units agree on a valid record through proposal,
PREVOTE, PRECOMMIT and locks under <i>S<sub>h</sub></i>. Correct validators
support it only after obtaining its bytes and checking all effects. Agreement
yields a provisional successor; it does not activate the next keys. The
separate seal gates in Section 8.2 establish selected finality. The cited
agreement argument in [1] does not establish the distribution of NAOME voting
authority or the adequacy of its research incentives.

### 8.2. Sealing and signing-capability retirement

Every height uses a handoff, including a height without a new owner. The plan
in the agreed record determines the exact incoming snapshot. Incoming members
verify the predecessor history and agreement, durably prepare the successor,
and supply at least <i>q(N<sub>in</sub>)</i> READY signatures. Outgoing members verify that quorum, save
exact TERMINAL signatures, stop old period consensus and TIME signing, retire
locally controlled old signing capabilities, and release the saved bytes.
At least <i>q(N<sub>out</sub>)</i> outgoing TERMINAL signatures complete the seal. The seal binds the
record, both state commitments and both authority snapshots; changing the
signer subset does not change record identity.

[FIG:agreement]

[CAPTION] The agreed record already contains the next-period plan. Incoming READY and outgoing TERMINAL use their own roster sizes; only the complete seal selects the successor.

Both consensus and transport keys rotate each height. Before selection,
bounded staged transport may carry handoff and replay messages, without
ordinary voting rights. Old transport identity closes before TERMINAL
release. A saved signature can be resent after a crash; the old signing
capability cannot be reconstructed to repair a failed seal.

Managed local retirement cannot erase copied keys, external backups or
regenerating seeds. Operators must attest that every external signing path is
retired; a height label on an Ed25519 signature cannot enforce it. Vacant and
unavailable slots retain their quorum weight. Handoffs need no membership
overlap, but still need q(N_in) reachable incoming and q(N_out) reachable outgoing
signers.

An outgoing unit remains responsible for TERMINAL even if its next slot is
vacant or replaced. After old-period transport closes, a separately authorized
fresh owner-authenticated recovery channel may relay saved signatures and
finality evidence without granting an incoming vote or reviving old signing power. Peers verify a
complete seal against their selected parent before adopting its successor.
Late recovery also depends on continued access to that sealed history.

A configured terminal record can seal one exact linked successor plan. The next run uses new stores and fresh keys while preserving carried ledger state; independent archive replay must verify the predecessor, bridge and successor. This current mechanism has finite limits in each run and does not establish perpetual storage or public service. Late readers still need a reachable history holder or an independently verified export; evidence transport grants no new voting authority.

### 8.3. Safety and progress assumptions

For signing period <i>h</i>, let <i>W<sub>h</sub></i> be installed weight and <i>A<sub>h</sub></i> the weight faulty or exposed at any time from capability creation through sealing. The safety assumption is:

[EQ] 3A<sub>h</sub> &lt; W<sub>h</sub>.

Purchased control, stolen copies and regenerating seeds count toward this exposure. Changing victims does not reset it. If one party controls all four starting units, the stated safety assumption fails against that party. Safety also depends on correct checking, cryptography and effective capability retirement. Retirement of a voting unit alone does not stop retained historical keys from signing a fabricated past. Service assumptions count the union of faulty or exposed owners over the applicable service cycle. Its boundaries remain unspecified, as recorded in Section 9.2.

Progress requires more than two thirds correct and available outgoing and incoming weight, bounded work and eventual message delivery within a delay bound. At least one third unavailable or withholding weight can block agreement and the membership replacements that might change participation. Unavailable weight remains in the denominator. Recovery outside these assumptions requires an explicit trust decision; neither elapsed time nor a reduced set of responders changes authority.

Certified protocol time determines deadlines. Correct clocks have a bounded error, while collection, agreement and sealing add delay. During a halt, no voting outcome finalizes. Fresh time evidence on recovery may close expired windows immediately, so the seven-day interval is not a guarantee of seven reachable days of review. Appendix C gives the time-certificate rule; Appendix D gives agreement timing conditions.

### 8.4. Durable history and current-state access

Readers validate history from an adopted genesis and retain an independent anchor. An artifact-set root can support presence or absence witnesses under a trusted root, but neither the root nor a storage receipt establishes mathematical validity or finality. A reader isolated from the network cannot infer that its valid history is current. Verified conflicting sealed successors cause a halt.

Durable recovery and archive storage support later checking and incur costs even without research rewards. Appendix E supplies the transport, persistence and authorization rules.

## 9. Parameters and amendments

### 9.1. Fixed rules and configurable values

Sections 4 and 6 specify the voting interval and completion budget. The strict quorum and once-only completion rules are separate from capacity settings and monetary allocation choices.

Genesis and the adopted policy supply four initial units, their authority and retirement order, queue and execution bounds, phase expiries, join limits, clock-error bounds and Test-NAO allocations. The v7 roster may grow to 32 through sealed claims; each exact snapshot determines its own quorum. These values determine capacity and operating costs and must support Appendix E.1's reservations and service conditions.

### 9.2. Bounded profile and open rules

Within the bounded v7 profile, parent-proof selection is deterministic: earliest admission height, operation order, then raw ProofId. Distinct new certificates with the same exact statement in one package are rejected, including a root/helper collision. Permitted identical aliases are checked and removed before publication. Reuse substitutes an eligible older proof with its existing attribution, prunes unused material and checks the normalized group. A versioned normalization receipt binds the original submission, selected parent and final result. New proofs in one package have one author who is also their recipient; joint authorship and separate-recipient authorization require further rules.

Each first completion credits one Test-NAO, or 1,000,000,000 atoms. Without eligible citations, the solution author receives 0.70 Test-NAO. With citations, the author receives 0.60 and the distinct first older boundary proofs share a 0.10 pool. Integer division precedes aggregation by beneficiary; remainder atoms follow canonical boundary order. The 0.20 validator service pool is split across all installed outgoing units under the selected parent. Each receives the integer quotient; remaining atoms follow canonical slot order. The reserve receives 0.10. Credits are independent of the agreement and seal signature subsets, including when a successor joins in the same record.

The bounded profile's balances are whole Test-NAO atoms, not fractional funded claims. Transfers, withdrawals and reserve spending are outside this profile.

At opening, an exact target already answered by an admitted unpaid helper closes as KNOWN_UNPAID, with no retrospective reward or claim. A paid family remains completed. Commitments bind the genesis, research attempt, author and authenticated original submission with secret randomness; the attempt differs from a consensus agreement round. Its reservation protects disclosure and settlement capacity. Expiry without a valid timely disclosure leaves the family unresolved.

The v7 profile includes bounded account registration, claim-backed finalized join intent, one contribution-ordered addition or replacement per sealed transition, stable-slot proposer priorities, per-height key rotation and incoming READY plus outgoing TERMINAL quorums. A terminal may select a linked successor run, but existing v5 history is not reinterpreted or upgraded in place. Broader public-network rules remain to be defined for multiple simultaneous research attempts, specialized proof-checking groups, joint authorship and separate recipients, historical-key security across external backups, sustainable recovery, reserve spending and live amendments. The exposure-service cycle and amendment-cycle duration and boundaries also remain undefined; neither is an agreement round, research attempt, voting window or signing period.

The v7 profile's genesis bounds records, storage and consensus retries; restart cannot reset those bounds. Such finite bounds do not establish continuous operation, which requires safe storage, synchronization and upgrade rules. Formal proof validity and the membership rule alone do not establish resistance to cheap-proof farming, manufactured citations, agenda censorship, concentrated ownership or historical-key compromise.

### 9.3. Open-ended public-network target and decisions

The target admits pseudonymous research keys without invitation and has no
fixed protocol-wide lifetime cap for accounts, participants, records or eventual
consensus participation across finite active committee snapshots. Independent
full nodes can verify the selected history without joining the committee. It
does not promise infinite physical capacity or an unbounded set of voters on
one record. Each action, verification step, record,
queue and active authority snapshot needs a finite work and byte budget. A
new key proves control of that key, not one-human-one-account. Research access,
network relay and voting authority are separate rights.

The current v7 bounds are 512 genesis accounts, 1,024 total accounts, 8,192
records per standard run, one active attempt and four to 32 installed units.
Linked successors carry state but do not remove these profile limits or prove
indefinite operation. Static literal peer endpoints and a bounded loopback
participant gateway do not provide public discovery or NAT traversal. The
founder may control all four starting units and thus a quorum; claims of
independent startup, resistance to founder censorship, and public safety are
not supported. The historical v6 256-seat experiments are not the current
v7 profile or physical multi-machine evidence.

The following choices require a versioned, agreed rule before this target can
be specified or implemented:

<b>Influence and research abuse.</b> Choose an objective, scarce source of
  validator influence and finite committee selection and rotation. Neither
  accounts nor earned claims establish independent operators by themselves.
  Specify proof-farming resistance separately from authority, and test key
  splitting, concentration and founder censorship. No stake, per-key vote
  or proof-as-consensus rule is selected.

<b>Work and state growth.</b> Choose enforceable admission pricing, quotas with
  fair access, rent or another resource mechanism; define who funds validation
  and archives, and whether safe pruning or verified checkpoints are allowed.
  Measure worst-case bytes and checking time per action and sustained separate
  machine service. No reward or test balance has established outside value.

<b>Continuation and amendments.</b> Choose the authority and consent rule for
  changing limits, active membership and software versions. Verify a unique
  linked history across transitions, preserve old proof IDs and beneficiaries,
  prevent a second settlement or eligibility claim for a completed family,
  and specify archive availability and conflicting-branch handling.

<b>Public transport.</b> Choose authenticated discovery and reachable routing
  for changing endpoints and NAT; bound connection and replay work. Test
  separate hosts under churn and hostile traffic. The current static peer
  list and loopback gateway do not meet this requirement.

Ethereum permits <link href="https://ethereum.org/guides/how-to-create-an-ethereum-account/" color="#222222">wallet-created accounts</link>, meters
execution with <link href="https://ethereum.org/developers/docs/gas/" color="#222222">gas and a block limit</link>, and weights <link href="https://ethereum.org/developers/docs/consensus-mechanisms/pos/attestations" color="#222222">validator participation</link>
by staked resources. These illustrate separate bounds on work and
influence; none is a selected NAOME rule. A NAOME rule must address formal
proof-checking costs, fabricated proof and citation chains, quorum handoff,
and founder censorship on its own terms.

These are open design decisions, not rules adopted by the current profile.
Founder control remains an explicit risk until a specified and observed
redistribution of effective authority changes it.

### 9.4. Candidate public committee and Proof of Useful Work

The public candidate uses no competitive nonce or hash search. Cryptographic
hashes bind identities, commitments and state roots without granting votes.
Research proofs are checked content, not votes. A finite committee could
order records under open, objective, Sybil-resistant entry and rotation.
Scarce influence, selection, quorum, recovery, governance and amendment
consent remain undecided. Records must continue without solved questions;
founder concentration can still censor or stop service. Every full node
checks signatures, resource bounds, formal results and state. Current v7
READY/TERMINAL seals do not automatically give a successor public finality.
Public records need exact bytes and atomic replay, plus conflict, finality,
archive and migration rules preserving attribution and once-only settlement.

At most a finite <i>C</i> questions may be active, each with a fixed family,
formal target and Foundation/checker version. The library stays live: any
verified proof in a prior accepted parent-chain block may be cited, even when
published after question opening. At full disclosure admission, check the
exact parent state and dependency closure. Neither a commitment nor an
earlier operation in the same block makes an unverified or same-block proof
citable. Replay checks this again if selected history changes. Appendix B's
opening-library root applies only to current v7. Reserve aggregate work and
storage for <i>C</i> questions and at most <i>K</i> submissions each.

Proof of Useful Work (PoUW) is useful formal proof search. Every approved
question has its own first fully valid solver prize. The proposed public
priority is its earliest fully valid disclosure confirmed in canonical
finalized chain order, by block height and operation position. Private
discovery time is unobservable. A commitment may protect against copying but
reserves no winner priority; an earlier unrevealed or invalid commitment
cannot delay a valid disclosure. Check the entire original proof and its
parent-eligible dependencies before assigning the prize. A later shorter
proof cannot revoke it. Finality, deadlines and invalid-input rules remain
to be defined. Current v7 instead prioritizes eligible commitment receipts.

If first valid results for different questions are ready in the same bounded
processing step, the shorter proof is processed first; each keeps its own
prize. Define that step (one block, settlement batch or another finalized
boundary), inclusion fairness, and any cross-question normalization. Fixed
and rolling submission schedules remain open. For example, A's first valid
proof has 18 steps and B's has 7. A joint batch processes B then A; both
win their own questions. A later 12-step proof cannot replace A's winner.

The proposed step score counts every canonical proof-normal-form step in the
original signed root and all new helpers, even helpers later pruned. The
current normal form treats an older reference as a leaf without minimizing
proofs. A new rule must choose whether each distinct certified reference
costs one step to reward reuse, or its recursively expanded lineage to limit
cheap reference chains. Reuse-aware counting is recommended for cumulative
research only with verified closure, anti-farming rules and separate hard
validation caps. A score binds to admission-parent dependencies and cannot
change with later library growth. Equal scores need a canonical tie-break.
Step count measures the proof result, not spent CPU time or voting weight.

A proof published through another question becomes citable in a later block,
but a completed target cannot earn a second paid completion. Specify its
known or settled state. Bound proof and lookup work, bytes, state growth and
peer buffers. Public relay needs home-NAT access; test floods, partitions,
concentration and independent archive replay on separate hosts. Importing a
v7 terminal state needs independent verification, consent and an exact
once-only map of accounts, proofs, outcomes, balances and claims.

A prototype should show empty records, parallel questions with independent
first-solver prizes and length-ordered ready results, later shorter proofs
without prize reversal, invalid disclosures, post-opening citations, and
one settlement per family. Test reference-score alternatives, authority,
conflicting histories, restart and aggregate resource limits.

### 9.5. Required operating properties

The safety, progress and recovery conditions in Section 8 and Appendices C through E are operating requirements. Choosing numerical parameters or approving a research question does not establish them.

### 9.6. Amendments and historical obligations

Amendments preserve sealed history, selected proofs and approved obligations. Changing the Foundation or identity rules requires an explicit mapping of historical completions that preserves their once-only effects and records conflicting polarities. A change cannot erase an earlier completion or issue a replacement eligibility claim. Voting-duration changes apply only to later openings; changes to question terms and reward shares apply prospectively and cannot reprice an approved obligation.

The proposed amendment gate calls for greater-than-two-thirds frozen-snapshot approval, two full intervening cycles, more-than-two-thirds outgoing migration readiness and the READY/TERMINAL gates. Its delay cannot be applied until the cycle boundaries noted in Section 9.2 are defined. The account and policy consent rules in Appendix E.3 also apply.
This roster-oriented amendment proposal does not automatically govern a
public successor; activation and any migration from v7 need an explicit
adoption rule.

The intended destination is an open-ended public research network with
permissionless pseudonymous access and a verifiable, bounded path to validator
authority. The v7 implementation demonstrates a finite trust-based slice,
including sealed proof attribution and linked successor replay. It does not resolve founder control, Sybil cost, resource funding or public transport.
The non-mining committee candidate separates record production from research
PoUW, but its authority, finality, reward, question and migration rules
remain open.
Those choices and separate-machine evidence are prerequisites to a public
safety or continuous-service claim.

<!-- APPENDICES -->

## Appendix A. Canonical objects and identities

Canonicalization expands permitted notation, removes unreachable material, orders dependencies, normalizes variables and merges exactly identical nodes. It neither minimizes proofs nor recognizes arbitrary mathematical equivalence. Parent-state substitution follows the separate rules in Appendix B.2. An identifier match is insufficient evidence of validity: referenced bytes, dependencies and checking evidence remain necessary.

[IDENTITIES]

ResolutionId uses a fixed hash domain and explicit length framing over the Foundation and canonical core <i>R</i>. QuestionId separately binds orientation, both targets, format version, checker profile, dependency context and resource bounds. Titles, authors, recipients and software labels do not reset the permanent completion key.

Inlining or citing a derivation preserves its DerivationId. Typed ArtifactIds use separate hash domains and explicit length encodings to bind the Foundation and canonical content. A group binds its root, canonically ordered surviving helpers, checked dependency edges and authenticated attribution without changing the approved targets or ResolutionId.

Changed derivations and certificates receive recomputed identities; existing referenced proofs retain theirs. Appendix B.3 binds these changes to the authenticated original. The artifact set uses a Merkle-Patricia root for presence and absence witnesses under an adopted trusted root.

Versioned identities preserve exact sealed references; historical migration follows Section 9.6. Offline definition authoring is separate from the proof-only selected library and cannot change a prototype question's targets or limits.

## Appendix B. Proof admission and reuse

### B.1. Original submission and authorization

A commitment binds the solution author, payment recipient, chain, research attempt, task and a canonical hash of the complete original submission, together with secret randomness. In the bounded profile the author and recipient are the same account. It covers the root, every helper, dependency edges and authenticated authorship and payment attribution. Its finalized receipt reserves a disclosure slot and the capacity defined in Appendix E.1. Section 4.4 governs disclosure and selection.

The original authenticated submission must satisfy its original well-formedness rules: its graph must be acyclic, helpers canonically ordered before their uses, every certificate and dependency valid, and its root a proof of an approved target. Lookup may precede costly checking, but substitution and pruning cannot repair an invalid original submission.

The approved v7 question fixes its targets and is bound to the immutable genesis profile, checker and selected library root at opening. The profile supplies the same proof-reference, exact duplicate-helper substitution and resource-limit rules for every question. It permits bounded helper certificates developed after approval, but no question-specific assumptions, definitions, reference permissions or limits. A broader network with selectable question policies would need explicit authorization and compatibility rules. Helpers cannot change the target or add axioms.

### B.2. Exact replacement and pruning

Before final validation, compare every submitted helper with proofs selected in the immutable sealed parent of the proposed settlement record. A duplicate requires matching StatementId and exact canonical actual-conclusion bytes under the fixed Foundation. A shared ResolutionId, opposite conclusion or arbitrary logically equivalent statement is insufficient. The fixed v7 rule replaces the helper's uses with a citation to an admissible existing proof. The existing proof retains its recorded author and payment beneficiary, including when its author is the submitter; the duplicate creates no new block or attribution. Section 9.2 gives the bounded profile's deterministic selector and single-author restriction.

After replacement, recursively remove every helper, dependency and citation no longer reachable from the root through actual proof uses. Recompute the surviving graph, canonical order and affected identities before checking it.

[FIG:reuse]

[CAPTION] Parent proof C establishes H's exact conclusion under the same Foundation and assumptions. Replacing H leaves F using A and C; B, used only by H, is pruned with its unused dependencies. Only F and A are new. C retains its beneficiary; discarded citations receive no payment.

### B.3. Final validation and the normalization receipt

The normalized graph must be acyclic, with each surviving helper ordered before its uses and reachable from the root through checked dependencies. Validate the root, every surviving helper and all actual final dependencies, including replaced references and their validity evidence. All required bytes must be available. Both this validation and B.1 are required within the capacity reserved under E.1; any failure prevents publication and settlement of the whole group.

A deterministic <i>normalization receipt</i> binds the original commitment receipt and submission hash, selected sealed parent, immutable profile identity, helper-to-existing-proof replacement map, final normalized bundle and recomputed identities. It also embeds the outgoing service-authority snapshot used to calculate service rewards. This permits historical inspection after later key and membership changes; the embedded snapshot is a claim until full history replay proves that it matches the selected parent. The receipt records the deterministic transformation from the authenticated original while leaving its commitment, signed bytes and signatures intact. An original signature does not authorize the rewritten bytes. Validators reproduce the transformation and check both forms. Joint authorization needs the further rules identified in Section 9.2.

If the proposed settlement parent changes, recompute and revalidate lookup, normalization, receipt, identities, citation eligibility and bounds against that parent. Timely valid disclosures remain eligible for later settlement subject to these checks; replacements, identities, beneficiaries and resource use may change.

### B.4. The direct bundle boundary

Follow validated dependencies from the normalized root through surviving helpers and every reached proof absent from the sealed parent. Stop each path at the first proof selected in that parent: these proofs form the <i>direct bundle boundary</i>. Traversal also crosses permitted intermediate proofs admitted earlier in the current record. Deduplicate by selected proof identity once per completion pool; repeated references and multiple paths add no entitlement. Ancestors behind the boundary receive no automatic payment, although dependencies required for validity still need checking. No proof admitted anywhere in the current record earns a citation payment anywhere in that record; eligibility uses the selected sealed parent before the entire record.

Replacement by an eligible old proof directs the citation allocation to its recorded beneficiary within <i>P</i>. Pruned helpers and discarded citations receive nothing. Section 6 defines the pool's funding; Section 9.2 gives the bounded allocation and identifies remaining choices.

### B.5. Publication and attribution

Surviving helpers become standalone proof blocks with their own addresses, authorship and references. They need no separate research-question vote or consensus decision and create no separate initial reward, question completion or eligibility claim. Disclosure supplies checking data; publication waits for the whole proof group to validate and actual final use to be confirmed.

Each surviving new block retains the authenticated authorship and payment attribution bound by the original submission. The bounded profile has one author and recipient for new blocks; a broader design would need explicit authorization for several authors or separate recipients. Authorization establishes neither historical discovery nor a resolution of all copying disputes. Reuse never overwrites existing attribution. A helper concerning a separately approved question does not by inclusion settle that question or authorize a second payment.

The settlement outputs in Section 5 enter the canonical state together. Any invalid original or final certificate, missing dependency, attribution failure or resource violation rejects the group as a whole. A reward-bearing record settles at most one approved and previously unpaid family, even if it admits several proof blocks. Invalid, duplicate, replayed or unfinalized candidates create no reward.

## Appendix C. Voting records and certified time

### C.1. Ballot and closure rules

A sealed opening fixes the exact proposal, attempt number, policy version, parent configuration, its <i>N<sub>open</sub></i> owner accounts in the frozen electorate and certified time <i>T</i>. The deadline and threshold are defined in Section 4.3. A ballot binds chain, proposal, attempt, snapshot and YES or NO. It counts only as the first valid recorded ballot by that owner for that attempt, in a subsequent sealed record with time strictly below <i>D</i>. Missing or malformed output creates no ballot; NO and absent weight remain in <i>W</i>.

Profile edits, repeated inference and changed keys cannot overwrite an existing ballot. Owners may deliberate before signing. Authorized key rotation or revocation affects subsequent ballot admission, with no change to recorded votes or snapshot weight; a replacement key grants no second vote. Retired owners keep only the research mandate of the opening snapshot until closure. New owners have no vote on that attempt. Owner account authorization for that mandate remains separate from retired consensus and transport keys.

Every record closes all due windows before ordinary operations. The first record with time at least <i>D</i> records APPROVED exactly when the threshold is met, otherwise NOT_APPROVED. Early quorum does not shorten the window. The bounded profile has at most one active window. Approval authorizes solution operations only in a later record after closure is sealed. A subsequent attempt receives no ballots from its predecessor.

### C.2. Time certificates

Each record contains one bounded certificate of integer UTC-second reports. At least q(N_out) and at most N_out distinct consensus keys in the selected outgoing snapshot sign reports bound to genesis, parent record, height and the TIME role. A vacant slot cannot report but still counts in the installed denominator. Correct owners report their current time only after verifying the parent. Let <i>m</i> be the lower median of the included reports:

[EQ] record time = max(parent time, m).

Record identity binds this time, and genesis supplies the initial value. Under less than one third faulty weight, correct reporters hold more than half the weight in every sufficient certificate, placing the median between correct reported times. Correct clocks must remain within the configured error bound <i>ε</i>. Collection and sealing can add delay, and a retained consensus value keeps its original time evidence.

An old-parent report cannot authorize a later height. TIME signing uses the current period key, separately from research ballots, and stops with that period's ordinary consensus signing. Historical replay checks signatures and arithmetic against the recorded parent snapshot, rather than the reader's current clock. No local clock event finalizes an outcome or changes authority.

## Appendix D. Agreement and handoff

### D.1. Round transitions

Outgoing signers and weights are fixed throughout a height. Proposer priorities advance over stable slot IDs; an empty scheduled slot consumes its turn without a proposer. Authenticated messages bind chain, outgoing snapshot, height, round and role. A quorum needs q(N_out) distinct current keys out of the installed units. Each round contains a proposal, PREVOTE and PRECOMMIT. Correct signers send at most one vote of each kind per round. NIL supports no record. A lock identifies a value and round; a retained valid value records verified earlier prevote evidence. Every height starts without either.

A proposer reuses its retained valid value and round, if any, or proposes a fresh value. An unlocked signer can prevote a valid proposal. A locked signer prevotes the proposed value if it matches the lock, or unlocks for matching verified quorum evidence strictly newer than its lock and below the current round. Otherwise it prevotes its locked value.

Before proposing or prevoting an unconstrained fresh record, a continuing signer requires its exact locally anchored rotation offer in the plan. Only at the 32-unit ceiling is the oldest unit exempt when a valid candidate replaces it. A proposal carrying a verified earlier prevote quorum follows the ordinary lock rules instead. Without the local offer, an unlocked signer prevotes NIL and a locked signer prevotes its locked value; a verified proposal remains retained for quorum and conflict checks. This protects a late owner's opportunity to prepare the next period, but cannot recover an agreed transition after its incoming quorum is lost.

From prevoting onward, current-round quorum prevotes that match a valid current proposal update the retained value and round. While the signer is prevoting, they also establish its lock and permit precommit. Evidence received after a NIL precommit updates retention but permits no second precommit. Without a proposal, including on proposal timeout, a signer prevotes its locked value or NIL if unlocked. Quorum NIL prevotes or timeout while prevoting cause NIL precommit.

Any current-round prevote quorum starts the prevote timer once while prevoting; any current-round precommit quorum starts the precommit timer once. Votes counted to start these timers need not match a value. Precommit timeout advances an undecided signer to the next round, retaining its lock. Messages from the same higher round above one-third weight permit joining that round. Matching non-NIL quorum precommits at any round of the height decide only with their complete, available and valid proposal.

For eventual message delay <i>Δ</i>, timers must eventually satisfy the conditions in [1]:

[EQ] T<sub>propose</sub>(r) &gt; T<sub>precommit</sub>(r-1) + 2Δ,<br/>T<sub>prevote</sub>(r), T<sub>precommit</sub>(r) &gt; 2Δ.

### D.2. Sealing and capability retirement

The selected parent contains the outgoing authority for the next record. Its
agreed record already commits a bounded plan of fresh owner-authorized key
offers and, optionally, one exact finalized candidate intent. A missing
rotation offer makes its stable slot vacant; the installed-unit threshold does not
shrink. The candidate must be the oldest eligible queued claim. Without a
candidate offer, no join occurs and the queue retains its position and expiry.

The agreement alone yields a provisional successor. Incoming validators replay
the selected predecessor, verify the agreement, durably stage the exact record
and successor, then sign READY. At least q(N_in) READY signatures attest preparation.
Outgoing validators verify this quorum, save exact TERMINAL signatures in
anchored custody, stop old consensus and TIME signing, close old transport and
retire locally controlled old-period secrets before releasing saved signatures.
At least q(N_out) outgoing TERMINAL and q(N_in) incoming READY signatures form
the seal. The context binds genesis, height, record, previous and next state
commitments, and both snapshot IDs. Only the complete envelope selects the
successor and activates ordinary incoming signing.

After a crash, saved signatures can be resent, but an old signing capability
may not be restored to repair a failed seal. Local custody retires managed
keys; external copies, backups, regenerating seeds and alternative signing
routes require operator attestation. Deleting local files or labeling
signatures with heights is insufficient. If sufficient reachable weight is
absent, transition and later progress can halt. Time does not reduce the
denominator or roll back sealed history.

A vacant or replaced incoming slot does not remove its outgoing owner's
TERMINAL duty. Fresh owner-authenticated evidence transport may carry that owner's saved
signature or a complete seal to peers without granting incoming voting
authority. Recipients verify the selected parent and seal before adopting the
successor.

## Appendix E. Capacity, persistence and authorization

### E.1. Ordered service

Authenticated proposals enter the bounded queue in finalized receipt order, using height and operation index. Per-record openings and ballot bytes are bounded. Allocation follows queue order as capacity becomes available. The parent must already contain an opening's required capacity; closures in the same record cannot supply immediately reusable slots. An opening reserves a voting slot, ballot and closure capacity, and maximum solution-phase capacity. Reservations bound helper count, original and final bytes, dependency depth, expansion and traversal, parent-match searches, normalization and both original and final validation. A small pruned result does not excuse an oversized or invalid original submission.

Queued entries expire after the policy-defined waiting interval without starting a vote; retry places them at the tail. A family has at most one queued, voting or approved live attempt. Later attempts require fresh admission, a new snapshot and a new full window; a completed family cannot reopen. Rejection releases the solution reservation. Approval retains it until settlement or expiry without a timely valid disclosure; timely valid disclosures remain settleable. Consumed or expired reservations cannot be reused.

Join intents enter a 32-family queue in finalized receipt order. Revisions retain the first receipt and expiry. Each record plan may use the oldest eligible claim once; without its candidate offer, the record rotates keys instead. Expired, stale or consumed claims cannot join. Service assumes honest proposers, bounded verification and eventual delivery. Churn or censorship can extend waits. Continuous submission has no fixed question quota, but admission remains bounded.

### E.2. Durable history

Encrypted transport bounds connections, bytes and work. Selected history, signer state, offers and handoff preparation require durable storage with an independent anchor. A receiver persists and anchors data before acknowledging; restart verifies its prefix and discards an incomplete tail. A write fault, corruption or anchor mismatch halts the node. Coordinated rollback of data and anchor remains undetected. Operating headroom covers the next signing height and handoff, checked throughout the run; it does not reserve the full possible archive. Addresses, indexes and storage receipts confer no authority.

Archive and handoff evidence require continuing storage and funding. Section 8.4 states the reader's independent-anchor and current-state requirements.

### E.3. Account and policy authority

Every distinct authorizing account signs the complete operation and consumes its nonce once, even when it fills several roles. The bounded profile credits whole-atom Test-NAO balances and records a separate nontransferable author eligibility claim. It has no transfer, withdrawal or reserve-spending operation; an empty control record cannot spend the reserve. Broader monetary claims or payments would need explicit authorization and conservation rules.

Policy changes require current and replacement-policy consent. Without preconfigured recovery, a lost authorizing key has no administrative remedy. Protocol amendments and preservation of historical obligations follow Section 9.6.

## Reference

[REF1] E. Buchman, J. Kwon and Z. Milosevic. The latest gossip on BFT consensus. 2019, version 3. <link href="https://arxiv.org/html/1807.04938v3" color="#222222">Algorithm 1 and agreement argument</link>.
