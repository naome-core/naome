# NAOME
# A Public Network for Formal Research

[META] Whitepaper · Public-network proposal and trusted MVP status · 20 September 2026

[ABSTRACT] NAOME is a proposed protocol for selecting mathematical research questions, checking answers and maintaining a public library of reusable results. Validator owners authorize research; contributors submit certificates under a declared formal rulebook. Settlement publishes the solution and its used helpers, completes the question family once, allocates a bounded reward and gives the solution author an eligibility claim. Approved reuse rules preserve older proofs and their attribution. Eligible authors may request entry to a finite validator electorate through contribution-ordered replacement. The protocol separates research judgment, mathematical verification and agreement on history. A trusted four-validator MVP implements the research workflow with fixed membership and test balances. The broader public-network proposal retains unresolved rules and explicit assumptions about authority, availability and signing capabilities.

## Implementation status: trusted MVP and next pilot

The executable trusted MVP now implements formal question submission, owner YES/NO votes, commitment and reveal, actual proof or refutation checking, helper reuse, atomic rewards, passive eligibility claims, durable restart and full-state replay. Its scope is four fixed equal validators, accounts registered in genesis, one active question, one author/recipient per new proof group and command-line operation. Three of the four validators form the quorum. A claim records eligibility only; it grants no voting weight in this implementation.

Recorded qualification includes complete local test and release runs, Linux/macOS/Windows CI, four-process fault and replay tests, and a real-window lab with actual bounded agenda-agent review. That lab used 300-second voting and 120-second commitment and reveal windows. These are snapshot-specific results from the repository verification record, not evidence for the whole public-network design. Windows checks include independent archive verification; validator custody requires Unix. Neither separate physical machines nor the full seven-day research window has yet been qualified.

The next milestone is a trusted multi-machine pilot. Portable per-node bundles and independent archive collection support its preparation. Operators must still demonstrate real placement, clock and network behavior, research completion with later citation, outages, restart and matching replay on the target hosts. The runbook and verification record remain the executable source of operating instructions and evidence. Sections 7, 8.2 and 9.4 describe proposed dynamic membership, signing-capability retirement and amendments; those mechanisms are outside this MVP. Section 9.2 distinguishes adopted MVP answers from remaining design questions.

## 1. Purpose and scope

NAOME coordinates three decisions in shared mathematical research: which questions receive resources, which answers satisfy their formal obligations, and which history assigns the resulting rights. The agenda directs finite attention, checking and storage capacity. The public library preserves checked results for later use. Agreement establishes submission order, completed question families, payments and validator membership.

A proposal combines a readable purpose with an exact mathematical task. Validator owners judge whether to authorize it; contributors seek a proof of an approved conclusion under the declared Foundation, or formal rulebook. Approval expresses a research preference, while checking establishes derivability. The shared history records both without treating either as evidence for the other.

A paid completion allocates currency to designated recipients and creates a nontransferable eligibility claim for its authenticated solution author. This claim provides a possible route to validation; currency holdings confer no voting weight.

Unless explicitly labelled as implemented MVP behavior, the following sections describe the broader public-network proposal. It contains specified mechanisms and material open rules, collected in Section 9.2. Applicable rules and bounds must be fixed before the affected question is approved. Safety and service also depend on the distribution, exposure and availability of authority; mathematical checking does not establish those conditions.

## 2. Network model and research lifecycle

### 2.1. Participants, records and rights

A <i>question author</i> proposes a task. A <i>solution author</i> authenticates a submitted bundle containing the solution and its helper proofs. A <i>validator</i> checks records and participates in agreement; its <i>owner</i> controls the associated authority. An owner may hold several voting units, whose weights are combined. A local <i>agent</i> assists its owner in reviewing research questions.

The installed electorate contains <i>K</i> equal voting units. Its owners authorize research and membership handoffs. Section 7 describes the initial allocation and how qualifying authors may request replacement of the oldest unit. Equal units do not by themselves establish dispersed ownership.

A solution author may designate a separate <i>research-payment recipient</i>. Each reusable proof block records authenticated <i>proof authorship</i> and payment attribution; eligible later use may generate a citation payment to the recorded beneficiary. These roles may differ within one submission. A <i>record proposer</i> packages operations for agreement and acquires no authorship merely by including them.

<i>NAO</i> is the accounting unit; one NAO equals one billion indivisible atoms. Proposing questions, enrolling, committing, disclosing and receiving rewards require no mandatory NAO prepayment. Admission and reservations bound the shared processing these activities can consume.

The history consists of ordered <i>consensus records</i>, or blockchain blocks, at successive <i>heights</i>. A <i>seal</i> authorizes an agreed record's successor. The selected sealed parent provides the historical state against which a proposed successor's use of older proofs is evaluated.

A <i>proof block</i> is an independently addressable library object containing a proof and its references. Several may enter through one consensus record, without separate consensus steps or heights. Agreement may use several <i>rounds</i> at one height. A research <i>attempt</i> includes voting and, if approved, a solution phase, potentially spanning many records and membership changes. Voting duration and the number of installed units are independent parameters; Section 9.2 addresses the separate round field in commitments.

### 2.2. From a question to a settled result

A well-formed question enters a bounded queue. When capacity is available, a sealed record opens a seven-day vote on its exact terms. Approval by more than two thirds of the opening electorate's full weight begins a separate solution phase.

Contributors commit to concealed proof bundles before disclosing them. The earliest eligible receipt with a valid disclosure wins across the approved outcomes. Acceptance checks the original submission, applies permitted reuse and pruning, and checks the final proof. Sections 4 and 5 explain this path.

[FIG:system]

[CAPTION] The research path runs from authorization to checked settlement. Published proofs support later research; the author's voluntary join request follows a separate membership installation.

For example, a certificate may prove the refutation target and cause the original question to be labelled REFUTED. Its author may designate a different research-payment recipient, who can be paid without the author operating a validator. The author may request admission later while the eligibility claim remains usable.

## 3. Formal questions and proof objects

### 3.1. The mathematical obligation

A question's <i>.nao</i> source declares a Foundation, a closed statement <i>Q</i>, permitted library dependencies, a bounded policy for new helpers and replacement by older proofs, resource bounds and <i>success = "resolve"</i>. A closed statement has no free variables. Its formal obligation must compile before voting begins; a solution need not accompany the proposal. The readable purpose must match the formal statement. Compilation checks syntax and bounds, not the fidelity or scientific value of the translation.

The Foundation <i>naome:zfc</i> consists of classical first-order logic with equality over sets, ZFC axioms, and the Separation and Replacement schemas. A certificate supplies axiom or schema instances, inference steps and checked references. Verification establishes derivability under this rulebook. The interpretation of that result relies on sound checking and a consistent Foundation. Unapproved assumptions are forbidden.

Approval covers both possible outcomes. A certificate must prove one of two exact conclusions determined before voting. A counterexample qualifies only when a checked certificate establishes the refutation target with the required domain and assumptions. Failure to find a proof leaves the question unresolved. A proof of the disjunction <i>Q or not-Q</i> alone selects neither outcome. Some statements have neither a proof nor a refutation in the chosen Foundation.

### 3.2. Question families and resolution identity

A question and its negation concern the same resolution for settlement purposes. Before voting, notation is expanded and only leading negations are removed from <i>Q</i>, leaving a canonical core <i>R</i> and their parity. The approved conclusions are exactly <i>R</i> and <i>¬R</i>. For even parity, these mean PROVED and REFUTED respectively; odd parity reverses the labels. This convention uses classical double-negation equivalence.

The permanent <i>ResolutionId</i> identifies the Foundation and canonical core. Opposite wording and additional leading double negations therefore share one completion key. The contextual <i>QuestionId</i> binds the exact orientation, approved targets and checking conditions. Different presentations can share a family-wide settlement identity, but the rule does not identify every logically equivalent formulation.

[FIG:graph]

[CAPTION] The library records the conclusion actually proved. Reversing the question's wording preserves its ResolutionId and cannot create another completion.

The library admits one selected solution of either target for a resolution family. Settlement, rather than validation alone, completes that family permanently. Another solution or author cannot create a second paid completion or eligibility claim. Repackaging an existing proof adds no proof block. Section 9.2 specifies the MVP treatment of later questions already answered by unpaid helpers.

After refutation, the rejected claim is not entered as a theorem. If certificates for both targets validate under the same Foundation, the conflicting evidence is retained for investigation. A second settlement is prohibited, and the earlier outcome remains in the recorded history.

### 3.3. Certificates, helpers and definitions

A bundle contains a root certificate for the approved question and helper certificates for their own closed statements. Surviving helpers become reusable proof blocks when the group settles; internal inference steps are not separate publications. Appendix B specifies publication and attribution.

Definitions introduce notation. Relations abbreviate primitive graphs; a function with one or more inputs requires a selected proof that its expanded graph gives exactly one output for every input. Definitions expand before checking and introduce no new axioms. Recursion, zero-input relations or functions, and standalone constants are excluded.

Helpers may be developed after approval within the frozen dependency context and used by later certificates in the normalized group. This checking order does not make them older proofs for payment. Appendix A distinguishes statements, derivations, certificates and typed artifacts; Appendix B gives the admission rules.

## 4. Research authorization and submission

### 4.1. Admission and reserved capacity

Anyone may submit a question with its purpose and exact terms. Admission checks formalization and byte limits and reserves capacity; it does not imply approval. Finalized receipts establish queue position. Raw arrival at a peer carries no position guarantee.

At most <i>C</i> questions may be voting concurrently. With fixed duration <i>X</i>, these slots permit at most <i>C/X</i> openings per unit time in steady operation. Queue waiting adds to the seven-day vote. Capacity must allow review, outages and delivery with headroom; the window guarantees neither a ballot from every owner nor fair admission under flooding.

Reservations cover voting and the bounded solution phase, including work on the original submission. Appendix E.1 specifies queue order, expiry, retries, family uniqueness, capacity reuse and join service.

### 4.2. Owner judgment and agent review

Each validator node maintains an owner-defined, editable <i>Research Profile</i> describing its research interests. Its agent reads the exact question and may retrieve related questions, checked results and their assumptions through bounded read-only tools. The agent returns YES or NO with a bounded reason. The owner authorizes the resulting ballot. This is a judgment about the proposed use of resources, including whether the formal task reflects its stated purpose.

[FIG:agenda]

[CAPTION] The Research Profile guides local review. The owner authorizes the ballot, whose weight comes from the opening snapshot; the agent's recommendation establishes no mathematical conclusion.

Agents continuously process open questions in deadline order, breaking ties by opening order and skipping decisions already recorded. Total inference time and tool use are bounded per question and attempt, including retries. Each validator reserves a review-work budget. A failed or exhausted review yields to other work and produces no ballot. Submitted text and retrieved material are untrusted input, separate from owner instructions. A valid signature establishes authorization; it does not establish the quality of the judgment or demonstrate that an AI was used.

### 4.3. The frozen seven-day vote

A sealed opening freezes the proposal and electorate for the seven-day vote. Let <i>W</i> be its full combined weight, <i>Y</i> the recorded YES weight, <i>T</i> the certified opening time and <i>D</i> the deadline:

[EQ] D = T + 604,800 seconds; approval requires 3Y &gt; 2W.

With 100 units, 67 YES approve the task; 66 do not. The result authorizes research resources and says nothing about the statement's truth. Appendix C.1 gives ballot admission, deadline and closure rules; C.2 defines certified time.

The frozen snapshot preserves a stable electorate even if membership changes during review. Former owners can therefore influence attempts opened during their membership, using research authority protected through closure. A halt can consume part of the voting interval, as discussed in Section 8.3.

### 4.4. Commitment, disclosure and selection

Approval permits a bounded solution phase with separate commitment, disclosure and expiry rules. A contributor authenticates a commitment to the complete original submission. Its finalized receipt reserves disclosure and checking capacity. Appendix B.1 specifies the committed contents and authorization.

The author discloses only after commitment closure has been sealed. After disclosure closure, the earliest eligible valid receipt wins in canonical order across both approved outcomes. A missing or invalid disclosure receives nothing. This order identifies the successful authenticated submission; it does not establish who first discovered the mathematics. Approval, commitment closure and settlement occur across the required sealed phases and cannot be combined into one unsealed record.

[FIG:delivery]

[CAPTION] Sealed closures separate commitment from disclosure and selection. Settlement follows only after the selected submission passes acceptance.

An unresolved solution phase expires without recording a refutation, issuing money or eligibility, or independently publishing its helpers. Timely valid disclosures remain eligible for later settlement under the parent-dependent checks in Appendix B.3.

## 5. Proof acceptance and publication

Acceptance connects an authenticated submission to a reusable public result. Both the original bundle and its final form must validate. Under the question's frozen policy, normalization may replace duplicate helpers with admissible older proofs and remove material no longer used by the root. Appendix B specifies the exact matching, pruning, authorization and validation rules.

[FIG:helpers]

[CAPTION] Original validation, authorized reuse and final validation lead to publication of the used proof group. A failed acceptance check rejects the group as a whole.

A normalization receipt makes the transformation reproducible while preserving the original signatures. This allows reuse without assigning the submitter another author's work. A changed settlement parent requires renewed checks under Appendix B.3.

Settlement atomically publishes the selected root and surviving helpers, permanently completes the approved resolution family, creates the solution author's eligibility claim and records research and citation allocations. The proof blocks remain independently reusable without copying the original bundle. Additional helpers do not create additional paid completions or initial eligibility claims.

Other valid records may carry research, transfers and maintenance without issuing currency. Appendix B.5 defines the publication boundary and the once-only reward conditions.

## 6. Rewards and accounting

### 6.1. The completion budget and its recipients

Each paid research completion issues exactly one NAO, equally for proof and refutation: 0.20 NAO funds validator service, 0.10 NAO enters the reserve, and 0.70 NAO funds the solution recipient and a citation pool of <i>P</i> NAO. The solution recipient receives 0.70 NAO minus <i>P</i>. Each completion has one pool within this budget; helper admission adds no issuance.

Section 9.2 records the implemented MVP citation terms and separates them from the broader proposal. The applicable terms must be fixed before the affected question is approved.

[FIG:payments]

[CAPTION] The one-NAO completion budget includes the citation pool P. Monetary allocations and the solution author's eligibility claim are separate rights.

### 6.2. Citation eligibility follows final use

Citation eligibility follows actual use in the final proof. Its <i>direct bundle boundary</i> consists of the first older proofs reached along dependency paths, where older means selected in the sealed parent before the entire record. Direct describes this boundary, which may lie beyond several helpers, rather than a fixed number of reference edges.

[FIG:citation]

[CAPTION] Traversal stops at the first selected parent proof on each path. Checking may continue beyond this payment boundary to establish validity.

Only eligible boundary proofs may share <i>P</i>. Appendix B.4 specifies traversal, deduplication, replacement attribution and exclusions. Newly published proofs may qualify through use in later paid completions.

Actual dependency checking establishes use, not scientific necessity; it does not prevent a contributor from constructing avoidable dependencies. A bounded pool limits the amount available for distribution but does not alone establish a fair allocation. Citation counts and NAO ownership create no additional voting units.

### 6.3. Conservation and the cost of operation

Service distribution is independent of which sufficient signature subset certifies the record. Exact fractional entitlements conserve the service pool and preserve an owner's combined entitlement if its weight is divided among keys. Account and nonce values use exact growing natural numbers; funded service entitlements retain their exact fractional amounts until whole-atom withdrawal under Appendix E.3.

Genesis records the initial monetary allocation <i>S<sub>0</sub></i>. For <i>N</i> finalized paid completions and no protocol burn, supply and its allocation obey:

[EQ] S = S<sub>0</sub> + 10<super>9</super>N atoms.<br/>liquid balances + funded claims + locked funds + reserve = S.

There is no fixed lifetime supply cap. Resource bounds limit admitted work, while approved questions may finish at different times or in clusters. Validators can authorize easy tasks; the approval rule alone provides no economic scarcity or measure of scientific value.

An empty reserve does not invalidate control transitions. Operators nevertheless need resources for review, agreement, storage and delivery, including periods without paid completions. Launch operators bear or separately fund these costs before the first discovery. Issuance, accumulated reserves and voluntary external support are possible funding sources; sustainable service depends on their actual value and availability. Appendix E.3 governs reserve spending.

## 7. Validator membership

### 7.1. Contribution-ordered replacement

The electorate has a fixed number <i>K</i> of equal voting units, each associated with an owner and an original contribution-completion ordinal. Active units add together for record agreement and research votes, subject to each attempt's frozen snapshot. There is no per-person cap or independent-identity assertion; splitting the same contributions among keys preserves combined weight.

The winning author may voluntarily request admission using the completion's nontransferable eligibility claim, independently of payment. The author authenticates the request and binds a validator key. The claim must be unused and strictly newer than the oldest installed unit. Successful installation inserts it at its original ordinal and retires that oldest unit. At most one unit is replaced per transition.

[FIG:membership]

[CAPTION] In this six-unit illustration, unused contribution 19 qualifies because it is newer than the oldest installed contribution, 10. A successful installation replaces 10 and places 19 in its original contribution order. This example shows the replacement arithmetic; ownership of the six units is a separate matter.

The ordinal does not change with delayed joining, retry, key rotation or re-registration. An installed claim is permanently consumed, including after retirement. An unused claim becomes stale when the oldest installed boundary passes it. Thus the active set remains finite and total weight stays constant after bootstrap. The permanent research archive continues to grow.

Time and ordinary records do not retire units; without joins the electorate remains unchanged. Earlier unused claims may still qualify, so replacement need not represent newly performed research. The rule uses neither calendar expiry nor fractional age weights.

Activation requires a previously sealed completion, author consent and an outgoing-authorized handoff. New weight cannot authorize its own installation. Section 8 and Appendix D describe preparation, sealing and the availability consequences of failed installation.

Genesis supplies a full initial allocation, its retirement order, <i>K</i> and join-service limits. This initial authority is adopted trust. The membership rule describes later replacement and does not establish that the initial allocation, or subsequent acquisition of claims, is fair.

### 7.2. Distribution of authority

Formal checking limits which certificates may settle a task. It does not establish the independence of authors or equal costs of acquiring eligibility. Incumbents influence the research agenda and may favor specialties, approve easy distinct targets, fragment work, buy solutions or censor questions and join requests. Owners' agents may share errors or respond to malicious descriptions. Authors can stockpile solutions or bank unused eligibility claims while the participation boundary is stationary.

One replacement changes a fixed coalition's share by at most <i>1/K</i>. A coalition close to one third can cross that boundary with a single replacement. Its active share can also differ substantially from its lifetime contribution share when its claims occupy the installed set. Contribution ordering prevents re-dating; it supplies no lower bound on the cost of acquiring control. Safety therefore requires the explicit concentration and exposure assumption in Section 8.3, alongside the membership rule.

## 8. Agreement, security and operation

### 8.1. Agreement on the shared state

A record applies an ordered, bounded sequence of operations to one immutable parent state. All operations are evaluated on provisional state; any failure rejects the entire candidate. The record commits to its predecessor, height, configuration, operations and complete resulting state. This includes artifacts, questions, ballots, commitments, completions, eligibility claims, accounts, funded balances, reserves and queues. A sufficient signature subset certifies the record without changing its identity.

Agreement selects a valid record; sealing authorizes its successor. For a height, outgoing signers and weights remain fixed. Quorums count distinct authenticated signers and require more than two thirds of that configuration. Correct validators support a record only after obtaining its bytes and checking all its effects. The round structure uses proposals, PREVOTE, PRECOMMIT and locks to restrict conflicting support, following the agreement model in [1]. Appendix D states the relevant transitions. The cited agreement argument does not establish the distribution of NAOME voting authority or the adequacy of its research incentives.

### 8.2. Sealing and signing-capability retirement

Sealing links an agreed record to its successor through two duties: incoming validators durably prepare the successor, and outgoing validators retire the period's signing capabilities. READY records preparation; TERMINAL seals the transition after retirement. Appendix D.2 gives the required sequence and quorum evidence.

[FIG:agreement]

[CAPTION] Preparation precedes READY. Saved TERMINAL signatures are released only after signing capabilities are retired; the outgoing seal authorizes the next height.

Effective capability retirement prevents further signing for the old period. It is an operating property beyond a change of configured membership. Surviving research-ballot mandates use separate authority under Appendix C.1.

Handoffs need no membership overlap, while contribution admission still replaces at most one unit per transition. Durable preparation alone does not guarantee continued availability.

### 8.3. Safety and progress assumptions

For signing period <i>h</i>, let <i>W<sub>h</sub></i> be installed weight and <i>A<sub>h</sub></i> the weight faulty or exposed at any time from capability creation through sealing. The safety assumption is:

[EQ] 3A<sub>h</sub> &lt; W<sub>h</sub>.

Purchased control, stolen copies and regenerating seeds count toward this exposure. Changing victims does not reset it. Safety also depends on correct checking, cryptography and effective capability retirement. Retirement of a voting unit alone does not stop retained historical keys from signing a fabricated past. Service assumptions count the union of faulty or exposed owners over the applicable service cycle. Its boundaries remain unspecified, as recorded in Section 9.2.

Progress requires more than two thirds correct and available outgoing and incoming weight, bounded work and eventual message delivery within a delay bound. At least one third unavailable or withholding weight can block agreement and the membership replacements that might change participation. Unavailable weight remains in the denominator. Recovery outside these assumptions requires an explicit trust decision; neither elapsed time nor a reduced set of responders changes authority.

Certified protocol time determines deadlines. Correct clocks have a bounded error, while collection, agreement and sealing add delay. During a halt, no voting outcome finalizes. Fresh time evidence on recovery may close expired windows immediately, so the seven-day interval is not a guarantee of seven reachable days of review. Appendix C gives the time-certificate rule; Appendix D gives agreement timing conditions.

### 8.4. Durable history and current-state access

Readers validate history from an adopted genesis and retain an independent anchor. An artifact-set root can support presence or absence witnesses under a trusted root, but neither the root nor a storage receipt establishes mathematical validity or finality. A reader isolated from the network cannot infer that its valid history is current. Verified conflicting sealed successors cause a halt.

Durable recovery and archive storage support later checking and incur costs even without research rewards. Appendix E supplies the transport, persistence and authorization rules.

## 9. Parameters and amendments

### 9.1. Fixed rules and configurable values

Sections 4 and 6 specify the voting interval and completion budget. The strict quorum and once-only completion rules are separate from capacity settings and monetary allocation choices.

Genesis and the adopted policy supply <i>K</i>, the initial authority and retirement order, <i>C</i>, queue and execution bounds, phase expiries, join limits, clock-error bounds and monetary allocations. These values determine capacity and operating costs and must support Appendix E.1's reservations and service conditions.

### 9.2. Adopted MVP rules and remaining public-network decisions

For the trusted MVP, parent-proof selection is deterministic: earliest admission height, operation order, then raw ProofId. Distinct new certificates with the same exact statement in one package are rejected, including a root/helper collision. Permitted identical aliases are checked and removed before publication. Reuse substitutes an eligible older proof with its existing attribution, prunes unused material and checks the normalized group. A concrete versioned normalization receipt binds the original submission, selected parent and final result. The MVP has one author, who is also the recipient, for all new proofs in a package; it does not implement joint authorship or recipient delegation.

Each first completion issues 1,000,000,000 Test-NAO atoms. Without citations, the author receives 700,000,000 atoms. With citations, the author receives 600,000,000 and the distinct first older boundary proofs share a 100,000,000-atom pool. Integer division precedes aggregation by recipient; remainder atoms follow the canonical boundary order. Each of the four validator accounts receives 50,000,000 atoms and the reserve receives 100,000,000. This conserves issuance independently of the signature subset. Test balances have no promised market value or redemption.

At opening, an exact target already answered by an admitted unpaid helper closes as KNOWN_UNPAID, with no retrospective reward or claim. A paid family remains completed. Commitments bind the genesis, research attempt, author and authenticated original submission with secret randomness; that attempt is distinct from a consensus agreement round. The active attempt protects its reserved reveal and settlement capacity. Expiry without a valid timely reveal remains unresolved. These are adopted, tested MVP rules, not open choices within that implementation.

The public network still needs decisions and evidence for account admission, multiple simultaneous research attempts, any joint authorship and separate recipients, contribution-based membership installation, effective signing-capability retirement, historical-key security and live amendments. Weighted service balances and reserve spending in Appendix E.3 are not implemented. The exposure-service cycle and amendment-cycle duration and boundaries remain undefined. They must not be equated with an agreement round, research attempt, voting window or signing period.

The MVP also remains finite: genesis bounds records, storage and consensus retries. Restart cannot reset those bounds. Continuous operation needs an explicit, safe storage, synchronization and upgrade design. Proof validity and a working trusted pilot do not establish resistance to cheap-proof farming, manufactured citations, agenda censorship, concentrated ownership or historical-key compromise.

### 9.3. Required operating properties

The safety, progress and recovery conditions in Section 8 and Appendices C through E are operating requirements. Choosing numerical parameters or approving a research question does not establish them.

### 9.4. Amendments and historical obligations

Amendments preserve sealed history, selected proofs and approved obligations. Changing the Foundation or identity rules requires an explicit mapping of historical completions that preserves their once-only effects and records conflicting polarities. A change cannot erase an earlier completion or issue a replacement eligibility claim. Voting-duration changes apply only to later openings; changes to question terms and reward shares apply prospectively and cannot reprice an approved obligation.

Amendments require greater-than-two-thirds frozen-snapshot approval, two full intervening cycles, more-than-two-thirds outgoing migration readiness and the READY/TERMINAL gates. Section 9.2 records the undefined cycle boundaries. The account and policy consent rules in Appendix E.3 also apply.

<!-- APPENDICES -->

## Appendix A. Canonical objects and identities

Canonicalization expands permitted notation, removes unreachable material, orders dependencies, normalizes variables and merges exactly identical nodes. It neither minimizes proofs nor recognizes arbitrary mathematical equivalence. Parent-state substitution follows the separate rules in Appendix B.2. An identifier match is insufficient evidence of validity: referenced bytes, dependencies and checking evidence remain necessary.

[IDENTITIES]

ResolutionId uses a fixed hash domain and explicit length framing over the Foundation and canonical core <i>R</i>. QuestionId separately binds orientation, both targets, format version, checker profile, dependency context and resource bounds. Titles, authors, recipients and software labels do not reset the permanent completion key.

Inlining or citing a derivation preserves its DerivationId. Typed ArtifactIds use separate hash domains and explicit length encodings to bind the Foundation and canonical content. A group binds its root, canonically ordered surviving helpers, checked dependency edges and authenticated attribution without changing the approved targets or ResolutionId.

Changed derivations and certificates receive recomputed identities; existing referenced proofs retain theirs. Appendix B.3 binds these changes to the authenticated original. The artifact set uses a Merkle-Patricia root for presence and absence witnesses under an adopted trusted root.

Versioned identities preserve exact sealed references; historical migration follows Section 9.4. Permitted definitions expand within the approved resource bounds.

## Appendix B. Proof admission and reuse

### B.1. Original submission and authorization

A commitment binds the solution author, research recipient, chain, round, task and a canonical hash of the complete original submission, together with secret randomness. It covers the root, every helper, dependency edges and authenticated authorship and payment attribution. Its finalized receipt reserves a disclosure slot and the capacity defined in Appendix E.1. Section 9.2 identifies the MVP field as the research attempt. Section 4.4 governs disclosure and selection.

The original authenticated submission must satisfy its original well-formedness rules: its graph must be acyclic, helpers canonically ordered before their uses, every certificate and dependency valid, and its root a proof of an approved target. Lookup may precede costly checking, but substitution and pruning cannot repair an invalid original submission.

The approved context fixes targets, Foundation, assumptions, permitted reference and substitution rules, definitions and total resource limits. It authorizes bounded helpers whose certificates may be developed later. Replacement must already be authorized by the question's frozen policy and satisfy its assumption, reference and resource bounds; older approved questions are not silently broadened. Helpers cannot change the target or add axioms.

### B.2. Exact replacement and pruning

Before final validation, compare every submitted helper with proofs selected in the immutable sealed parent of the proposed settlement record. A duplicate requires matching StatementId and exact canonical actual-conclusion bytes under the same Foundation and assumption context. A shared ResolutionId, opposite conclusion or arbitrary logically equivalent statement is insufficient. Where the frozen policy permits, replace the helper's uses with a citation to an admissible existing proof. The existing proof retains its recorded author and payment beneficiary, including when its author is the submitter; the duplicate creates no new block or attribution. Section 9.2 records the deterministic MVP selector and single-author restriction.

After replacement, recursively remove every helper, dependency and citation no longer reachable from the root through actual proof uses. Recompute the surviving graph, canonical order and affected identities before checking it.

[FIG:reuse]

[CAPTION] Parent proof C establishes H's exact conclusion under the same Foundation and assumptions. Replacing H leaves F using A and C; B, used only by H, is pruned with its unused dependencies. Only F and A are new. C retains its beneficiary; discarded citations receive no payment.

### B.3. Final validation and the normalization receipt

The normalized graph must be acyclic, with each surviving helper ordered before its uses and reachable from the root through checked dependencies. Validate the root, every surviving helper and all actual final dependencies, including replaced references and their validity evidence. All required bytes must be available. Both this validation and B.1 are required within the capacity reserved under E.1; any failure prevents publication and settlement of the whole group.

A deterministic <i>normalization receipt</i> binds the original commitment receipt and submission hash, selected sealed parent, frozen policy version, helper-to-existing-proof replacement map, final normalized bundle and recomputed identities. It records an authorized derivation from the authenticated original while leaving its commitment, signed bytes and signatures intact. An original signature does not authorize the rewritten bytes. Validators reproduce the transformation and check both forms. Section 9.2 distinguishes the implemented MVP receipt from unimplemented joint authorization.

If the proposed settlement parent changes, recompute and revalidate lookup, normalization, receipt, identities, citation eligibility and bounds against that parent. Timely valid disclosures remain eligible for later settlement subject to these checks; replacements, identities, beneficiaries and resource use may change.

### B.4. The direct bundle boundary

Follow validated dependencies from the normalized root through surviving helpers and every reached proof absent from the sealed parent. Stop each path at the first proof selected in that parent: these proofs form the <i>direct bundle boundary</i>. Traversal also crosses permitted intermediate proofs admitted earlier in the current record. Deduplicate by selected proof identity once per completion pool; repeated references and multiple paths add no entitlement. Ancestors behind the boundary receive no automatic payment, although dependencies required for validity still need checking. No proof admitted anywhere in the current record earns a citation payment anywhere in that record; eligibility uses the selected sealed parent before the entire record.

Replacement by an eligible old proof directs the citation allocation to its recorded beneficiary within <i>P</i>. Pruned helpers and discarded citations receive nothing. Section 6 defines the pool's funding; Section 9.2 lists its open allocation terms.

### B.5. Publication and attribution

Surviving helpers become standalone proof blocks with their own addresses, authorship and references. They need no separate research-question vote or consensus decision and create no separate initial reward, question completion or eligibility claim. Disclosure supplies checking data; publication waits for the whole proof group to validate and actual final use to be confirmed.

Each surviving new block retains the authenticated authorship and payment attribution bound by the original submission. A bundle may name several authors under the authorization format still requiring definition in Section 9.2. Authorization establishes neither historical discovery nor a resolution of all copying disputes. Reuse never overwrites existing attribution. A helper concerning a separately approved question does not by inclusion settle that question or authorize a second payment.

The settlement outputs in Section 5 enter the canonical state together. Any invalid original or final certificate, missing dependency, attribution failure or resource violation rejects the group as a whole. A reward-bearing record settles at most one approved and previously unpaid family, even if it admits several proof blocks. Invalid, duplicate, replayed or unfinalized candidates create no reward.

## Appendix C. Voting records and certified time

### C.1. Ballot and closure rules

A sealed opening fixes the exact proposal, attempt number, policy version, parent configuration, the parent's installed owners with combined weights and certified time <i>T</i>. The deadline and threshold are defined in Section 4.3. A ballot binds chain, proposal, attempt, snapshot and YES or NO. It counts only as the first valid recorded ballot by that owner for that attempt, in a subsequent sealed record with time strictly below <i>D</i>. Missing or malformed output creates no ballot; NO and absent weight remain in <i>W</i>.

Profile edits, repeated inference and changed keys cannot overwrite an existing ballot. Owners may deliberate before signing. Authorized key rotation or revocation affects subsequent ballot admission, with no change to recorded votes or snapshot weight; a replacement key grants no second vote. Retired owners keep only the research mandate of the opening snapshot until closure. New owners have no vote on that attempt. Snapshot research keys remain protected through closure, separately from retired consensus keys.

Every record closes all due windows before ordinary operations. The first record with time at least <i>D</i> records APPROVED exactly when the threshold is met, otherwise NOT_APPROVED. Early quorum does not shorten the window. At most <i>C</i> windows require closure. Approval authorizes solution operations only in a later record after closure is sealed. A subsequent attempt receives no ballots from its predecessor.

### C.2. Time certificates

Each record contains one bounded certificate of integer UTC-second reports. Distinct outgoing owners with more than two thirds of installed weight sign reports bound to chain, parent seal, height and the TIME role. Combined owner weight is counted once. Correct owners report their current time only after verifying the parent. Let <i>m</i> be the lower weighted median of the included reports:

[EQ] record time = max(parent time, m).

Record identity binds this time, and genesis supplies the initial value. Under less than one third faulty weight, correct reporters hold more than half the weight in every sufficient certificate, placing the median between correct reported times. Correct clocks must remain within the configured error bound <i>ε</i>. Collection and sealing can add delay, and a retained consensus value keeps its original time evidence.

An old-parent report cannot authorize a later height. TIME signing is separate from research ballots and consensus seals and follows period-capability retirement. Historical replay checks signatures and arithmetic against the recorded configuration, rather than the reader's current clock. No local clock event finalizes an outcome or changes authority.

## Appendix D. Agreement and handoff

### D.1. Round transitions

Outgoing signers and weights are fixed throughout a height. Authenticated messages bind chain, height, round and role. A quorum consists of distinct signers representing more than two thirds of that weight. Each round contains a proposal, PREVOTE and PRECOMMIT. Correct signers send at most one vote of each kind per round. NIL supports no record. A lock identifies a value and round; a retained valid value records verified earlier prevote evidence. Every height starts without either.

A proposer reuses its retained valid value and round, if any, or proposes a fresh value. A valid proposal claiming no earlier quorum receives a prevote only from an unlocked signer or a signer locked on that value. A proposal citing an earlier round must carry matching verified quorum prevotes below the current round. It must match the signer's lock or carry evidence at least as recent as that lock; otherwise the signer prevotes NIL.

From prevoting onward, current-round quorum prevotes that match a valid current proposal update the retained value and round. While the signer is prevoting, they also establish its lock and permit precommit. Evidence received after a NIL precommit updates retention but permits no second precommit. Proposal timeout causes NIL prevote. Quorum NIL prevotes or timeout while prevoting cause NIL precommit.

Any current-round prevote quorum starts the prevote timer once while prevoting; any current-round precommit quorum starts the precommit timer once. Votes counted to start these timers need not match a value. Precommit timeout advances an undecided signer to the next round, retaining its lock. Messages from the same higher round above one-third weight permit joining that round. Matching non-NIL quorum precommits at any round of the height decide only with their complete, available and valid proposal.

For eventual message delay <i>Δ</i>, timers must eventually satisfy the conditions in [1]:

[EQ] T<sub>propose</sub>(r) &gt; T<sub>precommit</sub>(r-1) + 2Δ,<br/>T<sub>prevote</sub>(r), T<sub>precommit</sub>(r) &gt; 2Δ.

### D.2. Sealing and capability retirement

A joining author presents consent and an earlier sealed completion. Incoming validators verify predecessor seals, agreement evidence, records and state. Once durably prepared, sufficient incoming weight signs READY for the exact successor; every new participant need not personally sign. Outgoing signers durably save exact TERMINAL signatures, irreversibly retire every signing capability for the period, then release the saved signatures. More than two thirds of outgoing weight seals the transition before the next height.

Retirement covers all backups, regenerating seeds and alternative signing routes; height labels on Ed25519 signatures do not provide this property. After a crash, saved signatures may be resent, but retired capabilities must never be restored. Failed or stale installation preserves previous configured weights without restoring capabilities or guaranteeing an available quorum.

## Appendix E. Capacity, persistence and authorization

### E.1. Ordered service

Authenticated proposals enter the bounded queue in finalized receipt order, using height and operation index. Per-record openings and ballot bytes are bounded. Allocation follows queue order as capacity becomes available. The parent must already contain an opening's required capacity; closures in the same record cannot supply immediately reusable slots. An opening reserves a voting slot, ballot and closure capacity, and maximum solution-phase capacity. Reservations bound helper count, original and final bytes, dependency depth, expansion and traversal, parent-match searches, normalization and both original and final validation. A small pruned result does not excuse an oversized or invalid original submission.

Queued entries expire after the policy-defined waiting interval without starting a vote; retry places them at the tail. A family has at most one queued, voting or approved live attempt. Later attempts require fresh admission, a new snapshot and a new full window; a completed family cannot reopen. Rejection releases the solution reservation. Approval retains it until settlement or expiry without a timely valid disclosure; timely valid disclosures remain settleable. Consumed or expired reservations cannot be reused.

Join requests likewise use bounded finalized receipts, deterministic eligible order, reservation and expiry. Incomplete requests must not block others permanently. Service bounds require available honest proposers, bounded verification and eventual delivery. Configuration churn or censorship can invalidate waiting-time estimates. Continuous submission imposes no fixed hourly or monthly question quota, but does not imply unlimited admission.

### E.2. Durable history

Authenticated encrypted transport bounds connections, bytes and work. A receiver journals data and evidence, updates a separate anchor, then acknowledges. On restart it verifies the prefix before discarding an incomplete final frame. Complete corruption or an anchor mismatch causes a halt. Joint rollback of journal and anchor remains undetected. Addresses, indexes and storage receipts confer no authority.

Archive and handoff evidence require continuing storage and funding. Section 8.4 states the reader's independent-anchor and current-state requirements.

### E.3. Account and policy authority

Every distinct authorizing account signs the complete operation and consumes its nonce once, even when it fills several roles. Funded monetary claims and author eligibility claims are distinct objects. A monetary withdrawal spends only whole atoms from previously sealed funded entitlement; an eligibility claim grants no transferable balance. Transfers need sufficient funds and existing recipients. Reserve spending uses funded balances under explicit, authenticated and bounded authorization; empty control records never trigger it automatically.

Policy changes require current and replacement-policy consent. Without preconfigured recovery, a lost authorizing key has no administrative remedy. Protocol amendments and preservation of historical obligations follow Section 9.4.

## Reference

[REF1] E. Buchman, J. Kwon and Z. Milosevic. The latest gossip on BFT consensus. 2019, version 3. <link href="https://arxiv.org/html/1807.04938v3" color="#222222">Algorithm 1 and agreement argument</link>.
