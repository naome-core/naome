# Mathematical fixtures for the trusted research MVP

These small actual Foundation proofs support acceptance scenarios AB-03 through
AB-05. They intentionally fit far below the proposed limits. They qualify the
mathematical examples, not network operation or the complete MVP.

| Object | Closed formula | Intended use |
|---|---|---|
| H | ∀x (x = x) | New helper owned by A's author |
| A | ∀y ∀x (x = x) | PROVED by a root that actually cites H |
| B | ¬(H → H) | REFUTED by a proof of the exact positive core H → H |
| C | H | KNOWN_UNPAID after H has been published with A |

A, B's core, and C have different canonical statement bytes. R3 removes B's
leading negation for its family core and treats a proof of that positive core
as REFUTED. The test does not silently change B to a positive question.

`helper-h.nao`, `solution-a.nao`, and `solution-b.nao` are complete proof sources.
The final solution sources cite H's exact ProofId:
`c617c9222df901d99404868aab415e917af76ce65699876342fe0c0ff1e62e73`.
The `question-*.nao` files are proof obligations (foundation and statement,
without a certificate); they are inputs for the research question compiler,
not complete proofs accepted by the existing proof-authoring command.

For actual MVP integration, A's signer must own both A and H; a different
registered signer owns B. A's atomic group contains H before A. B's group
contains only B and resolves H from the sealed library, preserving H's stored
author and recipient. No account keys or fake authorship fields are embedded in
mathematical certificates. The network acceptance run must retrieve H from a
second provider while its original provider is unavailable and establish the
positive payment to its original recipient. C must create neither a completion
payment nor an eligibility claim.

`crates/naome-authoring/tests/state_workflow_fixtures.rs` compiles these proofs,
checks original decoded and canonical normal-form certificates independently,
asserts the exact conclusions and reachable dependency, checks missing-reference
failure, and reloads H's encoded bytes into an independent checker state. Its
legacy artifact journal is only a source-authoring adapter; it does not simulate
atomic MVP publication, transport, authorship, settlement, or rewards.

`helper-h-duplicate.nao` is a different, longer valid certificate of exactly H.
`solution-b-original.nao` uses its ProofId
`4a9b8d6beabb010e33fddcec0000b66c257eb87e05fda21342e39dd4e7ec534a`.
This original pair supplies AB-04's duplicate-substitution case. The test checks
both certificates before replacement, rewrites the actual reference to H, and
checks that the result is byte-identical to `solution-b.nao`'s final certificate.
Actual parent selection, pruning, attribution, and receipt binding remain the
research admission layer's responsibility.
