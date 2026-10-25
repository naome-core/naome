# Release operations

## Trust and channels

`Cargo.toml` owns the workspace version. Mirror that value in the
`naome_knowledge` Bazel library's `version` attribute; the required Rust quality
job rejects drift. Release versions are `X.Y.Z`, `X.Y.Z-alpha.N`,
`X.Y.Z-beta.N`, or `X.Y.Z-rc.N`, with positive sequence numbers and no leading
zeros. Tags are `v<version>`. Versions advance monotonically across both
channels; published versions are never overwritten, retagged, or promoted by
editing a prerelease. Promotion is a new version commit and a new qualified
build. This system releases current `main`, not maintenance branches.

Every publication is an explicit `workflow_dispatch` of `release.yml` on
`main` with the exact version and `publish=true`. It requires successful,
complete **main-push** `CI` and `Full Cargo CI` runs for that exact commit,
including Linux/macOS and test/release profiles. An older success does not
override a newer failed or pending run. Missing evidence fails closed.
PR checks alone never qualify a release. If `main` advances during packaging,
publication stops; release its qualified new head instead.

Manual candidates and publications also scan the complete `Cargo.lock` against
a freshly fetched official RustSec database using a checksum-pinned
`cargo-audit`. Known vulnerabilities and unsoundness advisories block publication;
unmaintained/yanked notices remain visible in the report. No advisory ignore
list, severity threshold, platform filter, stale-DB fallback, or automatic
dependency fix is applied. The scan covers the conservative whole lockfile,
including dependencies that might not be linked into the ordinary node; a
finding needs assessment before claiming runtime exploitability. Fix source
dependencies through their existing owners rather than suppressing a release
failure. PR candidates exercise build/packaging without requiring an audit of
unchanged source dependencies; they do not qualify a release.

The publisher compares the audit's database revision with the official database
HEAD before staging and immediately before publication. A newer database blocks
publication until fresh qualification is obtained, including on a resumed run.

The workflow relies on the existing protected-main review and CI rules and on
GitHub's authorization of workflow dispatches. People with repository write or
administrative access, GitHub-hosted runners, the pinned Rust distribution,
system compiler/SDK, and the dependency registry are within the trust boundary.
This is not an independently reproducible-build or SLSA level certification.

## Repository setup

Enable **Settings > General > Releases > Release immutability** before the
first publication. The workflow checks the setting both before builds and
immediately before publishing. It will not publish mutable releases. Existing
releases are unaffected. See [GitHub's immutable-release documentation](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases).

Keep the existing main rules, required GitHub Actions checks, and review-thread
resolution enabled with no bypass. Do not grant build jobs write permissions.
Provenance uses a short-lived GitHub OIDC identity and Sigstore. No long-lived
signing key, cloud account, remote build service, or paid runner is required.
No repository protection or billing setting is changed by this code.

GitHub's immutable-release policy endpoint requires **Administration: read**,
which `GITHUB_TOKEN` cannot carry. Configure the repository Actions secret
`RELEASE_POLICY_TOKEN` with a fine-grained token limited to this repository,
**Administration: read only**, no write permissions, and an appropriate expiry.
Rotate it before expiry. Only explicit main publication receives this credential;
it is used exclusively to read `/immutable-releases` and full ruleset policies
(including bypass actors, which GitHub hides from ordinary readers). All build jobs remain
secret-free, and every other API call uses the job-scoped `GITHUB_TOKEN`.
Missing or expired policy access stops publication; never substitute a broad
personal write token. See the [GitHub API permission requirements](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository).

## Prepare and publish

1. Set the intended version in the workspace, update `Cargo.lock` with the
   pinned Cargo, and update the checked Bazel version mirror. Add
   `docs/releases/<version>.md` in the same PR. Its first line must be
   `# v<version>`. Describe changes, supported hosts, operational limits,
   data-format/upgrade implications, and known issues using actual evidence.
2. Merge through the ordinary protected PR path. Wait for both main `CI` and
   the complete `Full Cargo CI` matrix at that commit to succeed.
3. Optionally exercise a candidate without publishing:
   `gh workflow run release.yml --repo naome-core/naome --ref main`.
4. Publish deliberately:
   `gh workflow run release.yml --repo naome-core/naome --ref main -f version=<version> -F publish=true`.
5. Inspect the Release run and immutable GitHub Release. Follow
   [download verification](../../tools/release/DOWNLOAD.md) on a fresh download.

Do not create or push the version tag yourself. Publication creates the tag at
the verified source SHA only after both packages, checksums, and provenance
exist. A prerelease is marked as such and never changes `latest`. A stable
release becomes `latest`. The pipeline does not choose whether NAOME is ready
for a stable product promise; the reviewed version and notes are that decision.

## Pipeline and artifacts

Changes to the release pipeline run read-only candidates on PRs. The same
reusable builder is used for publication: native Ubuntu 24.04 x86_64 with musl
and macOS 15 ARM64, pinned Rust and locked dependencies, no build-cache restore,
no developer features, and only the `naome` binary. It verifies static Linux
linkage and the macOS architecture/ad-hoc signature. Both original and extracted
executables pass version/help/stopped-status smoke checks without creating node
state. The extracted binary additionally starts a real node with isolated
temporary state, a loopback listener, and discovery disabled; it checks status,
interest persistence and confirmed shutdown. Automatic
computation pauses require a reported reason; readiness is independent of
whether the host currently permits computation. Ordinary resource
budgets remain in force. The full matrix qualifies the source; package smoke
checks additionally exercise the distributed musl binary.

Pinned `cargo-cyclonedx` generates a target-specific CycloneDX 1.5 SBOM, and
`cargo-about` gathers dependency license texts under an explicit license policy.
New or unidentified licenses stop packaging. Archives include the node, license
notices (including musl where linked), installation instructions, SBOM,
lockfile, and build identity. Tar ownership, modes, ordering, and timestamps
and the gzip timestamp are deterministic for identical payloads. Different
hosted compiler, linker, or SDK images can still produce different binary bytes;
runner versions and the final binary digest are recorded.

The SBOM describes Cargo's resolved dependency graph, including build dependencies
and optional packages Cargo resolves even when they are not linked into the
node. It is a conservative inventory, not binary reachability evidence.
License collection independently selects the ordinary node's dependency graph.

The final download set contains two target archives, `release.json`,
`SHA256SUMS`, `cargo-audit.json`, and `provenance.sigstore.json`. The security
report records its database revision and binds the scan to the source lockfile
digest; the publisher independently rejects failed or suppressed reports.
The provenance job signs the exact
payload and checksum bytes; its only write permission is attestations, with
OIDC used for signing. A separate publisher verifies those signatures, source
identity and all digests, uploads to a draft, checks server-side asset digests,
repeats live qualification, and publishes atomically through GitHub's immutable
release boundary. It never runs downloaded node binaries with a write token.
GitHub additionally generates an immutable-release attestation. See
[artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

Candidate and intermediate run artifacts expire after seven days. Published
assets persist on the release. Candidates have no release provenance signature
and are not qualified distribution releases. Actions and release tools are pinned;
review dependency and workflow updates through normal PRs.

## Failures and recovery

Build, inventory, smoke-test, or attestation failure creates no published
release. Never relax CI or license checks to ship. Correct the cause on `main`
and choose a new version if an existing published version is involved.

A publisher failure may leave an unpublished draft, uploaded assets, or its
tag. Inspect the failed run and draft first. **Re-run failed jobs in the same
workflow run** to resume while its exact attested artifacts remain available.
Only that run's draft marker and source SHA are accepted, and existing asset
bytes must match exactly; nothing is replaced. A failed or ambiguously completed
mutation is not automatically retried. A published version makes a rerun fail
closed; verify that release rather than trying to republish it.

If artifacts expired, `main` moved, the advisory database changed, or the draft cannot be reconciled, an
authorized maintainer must inspect and remove only the unpublished draft and
its unused tag before retrying. Never delete a published release as a retry
strategy. Release revocation/incident handling remains an explicit maintainer
decision. There are no background publication jobs or unattended updates.
