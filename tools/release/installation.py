"""Canonical download verification and installation text for release consumers."""

from policy import REPOSITORY, identity


def instructions(version, sha):
    identity(version)
    if len(sha) != 40 or any(character not in "0123456789abcdef" for character in sha):
        raise ValueError("installation instructions require the exact source commit")
    return f"""NAOME {version}: verify before extracting or executing

Linux x86_64 uses a static musl executable, smoke-tested on Ubuntu 24.04.
Apple Silicon requires macOS 13 or later, smoke-tested on macOS 15.
Choose x86_64-unknown-linux-musl or aarch64-apple-darwin below.
Use a recent GitHub CLI supporting release verify-asset and attestation verify.
Run these commands in a fresh directory:

version={version}
target=x86_64-unknown-linux-musl
source_commit={sha}
archive="naome-$version-$target.tar.gz"
gh release download "v$version" --repo {REPOSITORY}
gh release verify "v$version" --repo {REPOSITORY}
for asset in naome-*.tar.gz release.json cargo-audit.json SHA256SUMS provenance.sigstore.json; do
  gh release verify-asset "v$version" "$asset" --repo {REPOSITORY} || exit 1
done
for asset in naome-*.tar.gz release.json cargo-audit.json SHA256SUMS; do
  gh attestation verify "$asset" --repo {REPOSITORY} \\
    --bundle provenance.sigstore.json \\
    --signer-workflow {REPOSITORY}/.github/workflows/release.yml \\
    --source-ref refs/heads/main --source-digest "$source_commit" \\
    --deny-self-hosted-runners || exit 1
done
if command -v sha256sum >/dev/null; then sha256sum -c SHA256SUMS; else shasum -a 256 -c SHA256SUMS; fi

Proceed only after every verification command succeeds. Checksums detect
corruption; signed provenance and the immutable release bind the downloaded
bytes to the official workflow and source. GitHub CLI may obtain trusted
Sigstore material while verifying the supplied offline bundle.

tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 755 "naome-$version-$target/naome" "$HOME/.local/bin/naome"
naome --version
naome --help
naome start
naome status
naome stop

Run as your own user. Installation does not start the node and needs no root.
The CLI help explains configuration, discovery and automatic computation.
Keep the included license notices. Cargo.lock, sbom.cdx.json and build.json
record dependencies, source, features, binary digest and build environment.
The CycloneDX inventory can include resolved optional dependencies not linked
into the binary. The RustSec audit is a point-in-time whole-lockfile check.

The macOS executable is ad-hoc signed, without Apple Developer ID signing or
notarization. Browser downloads remain subject to Gatekeeper policy. Use an
approved distribution process if notarization is required; GitHub provenance
does not substitute for Apple notarization.

Before updating, stop the node, back up its entire data directory and read
that version's release notes. Replace the executable and restart. Pre-release
NAOME supports current data formats; restore the matching backup when reverting
across format changes. NAOME_NODE_DIR selects an isolated trial directory.
There is no automatic updater or remotely executed installer.
"""
