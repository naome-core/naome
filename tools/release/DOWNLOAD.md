# Download, verify, and run NAOME

Download published binaries from the [official releases](https://github.com/naome-core/naome/releases).
Versions ending in `-alpha.N`, `-beta.N`, or `-rc.N` are prereleases; GitHub's
latest release points only to a stable version. A stable channel label describes
the release process, not a guarantee of protocol maturity or production workload qualification.

| Package target | Supported host |
| --- | --- |
| `x86_64-unknown-linux-musl` | Linux x86_64, static musl binary; smoke-tested on Ubuntu 24.04 |
| `aarch64-apple-darwin` | Apple Silicon, built for macOS 13 or later; smoke-tested on macOS 15 |

No developer tools, trained models, private configuration, node identity, or
existing node data are included. The node uses its built-in ordinary product
configuration and preserves its automatic resource budgets.

## Verify before extracting or running

Use a recent [GitHub CLI](https://cli.github.com/) with `gh attestation verify`
and `gh release verify-asset`. Substitute the exact version, target, and source
commit published on the release page; do not execute a downloaded binary to
discover its version before verifying it.

```sh
version=0.1.0-rc.1
target=x86_64-unknown-linux-musl
source_commit=REPLACE_WITH_THE_FULL_RELEASE_COMMIT
archive="naome-$version-$target.tar.gz"
gh release download "v$version" --repo naome-core/naome \
  --pattern "$archive" --pattern SHA256SUMS --pattern release.json \
  --pattern provenance.sigstore.json
gh release verify "v$version" --repo naome-core/naome
gh release verify-asset "v$version" "$archive" --repo naome-core/naome
gh attestation verify "$archive" --repo naome-core/naome \
  --bundle provenance.sigstore.json \
  --signer-workflow naome-core/naome/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest "$source_commit" \
  --deny-self-hosted-runners
```

The offline bundle accompanies the assets; GitHub CLI may still obtain trusted
Sigstore verification material. Checksums detect corruption, while the signed
provenance and immutable release bind the bytes to the official workflow and
source. Verify `release.json` with the same attestation command if using its
metadata in automation. `SHA256SUMS` covers both target archives and
`release.json` and `cargo-audit.json`; checking all its entries requires
downloading both archives and both JSON files. The audit report records the
RustSec database revision used for qualification. It covers the whole lockfile
and is a point-in-time check, not a guarantee against undiscovered vulnerabilities.

## Install and operate

After verification, extract into a fresh directory, inspect the package, and
install the single `naome` executable in a user-owned directory on `PATH`:

```sh
tar -xzf "$archive"
mkdir -p "$HOME/.local/bin"
install -m 755 "naome-$version-$target/naome" "$HOME/.local/bin/naome"
naome --version
naome --help
naome start
naome status
naome interest 'Your exact interest text'
naome stop
```

The default data directory is `$XDG_DATA_HOME/naome`, or
`$HOME/.local/share/naome` when `XDG_DATA_HOME` is unset. `NAOME_NODE_DIR`
selects a separate directory. Run as your own user. Installing or replacing the
binary does not require root and does not start the node. Keep the included
license notices. `sbom.cdx.json`, `Cargo.lock`, and `build.json` describe the
dependencies, ordinary build features, binary digest, source commit, and runner.
The SBOM is conservative: it can include optional dependencies resolved by Cargo
that are not linked into the executable.

The macOS CLI has an ad-hoc signature checked during packaging. It is **not**
Apple Developer ID signed or notarized. Browser downloads can therefore be
subject to Gatekeeper policy. Build from reviewed source or use your
organization's approved software-distribution process if notarization is
required. GitHub provenance does not substitute for Apple notarization.

Before updating, stop the node and make a consistent backup of its data
directory. Read that version's release notes, replace the executable, and
restart. Pre-release NAOME supports the current data format; an older binary
may not read newer state. Restore the matching backup when reverting across
format changes. There is no automatic updater or remotely executed installer.
