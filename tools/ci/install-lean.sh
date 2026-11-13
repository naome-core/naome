#!/usr/bin/env bash
# Prepare the pinned Lean runtime and imported Mathlib modules for integration tests.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
project="$root/crates/naome-proof-loop"
toolchain=$(cat "$project/lean-toolchain")
version=${toolchain#leanprover/lean4:v}
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux ;;
  Darwin-arm64) platform=darwin_aarch64 ;;
  *) echo "Unsupported Lean host: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
install_dir="${RUNNER_TEMP:-$root/.local}/naome-lean"
asset="lean-$version-$platform.tar.zst"
lake="$install_dir/lean-$version-$platform/bin/lake"
mkdir -p "$install_dir"
if [[ ! -x "$lake" ]]; then
  curl --fail --location --retry 2 --output "$install_dir/$asset" \
    "https://github.com/leanprover/lean4/releases/download/v$version/$asset"
  python3 - "$root/tools/ci/lean.sha256" "$install_dir/$asset" <<'VERIFY'
import hashlib
import pathlib
import sys

checksums = dict(line.split()[::-1] for line in pathlib.Path(sys.argv[1]).read_text().splitlines())
path = pathlib.Path(sys.argv[2])
with path.open("rb") as stream:
    actual = hashlib.file_digest(stream, "sha256").hexdigest()
if actual != checksums[path.name]:
    raise SystemExit(f"Lean checksum mismatch: {path.name}")
VERIFY
  zstd -dc "$install_dir/$asset" | tar -xf - -C "$install_dir"
  rm "$install_dir/$asset"
fi
(
  cd "$project"
  "$lake" exe cache get Mathlib.SetTheory.ZFC.Basic Mathlib.Data.List.Basic \
    Mathlib.Data.Option.Basic Mathlib.Data.Set.Basic Mathlib.Data.Nat.Basic
)
if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'NAOME_LEAN_LAKE=%s\n' "$lake" >> "$GITHUB_ENV"
fi
"$lake" --version
