#!/usr/bin/env bash
# Install only the pinned upstream binary; no service credentials are used.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
version=$(cat "$root/.bazelversion")
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform=linux-x86_64 ;;
  Darwin-arm64) platform=darwin-arm64 ;;
  *) echo "Unsupported Bazel host: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac
bin_dir="${RUNNER_TEMP:-$root/.local}/naome-tools/bin"
mkdir -p "$bin_dir"
asset="bazel-$version-$platform"
curl --fail --location --retry 2 --output "$bin_dir/$asset" \
  "https://github.com/bazelbuild/bazel/releases/download/$version/$asset"
python3 - "$root/tools/ci/bazel.sha256" "$bin_dir/$asset" <<'VERIFY'
import hashlib
import pathlib
import sys
checksums = dict(line.split()[::-1] for line in pathlib.Path(sys.argv[1]).read_text().splitlines())
path = pathlib.Path(sys.argv[2])
expected = checksums[path.name]
actual = hashlib.sha256(path.read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(f"Bazel checksum mismatch: {path.name}")
VERIFY
chmod +x "$bin_dir/$asset"
mv "$bin_dir/$asset" "$bin_dir/bazel"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$bin_dir" >> "$GITHUB_PATH"
fi
"$bin_dir/bazel" --version
