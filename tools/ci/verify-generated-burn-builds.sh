#!/usr/bin/env bash
set -euo pipefail
root=${1:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$root"

# A cached extension may not generate files in this checkout.
if [[ ! -e vendor/burn-dispatch/BUILD.bazel && ! -e vendor/burn-tensor/BUILD.bazel ]]; then
  exit 0
fi

for crate in burn-dispatch burn-tensor; do
  generated="vendor/$crate/BUILD.bazel"
  test -f "$generated"
  diff -u <(sed 's/[[:blank:]]*$//' "tools/bazel/$crate.BUILD") \
    <(sed 's/[[:blank:]]*$//' "$generated")
done
