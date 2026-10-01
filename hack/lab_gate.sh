#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The P0 exit gate (roadmap §10, plan S3): `lab validate` and `lab plan`
# green and byte-for-byte deterministic on every catalog template, from
# the binary alone (schemas and the module library are embedded). Runs as
# the `templates` CI job and by hand:
#
#   hack/lab_gate.sh                 # builds ./cmd/podaro into a temp dir
#   PODARO=/usr/local/bin/podaro hack/lab_gate.sh   # an installed binary
set -euo pipefail
cd "$(dirname "$0")/.."

bin="${PODARO:-}"
if [ -z "$bin" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  go build -o "$tmp/podaro" ./cmd/podaro
  bin="$tmp/podaro"
fi

status=0
for dir in scenarios/*/; do
  dir="${dir%/}"
  echo "== $dir"
  "$bin" lab validate "$dir"
  human1="$("$bin" lab plan "$dir" | sha256sum | cut -d' ' -f1)"
  human2="$("$bin" lab plan "$dir" | sha256sum | cut -d' ' -f1)"
  json1="$("$bin" lab plan --json "$dir" | sha256sum | cut -d' ' -f1)"
  json2="$("$bin" lab plan --json "$dir" | sha256sum | cut -d' ' -f1)"
  if [ "$human1" != "$human2" ] || [ "$json1" != "$json2" ]; then
    echo "FAIL $dir: lab plan is not deterministic"
    status=1
  fi
  echo "   plan sha256 $human1 (twice, equal) · --json $json1 (twice, equal)"
  # Zero secrets anywhere: a plan never carries an unrendered reference
  # (validation forbids references outside rendered config), and its
  # secret records carry name, kind, and declared_by only — the latter is
  # asserted structurally by TestPlanSecretsCarryNoValues (build-test).
  if "$bin" lab plan --json "$dir" | grep -Fq '${secret:'; then
    echo "FAIL $dir: plan output carries a secret reference"
    status=1
  fi
done
exit "$status"
