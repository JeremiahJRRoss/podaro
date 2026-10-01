#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S6 acceptance (invariant 6; threat model B8/B9): every generated
# secret value of every instance under a state directory is searched for
# across everything else — the engine's log, evidence, the state database,
# the runtime world, API dumps, CLI output — and must appear nowhere but
# the secret store itself and the 0600 env files the containers read.
# Values are never printed; hits name the file only.
#
#   hack/secret_leak_scan.sh <state-dir> [file-or-dir ...]
#
# Exit 0 with zero hits; 1 on any hit, a store file with the wrong mode,
# or no secret values to scan for (a scan of nothing proves nothing).
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: hack/secret_leak_scan.sh <state-dir> [file-or-dir ...]"; exit 2; }
state="$1"; shift
needles="$(mktemp)"
trap 'rm -f "$needles"' EXIT

count=0
for f in "$state"/instances/*/secrets/*; do
  [ -f "$f" ] || continue
  mode="$(stat -c %a "$f")"
  [ "$mode" = "600" ] || { echo "FAIL $f is mode $mode, want 600"; exit 1; }
  v="$(tr -d '\n' <"$f")"
  [ "${#v}" -ge 6 ] || { echo "FAIL $f holds a value shorter than 6 bytes"; exit 1; }
  printf '%s\n' "$v" >>"$needles"
  count=$((count + 1))
done
[ "$count" -gt 0 ] || { echo "FAIL no secret values found under $state/instances/*/secrets — nothing to scan for"; exit 1; }

# The rendered env files may hold values (that is how a product learns its
# password, spec 0003 §5) and must be 0600.
for f in "$state"/instances/*/env/*.env; do
  [ -f "$f" ] || continue
  mode="$(stat -c %a "$f")"
  [ "$mode" = "600" ] || { echo "FAIL $f is mode $mode, want 600"; exit 1; }
done

hits=0
scanned=0
scan_file() {
  local f="$1"
  case "$f" in
    */instances/*/secrets/*|*/instances/*/env/*.env) return ;;
  esac
  scanned=$((scanned + 1))
  if grep -aqFf "$needles" "$f"; then
    echo "LEAK $f contains a secret value"
    hits=$((hits + 1))
  fi
}
scan() {
  local p="$1"
  if [ -d "$p" ]; then
    while IFS= read -r -d '' f; do scan_file "$f"; done < <(find "$p" -type f -print0)
  elif [ -f "$p" ]; then
    scan_file "$p"
  fi
}
scan "$state"
for p in "$@"; do scan "$p"; done

if [ "$hits" -ne 0 ]; then
  echo "FAIL $hits file(s) leak a secret value ($scanned scanned)"
  exit 1
fi
echo "✓ secret leak scan: $count value(s) · $scanned files scanned · zero hits outside the secret store and the 0600 env files"
