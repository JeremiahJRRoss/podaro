#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The retirement guard — CI job `retirement` (the reconciliation plan's R6,
# task 1; the reconciliation §9.1–§9.2; the owner's mission of 2026-09-23,
# §7): nothing the owner retired — the golden lab, its modules, adapters,
# composites and generators, their images and digests, its playbook, its
# licence ids, its pack — comes back unnoticed, in the tree, the embedded
# filesystem, the built binary or the extracted release.
#
#   hack/retirement_guard.sh [--binary PATH --tarball PATH]...
#
#   1. TestEmbedded (the root package) lists what a binary embeds under
#      scenarios/ and modules/, and holds it to the retained catalog;
#   2. the release for every architecture it ships (hack/release_package.sh's
#      list: amd64 and arm64 — the plan's D-R17), built from this tree — each
#      bare binary, and each tarball extracted — unless --binary and
#      --tarball pairs name ones already built from it;
#   3. hack/retirement_guard.py judges the tree, the embedded files, every
#      binary and every tarball's entries by file role against
#      hack/retirement.json and its allowlist, hack/retirement_allow.txt —
#      its docstring states the nine rules — and calls check 5's scan,
#      hack/retirement_scan.py, for the binaries, with its self-test, rather
#      than repeating it (the plan's Q-R5).
#
# It is never a substring ban (the reconciliation §9.1): a retired name may
# stand where a row of the allowlist gives the file's role, and never in a
# maintained surface — the catalog, the modules, the current schemas, the
# installer, the registries, the session prompts, what the binary embeds
# and what the release carries — but the instruction that forbids
# restoring the lab and the embedded frozen files the manifest names.
#
# It judges the tree it lives in, so an extracted source archive (the
# snapshot of the plan's R8, which has no .git) is judged by running its own
# copy; the snapshot keeps this guard, its judge and check 5's scan, and
# needs nothing the snapshot leaves out (the plan's D-R17). In a git checkout the release script needs the checkout clean, as
# hack/legal_surfaces_test.sh does. Nothing outside a temporary directory is
# written. Exit 0 only when every rule holds.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { echo "usage: hack/retirement_guard.sh [--binary PATH --tarball PATH]..." >&2; exit 2; }
binaries=()
tarballs=()
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) [ $# -ge 2 ] || usage; binaries+=("$2"); shift 2 ;;
    --tarball) [ $# -ge 2 ] || usage; tarballs+=("$2"); shift 2 ;;
    *) usage ;;
  esac
done
if [ "${#binaries[@]}" != "${#tarballs[@]}" ]; then
  echo "✗ --binary and --tarball go together: the two artifacts of one release, a pair per architecture" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*"; exit 1; }
GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export GOMODCACHE GOCACHE GOPATH
export PYTHONDONTWRITEBYTECODE=1

echo "== the embedded catalog: go test -run '^TestEmbedded\$' . (the reconciliation's A2)"
# A failing test is a finding like the others: the judge reports it beside
# everything else that catches the same restoration, so the run goes on.
go test -count=1 -run '^TestEmbedded$' -v . >"$tmp/embedded.log" 2>&1 \
  || echo "   ✗ TestEmbedded failed — the judge reports it below, with the rest"

if [ "${#binaries[@]}" = 0 ]; then
  version="$(tr -d '[:space:]' <VERSION)"
  host="$(go env GOHOSTARCH)"
  echo "== the release, built from this tree for every architecture it ships: hack/release_package.sh $version"
  hack/release_package.sh "$version" "$tmp/out" >"$tmp/release.out" 2>&1 \
    || { cat "$tmp/release.out"; fail "hack/release_package.sh"; }
  grep -E '^✓ (binary|tarball) ' "$tmp/release.out" | sed 's/^/   /'
  # The host's architecture first (check 5's self-test runs against the first binary), then the others.
  dir="$tmp/out/download/v$version"
  for b in "$dir/podaro-${version}-linux-${host}" "$dir"/podaro-"${version}"-linux-*; do
    arch="${b##*-linux-}"
    [ "$arch" != "$host" ] || [ "${#binaries[@]}" = 0 ] || continue
    binaries+=("$b")
    tarballs+=("$dir/podaro_v${version}_linux_${arch}.tar.gz")
  done
fi
args=()
for i in "${!binaries[@]}"; do
  [ -f "${binaries[$i]}" ] || fail "no binary at ${binaries[$i]}"
  [ -f "${tarballs[$i]}" ] || fail "no tarball at ${tarballs[$i]}"
  mkdir -p "$tmp/tarball-$i"
  tar -xzf "${tarballs[$i]}" -C "$tmp/tarball-$i"
  args+=(--binary "${binaries[$i]}" --tarball-dir "$tmp/tarball-$i" --tarball-name "$(basename "${tarballs[$i]}")")
done

python3 hack/retirement_guard.py --embedded-log "$tmp/embedded.log" "${args[@]}"
