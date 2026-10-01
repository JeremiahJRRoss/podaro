#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The identity guard — CI job `identity` (the reconciliation plan's R6,
# task 2; the reconciliation §5.6.3–§5.6.5 and §9.4; the owner's mission of
# 2026-09-23, §9): no current attribution to the former organization comes
# back unnoticed. Every match of a detector, in any letter case, must be a
# row of the residual-identity ledger, path by path — a blanket exclusion of
# docs/, NOTICE, generated files or all URLs is refused by construction —
# over what a person meets, not the source alone. Where the ledger does not
# travel (the published snapshot: the plan's D-R17), the detectors are the
# hashes in hack/identity_detectors.txt and the target is an empty ledger;
# given neither, the guard fails. hack/identity_guard.py has the rules.
#
#   1. the tree (git's tracked files);
#   2. the strings of every binary the release ships, and 4. every tarball,
#      extracted — built from this tree by hack/release_package.sh for each
#      architecture it ships (amd64 and arm64: D-R17), unless --binary and
#      --tarball pairs name ones already built, the host's first;
#   5. the CLI's output: `podaro <command> --help` for every command, the
#      hidden ones too (TestEveryCommandRendersItsHelp lists them), `podaro
#      legal`, `legal --licenses`, `legal --json` and `podaro version`, run
#      on the host's binary;
#   6. the rendered console: hack/console_walk.sh's page-text dump and DOM
#      dumps, unless --walk-dir names a walk's output already taken. Without
#      a Chromium the walk skips, and so does this step — said, never passed
#      — unless --require-walk (CI) makes the skip a failure.
#
# 3. is the ledger itself: every row with a category and a blocks-publication
# value, every row still matching. The report ends with the line
# "identity migration: pending" while a migration-compatibility row is open.
#
#   hack/identity_guard.sh [--binary PATH --tarball PATH]... [--walk-dir DIR] [--require-walk]
#   hack/identity_guard.sh --snapshot ARCHIVE [--destination CLONE] [--detectors FILE]
#
# The snapshot mode (the plan's R8, D-R14) judges an extracted archive, or the
# archive itself, against an empty ledger, and with --destination a clone of
# the destination after the snapshot's push: its commits and tags carry one
# identity, Jeremiah Ross <dev@podaro.dev>. Its detectors — the former
# organization's name, the executing sessions' identity, the owner's earlier
# handles and e-mail — are given at run time, in a file outside the snapshot
# (--detectors) or in PODARO_IDENTITY_DETECTORS; the tree the snapshot
# publishes spells none of them, this guard included (hack/identity_guard.py
# has the rules).
#
# The tree mode needs Go, python3 and, for step 6, Chromium and node; in a git
# checkout the release script needs the checkout clean. Nothing outside a
# temporary directory is written. Exit 0 only when every match is a row.
set -euo pipefail
cd "$(dirname "$0")/.."

usage() {
  echo "usage: hack/identity_guard.sh [--binary PATH --tarball PATH]... [--walk-dir DIR] [--require-walk]" >&2
  echo "       hack/identity_guard.sh --snapshot ARCHIVE [--destination CLONE] [--detectors FILE]" >&2
  exit 2
}
binaries=(); tarballs=(); walk=""; require_walk=0
snapshot=""; destination=""; detectors=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) [ $# -ge 2 ] || usage; binaries+=("$2"); shift 2 ;;
    --tarball) [ $# -ge 2 ] || usage; tarballs+=("$2"); shift 2 ;;
    --walk-dir) [ $# -ge 2 ] || usage; walk="$2"; shift 2 ;;
    --require-walk) require_walk=1; shift ;;
    --snapshot) [ $# -ge 2 ] || usage; snapshot="$2"; shift 2 ;;
    --destination) [ $# -ge 2 ] || usage; destination="$2"; shift 2 ;;
    --detectors) [ $# -ge 2 ] || usage; detectors="$2"; shift 2 ;;
    *) usage ;;
  esac
done
export PYTHONDONTWRITEBYTECODE=1

if [ -n "$snapshot" ]; then
  args=(--snapshot "$snapshot")
  [ -z "$destination" ] || args+=(--destination "$destination")
  [ -z "$detectors" ] || args+=(--detectors "$detectors")
  exec python3 hack/identity_guard.py "${args[@]}"
fi
if [ -n "$destination" ] || [ -n "$detectors" ]; then
  echo "✗ --destination and --detectors belong to the snapshot mode (--snapshot ARCHIVE); the tree mode reads the ledger's, or the detector hashes" >&2
  exit 2
fi
if [ "${#binaries[@]}" != "${#tarballs[@]}" ]; then
  echo "✗ --binary and --tarball go together: the two artifacts of one release, a pair per architecture" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*"; exit 1; }
GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export GOMODCACHE GOCACHE GOPATH

if [ "${#binaries[@]}" = 0 ]; then
  version="$(tr -d '[:space:]' <VERSION)"
  host="$(go env GOHOSTARCH)"
  echo "== the release, built from this tree for every architecture it ships: hack/release_package.sh $version"
  hack/release_package.sh "$version" "$tmp/out" >"$tmp/release.out" 2>&1 \
    || { cat "$tmp/release.out"; fail "hack/release_package.sh"; }
  grep -E '^✓ (binary|tarball) ' "$tmp/release.out" | sed 's/^/   /'
  # The host's architecture first: the CLI's outputs and the walk come from the first binary.
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
  args+=(--binary "${binaries[$i]}" --tarball-dir "$tmp/tarball-$i")
done
binary="${binaries[0]}"

echo "== the CLI's output, from $(basename "$binary")"
go test -count=1 -run '^TestEveryCommandRendersItsHelp$' -v ./internal/cli >"$tmp/commands.log" 2>&1 \
  || { cat "$tmp/commands.log"; fail "TestEveryCommandRendersItsHelp"; }
mapfile -t commands < <(sed -n 's/^ *r6_help_test\.go:[0-9]*: command: //p' "$tmp/commands.log")
[ "${#commands[@]}" -gt 1 ] || fail "TestEveryCommandRendersItsHelp listed no command"
mkdir -p "$tmp/cli" "$tmp/home" "$tmp/state" "$tmp/run" "$tmp/config"
i=0
run() {
  i=$((i + 1))
  local out
  out="$tmp/cli/$(printf '%03d' "$i").txt"
  printf '$ %s\n' "$*" >"$out"
  # A command that refuses (no engine to reach) still prints its help and the
  # CLI's words; what it printed is scanned, whatever it exited with.
  HOME="$tmp/home" XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" \
    "$binary" "${@:2}" >>"$out" 2>&1 </dev/null || true
}
for c in "${commands[@]}"; do
  # shellcheck disable=SC2086  # a command path is words: `podaro auth token create`
  run $c --help
done
run podaro legal
run podaro legal --licenses
run podaro legal --json
run podaro version
echo "   ${#commands[@]} commands' --help, podaro legal (plain, --licenses, --json) and podaro version: $i outputs"

walkargs=()
if [ -n "$walk" ]; then
  [ -f "$walk/page-text.txt" ] || fail "--walk-dir $walk holds no page-text.txt"
  walkargs=(--walk-dir "$walk")
else
  echo "== the rendered console: hack/console_walk.sh"
  PODARO_WALK_OUT="$tmp/walk" hack/console_walk.sh >"$tmp/walk.log" 2>&1 || {
    # What the walk said before its engine log — its failed checks, a browser
    # that would not start, its FAIL line — and then that log's tail: a failed
    # walk ends with forty lines of the engine's log, which alone hide the cause.
    sed '/^--- engine log$/,$d' "$tmp/walk.log" | grep -v '^✓ ' | tail -40 || true
    sed -n '/^--- engine log$/,$p' "$tmp/walk.log" | tail -41
    fail "hack/console_walk.sh"
  }
  if [ -f "$tmp/walk/page-text.txt" ]; then
    walkargs=(--walk-dir "$tmp/walk")
    grep -E '^✓ the rendered text of every visited page' "$tmp/walk.log" | sed 's/^/   /'
  else
    why="$(grep -m1 '^○' "$tmp/walk.log" || echo "the walk wrote no page-text.txt")"
    [ "$require_walk" = 0 ] || fail "the rendered console was not scanned: $why"
    walkargs=(--walk-skipped "$why")
  fi
fi

python3 hack/identity_guard.py "${args[@]}" --cli-dir "$tmp/cli" "${walkargs[@]}"
