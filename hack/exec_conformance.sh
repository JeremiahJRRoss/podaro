#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S6 acceptance, Spec 0002 §6: the exec conformance fixture
# (hack/fixtures/exec-conformance) passes, fails, and errors per the error
# table. This script builds the fixture image and drives every behavior
# through rootless Podman under the five walls the engine applies (Spec
# 0002 §3), asserting the row each one produces:
#   pass    → exit 0, contract JSON, status pass
#   fail    → exit 0, contract JSON, status fail   (a fail is a successful run)
#   crash   → exit 2, no verdict                   (PDR-E502 at the engine)
#   garbage → exit 0, stdout is not contract JSON  (PDR-E504)
#   sleep   → still running past its budget        (PDR-E503: the engine kills it)
#   secret  → reads the granted secret as a 0400 file, reports its length only
#   leak    → echoes the granted secret into observed/capture/sent (the engine redacts)
#   claim   → writes the engine's own capture keys (the engine reserves them)
#   root    → the image's user is 0                (PDR-E505: refused before running)
#   seed    → a seed input gets the seed verdict with sent counts
# The engine's mapping of these rows to PDR-E50x codes is proven against
# the fake runtime, which mirrors this table, by
#   go test ./internal/engine -run TestExecCheckpointsAndSeedsOnTheFake
# Without a usable Podman the script says so and exits 0: nothing is
# simulated. CI runs it on ubuntu-24.04, where Podman is installed.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v podman >/dev/null 2>&1; then
  echo "○ podman not available; the exec conformance fixture was not built or run here (go test covers the same table on the fake runtime)"
  exit 0
fi
if ! podman info >/dev/null 2>&1; then
  echo "○ podman is installed but not usable in this environment; the exec conformance fixture was not run here"
  exit 0
fi

tmp="$(mktemp -d)"
img=localhost/podaro/exec-conformance:test
rootimg=localhost/podaro/exec-conformance:root-test
secret=pdrs-conformance-test-tok
cleanup() {
  podman rm -f pdr-conformance-sleep >/dev/null 2>&1 || true
  podman secret rm "$secret" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; exit 1; }

echo "== build the fixture (non-root) and its refused root variant"
podman build -q -t "$img" --target nonroot hack/fixtures/exec-conformance >/dev/null
podman build -q -t "$rootimg" --target root hack/fixtures/exec-conformance >/dev/null
user="$(podman image inspect --format '{{.Config.User}}' "$img")"
rootuser="$(podman image inspect --format '{{.Config.User}}' "$rootimg")"
[ "$user" = "65532:65532" ] || fail "fixture runs as $user, want 65532:65532"
[ "$rootuser" = "0:0" ] || fail "root variant runs as $rootuser, want 0:0"
echo "✓ built · user $user · root variant $rootuser (the engine refuses it: PDR-E505)"

# The five walls as the engine spells them (internal/runtime/podman.go
# RunCreateArgs); resource limits only where this host delegates the
# controllers to rootless Podman, and said so when it does not.
walls=(--rm --interactive --network none --read-only --tmpfs /tmp:rw,size=64m,mode=1777 --security-opt no-new-privileges --cap-drop ALL)
controllers="$(podman info --format '{{.Host.CgroupControllers}}' 2>/dev/null || true)"
if [[ "$controllers" == *memory* && "$controllers" == *cpu* && "$controllers" == *pids* ]]; then
  walls+=(--pids-limit 128 --cpus 0.5 --memory 256m)
  echo "✓ cgroup controllers delegated ($controllers): resource walls applied"
else
  echo "○ cgroup controllers not delegated to rootless Podman here ($controllers): pids/cpu/memory walls not applied in this run"
fi

input='{"contract":"podaro.dev/exec/v1","kind":"checkpoint","run_id":"run_conformance","timeout":"5s","instance":{"name":"conf","mode":"delivery","endpoints":[{"service":"web","purpose":"ui","scheme":"http","host":"web","port":80}]},"secrets":{"granted":[],"mount":"/run/podaro/secrets"},"checkpoint":{"id":"c","args":[],"env":{},"expect":{"lag":0}}}'
run() { # mode [podman args...] → stdout to $tmp/out, stderr to $tmp/err, exit code printed
  local mode="$1"; shift
  local code=0
  printf '%s' "$input" | timeout 60 podman run "${walls[@]}" "$@" "$img" "$mode" >"$tmp/out" 2>"$tmp/err" || code=$?
  echo "$code"
}
is_verdict() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["contract"]=="podaro.dev/exec/v1"; assert d["status"]==sys.argv[2], d' "$tmp/out" "$1"; }

echo "== pass"
[ "$(run pass)" = "0" ] || fail "pass exited non-zero: $(cat "$tmp/err")"
is_verdict pass || fail "pass verdict: $(cat "$tmp/out")"
grep -q '"observed":{"lag":0}' "$tmp/out" || fail "pass passes expect through as observed: $(cat "$tmp/out")"
echo "✓ pass → exit 0, status pass"

echo "== fail (a successful run)"
[ "$(run fail)" = "0" ] || fail "fail exited non-zero"
is_verdict fail || fail "fail verdict: $(cat "$tmp/out")"
grep -q "diagnostic chatter" "$tmp/err" || fail "stderr carries the diagnostics"
echo "✓ fail → exit 0, status fail, chatter on stderr"

echo "== crash (PDR-E502)"
[ "$(run crash)" = "2" ] || fail "crash must exit 2"
[ ! -s "$tmp/out" ] || fail "crash must print no verdict"
grep -q "crashing on purpose" "$tmp/err" || fail "crash stderr excerpt"
echo "✓ crash → exit 2, stderr excerpt, no verdict"

echo "== garbage (PDR-E504)"
[ "$(run garbage)" = "0" ] || fail "garbage exits 0"
if python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$tmp/out" 2>/dev/null; then fail "garbage must not be JSON"; fi
echo "✓ garbage → exit 0, stdout is not contract JSON"

echo "== sleep (PDR-E503: outlives the budget; the engine kills it)"
# Detached, so no --rm (the container must still be there to inspect) and
# no --interactive (nothing attaches; the fixture reads EOF on stdin and
# sleeps). A pattern substitution would leave an empty element podman
# reads as an image name.
detached=()
for w in "${walls[@]}"; do
  case "$w" in --rm|--interactive) ;; *) detached+=("$w") ;; esac
done
podman run --detach --name pdr-conformance-sleep "${detached[@]}" "$img" sleep >/dev/null
sleep 3
[ "$(podman inspect --format '{{.State.Running}}' pdr-conformance-sleep)" = "true" ] || fail "sleep must still be running after 3s"
podman rm -f pdr-conformance-sleep >/dev/null
echo "✓ sleep → still running after 3s (killed here as the engine would at its deadline)"

echo "== secret (a granted secret is a 0400 file, read, never echoed)"
printf 'correct-horse-battery-staple-0000\n' >"$tmp/tok"
podman secret create "$secret" "$tmp/tok" >/dev/null
[ "$(run secret --secret "source=$secret,type=mount,target=/run/podaro/secrets/tok,mode=0400,uid=65532,gid=65532")" = "0" ] || fail "secret run exited non-zero: $(cat "$tmp/err")"
is_verdict pass || fail "secret verdict: $(cat "$tmp/out")"
grep -q '"secret_bytes":33' "$tmp/out" || fail "secret length observed: $(cat "$tmp/out")"
grep -q "correct-horse" "$tmp/out" "$tmp/err" && fail "the secret value must never appear in the output"
echo "✓ secret → length 33 observed, value absent from stdout and stderr"

echo "== leak (a misbehaving adapter echoes the granted secret; the engine's filter is what redacts it)"
[ "$(run leak --secret "source=$secret,type=mount,target=/run/podaro/secrets/tok,mode=0400,uid=65532,gid=65532")" = "0" ] || fail "leak run exited non-zero: $(cat "$tmp/err")"
is_verdict pass || fail "leak verdict: $(cat "$tmp/out")"
grep -q '"deep":\["correct-horse-battery-staple-0000"\]' "$tmp/out" || fail "the leak fixture must echo the (test) secret nested in its verdict: $(cat "$tmp/out")"
podman secret rm "$secret" >/dev/null
echo "✓ leak → the fixture echoes the test value nested in observed and capture (go test ./internal/engine -run TestExecOutputIsRedactedRecursively proves the engine redacts it before evidence)"

echo "== claim (a misbehaving adapter writes the engine's own capture keys; the engine reserves them)"
[ "$(run claim)" = "0" ] || fail "claim run exited non-zero: $(cat "$tmp/err")"
is_verdict pass || fail "claim verdict: $(cat "$tmp/out")"
grep -q '"image":"docker.io/attacker/other@sha256:' "$tmp/out" || fail "the claim fixture must write an image key of its own: $(cat "$tmp/out")"
grep -q '"secrets":\["never-granted"\]' "$tmp/out" || fail "the claim fixture must write a secrets key of its own: $(cat "$tmp/out")"
echo "✓ claim → the fixture claims image and secrets (go test ./internal/engine -run TestAnAdapterCannotClaimTheEnginesCaptureKeys proves the engine writes its own over them)"

echo "== seed input"
input='{"contract":"podaro.dev/exec/v1","kind":"seed","run_id":"run_seed","timeout":"5s","instance":{"name":"conf","mode":"delivery","endpoints":[]},"secrets":{"granted":[],"mount":"/run/podaro/secrets"},"seed":{"name":"orders","args":[],"count":42,"params":{},"seed_value":"0123456789abcdef"}}'
[ "$(run pass)" = "0" ] || fail "seed run exited non-zero"
is_verdict ok || fail "seed verdict: $(cat "$tmp/out")"
grep -q '"sent":{"events":42}' "$tmp/out" || fail "seed sent counts: $(cat "$tmp/out")"
grep -q "seeded rng 0123456789abcdef" "$tmp/out" || fail "seed message names the seed_value"
echo "✓ seed → status ok, sent.events 42, seed_value echoed in the message"

echo "all Spec 0002 §6 conformance rows produced by the fixture under the walls"
