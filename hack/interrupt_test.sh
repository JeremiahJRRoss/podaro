#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S4 acceptance, scripted (roadmap §9 Engine row; Manual §8 "up is
# safe to interrupt … instances survive host reboots"):
#   1. kill -9 the engine mid-create → restart → the job resumes and the
#      instance reaches ready (plan S6: the ladder's top rung — baselines
#      verified — not merely healthy);
#   2. reboot simulation (engine stopped, every container stopped) →
#      start → reconcile returns the instance to ready;
#   3. create twice → identical container and network names;
#   4. destroy → zero runtime objects, zero state.
#
# Runs against the fake runtime (PODARO_RUNTIME=fake): the world persists
# on disk and its containers answer real HTTP on loopback, so the job
# engine's journal, resumption, and reconcile paths are exercised end to
# end. Against Podman the same script proves the real thing:
#   PODARO_RUNTIME=podman hack/interrupt_test.sh
# (requires rootless Podman; the reboot step then stops containers with
# podman itself).
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
ENGINE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-4s}"
mkdir -p "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
fixture="hack/fixtures/hello-nginx"

start_engine() {
  rm -f "$sock"   # a kill -9 leaves the old socket file; wait for the new engine's
  "$bin" engine serve >>"$tmp/engine.log" 2>&1 &
  ENGINE_PID=$!
  for _ in $(seq 1 100); do
    [ -S "$sock" ] && return 0
    sleep 0.1
  done
  echo "FAIL engine did not open its socket"; cat "$tmp/engine.log"; exit 1
}
stop_engine() {
  kill "$ENGINE_PID" 2>/dev/null || true
  wait "$ENGINE_PID" 2>/dev/null || true
  ENGINE_PID=""
}
# stage_of prints the ladder stage once no job is in progress on the
# instance; while one runs it prints "<stage>+job", so a stage reached
# mid-job (healthy, with the job's own record still to land) never
# satisfies wait_stage — the next command would find the slot busy.
stage_of() {
  local json stage
  json="$("$bin" status "$1" --json)" || return 1
  stage="$(printf '%s' "$json" | grep -o '"ladder":{"stage":"[a-z]*"' | sed 's/.*"stage":"//; s/"$//')"
  if printf '%s' "$json" | grep -q '"in_progress":true'; then printf '%s+job\n' "$stage"; else printf '%s\n' "$stage"; fi
}
wait_log() { # pattern seconds — the engine's own journal line
  for _ in $(seq 1 $(( $2 * 10 ))); do
    grep -q "$1" "$tmp/engine.log" && return 0
    sleep 0.1
  done
  return 1
}
wait_stage() { # instance stage seconds (settled: no job in progress)
  for _ in $(seq 1 $(( $3 * 10 ))); do
    if [ "$(stage_of "$1" 2>/dev/null || true)" = "$2" ]; then return 0; fi
    sleep 0.1
  done
  echo "FAIL $1 did not reach $2 (last: $(stage_of "$1" || echo none))"; "$bin" status "$1" || true; cat "$tmp/engine.log"; exit 1
}

echo "== 1. kill -9 mid-create, restart, resume"
start_engine
"$bin" up "$fixture" --name t1 --json >"$tmp/up.json" 2>"$tmp/up.err" &
UP_PID=$!
sleep 1.5                       # the fake takes ${PODARO_FAKE_READY_DELAY} to answer 200: mid-job
kill -9 "$ENGINE_PID"; wait "$ENGINE_PID" 2>/dev/null || true; ENGINE_PID=""
wait "$UP_PID" && { echo "FAIL up should have lost its engine"; exit 1; } || true
grep -q '"state":"running"\|"state":"queued"' <("$bin" status t1 --json 2>/dev/null || echo '') && true
start_engine
wait_log "resuming create job" 5 || { echo "FAIL engine did not resume the interrupted job"; cat "$tmp/engine.log"; exit 1; }
wait_stage t1 ready 30
echo "✓ interrupted create resumed on restart · t1 is ready"

echo "== 2. reboot simulation, reconcile-on-start"
stop_engine
if [ "$PODARO_RUNTIME" = "fake" ]; then
  "$bin" engine simulate-reboot
else
  podman stop -t 1 pdr-t1-web >/dev/null
fi
start_engine
wait_log "reconciling t1" 5 || { echo "FAIL engine did not reconcile after the reboot"; cat "$tmp/engine.log"; exit 1; }
wait_stage t1 ready 30
# Ready after a reboot is a claim, and the evidence must carry the proof
# behind it: the baselines were re-verified, and the journal says so
# (Manual §8; plan S9). Read the instance's own evidence, as an operator
# would after coming back to a host that restarted.
"$bin" status t1 --json >/dev/null
curl -sS --unix-socket "$sock" "http://podaro/api/v1alpha1/instances/t1/evidence" >"$tmp/reconcile-evidence.json" \
  || { echo "FAIL reading t1's evidence after the reconcile"; exit 1; }
python3 - "$tmp/reconcile-evidence.json" <<'EOF' || { echo "FAIL the reconcile did not say what it re-verified"; exit 1; }
import json, sys
entries = json.load(open(sys.argv[1]))["evidence"]
life = [e["lifecycle"] for e in entries if e.get("lifecycle")]
recon = [l for l in life if l.get("event") == "reconcile"]
assert recon, "no reconcile lifecycle entry; events seen: %r" % [l.get("event") for l in life]
assert "re-verified" in recon[-1].get("detail", ""), recon[-1]
ready = [l for l in life if l.get("event") == "ready"]
assert ready and ready[-1].get("detail", "").startswith("reconciled ·"), \
    "the ready line does not say which run produced its counts: %r" % (ready[-1],)
print("   evidence: %s · %s" % (recon[-1]["detail"], ready[-1]["detail"]))
EOF
echo "✓ reboot reconciled · t1 is ready again · baselines re-verified, and the evidence says so"

echo "== 3. create twice → identical names"
shape() { "$bin" status "$1" --json | grep -o '"name":"[^"]*"\|"template":"[^"]*"' | paste -sd' '; }
first="$(shape t1)"
"$bin" destroy t1 --yes >/dev/null
"$bin" up "$fixture" --name t1 --json >/dev/null
second="$(shape t1)"
[ "$first" = "$second" ] || { echo "FAIL shapes differ:"; echo "$first"; echo "$second"; exit 1; }
echo "✓ create twice → identical: $second"

echo "== 4. destroy leaves nothing"
"$bin" destroy t1 --yes >/dev/null
if "$bin" status t1 >/dev/null 2>&1; then echo "FAIL instance survives destroy"; exit 1; fi
if [ "$PODARO_RUNTIME" = "fake" ]; then
  if grep -q 'pdr-t1' "$XDG_STATE_HOME/podaro/fake-runtime.json"; then echo "FAIL runtime objects remain"; exit 1; fi
else
  leftover="$(podman ps -a --filter label=dev.podaro/instance=t1 --format '{{.Names}}'; podman network ls --filter label=dev.podaro/instance=t1 --format '{{.Name}}')"
  [ -z "$leftover" ] || { echo "FAIL podman objects remain: $leftover"; exit 1; }
fi
[ -e "$XDG_STATE_HOME/podaro/instances/t1" ] && { echo "FAIL instance dir remains"; exit 1; }
echo "✓ destroy left zero runtime objects and zero state"

stop_engine
echo "all S4 acceptance checks passed (runtime: $PODARO_RUNTIME)"
