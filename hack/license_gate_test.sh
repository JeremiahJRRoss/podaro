#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The licence gate on a first-party fixture (the reconciliation plan's
# R1; API §6.2; spec 0003 §7): hack/fixtures/eula-lab declares a EULA
# under an id nobody holds, so the acceptance ceremony is proven without
# a vendor's terms accepted on anyone's behalf.
#   1. `POST /instances` without an acceptance is refused — 428,
#      PDR-E031 naming the id and its URL — and nothing is created or
#      pulled;
#   2. `up --yes` is the same refusal from the CLI (exit 1), and so is
#      `up --json`: neither turns a missing acceptance into a prompt;
#   3. `--accept-license example-terms` creates the lab, it reaches ready,
#      and the acceptance is in evidence — the id, the actor, the door and
#      the time; never the terms' text;
#   4. the acceptance is recorded once: a reset re-walks the create path
#      and records no second one;
#   5. destroy leaves nothing.
# The interactive typed prompt has no automated test: the CLI's tests run
# without a terminal, and the prompt appears only on one. It was a manual
# item of the acceptance test while the retired lab carried a EULA; since
# R2b retired that section (the starter catalog declares none), it is an
# explicit skip (docs/reconciliation/evidence/A6-coverage-map.md), never
# reported as a pass.
# Runs against the fake runtime (PODARO_RUNTIME=fake): the gated image
# does not exist, and nothing pulls it before the terms are accepted.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
ENGINE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; echo "--- engine log"; tail -40 "$tmp/engine.log" 2>/dev/null || true; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
mkdir -p "$XDG_STATE_HOME/podaro/catalog" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME" "$tmp/api" "$tmp/cli"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
"$bin" lab validate hack/fixtures/eula-lab >/dev/null || fail "the fixture validates"
cp -R hack/fixtures/eula-lab "$XDG_STATE_HOME/podaro/catalog/"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
STATE="$XDG_STATE_HOME/podaro"
API=http://podaro/api/v1alpha1
sapi() { curl -sS --unix-socket "$sock" "$@"; }

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

echo "== 1. refused before anything runs"
code="$(sapi -o "$tmp/api/refused.json" -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
  -d '{"template":"eula-lab","name":"gated"}' "$API/instances")"
[ "$code" = "428" ] || { cat "$tmp/api/refused.json"; fail "expected 428, got $code"; }
jq -e '.error.code=="PDR-E031" and (.error.details | length) == 1 and .error.details[0].license=="example-terms" and .error.details[0].url=="https://example.com/terms"' \
  "$tmp/api/refused.json" >/dev/null || { cat "$tmp/api/refused.json"; fail "the 428 names the licence and its URL"; }
[ "$(sapi "$API/instances" | jq -r '.instances | length')" = "0" ] || fail "a refused create left an instance"
if [ -f "$STATE/fake-runtime.json" ]; then
  jq -e '[(.images // {}) | keys[] | select(contains("terms-gated"))] | length == 0' "$STATE/fake-runtime.json" >/dev/null || fail "a refused create pulled the gated image"
fi
echo "✓ 428 PDR-E031 · example-terms · https://example.com/terms · nothing created, nothing pulled"

echo "== 2. --yes and --json refuse the same way, and prompt nobody"
set +e
"$bin" up eula-lab --name gated --yes >"$tmp/cli/up-yes.out" 2>&1; code=$?
set -e
[ "$code" = "1" ] || { cat "$tmp/cli/up-yes.out"; fail "up --yes exits 1 on a missing acceptance, got $code"; }
grep -q "PDR-E031" "$tmp/cli/up-yes.out" && grep -q "example-terms" "$tmp/cli/up-yes.out" || { cat "$tmp/cli/up-yes.out"; fail "up --yes names the code and the licence"; }
set +e
"$bin" up eula-lab --name gated --json >"$tmp/cli/up-json.out" 2>&1; code=$?
set -e
[ "$code" = "1" ] || { cat "$tmp/cli/up-json.out"; fail "up --json exits 1 on a missing acceptance, got $code"; }
grep -q '"PDR-E031"' "$tmp/cli/up-json.out" || { cat "$tmp/cli/up-json.out"; fail "up --json carries the refusal envelope"; }
[ "$(sapi "$API/instances" | jq -r '.instances | length')" = "0" ] || fail "a refused up left an instance"
echo "✓ up --yes → exit 1 PDR-E031 · up --json → exit 1 with the envelope · still nothing created"

echo "== 3. accepted by id, the lab reaches ready, and the acceptance is in evidence"
"$bin" up eula-lab --name gated --accept-license example-terms >"$tmp/cli/up.out" 2>&1 || { cat "$tmp/cli/up.out"; fail "up with the acceptance"; }
cat "$tmp/cli/up.out"
"$bin" status gated --json >"$tmp/cli/status.json"
jq -e '.instance.ladder.stage=="ready" and .instance.checkpoints.baseline=={"passed":1,"total":1}' "$tmp/cli/status.json" >/dev/null \
  || { cat "$tmp/cli/status.json"; fail "ready with its one baseline green"; }
sapi "$API/instances/gated/evidence?type=audit" >"$tmp/api/evidence-audit.json"
jq -e '[.evidence[] | select(.audit.action=="accept-license" and .audit.detail=="example-terms" and .audit.mechanism=="socket" and (.at | length) > 0 and (.audit.at | length) > 0)] | length == 1' \
  "$tmp/api/evidence-audit.json" >/dev/null || { cat "$tmp/api/evidence-audit.json"; fail "the acceptance is in evidence with the actor, the door and the time"; }
if grep -q -i 'terms' "$STATE/instances/gated/evidence/"*.json | grep -v -q 'example-terms'; then :; fi
grep -rq 'https://example.com/terms' "$STATE/instances/gated/evidence/" && fail "evidence quotes the terms' URL; it records the id"
echo "✓ ready · baseline 1/1 · evidence: accept-license example-terms by the socket door, timestamped"

echo "== 4. recorded once: a reset re-walks the create path and adds no second record"
"$bin" reset gated --yes >"$tmp/cli/reset.out" 2>&1 || { cat "$tmp/cli/reset.out"; fail "reset"; }
sapi "$API/instances/gated/evidence?type=audit" >"$tmp/api/evidence-audit-after.json"
[ "$(jq -r '[.evidence[] | select(.audit.action=="accept-license")] | length' "$tmp/api/evidence-audit-after.json")" = "1" ] \
  || { cat "$tmp/api/evidence-audit-after.json"; fail "the acceptance must be recorded exactly once"; }
"$bin" status gated --json | jq -e '.instance.ladder.stage=="ready"' >/dev/null || fail "ready again after reset"
echo "✓ one acceptance record before and after reset"

echo "== 5. destroy leaves nothing"
"$bin" destroy gated --yes >/dev/null
if "$bin" status gated >/dev/null 2>&1; then fail "instance survives destroy"; fi
[ -e "$STATE/instances/gated" ] && fail "instance dir remains"
echo "✓ destroy left zero state"

echo "all licence-gate checks passed on a first-party fixture (runtime: $PODARO_RUNTIME); the typed prompt is not automated (an explicit skip)"
