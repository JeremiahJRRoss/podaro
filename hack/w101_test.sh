#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# PDR-W101 on a first-party fixture (the reconciliation plan's R1; spec
# 0001 §1, §9): hack/fixtures/w101-lab carries one objective the template
# already makes true.
#   1. `up` reaches ready and says so — one PDR-W101 line naming the
#      objective; the tally counts it as passed; evidence carries the
#      warning, never a verdict the learner earned;
#   2. reset re-judges the objectives and flags it again, in evidence too;
#   3. destroy leaves nothing.
# Runs against the fake runtime (PODARO_RUNTIME=fake).
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
"$bin" lab validate hack/fixtures/w101-lab >/dev/null || fail "the fixture validates"
cp -R hack/fixtures/w101-lab "$XDG_STATE_HOME/podaro/catalog/"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
STATE="$XDG_STATE_HOME/podaro"
API=http://podaro/api/v1alpha1
sapi() { curl -sS --unix-socket "$sock" "$@"; }

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

echo "== 1. up reaches ready and flags the objective that was already true"
"$bin" up w101-lab --name w101 >"$tmp/cli/up.out" 2>&1 || { cat "$tmp/cli/up.out"; fail "up"; }
cat "$tmp/cli/up.out"
[ "$(grep -c "PDR-W101" "$tmp/cli/up.out")" = "1" ] || fail "exactly one PDR-W101 line at create"
grep -q "PDR-W101 objective page-answers passed at create" "$tmp/cli/up.out" || fail "the warning names the objective"
"$bin" status w101 --json >"$tmp/cli/status.json"
jq -e '.instance.ladder.stage=="ready" and .instance.checkpoints.baseline=={"passed":1,"total":1} and .instance.checkpoints.objective=={"passed":1,"failed":0,"total":1}' \
  "$tmp/cli/status.json" >/dev/null || { cat "$tmp/cli/status.json"; fail "the tally counts the objective as passed, and says so"; }
sapi "$API/instances/w101/checkpoints" >"$tmp/api/checkpoints.json"
jq -e '[.checkpoints[] | select(.id=="page-answers" and .class=="objective" and .result.status=="pass")] | length == 1' "$tmp/api/checkpoints.json" >/dev/null \
  || { cat "$tmp/api/checkpoints.json"; fail "page-answers is a green objective"; }
sapi "$API/instances/w101/evidence?type=lifecycle" >"$tmp/api/evidence-lifecycle.json"
[ "$(jq -r '[.evidence[] | select(.lifecycle.event=="warning" and .lifecycle.code=="PDR-W101" and (.lifecycle.detail | contains("page-answers")))] | length' "$tmp/api/evidence-lifecycle.json")" = "1" ] \
  || { cat "$tmp/api/evidence-lifecycle.json"; fail "evidence carries the warning once, naming the objective"; }
sapi "$API/instances/w101/evidence/report.junit.xml" >"$tmp/api/report.junit.xml"
python3 - "$tmp/api/report.junit.xml" <<'PYEOF' || fail "junit"
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = {s.get("name"): s for s in root.findall("testsuite")}
assert set(suites) == {"baseline", "objective"}, set(suites)
assert suites["baseline"].get("tests") == "1" and suites["baseline"].get("failures") == "0", suites["baseline"].attrib
assert suites["objective"].get("tests") == "1" and suites["objective"].get("failures") == "0", suites["objective"].attrib
print("junit: baseline 1 · objective 1")
PYEOF
echo "✓ ready · baseline 1/1 · objectives 1/1 flagged PDR-W101 · the warning is in evidence"

echo "== 2. reset re-judges and flags it again"
"$bin" reset w101 --yes >"$tmp/cli/reset.out" 2>&1 || { cat "$tmp/cli/reset.out"; fail "reset"; }
[ "$(grep -c "PDR-W101" "$tmp/cli/reset.out")" = "1" ] || { cat "$tmp/cli/reset.out"; fail "one PDR-W101 after reset, as at create"; }
sapi "$API/instances/w101/evidence?type=lifecycle" >"$tmp/api/evidence-lifecycle-after.json"
[ "$(jq -r '[.evidence[] | select(.lifecycle.event=="warning" and .lifecycle.code=="PDR-W101")] | length' "$tmp/api/evidence-lifecycle-after.json")" = "2" ] \
  || fail "evidence holds the create's warning and the reset's"
"$bin" status w101 --json | jq -e '.instance.checkpoints.objective=={"passed":1,"failed":0,"total":1}' >/dev/null || fail "tally after reset"
echo "✓ reset → PDR-W101 again · evidence keeps both warnings"

echo "== 3. destroy leaves nothing"
"$bin" destroy w101 --yes >/dev/null
if "$bin" status w101 >/dev/null 2>&1; then fail "instance survives destroy"; fi
[ -e "$STATE/instances/w101" ] && fail "instance dir remains"
echo "✓ destroy left zero state"

echo "all PDR-W101 checks passed on a first-party fixture (runtime: $PODARO_RUNTIME)"
