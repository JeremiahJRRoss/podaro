#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The conformance lab, end to end (the reconciliation plan's R1):
# hack/fixtures/conformance-lab exercises every built-in the platform
# keeps — http, container, attest and exec checkpoints; the http-requests
# and web-logs generators; a secret rendered and revealed; a soft-gated
# playbook whose seeds are step actions — on services that belong to no
# vendor.
#   1. `up` reaches ready honestly — baseline 3/3, objectives 0/3, no
#      PDR-W101;
#   2. `verify --json` lists results by class;
#   3. the playbook, completed the way a learner completes it: the knock
#      seed pressed from its step and its objective judged green over the
#      sink's own count; the events seed likewise, over what the sink
#      holds; the admin credential revealed, and the reveal audited; the
#      attestation made by a person and never upgraded; progress written
#      only over verdicts that exist;
#   4. the JUnit export is well-formed — one suite per class, the
#      attestation reported as what it is;
#   5. reset returns the lab to its create-time state — the sink empty,
#      the attestation cleared, progress cleared — and evidence only grows;
#   6. secrets appear nowhere but the store (hack/secret_leak_scan.sh);
#   7. destroy leaves nothing.
# Runs against the fake runtime (PODARO_RUNTIME=fake): the sink is the
# fake's example/ndjson-sink, the exec judge its conformance fixture.
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
# await_job polls one job to its end and fails unless it succeeded (a
# loop that runs out of polls must never let an assertion after it hold
# vacuously).
await_job() {
  local job="$1" what="$2" state=""
  for _ in $(seq 1 300); do
    state="$(sapi "$API/jobs/$job" | jq -r '.job.state')"
    [ "$state" = "succeeded" ] && return 0
    [ "$state" = "failed" ] && fail "$what failed"
    sleep 0.1
  done
  fail "$what did not finish: its job is still ${state:-unknown} after thirty seconds"
}

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
mkdir -p "$XDG_STATE_HOME/podaro/catalog" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME" "$tmp/api" "$tmp/cli"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
"$bin" lab validate hack/fixtures/conformance-lab >/dev/null || fail "the fixture validates"
cp -R hack/fixtures/conformance-lab "$XDG_STATE_HOME/podaro/catalog/"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
STATE="$XDG_STATE_HOME/podaro"
API=http://podaro/api/v1alpha1
sapi() { curl -sS --unix-socket "$sock" "$@"; }
port() { sapi "$API/instances/conformance" | jq -r --arg s "$1" --arg p "$2" '.instance.services[] | select(.name==$s) | .ports[$p]'; }

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

echo "== 1. up reaches ready honestly"
"$bin" up conformance-lab --name conformance >"$tmp/cli/up.out" 2>&1 || { cat "$tmp/cli/up.out"; fail "up"; }
cat "$tmp/cli/up.out"
grep -q "^✓ conformance is ready — baseline 3/3 verified · objectives 0/3 (those are yours to earn)$" "$tmp/cli/up.out" || fail "the Manual §6 closing line"
grep -q "PDR-W101" "$tmp/cli/up.out" && fail "no objective may be green at create"
"$bin" status conformance --json >"$tmp/cli/status.json"
jq -e '.instance.ladder.stage=="ready" and .instance.checkpoints.baseline=={"passed":3,"total":3} and .instance.checkpoints.objective=={"passed":0,"failed":3,"total":3}' "$tmp/cli/status.json" >/dev/null \
  || { cat "$tmp/cli/status.json"; fail "status --json shape"; }
sapi "$API/instances/conformance/checkpoints" >"$tmp/api/checkpoints.json"
for pair in "web-answers=http" "web-running=container" "judge-runs=exec"; do
  id="${pair%%=*}"; adapter="${pair##*=}"
  jq -e --arg id "$id" --arg a "$adapter" '[.checkpoints[] | select(.id==$id and .class=="baseline" and .adapter==$a and .result.status=="pass")] | length == 1' "$tmp/api/checkpoints.json" >/dev/null \
    || { jq --arg id "$id" '.checkpoints[] | select(.id==$id)' "$tmp/api/checkpoints.json"; fail "baseline $id ($adapter) green"; }
done
for pair in "knocks-counted=http" "events-held=http" "routes-understood=attest"; do
  id="${pair%%=*}"; adapter="${pair##*=}"
  jq -e --arg id "$id" --arg a "$adapter" '[.checkpoints[] | select(.id==$id and .class=="objective" and .adapter==$a and .result.status=="fail")] | length == 1' "$tmp/api/checkpoints.json" >/dev/null \
    || { jq --arg id "$id" '.checkpoints[] | select(.id==$id)' "$tmp/api/checkpoints.json"; fail "objective $id ($adapter) red at create"; }
done
echo "✓ ready: http, container and exec baselines green · http and attest objectives red · no PDR-W101"

echo "== 2. verify --json by class"
"$bin" verify conformance --json >"$tmp/cli/verify.json" 2>"$tmp/cli/verify.err" || { cat "$tmp/cli/verify.err"; fail "verify"; }
classes="$(jq -r '.results[].class' "$tmp/cli/verify.json" | sort | uniq -c | awk '{print $2"="$1}' | paste -sd' ')"
[ "$classes" = "baseline=3 objective=3" ] || fail "verify --json classes: $classes"
echo "✓ podaro verify --json | jq '.results[].class' → $classes"

echo "== 3. the playbook, completed the way a learner completes it"
sink="$(port sink 8080)"
[ -n "$sink" ] && [ "$sink" != "null" ] || fail "the sink's published port"
echo "-- step knock: the seed pressed from its step, the objective judged over the sink's own count"
"$bin" seed conformance knock >"$tmp/cli/seed-knock.out" 2>&1 || { cat "$tmp/cli/seed-knock.out"; fail "seed knock"; }
grep -q "^✓ seed knock sent · " "$tmp/cli/seed-knock.out" || { cat "$tmp/cli/seed-knock.out"; fail "seed closing line"; }
[ "$(curl -sS "http://127.0.0.1:$sink/_stats" | jq -r '.requests')" -ge 50 ] || fail "the sink counted the knocks"
sapi -X POST "$API/instances/conformance/checkpoints/knocks-counted/run" >"$tmp/api/run-knocks.json"
jq -e '.result.status=="pass" and .result.class=="objective"' "$tmp/api/run-knocks.json" >/dev/null || { cat "$tmp/api/run-knocks.json"; fail "knocks-counted after the seed"; }
echo "   ✓ knocks-counted: red at create, green after fifty requests"
echo "-- step deliver: events land, the credential is revealed, the objective judged over what the sink holds"
sapi -X POST -H 'Content-Type: application/json' -d '{}' "$API/instances/conformance/seeds/events" >"$tmp/api/seed-events.json"
jq -e '.job.kind=="seed"' "$tmp/api/seed-events.json" >/dev/null || { cat "$tmp/api/seed-events.json"; fail "press the events seed"; }
await_job "$(jq -r '.job.id' "$tmp/api/seed-events.json")" "the events seed"
curl -sS "http://127.0.0.1:$sink/_stats" >"$tmp/api/sink-stats.json"
jq -e '.events == 120 and .requests >= 53' "$tmp/api/sink-stats.json" >/dev/null || { cat "$tmp/api/sink-stats.json"; fail "the sink holds the 120 events, delivered in batches"; }
pw="$(sapi -X POST "$API/instances/conformance/secrets/admin/reveal" | jq -r '.value')"
[ "${#pw}" = "24" ] || fail "revealed password length ${#pw}"
sapi -X POST "$API/instances/conformance/checkpoints/events-held/run" >"$tmp/api/run-events.json"
jq -e '.result.status=="pass"' "$tmp/api/run-events.json" >/dev/null || { cat "$tmp/api/run-events.json"; fail "events-held after the seed"; }
echo "   ✓ events-held: green over 120 events the sink holds · admin revealed"
echo "-- step confirm: the attestation is a person's, never the machine's"
sapi -X POST "$API/instances/conformance/checkpoints/routes-understood/run" | jq -e '.result.status=="fail"' >/dev/null || fail "an attest checkpoint is red until it is confirmed"
sapi -X POST -H 'Content-Type: application/json' -d '{}' "$API/instances/conformance/checkpoints/routes-understood/attest" >"$tmp/api/attest.json"
jq -e '.result.status=="attested"' "$tmp/api/attest.json" >/dev/null || { cat "$tmp/api/attest.json"; fail "attest"; }
echo "   ✓ routes-understood: fail → attested"
echo "-- step receipts: progress written over verdicts that exist"
sapi -o "$tmp/api/progress.json" -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
  -d '{"current_step":"receipts","steps":{"knock":{"status":"pass"},"deliver":{"status":"pass"},"confirm":{"status":"attested"}}}' \
  "$API/instances/conformance/playbooks/conformance/progress" >"$tmp/api/progress.code"
[ "$(cat "$tmp/api/progress.code")" = "200" ] || { cat "$tmp/api/progress.json"; fail "progress over real verdicts is accepted"; }
"$bin" status conformance --json | jq -e '.instance.checkpoints.objective=={"passed":3,"failed":0,"total":3}' >/dev/null || fail "objectives 3/3 after the playbook"
sapi "$API/instances/conformance/evidence?type=seed" >"$tmp/api/evidence-seed.json"
jq -e '[.evidence[] | .seed.name] | sort == ["events","knock"]' "$tmp/api/evidence-seed.json" >/dev/null || { cat "$tmp/api/evidence-seed.json"; fail "both seed runs in evidence"; }
sapi "$API/instances/conformance/evidence?type=audit" >"$tmp/api/evidence-audit.json"
jq -e '[.evidence[] | select(.audit.action=="reveal" and .audit.detail=="admin")] | length == 1' "$tmp/api/evidence-audit.json" >/dev/null || fail "the reveal is audited"
echo "   ✓ objectives 3/3 · two seed runs and the reveal in evidence"

echo "== 4. the JUnit export is well-formed"
sapi "$API/instances/conformance/evidence/report.junit.xml" >"$tmp/api/report.junit.xml"
python3 - "$tmp/api/report.junit.xml" <<'PYEOF' || fail "junit"
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
suites = {s.get("name"): s for s in root.findall("testsuite")}
assert set(suites) == {"baseline", "objective"}, set(suites)
b, o = suites["baseline"].attrib, suites["objective"].attrib
assert b.get("tests") == "3" and b.get("failures") == "0" and b.get("errors") == "0", b
assert o.get("tests") == "3" and o.get("failures") == "0" and o.get("errors") == "0" and o.get("skipped") == "1", o
cases = {c.get("name") for s in suites.values() for c in s.findall("testcase")}
assert {"web-answers", "web-running", "judge-runs", "knocks-counted", "events-held", "routes-understood"} <= cases, cases
print("junit: baseline 3 · objective 3, one attested")
PYEOF
echo "✓ report.junit.xml parses: the attestation is reported as what it is"

echo "== 5. reset returns the lab to its create-time state and keeps the evidence"
before="$(sapi "$API/instances/conformance/evidence" | jq '.evidence | length')"
"$bin" reset conformance --yes >"$tmp/cli/reset.out" 2>&1 || { cat "$tmp/cli/reset.out"; fail "reset"; }
grep -q "^✓ conformance is ready — baseline 3/3 verified · objectives 0/3 (those are yours to earn)$" "$tmp/cli/reset.out" || { cat "$tmp/cli/reset.out"; fail "reset closing line"; }
sink="$(port sink 8080)"
jq -e '.events == 0 and .requests == 0' <(curl -sS "http://127.0.0.1:$sink/_stats") >/dev/null || fail "the sink is empty after reset"
sapi -X POST "$API/instances/conformance/checkpoints/routes-understood/run" | jq -e '.result.status=="fail"' >/dev/null || fail "reset clears the attestation"
sapi "$API/instances/conformance/playbooks/conformance/progress" | jq -e '.current_step=="knock" and (.steps | length == 0)' >/dev/null || fail "reset clears objective progress"
after="$(sapi "$API/instances/conformance/evidence" | jq '.evidence | length')"
[ "$after" -gt "$before" ] || fail "evidence only grows: $before then $after"
echo "✓ reset → ready · sink empty · attestation and progress cleared · evidence $before → $after"

echo "== 6. secrets appear nowhere but the store"
sapi "$API/instances/conformance" >"$tmp/api/instance.json"
sapi "$API/instances/conformance/playbooks/conformance" >"$tmp/api/playbook.json"
sapi "$API/instances/conformance/reset-plan" >"$tmp/api/reset-plan.json"
"$bin" status conformance --json >"$tmp/cli/status-final.json"
hack/secret_leak_scan.sh "$STATE" "$tmp/engine.log" "$tmp/api" "$tmp/cli" || fail "secret leak scan"

echo "== 7. destroy leaves nothing"
"$bin" destroy conformance --yes >/dev/null
if "$bin" status conformance >/dev/null 2>&1; then fail "instance survives destroy"; fi
[ -e "$STATE/instances/conformance" ] && fail "instance dir remains"
if [ "$PODARO_RUNTIME" = "fake" ]; then
  grep -q 'pdr-conformance' "$STATE/fake-runtime.json" && fail "runtime objects remain"
fi
echo "✓ destroy left zero runtime objects and zero state"

echo "all conformance-lab checks passed (runtime: $PODARO_RUNTIME)"
