#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S6 acceptance, scripted (roadmap §5; spec 0001 §1; User Manual
# §2, §6, §8; UX §5, §7), against a real engine over its socket door:
#   1. `up` of the small template reaches ready honestly — baseline 4/4,
#      objectives 0/2, the Manual §6 closing line, no PDR-W101;
#   2. `verify --json` lists results by class (`jq '.results[].class'`);
#   3. the objective flips green when its condition is made true by hand
#      (a dashboard created against the product with the revealed, audited
#      admin password), and evidence shows both runs — fail, then pass;
#   4. the seed a step names runs on demand and its objective turns green;
#   5. the JUnit export is well-formed, one suite per class;
#   6. reset shows its two-column impact, returns to a verified baseline,
#      clears objective progress, and evidence only grows;
#   7. secrets appear nowhere but the store (hack/secret_leak_scan.sh over
#      the state directory, the engine log, every API dump, every CLI output);
#   8. destroy leaves nothing.
# Runs against the fake runtime (PODARO_RUNTIME=fake): its Prometheus and
# Grafana personalities answer the checkpoints' real HTTP on loopback. The
# same script against Podman proves the real products:
#   PODARO_RUNTIME=podman hack/ready_test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
ENGINE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; echo "--- engine log"; cat "$tmp/engine.log" 2>/dev/null || true; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
mkdir -p "$XDG_STATE_HOME/podaro/catalog" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME" "$tmp/api" "$tmp/cli"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
# The catalog the engine serves templates from (INSTALL §3): the small
# template, as `podaro system install` would place it.
cp -R scenarios/grafana-prometheus-intro "$XDG_STATE_HOME/podaro/catalog/"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
STATE="$XDG_STATE_HOME/podaro"
API=http://podaro/api/v1alpha1
sapi() { curl -sS --unix-socket "$sock" "$@"; }

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

echo "== 1. up reaches ready honestly"
"$bin" up grafana-prometheus-intro --name intro >"$tmp/cli/up.out" 2>&1 || { cat "$tmp/cli/up.out"; fail "up"; }
cat "$tmp/cli/up.out"
grep -q "^✓ intro is ready — baseline 4/4 verified · objectives 0/2 (those are yours to earn)$" "$tmp/cli/up.out" || fail "the Manual §6 closing line"
grep -q "PDR-W101" "$tmp/cli/up.out" && fail "no objective may be green at create"
"$bin" status intro >"$tmp/cli/status.out"
grep -q "^intro · grafana-prometheus-intro@1.0.0 · ●●●●●●● ready$" "$tmp/cli/status.out" || { cat "$tmp/cli/status.out"; fail "status headline"; }
grep -q "checkpoints *baseline 4/4 · objectives 0/2$" "$tmp/cli/status.out" || fail "status tally row"
"$bin" status intro --json >"$tmp/cli/status.json"
jq -e '.instance.ladder.stage=="ready" and .instance.checkpoints.baseline=={"passed":4,"total":4} and .instance.checkpoints.objective=={"passed":0,"failed":2,"total":2}' "$tmp/cli/status.json" >/dev/null || { cat "$tmp/cli/status.json"; fail "status --json shape"; }
sapi "$API/instances/intro/checkpoints" >"$tmp/api/checkpoints.json"
[ "$(jq -r '[.checkpoints[] | select(.class=="baseline" and .result.status=="pass")] | length' "$tmp/api/checkpoints.json")" = "4" ] || fail "four green baselines"
[ "$(jq -r '[.checkpoints[] | select(.class=="objective" and .result.status=="fail")] | length' "$tmp/api/checkpoints.json")" = "2" ] || fail "two red objectives"
echo "✓ ready: baseline 4/4 · objectives 0/2, exactly as UX §5 renders it"

echo "== 2. verify --json by class"
"$bin" verify intro --json >"$tmp/cli/verify.json" 2>"$tmp/cli/verify.err" || { cat "$tmp/cli/verify.err"; fail "verify"; }
classes="$(jq -r '.results[].class' "$tmp/cli/verify.json" | sort | uniq -c | awk '{print $2"="$1}' | paste -sd' ')"
[ "$classes" = "baseline=4 objective=2" ] || fail "verify --json classes: $classes"
jq -e '.job.kind=="verify" and .job.state=="succeeded"' "$tmp/cli/verify.json" >/dev/null || fail "verify job"
echo "✓ podaro verify --json | jq '.results[].class' → $classes"

echo "== 3. the objective flips green when the condition is made true by hand; evidence shows both runs"
pw="$(sapi -X POST "$API/instances/intro/secrets/grafana/reveal" | jq -r '.value')"
[ "${#pw}" = "24" ] || fail "revealed password length ${#pw}"
sapi "$API/instances/intro/secrets" >"$tmp/api/secrets.json"
jq -e '.secrets[0].name=="grafana" and .secrets[0].kind=="password" and .secrets[0].reveals==1 and (.secrets[0] | has("value") | not)' "$tmp/api/secrets.json" >/dev/null || fail "secret listing: names and metadata only, the reveal counted"
sapi "$API/instances/intro/evidence?type=audit" >"$tmp/api/evidence-audit.json"
[ "$(jq -r '[.evidence[] | select(.audit.action=="reveal" and .audit.detail=="grafana" and .audit.mechanism=="socket")] | length' "$tmp/api/evidence-audit.json")" = "1" ] || fail "the reveal is in the audit evidence"
port="$(sapi "$API/instances/intro" | jq -r '.instance.services[] | select(.name=="grafana") | .ports["3000"]')"
[ -n "$port" ] && [ "$port" != "null" ] || fail "grafana's published port"
curl -sS -u "admin:$pw" -H 'Content-Type: application/json' -d '{"dashboard":{"title":"Lab Overview"}}' "http://127.0.0.1:$port/api/dashboards/db" | grep -q '"status":"success"' || fail "create the dashboard by hand"
sapi -X POST "$API/instances/intro/checkpoints/dashboard-exists/run" >"$tmp/api/run-dashboard.json"
jq -e '.result.status=="pass" and .result.class=="objective" and (.result.evidence | startswith("/api/v1alpha1/instances/intro/evidence/ev_"))' "$tmp/api/run-dashboard.json" >/dev/null || { cat "$tmp/api/run-dashboard.json"; fail "dashboard-exists after the act"; }
sapi "$API/instances/intro/evidence?type=checkpoint" >"$tmp/api/evidence-checkpoint.json"
runs="$(jq -r '[.evidence[] | select(.checkpoint.id=="dashboard-exists") | .checkpoint.status] | join(",")' "$tmp/api/evidence-checkpoint.json")"
[ "$runs" = "fail,fail,pass" ] || fail "evidence must show the red runs then the green one: $runs"
"$bin" status intro --json | jq -e '.instance.checkpoints.objective=={"passed":1,"failed":1,"total":2}' >/dev/null || fail "tally after the act"
echo "✓ dashboard-exists: fail at create, fail at verify, pass after the act — all three in evidence; reveal audited"

echo "== 4. the step's seed runs on demand"
"$bin" seed intro query-load >"$tmp/cli/seed.out" 2>&1 || { cat "$tmp/cli/seed.out"; fail "seed"; }
grep -q "^✓ seed query-load sent · " "$tmp/cli/seed.out" || { cat "$tmp/cli/seed.out"; fail "seed closing line"; }
sapi -X POST "$API/instances/intro/checkpoints/traffic-observed/run" >"$tmp/api/run-traffic.json"
jq -e '.result.status=="pass"' "$tmp/api/run-traffic.json" >/dev/null || { cat "$tmp/api/run-traffic.json"; fail "traffic-observed after the seed"; }
sapi "$API/instances/intro/evidence?type=seed" >"$tmp/api/evidence-seed.json"
jq -e '.evidence | length == 1 and .[0].seed.name=="query-load" and .[0].seed.count==200' "$tmp/api/evidence-seed.json" >/dev/null || fail "seed evidence"
echo "✓ query-load sent on demand · traffic-observed pass · seed run in evidence"

echo "== 5. the JUnit export is well-formed"
sapi "$API/instances/intro/evidence/report.junit.xml" >"$tmp/api/report.junit.xml"
python3 - "$tmp/api/report.junit.xml" <<'EOF' || fail "junit"
import sys, xml.etree.ElementTree as ET
root = ET.parse(sys.argv[1]).getroot()
assert root.tag == "testsuites", root.tag
suites = {s.get("name"): s for s in root.findall("testsuite")}
assert set(suites) == {"baseline", "objective"}, set(suites)
assert suites["baseline"].get("tests") == "4" and suites["baseline"].get("failures") == "0", suites["baseline"].attrib
assert suites["objective"].get("tests") == "2", suites["objective"].attrib
cases = {c.get("name") for s in suites.values() for c in s.findall("testcase")}
assert {"prometheus-ready", "grafana-healthy", "self-scrape-up", "grafana-scraped", "traffic-observed", "dashboard-exists"} <= cases, cases
print("junit: 2 suites, %d cases" % len(cases))
EOF
echo "✓ report.junit.xml parses: suites baseline (4) and objective (2)"

echo "== 6. reset: impact shown, back to verified baseline, objective progress cleared, evidence keeps the history"
sapi -X PUT -H 'Content-Type: application/json' -d '{"current_step":"build-a-dashboard","steps":{"meet-the-stack":{"status":"skipped"}}}' "$API/instances/intro/playbooks/first-dashboard/progress" | jq -e '.current_step=="build-a-dashboard"' >/dev/null || fail "write progress"
before="$(sapi "$API/instances/intro/evidence" | jq '.evidence | length')"
"$bin" reset intro --yes >"$tmp/cli/reset.out" 2>&1 || { cat "$tmp/cli/reset.out"; fail "reset"; }
cat "$tmp/cli/reset.out"
grep -q "^reset intro — impact$" "$tmp/cli/reset.out" || fail "reset preview header"
grep -q "^  destroyed *survives$" "$tmp/cli/reset.out" || fail "reset preview columns"
grep -q "^✓ intro is ready — baseline 4/4 verified · objectives 0/2 (those are yours to earn)$" "$tmp/cli/reset.out" || fail "reset closing line"
sapi "$API/instances/intro/playbooks/first-dashboard/progress" | jq -e '.current_step=="meet-the-stack" and (.steps | length == 0)' >/dev/null || fail "reset clears objective progress"
sapi -X POST "$API/instances/intro/checkpoints/dashboard-exists/run" | jq -e '.result.status=="fail"' >/dev/null || fail "the dashboard is gone after reset"
after="$(sapi "$API/instances/intro/evidence" | jq '.evidence | length')"
[ "$after" -gt "$before" ] || fail "evidence only grows: $before then $after"
sapi "$API/instances/intro/evidence" >"$tmp/api/evidence-all.json"
jq -e '[.evidence[] | select(.audit.action=="reset")] | length == 1' "$tmp/api/evidence-all.json" >/dev/null || fail "the reset is audited"
echo "✓ reset → ready with objectives 0/2 · progress cleared · evidence $before → $after entries, reset audited"

echo "== 7. secrets appear nowhere but the store"
sapi "$API/instances" >"$tmp/api/instances.json"
sapi "$API/instances/intro" >"$tmp/api/instance.json"
sapi "$API/instances/intro/playbooks/first-dashboard" >"$tmp/api/playbook.json"
sapi "$API/instances/intro/reset-plan" >"$tmp/api/reset-plan.json"
"$bin" status intro --json >"$tmp/cli/status-final.json"
hack/secret_leak_scan.sh "$STATE" "$tmp/engine.log" "$tmp/api" "$tmp/cli" || fail "secret leak scan"

echo "== 8. destroy leaves nothing"
"$bin" destroy intro --yes >/dev/null
if "$bin" status intro >/dev/null 2>&1; then fail "instance survives destroy"; fi
[ -e "$STATE/instances/intro" ] && fail "instance dir remains"
if [ "$PODARO_RUNTIME" = "fake" ]; then
  grep -q 'pdr-intro' "$STATE/fake-runtime.json" && fail "runtime objects remain"
fi
echo "✓ destroy left zero runtime objects and zero state"

echo "all S6 acceptance checks passed (runtime: $PODARO_RUNTIME)"
