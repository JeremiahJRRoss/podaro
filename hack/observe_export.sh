#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S9 acceptance (Manual §4; roadmap §9; threat model B10): the
# observability export, proven against destinations this script holds.
#
#   1. off by default: an engine with no observability block runs a
#      whole create and sends nothing anywhere;
#   2. configured, the engine says where its signals go at startup;
#   3. `observe status` reports the posture; `observe test` lands one
#      probe per signal — on a mock OTLP collector at OTLP's own paths,
#      and on a mock HEC with Splunk's own authorization scheme;
#   4. real traffic follows: the engine's journal lines, one span per
#      job and the job's counts arrive at those destinations;
#   5. a destination that refuses is reported as refusing, and the
#      command fails — no probe is ever summarized as landing;
#   6. the secret-leak scan passes on everything captured.
#
# What this does NOT prove is that the redaction filter runs on the
# export path — nothing the engine logs during a healthy run contains a
# secret, so the scan below would pass either way. That proof is a unit
# test, where a secret can be put into a record on purpose:
# internal/observe TestEverythingExportedIsFiltered (the filter runs on
# every string that leaves) and TestWithheldWhenFilterFails (a filter
# that cannot be built withholds the record), and internal/engine
# TestExportFilterCoversEveryInstance (the filter is every instance's).
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
ENGINE_PID=""
CAPTURE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  if [ -n "$CAPTURE_PID" ]; then kill "$CAPTURE_PID" 2>/dev/null || true; wait "$CAPTURE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; echo "--- engine log"; tail -40 "$tmp/engine.log" 2>/dev/null || true; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-500ms}"
export no_proxy="${no_proxy:+$no_proxy,}127.0.0.1,localhost" NO_PROXY="${NO_PROXY:+$NO_PROXY,}127.0.0.1,localhost"
mkdir -p "$XDG_STATE_HOME/podaro/catalog" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME/podaro" "$HOME"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
cp -R scenarios/grafana-prometheus-intro "$XDG_STATE_HOME/podaro/catalog/"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
cap="$tmp/captured.jsonl"
: >"$cap"

HEC_TOKEN="hec-$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$HEC_TOKEN" >"$XDG_CONFIG_HOME/podaro/hec.token"
chmod 600 "$XDG_CONFIG_HOME/podaro/hec.token"

# The destinations: one OTLP collector, one HEC. Each appends a JSON
# line per request — method, path, authorization and body — so the whole
# of what left the engine can be read back and scanned.
cat >"$tmp/capture.py" <<'PY'
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

out, token = sys.argv[1], sys.argv[2]
lock = threading.Lock()

def handler(kind):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("content-length", 0))
            body = self.rfile.read(n).decode("utf-8", "replace")
            auth = self.headers.get("authorization", "")
            with lock:
                with open(out, "a") as f:
                    f.write(json.dumps({"dest": kind, "path": self.path, "auth": auth,
                                        "content_type": self.headers.get("content-type", ""),
                                        "host": self.headers.get("host", ""), "body": body}) + "\n")
            # The mock HEC checks its own credential, as Splunk does: a
            # wrong token is a 401 the engine must report as one.
            if kind == "hec" and auth != "Splunk " + token:
                self.send_response(401); self.end_headers(); self.wfile.write(b'{"text":"Invalid token"}'); return
            self.send_response(200); self.end_headers(); self.wfile.write(b'{"text":"Success","code":0}')
        def log_message(self, *a): pass
    return H

servers = []
for kind in ("otlp", "hec"):
    s = HTTPServer(("127.0.0.1", 0), handler(kind))
    servers.append((kind, s))
print(json.dumps({k: s.server_address[1] for k, s in servers}), flush=True)
for _, s in servers:
    threading.Thread(target=s.serve_forever, daemon=True).start()
threading.Event().wait()
PY
python3 "$tmp/capture.py" "$cap" "$HEC_TOKEN" >"$tmp/ports.json" &
CAPTURE_PID=$!
for _ in $(seq 1 100); do [ -s "$tmp/ports.json" ] && break; sleep 0.1; done
[ -s "$tmp/ports.json" ] || fail "the capture destinations did not start"
OTLP_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["otlp"])' "$tmp/ports.json")"
HEC_PORT="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hec"])' "$tmp/ports.json")"
echo "✓ destinations up · otlp 127.0.0.1:$OTLP_PORT · hec 127.0.0.1:$HEC_PORT"

start_engine() {
  "$bin" engine serve >>"$tmp/engine.log" 2>&1 &
  ENGINE_PID=$!
  for _ in $(seq 1 150); do [ -S "$sock" ] && break; sleep 0.1; done
  [ -S "$sock" ] || fail "engine did not open its socket"
}
stop_engine() {
  [ -n "$ENGINE_PID" ] || return 0
  kill "$ENGINE_PID" 2>/dev/null || true
  wait "$ENGINE_PID" 2>/dev/null || true
  ENGINE_PID=""
  for _ in $(seq 1 100); do [ -S "$sock" ] || break; sleep 0.1; done
}

# ---------------------------------------------------------------- 1. off
: >"$tmp/engine.log"
start_engine
"$bin" up grafana-prometheus-intro --name off >"$tmp/up-off.log" 2>&1 \
  || fail "create with export off: $(cat "$tmp/up-off.log")"
"$bin" observe status >"$tmp/status-off.log" 2>&1 || fail "observe status with export off"
grep -q "export is off" "$tmp/status-off.log" || fail "status does not say export is off: $(cat "$tmp/status-off.log")"
"$bin" observe test >"$tmp/test-off.log" 2>&1 || fail "observe test with export off"
grep -q "nothing to probe" "$tmp/test-off.log" || fail "test with export off: $(cat "$tmp/test-off.log")"
stop_engine
[ ! -s "$cap" ] || fail "with no observability block the engine sent $(wc -l <"$cap") request(s) — export must be off by default"
echo "✓ off by default · a whole create, a status and a test · zero requests to any destination"

# --------------------------------------------------------- 2. configured
cat >"$XDG_CONFIG_HOME/podaro/config.yaml" <<YAML
observability:
  logs:    { exporter: hec,  endpoint: http://127.0.0.1:$HEC_PORT, token_file: $XDG_CONFIG_HOME/podaro/hec.token }
  metrics: { exporter: otlp, endpoint: http://127.0.0.1:$OTLP_PORT }
  traces:  { exporter: otlp, endpoint: http://127.0.0.1:$OTLP_PORT }
  attributes: { host: lab-01 }
YAML
: >"$tmp/engine.log"
start_engine
grep -q "observability export · logs → hec" "$tmp/engine.log" || fail "the engine did not say where its logs go: $(cat "$tmp/engine.log")"
grep -q "observability export · traces → otlp" "$tmp/engine.log" || fail "the engine did not say where its traces go"
echo "✓ startup names every destination in the operator's own journal"

"$bin" observe status --json >"$tmp/status.json" || fail "observe status"
python3 - "$tmp/status.json" "$OTLP_PORT" "$HEC_PORT" <<'PY' || exit 1
import json, sys
p = json.load(open(sys.argv[1])); otlp, hec = sys.argv[2], sys.argv[3]
want = {"logs": ("hec", "http://127.0.0.1:" + hec), "metrics": ("otlp", "http://127.0.0.1:" + otlp),
        "traces": ("otlp", "http://127.0.0.1:" + otlp)}
for sig, (exporter, endpoint) in want.items():
    got = p[sig]
    if got["exporter"] != exporter or got["endpoint"] != endpoint:
        print("FAIL %s posture = %s, want %s %s" % (sig, got, exporter, endpoint)); sys.exit(1)
    if got.get("insecure"):
        print("FAIL %s reports insecure and nothing asked for it" % sig); sys.exit(1)
PY
echo "✓ observe status · three signals, each naming its exporter and endpoint"

# ------------------------------------------------------------- 3. probes
"$bin" observe test >"$tmp/test.log" 2>&1 || fail "observe test: $(cat "$tmp/test.log")"
grep -q "3 of 3 signals landed" "$tmp/test.log" || fail "observe test: $(cat "$tmp/test.log")"
python3 - "$cap" <<'PY' || exit 1
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
by = {}
for r in rows:
    by.setdefault((r["dest"], r["path"]), []).append(r)
for want in [("hec", "/services/collector/event"), ("otlp", "/v1/metrics"), ("otlp", "/v1/traces")]:
    if want not in by:
        print("FAIL nothing reached %s%s; saw %s" % (want[0], want[1], sorted(by))); sys.exit(1)
hec = by[("hec", "/services/collector/event")][0]
if not hec["auth"].startswith("Splunk "):
    print("FAIL HEC authorization = %r — want Splunk's own scheme" % hec["auth"]); sys.exit(1)
probe = json.loads(hec["body"].splitlines()[0])
if probe["event"]["message"] != "podaro observe test":
    print("FAIL the HEC probe body = %r" % probe); sys.exit(1)
if probe["event"]["attributes"].get("host") != "lab-01":
    print("FAIL the configured attributes are missing: %r" % probe); sys.exit(1)
traces = json.loads(by[("otlp", "/v1/traces")][0]["body"])
span = traces["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
if span["name"] != "podaro observe test" or not span["traceId"]:
    print("FAIL the OTLP trace probe = %r" % span); sys.exit(1)
print("  probe bodies: HEC event %r · OTLP span %r" % (probe["event"]["message"], span["name"]))
PY
echo "✓ observe test · one probe per signal, at each destination's own path, with its own credential"

# ------------------------------------------------- 4. real engine traffic
before="$(wc -l <"$cap")"
"$bin" up grafana-prometheus-intro --name exported >"$tmp/up.log" 2>&1 || fail "create: $(cat "$tmp/up.log")"
stop_engine   # Close() flushes what is queued
python3 - "$cap" "$before" <<'PY' || exit 1
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()][int(sys.argv[2]):]
logs = [r for r in rows if r["path"] == "/services/collector/event"]
traces = [r for r in rows if r["path"] == "/v1/traces"]
metrics = [r for r in rows if r["path"] == "/v1/metrics"]
if not logs or not traces or not metrics:
    print("FAIL after a create: %d log, %d trace, %d metric request(s)" % (len(logs), len(traces), len(metrics))); sys.exit(1)
journal = [json.loads(l)["event"]["message"] for r in logs for l in r["body"].splitlines()]
if not any("exported" in m for m in journal):
    print("FAIL no journal line about the instance reached the export; saw %r" % journal[:8]); sys.exit(1)
spans = [s for r in traces for s in json.loads(r["body"])["resourceSpans"][0]["scopeSpans"][0]["spans"]]
create = [s for s in spans if s["name"] == "podaro.create"]
if not create:
    print("FAIL no span for the create job; saw %r" % [s["name"] for s in spans]); sys.exit(1)
attrs = {a["key"]: a["value"]["stringValue"] for a in create[0]["attributes"]}
if attrs.get("instance") != "exported" or attrs.get("job.state") != "succeeded":
    print("FAIL the create span = %r" % attrs); sys.exit(1)
if int(create[0]["endTimeUnixNano"]) <= int(create[0]["startTimeUnixNano"]):
    print("FAIL the span has no duration"); sys.exit(1)
names = {m["name"] for r in metrics for sm in json.loads(r["body"])["resourceMetrics"][0]["scopeMetrics"] for m in sm["metrics"]}
for want in ("podaro.job.duration_seconds", "podaro.jobs.finished"):
    if want not in names:
        print("FAIL %s never exported; saw %r" % (want, sorted(names))); sys.exit(1)
print("  %d journal line(s) · span podaro.create on 'exported' · metrics %s" % (len(journal), ", ".join(sorted(names))))
PY
echo "✓ real traffic · journal lines, one span per job, and the job's counts"


# Every component's journal line, not only the engine's. The startup
# line naming each destination is written by the engine *process* — the
# same function the gateway and the authentication sweeper log through
# — so it is the cheapest proof that the export seam sits where they are
# all wired rather than inside one of them. Only
# the stable half is matched, so the assertion does not depend on which
# port the destinations took. (Round 20's comment here claimed the endpoint is redacted on the way out. It is not: the export path filters this deployment's *secret values*, and a loopback endpoint is not one. The claim was wrong and is corrected rather than left standing)
python3 - "$cap" <<'PYCHECK' || exit 1
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
logs = [r for r in rows if r["path"] == "/services/collector/event"]
msgs = [json.loads(l)["event"]["message"] for r in logs for l in r["body"].splitlines()]
if not any("observability export \u00b7 logs \u2192" in m for m in msgs):
    print("FAIL a line the engine process itself wrote — the startup line naming each destination — never reached the export; saw %r" % msgs[:12]); sys.exit(1)
# The banner and the stop line are the process's own lifecycle, written
# straight to the journal writer rather than through the logger the
# components share — so they are the ones a wrap at the component level
# could never reach.
for want, what in (("podaro engine v", "the start-up banner"), ("podaro engine stopped", "the stop line")):
    if not any(want in m for m in msgs):
        print("FAIL %s never reached the export; saw %r" % (what, msgs[:12])); sys.exit(1)
print("  the process's own lines export too, banner and stop included (%d line(s) captured)" % len(msgs))
PYCHECK
echo "✓ every component's journal line takes the export path, not only the engine's"

# -------------------------------------------- 5. a refusal is a refusal
printf '%s\n' "not-the-token" >"$XDG_CONFIG_HOME/podaro/hec.token"
chmod 600 "$XDG_CONFIG_HOME/podaro/hec.token"
: >"$tmp/engine.log"
start_engine
set +e
"$bin" observe test >"$tmp/test-bad.log" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] || fail "observe test with a wrong HEC token exited 0: $(cat "$tmp/test-bad.log")"
grep -q "401" "$tmp/test-bad.log" || fail "the refusal does not carry what the destination answered: $(cat "$tmp/test-bad.log")"
grep -q "1 of 3 signals did not land" "$tmp/test-bad.log" || fail "observe test: $(cat "$tmp/test-bad.log")"
grep -q "not-the-token" "$tmp/test-bad.log" && fail "the credential appeared in the CLI's output"
stop_engine
echo "✓ a destination that refuses is reported as refusing · exit $rc · the credential is never printed"

# ------------------------------------------------------- 6. the leak scan
hack/secret_leak_scan.sh "$XDG_STATE_HOME/podaro" "$cap" "$tmp/engine.log" "$tmp/test.log" "$tmp/status.json"

echo
echo "S9 observability export: off by default · configured and announced · probes land at each"
echo "destination's own path and credential · journal, spans and counts follow · a refusal is"
echo "reported as one · nothing captured carries a secret value."
