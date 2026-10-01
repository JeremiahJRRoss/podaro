#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S9 acceptance (API §2.4; threat model D4): an attendee link opens
# one lab and nothing else.
#
#   1. the operator issues a link, and it is shown once;
#   2. joining it lands a session bound to that instance, on that
#      instance's hostname;
#   3. the positive matrix: the attendee can do the learner's work —
#      read the lab, run verify and a checkpoint, attest, press a step's
#      seed, write progress, reveal this instance's secret;
#   4. the negative matrix: destroy, reset, logs, another instance,
#      another instance's hostname, issuing access, creating instances,
#      listing tokens — every one refused, by resource and by hostname;
#   5. revocation stops the next join;
#   6. every join, reveal and revocation is in the audit stream, and no
#      secret value appears outside the store;
#   7. the evidence report (API §10) opens standalone, carries the
#      attendee identity and the reveal event, and holds no secret value,
#      host address or internal hostname — this is the run that has an
#      attendee and a reveal to report, so it is the run that checks it.
#
# Runs against the fake runtime, through the real gateway with real TLS.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
ENGINE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; echo "--- engine log"; tail -30 "$tmp/engine.log" 2>/dev/null || true; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
mkdir -p "$XDG_STATE_HOME/podaro/catalog" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
cp -R scenarios/grafana-prometheus-intro "$XDG_STATE_HOME/podaro/catalog/"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
API=/api/v1alpha1
DOMAIN=lab.test
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')"
export no_proxy="${no_proxy:+$no_proxy,}$DOMAIN,.$DOMAIN,127.0.0.1" NO_PROXY="${NO_PROXY:+$NO_PROXY,}$DOMAIN,.$DOMAIN,127.0.0.1"

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

"$bin" setup --domain "$DOMAIN" --port "$PORT" --ip 203.0.113.10 >"$tmp/setup.out" 2>&1 || { cat "$tmp/setup.out"; fail "setup"; }
CA="$XDG_STATE_HOME/podaro/ca/ca.crt"
printf 'correct horse battery staple\n' > "$tmp/pw"; chmod 600 "$tmp/pw"
"$bin" auth setup --username jross --password-file "$tmp/pw" >"$tmp/authsetup.out" 2>&1 || { cat "$tmp/authsetup.out"; fail "auth setup"; }

"$bin" up grafana-prometheus-intro --name one >"$tmp/up1.out" 2>&1 || { cat "$tmp/up1.out"; fail "up one"; }
"$bin" up grafana-prometheus-intro --name two >"$tmp/up2.out" 2>&1 || { cat "$tmp/up2.out"; fail "up two"; }

# A real TLS client trusting the local CA, resolving the lab hostnames to
# loopback as a wildcard record would.
c() { # host path [curl args]
  local host="$1" path="$2"; shift 2
  curl -sS --cacert "$CA" --resolve "$host:$PORT:127.0.0.1" "$@" "https://$host:$PORT$path"
}
code() { c "$@" -o /dev/null -w '%{http_code}'; }

echo "== 1. the operator issues a link, shown once"
"$bin" access create one --name alice --expires 2h >"$tmp/grant.out" 2>&1 || { cat "$tmp/grant.out"; fail "access create"; }
cat "$tmp/grant.out"
grep -q "shown once" "$tmp/grant.out" || fail "the CLI says the link is shown once"
"$bin" access create one --name alice2 --json >"$tmp/grant.json" 2>&1 || { cat "$tmp/grant.json"; fail "access create --json"; }
LINK="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["join"])' "$tmp/grant.json")"
TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$tmp/grant.json")"
ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access"]["id"])' "$tmp/grant.json")"
case "$TOKEN" in pdi_*) ;; *) fail "the credential is a pdi_ link: $TOKEN";; esac
case "$LINK" in https://one.$DOMAIN:*) ;; *) fail "the link is on the instance's own hostname: $LINK";; esac
"$bin" access list one >"$tmp/list.out" 2>&1 || fail "access list"
grep -q "alice" "$tmp/list.out" || fail "the listing names the attendee"
grep -q "$TOKEN" "$tmp/list.out" && fail "the listing carried the secret"
echo "✓ two links issued · the secret is printed once and never listed"

echo "== 2. joining lands a session bound to the instance"
c "one.$DOMAIN" "$API/join/$TOKEN" -H 'Accept: application/json' -c "$tmp/jar" >"$tmp/join.json" || fail "join"
python3 - "$tmp/join.json" <<'EOF' || fail "the join's session"
import json, sys
s = json.load(open(sys.argv[1]))["session"]
assert s["instance"] == "one", s
assert s["subject"] == "alice2", s
print("   session:", s["subject"], "on", s["instance"])
EOF
grep -q podaro_session "$tmp/jar" || fail "the join set no session cookie"
echo "✓ joined as alice2, bound to one"

a() { # path [curl args] — the attendee, on their own instance's hostname
  local path="$1"; shift
  c "one.$DOMAIN" "$path" -b "$tmp/jar" "$@"
}
acode() { a "$@" -o /dev/null -w '%{http_code}'; }
CSRF="$(a "$API/auth/session" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["csrf"])')"
[ -n "$CSRF" ] || fail "the attendee session carries no csrf"

echo "== 3. the positive matrix: the learner's work"
for path in "$API/instances/one" "$API/instances/one/checkpoints" "$API/instances/one/playbooks" \
            "$API/instances/one/evidence" "$API/instances/one/secrets" "$API/instances"; do
  got="$(acode "$path")"
  [ "$got" = "200" ] || fail "an attendee must be able to GET $path (got $got)"
done
[ "$(a "$API/instances" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["instances"]))')" = "1" ] \
  || fail "the listing shows their instance alone"
# The attendee's own job: wait for it before the next one, as the console
# does — an instance runs one job at a time (API §7).
idle() {
  for _ in $(seq 1 200); do
    state="$(a "$API/instances/one" | python3 -c 'import json,sys; d=json.load(sys.stdin)["instance"].get("job") or {}; print(d.get("state",""))')"
    case "$state" in ""|succeeded|failed) return 0;; esac
    sleep 0.1
  done
  fail "a job never finished (last state $state)"
}
got="$(acode "$API/instances/one/verify" -X POST -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{}')"
[ "$got" = "202" ] || fail "an attendee may run verify (got $got)"
idle
got="$(acode "$API/instances/one/checkpoints/prometheus-ready/run" -X POST -H "X-Podaro-CSRF: $CSRF")"
[ "$got" = "200" ] || fail "an attendee may run a checkpoint (got $got)"
got="$(acode "$API/instances/one/seeds/query-load" -X POST -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{}')"
[ "$got" = "202" ] || fail "an attendee may press a step's seed (got $got)"
idle
# A seed no step of this lab names is outside the grant, and the refusal
# says so in one shape whether the seed is standing or absent: the check
# is `StepSeeds`, before any lookup, so the answer is not an oracle for
# which seeds a template declares (API §2.4).
got="$(acode "$API/instances/one/seeds/not-a-seed" -X POST -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{}')"
[ "$got" = "403" ] || fail "a seed no step names is outside the grant (got $got)"
got="$(acode "$API/instances/one/playbooks/first-dashboard/progress" -X PUT -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{"current_step":"meet-the-stack"}')"
[ "$got" = "200" ] || fail "an attendee may write progress (got $got)"
got="$(acode "$API/instances/one/secrets/grafana/reveal" -X POST -H "X-Podaro-CSRF: $CSRF")"
[ "$got" = "200" ] || fail "an attendee may reveal this instance's secret (got $got)"
echo "✓ read the lab · verify · run a checkpoint · press a seed · write progress · reveal"

echo "== 4. the negative matrix: everything outside the grant"
neg() { # description path expected [curl args]
  local what="$1" path="$2" want="$3"; shift 3
  local got; got="$(acode "$path" "$@")"
  [ "$got" = "$want" ] || fail "$what: expected $want, got $got"
  echo "   ✓ $what → $got"
}
neg "destroy"                "$API/instances/one" 403 -X DELETE -H "X-Podaro-CSRF: $CSRF"
neg "reset"                  "$API/instances/one/reset" 403 -X POST -H "X-Podaro-CSRF: $CSRF"
# Logs are the D4 exclusion that had no endpoint to refuse until S9.
neg "logs"                   "$API/instances/one/services/prometheus/logs" 403
neg "another instance"       "$API/instances/two" 404
neg "another instance's jobs" "$API/jobs/job_deadbeefdeadbeef" 404
neg "issuing access"         "$API/instances/one/access" 403 -X POST -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{"name":"mallory"}'
neg "listing access"         "$API/instances/one/access" 403
neg "creating an instance"   "$API/instances" 403 -X POST -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{"template":"grafana-prometheus-intro","name":"three"}'
neg "listing tokens"         "$API/auth/tokens" 403
# The system audit is socket-only and absent from the network door
# altogether (API §5), so it is not there to refuse.
neg "the system audit"       "$API/system/audit" 404
# The hostname half: the same session on another instance's console.
got="$(c "two.$DOMAIN" "$API/instances/two" -b "$tmp/jar" -o /dev/null -w '%{http_code}')"
[ "$got" = "403" ] || fail "the gateway must refuse this session on another instance's hostname (got $got)"
echo "   ✓ another instance's hostname → 403"

echo "== 5. revocation stops the next join"
"$bin" access revoke one "$ID" >"$tmp/revoke.out" 2>&1 || { cat "$tmp/revoke.out"; fail "revoke"; }
got="$(code "one.$DOMAIN" "$API/join/$TOKEN")"
[ "$got" = "403" ] || fail "a revoked link must not join (got $got)"
echo "✓ revoked · the link is refused"

echo "== 6. the audit stream, and no secret outside the store"
# The system audit stream is socket-only (API §5): read it there, as an
# operator would, and require every act to be in it. No fallback — a
# check that passes by not checking is not a check.
curl -sS --unix-socket "$sock" "http://podaro$API/system/audit?instance=one" >"$tmp/audit.json" || fail "reading the audit stream"
python3 - "$tmp/audit.json" "$TOKEN" <<'EOF' || fail "the audit stream"
import json, sys
records = json.load(open(sys.argv[1]))["audit"]
actions = {r.get("action") for r in records}
for want in ("access-issue", "join", "reveal", "access-revoke"):
    assert want in actions, (want, sorted(a for a in actions if a))
secret = sys.argv[2]
for r in records:
    assert secret not in json.dumps(r), r
print("   audit:", ", ".join(sorted(a for a in actions if a)))
EOF

# The address a join came from is the operator's record, not the lab's.
# An instance's audit stream is inside the attendee grant — the evidence
# listing merges it and the event feed serializes every row's detail — so
# it carries no peer address at all, while the socket-only system stream
# does.
a "$API/instances/one/evidence?type=audit" >"$tmp/attendee-audit.json" || fail "the attendee's own evidence"
curl -sS --unix-socket "$sock" "http://podaro$API/system/audit" >"$tmp/system-audit.json" || fail "reading the system audit stream"
python3 - "$tmp/audit.json" "$tmp/attendee-audit.json" "$tmp/system-audit.json" <<'EOF' || fail "the join's peer address"
import json, sys
lab = json.load(open(sys.argv[1]))["audit"]
served = json.load(open(sys.argv[2]))["evidence"]
system = json.load(open(sys.argv[3]))["audit"]
joins = [r for r in lab if r.get("action") == "join"]
assert joins, lab
for r in joins:
    assert not r.get("detail"), r
# And in what the attendee is actually served, through the endpoint that
# is theirs.
rows = [e["audit"] for e in served if e.get("type") == "audit" and e.get("audit")]
assert [r for r in rows if r.get("action") == "join"], rows
for r in rows:
    assert not (r.get("action") == "join" and r.get("detail")), r
# The operator's own stream still says where, at the socket: instance,
# credential, source.
sysjoins = [r for r in system if r.get("action") == "join"]
assert sysjoins, system
for r in sysjoins:
    parts = [p.strip() for p in r.get("detail", "").split("\u00b7")]
    assert len(parts) == 3 and parts[0] == "one" and parts[1] and parts[2], r
print("   the join's address: the system stream only")
EOF

echo "== 7. the evidence report (API §10)"
# The report is fetched here because this is the run that has what its
# content contract is about: an attendee who joined by link, and a
# reveal. The operator fetches it over the socket, as they would.
curl -sS --unix-socket "$sock" "http://podaro$API/instances/one/evidence/report.html" >"$tmp/report.html" \
  || fail "fetching the report"
python3 - "$tmp/report.html" "$DOMAIN" "$TOKEN" <<'EOF' || fail "the report content contract"
import json, re, sys
page = open(sys.argv[1], encoding="utf-8").read()
domain, token = sys.argv[2], sys.argv[3]

# It opens standalone: no script, no external reference of any kind.
for pattern in (r"(?i)<script", r"(?i)<link\b", r"(?i)\bsrc\s*=", r"(?i)@import",
                r"(?i)url\(\s*['\"]?https?:", r"(?i)<img\b", r"(?i)<iframe\b"):
    m = re.search(pattern, page)
    assert not m, "the report reaches outside itself: %r" % (m.group(0),)
assert "<style>" in page, "the report carries no stylesheet of its own"

# It carries what the contract says it carries.
for want in ("one", "grafana-prometheus-intro", "sha256:", "Baseline", "Objective",
             "alice", "grafana", "passed,"):
    assert want in page, "the report does not carry %r" % want

# And not what it excludes: no secret value, no access token, no host
# address, no hostname under this deployment's domain.
assert token not in page, "the access token is in the report"
assert domain not in page, "a hostname under %s is in the report" % domain
ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", page)
assert not ip, "a host address is in the report: %r" % (ip.group(0),)
# IPv6 in the two forms an address reaches a page in: bracketed, as a URL
# authority, or the loopback literal. A bare run of hex and colons is not
# searched for, because digests and timestamps are made of those and a
# check that cries wolf is a check that gets loosened.
v6 = re.search(r"\[[0-9A-Fa-f:]*:[0-9A-Fa-f:]*\]|(?<![\w:])::1(?![\w:])", page)
assert not v6, "a host address is in the report: %r" % (v6.group(0),)
print("   report: %d bytes · standalone · attendee and reveal present · no address, hostname or token" % len(page))
EOF

STATE="$XDG_STATE_HOME/podaro"
hack/secret_leak_scan.sh "$STATE" "$tmp/engine.log" "$tmp" || fail "a secret value appeared outside the store"

echo "all S9 attendee-matrix checks passed (runtime: $PODARO_RUNTIME)"
