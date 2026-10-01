#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The reconciliation plan's R3, scripted (its A4 and A5; the reconciliation
# §4.2): installed state survives the retirement. A host that ran an earlier
# build keeps its data, its evidence and any running containers; nothing
# recreates, repairs or offers the retired lab; the operator is told what
# remains.
#
#   (a) a fresh install: <state>/catalog/ holds the retained lab alone;
#   (b) the state an earlier build left — the retired template in the catalog
#       (hack/fixtures/retired-catalog/, a negative fixture) and an instance
#       of it with evidence, a secret, a running and a stopped container —
#       under this build: the engine starts and reconciles nothing of it,
#       logs PDR-W103 once, status reports it unsupported, its evidence reads
#       unchanged, up and lab init --from it are PDR-E107, verify, seed,
#       reset, a checkpoint run and a playbook action are PDR-E215, a system
#       install re-run, a restart and a reboot recreate nothing (a supported
#       lab beside it is reconciled as always), the upgrade's preflight lists
#       what remains, no secret value appears in anything the leg wrote (its
#       transcript, its record, the export, the engine's logs), and destroy —
#       after the evidence is exported — removes what its labels name and
#       nothing else;
#   (c) a user-modified copy (metadata.name changed): validated, refused by
#       PDR-E106 at the retired names, never substituted — and an instance of
#       it an earlier build left is refused the same way when its repair runs,
#       recreating nothing.
#
#   hack/retirement_migration_test.sh [--evidence DIR]
#
# --evidence writes DIR/A4-restore-paths.txt (this run's transcript) and
# DIR/A5-preserved-data.txt (the rows and evidence before and after), with the
# temporary paths written as <tmp>. The retired template's name is read from
# hack/retirement.json and never spelled here. The runtime is the fake
# (PODARO_RUNTIME=fake): the containers are the fake's world, and Podman is
# neither needed nor touched. `system install` meets a systemctl stub that
# fails — this script has no systemd user session and must never touch a real
# one — so the install stops at its user-service row, after the catalog rows
# under test.
set -euo pipefail
cd "$(dirname "$0")/.."

EVIDENCE=""
case "${1:-}" in
  --evidence) EVIDENCE="$(mkdir -p "$2" && cd "$2" && pwd)" ;;
  "") ;;
  *) echo "usage: $0 [--evidence DIR]"; exit 2 ;;
esac

tmp="$(mktemp -d)"
ENGINE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

transcript="$tmp/transcript.txt"
preserved="$tmp/preserved.txt"
: >"$transcript"
: >"$preserved"
say() { printf '%s\n' "$*" | sed "s#$tmp#<tmp>#g" | tee -a "$transcript"; }
fail() {
  say "FAIL $*"
  [ -f "${log:-/dev/null}" ] && { echo "--- engine log"; tail -40 "$log"; }
  exit 1
}

GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export GOMODCACHE GOCACHE GOPATH
export PODARO_RUNTIME=fake
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
export no_proxy="${no_proxy:+$no_proxy,}127.0.0.1,localhost" NO_PROXY="${NO_PROXY:+$NO_PROXY,}127.0.0.1,localhost"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
go build -o "$tmp/earlierbuild" ./internal/state/earlierbuild
retired="$(python3 -c 'import json; print(json.load(open("hack/retirement.json"))["scenarios"][0]["name"])')"
fixture="hack/fixtures/retired-catalog/$retired"
[ -f "$fixture/lab.yaml" ] || fail "the negative fixture is missing: hack/fixtures/retired-catalog/<the retired template>/"
# The fixture is a negative one: no digest in it may be one a registry serves.
if grep -hoE 'sha256:[0-9a-f]{64}' -r "$fixture" | grep -vqE 'sha256:0{64}'; then
  fail "the negative fixture pins a real image digest"
fi

# A systemctl that fails, first on PATH: system install stops at its
# user-service row and no real service manager is ever asked anything.
mkdir -p "$tmp/stub"
printf '#!/bin/sh\necho "systemctl --user: no user service manager in this test (a stub)" >&2\nexit 1\n' >"$tmp/stub/systemctl"
chmod +x "$tmp/stub/systemctl"
export PATH="$tmp/stub:$PATH"

# One host per leg: its own XDG tree and its own engine.
host() {
  local root="$tmp/$1"
  export XDG_STATE_HOME="$root/state" XDG_RUNTIME_DIR="$root/run" XDG_CONFIG_HOME="$root/config" HOME="$root/home"
  mkdir -p "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME"
  state="$XDG_STATE_HOME/podaro"
  sock="$XDG_RUNTIME_DIR/podaro/api.sock"
  starts=0
}
start_engine() {
  starts=$((starts + 1))
  log="$tmp/$(basename "$(dirname "$XDG_STATE_HOME")")-engine-$starts.log"
  rm -f "$sock"
  "$bin" engine serve >"$log" 2>&1 &
  ENGINE_PID=$!
  for _ in $(seq 1 100); do
    "$bin" status >/dev/null 2>&1 && return 0
    sleep 0.1
  done
  fail "the engine did not answer"
}
stop_engine() {
  kill "$ENGINE_PID" 2>/dev/null || true
  wait "$ENGINE_PID" 2>/dev/null || true
  ENGINE_PID=""
}
# shown prints a command's output into the transcript: whole, or its first
# twelve lines and a count of the rest (the full text is what was asserted).
shown() {
  local n
  n="$(printf '%s\n' "$1" | wc -l)"
  if [ "$n" -le 12 ]; then say "$1"; return; fi
  say "$(printf '%s\n' "$1" | head -12)"
  say "  … $((n - 12)) more lines"
}
# pod runs the binary, prints the command and what it printed into the
# transcript, and leaves the exit status in $rc and the output in $out.
pod() {
  say "\$ podaro $*"
  set +e
  out="$("$bin" "$@" 2>&1)"
  rc=$?
  set -e
  [ -z "$out" ] || shown "$out"
  [ "$rc" -eq 0 ] || say "(exit $rc)"
}
# api asks the local door directly, for the routes the CLI has no command
# for: a checkpoint run, a playbook action.
api() { # method path [json]
  say "\$ curl -X $1 --unix-socket <sock> http://podaro/api/v1alpha1$2"
  set +e
  out="$(curl -sS -X "$1" --unix-socket "$sock" -H 'Content-Type: application/json' ${3:+--data "$3"} \
    -w '\n%{http_code}' "http://podaro/api/v1alpha1$2" 2>&1)"
  set -e
  code="${out##*$'\n'}"
  out="${out%$'\n'*}"
  say "$code $(printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if d.get("error"): print(d["error"]["code"], d["error"]["message"])
elif d.get("job"): print("job", d["job"]["id"], d["job"]["kind"], d["job"]["state"])
elif "evidence" in d: print(len(d["evidence"]), "entries")
' 2>/dev/null || true)"
}
# containers prints an instance's containers in the fake's world: name,
# running or stopped, and the first twelve characters of the id.
containers() {
  python3 - "$state/fake-runtime.json" "$1" <<'EOF'
import json, sys
world = json.load(open(sys.argv[1]))
for name, c in sorted(world.get("containers", {}).items()):
    if c["spec"]["Labels"].get("dev.podaro/instance") == sys.argv[2]:
        print("%s %s %s" % (name, "running" if c["running"] else "stopped", c["id"][:12]))
EOF
}
# rows prints what the state database holds for an instance, read-only;
# a secret is named, never shown.
rows() {
  python3 - "$state/state.db" "$1" <<'EOF'
import sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
name = sys.argv[2]
def q(sql):
    return db.execute(sql, (name,)).fetchall()
for r in q("select name, template, version, mode, stage, reached, unsupported from instances where name = ?"):
    print("instance  %s · template %s@%s · %s · stage %s · reached %s · unsupported %r" % r)
for r in q("select name, container, stage from services where instance = ? order by name"):
    print("service   %s · container %s · stage %s" % r)
for r in q("select id, kind, state from jobs where instance = ? order by seq"):
    print("job       %s · %s · %s" % r)
for r in q("select id, class, status from checkpoint_results where instance = ? order by id"):
    print("result    %s · %s · %s" % r)
for r in q("select name from generated_secrets where instance = ? order by name"):
    print("secret    %s (named; its value stays in the secret store)" % r)
for r in q("select seq, action, actor, detail from audit where instance = ? order by seq"):
    print("audit     #%s · %s · %s · %s" % r)
EOF
}
# journal prints an instance's evidence files: name, digest, and what each is.
journal() {
  python3 - "$state/instances/$1/evidence" <<'EOF'
import hashlib, json, os, sys
d = sys.argv[1]
if not os.path.isdir(d):
    print("(no evidence directory)")
    sys.exit(0)
for f in sorted(os.listdir(d)):
    raw = open(os.path.join(d, f), "rb").read()
    e = json.loads(raw)
    what = e["type"]
    if e.get("lifecycle"):
        l = e["lifecycle"]
        what += " · " + l["event"] + (" · " + l["code"] if l.get("code") else "") + (" · " + l["detail"] if l.get("detail") else "")
    if e.get("checkpoint"):
        what += " · %s %s" % (e["checkpoint"]["id"], e["checkpoint"]["status"])
    print("%s  sha256:%s  %s" % (f, hashlib.sha256(raw).hexdigest()[:16], what))
EOF
}
record() { # title: append the rows and the journal of an instance to the A5 record
  {
    printf '== %s\n' "$1"
    printf -- '-- state.db rows (read-only)\n'
    rows "$2"
    printf -- '-- evidence files under instances/%s/evidence/\n' "$2"
    journal "$2"
    printf -- '-- containers in the runtime\n'
    containers "$2"
    printf '\n'
  } >>"$preserved"
}

# ------------------------------------------------------------ (a) fresh install
say "== (a) a fresh install: the catalog holds the retained lab alone"
host a
pod system install
[ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'user service.*a stub' || fail "system install should stop at the stub's user-service row"
printf '%s' "$out" | grep -q '^✓ starter catalog    grafana-prometheus-intro$' || fail "the catalog row"
printf '%s' "$out" | grep -q 'retired template' && fail "a fresh install reports retired content"
listing="$(cd "$state/catalog" && ls -1)"
say "\$ ls <state>/catalog"
say "$listing"
[ "$listing" = "grafana-prometheus-intro" ] || fail "a fresh install's catalog holds more than the retained lab"
start_engine
pod status
[ "$out" = $'no instances yet\n→ podaro up grafana-prometheus-intro    4 GB host · all open source' ] || fail "the fresh empty state"
stop_engine
say "✓ (a) the fresh install extracted the retained lab and nothing else, and offers it"

# ------------------------------------------------ (b) what an earlier build left
say ""
say "== (b) an earlier build's state: the retired template in the catalog, an instance of it"
host b
mkdir -p "$state/catalog"
cp -R scenarios/grafana-prometheus-intro "$state/catalog/"
cp -R "$fixture" "$state/catalog/"   # as the earlier build's extraction left it
catalog_sum() { (cd "$state/catalog" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16); }
before_catalog="$(catalog_sum)"

say "-- the catalog, before any instance: offered and not"
start_engine
pod status
[ "$(printf '%s\n' "$out" | sed -n 2p)" = "→ podaro up grafana-prometheus-intro    4 GB host · all open source" ] || fail "the empty state's offer"
printf '%s' "$out" | grep -q "podaro up $retired" && fail "the empty state offers the retired template"
[ "$(printf '%s\n' "$out" | grep -c 'PDR-W103')" = 1 ] || fail "the empty state must say once that the retired entry is present"
stop_engine

say "-- the instance an earlier build created from it (hack's state helper; the fake's world)"
"$tmp/earlierbuild" -state "$state" -instance old-lab -template "$retired" -source "$fixture" -running index -stopped search | tee -a "$transcript"
record "(b) before this build's engine first starts" old-lab
before_journal="$(journal old-lab)"
before_containers="$(containers old-lab)"
say "$before_containers"

say "-- start: reconcile passes it by"
start_engine
[ "$(grep -c 'PDR-W103 old-lab' "$log")" = 1 ] || fail "want one PDR-W103 line for old-lab in the engine's log"
say "engine log: $(grep 'PDR-W103 old-lab' "$log")"
grep -q 'reconciling old-lab' "$log" && fail "the retired instance was reconciled"
grep -q 'resuming .* for old-lab' "$log" && fail "a job of the retired instance was resumed"
[ "$(containers old-lab)" = "$before_containers" ] || fail "the start touched the retired instance's containers"
pod status
printf '%s' "$out" | grep -q "^old-lab · $retired@1.0.0 · ●●●●●●● unsupported · retired template$" || fail "status must show it unsupported"
pod status old-lab
printf '%s' "$out" | grep -q 'PDR-W103 unsupported by this release: retired template' || fail "status <instance> must say why"
"$bin" status old-lab --json | python3 -c 'import json,sys; v=json.load(sys.stdin)["instance"]; assert v["unsupported"]=="retired template", v' \
  || fail "status --json must carry unsupported"
say "✓ reconcile skipped it · PDR-W103 logged once · status: unsupported · retired template"
record "(b) after this build's first start: nothing reconciled, the running container still running" old-lab

say "-- the evidence reads, unchanged, with one entry more"
api GET /instances/old-lab/evidence
[ "$code" = 200 ] || fail "the evidence must read"
after_journal="$(journal old-lab)"
while IFS= read -r line; do
  printf '%s\n' "$after_journal" | grep -qxF "$line" || fail "an evidence entry changed: $line"
done <<<"$before_journal"
[ "$(printf '%s\n' "$after_journal" | wc -l)" = $(( $(printf '%s\n' "$before_journal" | wc -l) + 1 )) ] || fail "want exactly one new evidence entry"
printf '%s' "$after_journal" | grep -q 'lifecycle · unsupported · PDR-W103 · unsupported by this release: retired template; not reconciled' || fail "the new entry"
say "✓ every earlier entry byte for byte · one lifecycle entry: unsupported by this release: retired template; not reconciled"

say "-- nothing offers or recreates the retired template"
pod up "$retired"
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E107' || fail "up of the retired template must be PDR-E107"
pod up "$retired" --name another
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E107' || fail "up --name of the retired template must be PDR-E107"
pod lab init --from "$retired" "$tmp/scaffold"
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E107' || fail "lab init --from the retired template must be PDR-E107"
[ -e "$tmp/scaffold" ] && fail "lab init --from the retired template wrote a scaffold"
pod up nope
printf '%s' "$out" | grep -q 'PDR-E207' && ! printf '%s' "$out" | grep -q "$retired" || fail "a typo's refusal must not offer the retired template"
pod up "$state/catalog/$retired" --name from-the-copy
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E106' || fail "up of the catalog copy by its path must fail validation with PDR-E106"
[ -z "$(containers another)$(containers from-the-copy)" ] || fail "a refused up made containers"
say "✓ up and lab init --from it: PDR-E107 · its copy by path: PDR-E106 · nothing created"

say "-- verify, seed, reset, a checkpoint run and a playbook action: PDR-E215, and nothing runs"
pod verify old-lab
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E215' || fail "verify must be PDR-E215"
pod seed old-lab pii
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E215' || fail "seed must be PDR-E215"
pod reset old-lab --yes
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E215' || fail "reset must be PDR-E215"
api POST /instances/old-lab/reset
[ "$code" = 409 ] && printf '%s' "$out" | grep -q 'PDR-E215' || fail "the engine must refuse the reset itself: $code"
api POST /instances/old-lab/checkpoints/events-arrived/run
[ "$code" = 409 ] || fail "a checkpoint run must be 409"
api PUT /instances/old-lab/playbooks/any/progress '{"current_step":"look"}'
[ "$code" = 409 ] || fail "a playbook action must be 409"
api POST /instances/old-lab/checkpoints/events-arrived/attest '{"note":"seen"}'
[ "$code" = 409 ] || fail "an attestation must be 409"
[ "$(containers old-lab)" = "$before_containers" ] || fail "a refusal touched the containers"
say "✓ every operation that would run the lab refused · the containers as they were"

say "-- the upgrade's preflight"
pod system upgrade --to "$("$bin" version | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+[^ ]*' | head -1)"
printf '%s' "$out" | grep -q "^! retired template              $retired in the catalog · not offered, never recreated · PDR-W103$" || fail "the preflight's catalog row"
printf '%s' "$out" | grep -q '^! unsupported instance          old-lab · retired template · 1 of 2 containers running, left as they are · not reconciled · PDR-W103$' || fail "the preflight's instance row"
say "✓ the preflight lists the retired catalog entry and the unsupported instance with its containers, and proceeds"

say "-- the repair paths: a system install re-run, a restart, a reboot"
pod system install
printf '%s' "$out" | grep -q '^✓ starter catalog    grafana-prometheus-intro$' || fail "the re-run's catalog row"
printf '%s' "$out" | grep -q "^! retired template   $retired present, unsupported by this release · not offered · PDR-W103$" || fail "the re-run's retired row"
[ "$(catalog_sum)" = "$before_catalog" ] || fail "the install re-run changed the catalog"
pod up grafana-prometheus-intro --name intro
[ "$rc" -eq 0 ] || fail "the supported lab beside it"
stop_engine
start_engine
[ "$(grep -c 'PDR-W103 old-lab' "$log")" = 1 ] || fail "a restart: want one PDR-W103 line"
grep -q 'reconciling old-lab' "$log" && fail "a restart reconciled the retired instance"
[ "$(journal old-lab)" = "$after_journal" ] || fail "a restart wrote its evidence again"
[ "$(containers old-lab)" = "$before_containers" ] || fail "a restart touched the containers"
say "engine log: $(grep 'PDR-W103 old-lab' "$log")"
say "$(containers old-lab)"
say "✓ a restart: PDR-W103 once in its log, no second evidence entry, the containers as they were"
stop_engine
pod engine simulate-reboot
start_engine
grep -q 'reconciling intro' "$log" || fail "a reboot must reconcile the supported lab"
grep -q 'reconciling old-lab' "$log" && fail "a reboot reconciled the retired instance"
for _ in $(seq 1 150); do
  "$bin" status intro --json 2>/dev/null | grep -q '"stage":"ready","condensed":"●●●●●●●","rank":7,"in_progress":false' && break
  sleep 0.2
done
"$bin" status intro --json | grep -q '"in_progress":false' || fail "intro did not settle after its reconcile"
say "engine log: $(grep -E 'reconciling|PDR-W103' "$log" | paste -sd'|' | sed 's/|/ ··· /g')"
pod status
say "$(containers old-lab)"
[ -z "$(containers old-lab | grep running)" ] || fail "the reboot's stopped containers were started"
[ "$(containers old-lab | awk '{print $1, $3}')" = "$(printf '%s\n' "$before_containers" | awk '{print $1, $3}')" ] || fail "a container was recreated"
say "✓ a reboot: the supported lab reconciled, the retired instance's containers left stopped, none recreated"

say "-- the evidence exported, then destroy"
mkdir -p "$tmp/export"
for p in evidence evidence/report.html evidence/report.junit.xml; do
  curl -sSf --unix-socket "$sock" "http://podaro/api/v1alpha1/instances/old-lab/$p" >"$tmp/export/$(basename "$p")" || fail "export $p"
done
say "exported: $(cd "$tmp/export" && ls -1 | paste -sd' ') ($(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["evidence"]))' "$tmp/export/evidence") entries)"
grep -q 'events-arrived' "$tmp/export/report.junit.xml" || fail "the JUnit report must carry the recorded result"
record "(b) after the starts, the refusals, the repair paths — before destroy" old-lab
say "-- no secret value in anything this leg wrote: the transcript, the A5 record, the export, the engine's logs"
set +e
scan_out="$(hack/secret_leak_scan.sh "$state" "$transcript" "$preserved" "$tmp/export" "$tmp"/b-engine-*.log 2>&1)"
scan_rc=$?
set -e
say "$scan_out"
[ "$scan_rc" -eq 0 ] || fail "a secret value leaked"
intro_before="$(containers intro)"
pod destroy old-lab --yes
[ "$rc" -eq 0 ] || fail "destroy"
[ -z "$(containers old-lab)" ] || fail "destroy left the retired instance's containers"
python3 -c 'import json,sys; w=json.load(open(sys.argv[1])); assert "pdr-old-lab" not in w["networks"], w["networks"]' "$state/fake-runtime.json" || fail "destroy left the network"
# The instance's rows go; its jobs and its audit rows stay, as for any destroy:
# they are the record of what happened, and the security record.
[ -z "$(rows old-lab | grep -E '^(instance|service|result|secret) ')" ] || fail "destroy left rows: $(rows old-lab)"
[ -e "$state/instances/old-lab" ] && fail "destroy left the instance directory"
[ -n "$intro_before" ] && [ "$(containers intro)" = "$intro_before" ] || fail "destroy touched the other lab"
[ "$(catalog_sum)" = "$before_catalog" ] || fail "destroy touched the catalog"
[ -s "$tmp/export/evidence" ] || fail "the exported evidence is gone"
record "(b) after destroy (its jobs and audit rows stay, as for any destroy: the record)" old-lab
{
  printf -- '-- the evidence exported before destroy, where it stays\n'
  python3 - "$tmp/export/evidence" <<'EOF2'
import json, sys
for e in json.load(open(sys.argv[1]))["evidence"]:
    what = e["type"]
    if e.get("lifecycle"):
        what += " · " + e["lifecycle"]["event"]
    if e.get("checkpoint"):
        what += " · %s %s" % (e["checkpoint"]["id"], e["checkpoint"]["status"])
    if e.get("audit"):
        what += " · %s by %s" % (e["audit"]["action"], e["audit"]["actor"])
    print("%s  %s" % (e["id"], what))
EOF2
  (cd "$tmp/export" && ls -1 | paste -sd' ' | sed 's/^/files: /')
  printf '\n'
} >>"$preserved"
say "✓ destroy removed the containers, the network, the rows and the directory; the catalog, the other lab and the export stay"
stop_engine

# ----------------------------------------------------- (c) a user-modified copy
say ""
say "== (c) a user-modified copy: metadata.name changed, the retired names inside"
host c
mkdir -p "$state/catalog"
cp -R "$fixture" "$state/catalog/my-copy"
python3 - "$state/catalog/my-copy/lab.yaml" "$retired" <<'EOF'
import sys
p, name = sys.argv[1], sys.argv[2]
s = open(p).read()
assert ("  name: %s\n" % name) in s
open(p, "w").write(s.replace("  name: %s\n" % name, "  name: my-copy\n", 1))
EOF
start_engine
pod status
printf '%s' "$out" | grep -q '^→ podaro up my-copy' || fail "a copy under a name of its own is a template like any other: offered"
pod lab validate "$state/catalog/my-copy"
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q '^✗ PDR-E106' || fail "the copy must fail validation with PDR-E106"
[ "$(printf '%s' "$out" | grep -c 'is retired by the owner')" = 11 ] || fail "every retired name in the copy must be named"
pod up my-copy
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E106' || fail "up of the copy must be PDR-E106"
[ -z "$(containers my-copy)" ] || fail "a refused up made containers"
say "✓ validated and refused by PDR-E106 at the retired names; nothing substituted, nothing created"
stop_engine
"$tmp/earlierbuild" -state "$state" -instance copy-lab -template my-copy -source "$state/catalog/my-copy" -stopped web | tee -a "$transcript"
before_copy="$(containers copy-lab)"
start_engine
grep -q 'PDR-W103 copy-lab' "$log" && fail "a copy under a name of its own is not a retired template"
grep -q 'reconciling copy-lab' "$log" || fail "its stopped container owes it a repair"
say "engine log: $(grep 'reconciling copy-lab' "$log")"
for _ in $(seq 1 100); do
  "$bin" status copy-lab --json 2>/dev/null | grep -q '"in_progress":false' && break
  sleep 0.1
done
pod status copy-lab
printf '%s' "$out" | grep -q 'PDR-E106' || fail "the repair must fail with PDR-E106"
[ "$(containers copy-lab)" = "$before_copy" ] || fail "the failed repair touched the container"
pod reset copy-lab --yes
[ "$rc" -eq 1 ] && printf '%s' "$out" | grep -q 'PDR-E106' || fail "reset of the copy's instance must be PDR-E106"
api POST /instances/copy-lab/reset
[ "$code" = 202 ] || fail "the engine admits a reset of a template of the user's own: $code"
for _ in $(seq 1 100); do
  "$bin" status copy-lab --json 2>/dev/null | grep -q '"in_progress":false' && break
  sleep 0.1
done
"$bin" status copy-lab --json | python3 -c '
import json, sys
j = json.load(sys.stdin)["instance"]["job"]
assert j["kind"] == "reset" and j["state"] == "failed" and j["error"]["code"] == "PDR-E106", j
print("the reset job:", j["id"], j["state"], j["error"]["code"], "— before any runtime call")' | tee -a "$transcript" \
  || fail "the reset job must fail with PDR-E106"
[ "$(containers copy-lab)" = "$before_copy" ] || fail "the reset took the container down or recreated it"
say "✓ its repair and its reset fail on the retired names before any runtime call; the container as it was"
pod destroy copy-lab --yes
[ "$rc" -eq 0 ] && [ -z "$(containers copy-lab)" ] || fail "destroy of the copy's instance"
stop_engine

say ""
say "all R3 checks passed (runtime: fake): a fresh install offers the retained lab alone; the retired entry and"
say "instance an earlier build left are kept, never offered, reconciled, repaired or run, reported once, readable,"
say "and removed only by destroy; a modified copy is validated and refused at the retired names"

if [ -n "$EVIDENCE" ]; then
  commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    printf '# SPDX-License-Identifier: AGPL-3.0-only\n'
    printf '# A4 — fresh install, reset, repair/reconcile and start cannot restore the retired lab (the reconciliation §10 A4; plan R3)\n'
    printf '# commit %s · generated %s · runtime: fake · go %s\n' "$commit" "$stamp" "$(go env GOVERSION)"
    printf '# command: hack/retirement_migration_test.sh --evidence docs/reconciliation/evidence\n'
    printf '# the retired template is written <retired-template>; temporary paths <tmp>\n\n'
    sed "s#$retired#<retired-template>#g" "$transcript"
  } >"$EVIDENCE/A4-restore-paths.txt"
  {
    printf '# SPDX-License-Identifier: AGPL-3.0-only\n'
    printf '# A5 — existing data and evidence are not silently deleted (the reconciliation §10 A5; plan R3)\n'
    printf '# commit %s · generated %s · runtime: fake\n' "$commit" "$stamp"
    printf '# command: hack/retirement_migration_test.sh --evidence docs/reconciliation/evidence\n'
    printf '# the rows are read read-only from state.db; a secret is named, never shown; each evidence file with its digest\n'
    printf '# the retired template is written <retired-template>; temporary paths <tmp>\n\n'
    sed -e "s#$tmp#<tmp>#g" -e "s#$retired#<retired-template>#g" "$preserved"
  } >"$EVIDENCE/A5-preserved-data.txt"
  echo "evidence written: $EVIDENCE/A4-restore-paths.txt $EVIDENCE/A5-preserved-data.txt"
fi
