#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S7 acceptance: the console, walked in a real browser against a
# real engine and gateway on the fake runtime. The soft gate the plan
# asks for — a screenshot set and DOM dumps for the owner's eyeball —
# lands in the output directory beside the assertions.
#
# Chromium is driven over the DevTools protocol by hack/console_walk.mjs
# using Node's own WebSocket, so nothing is installed and no npm
# dependency enters the repository. Without a Chromium the script skips
# honestly, as the exec conformance fixture does without Podman.
set -euo pipefail
cd "$(dirname "$0")/.."

CHROME="${PODARO_CHROME:-}"
if [ -z "$CHROME" ]; then
  for c in /opt/pw-browsers/chromium-*/chrome-linux/chrome "$(command -v chromium || true)" "$(command -v google-chrome || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && CHROME="$c" && break
  done
fi
if [ -z "$CHROME" ] || ! command -v node >/dev/null 2>&1; then
  echo "○ no Chromium or no node; the S7 browser walk was not run here (the fragment goldens cover the same components' markup)"
  exit 0
fi

tmp="$(mktemp -d)"
# The soft gate the plan asks for is a directory the owner looks in
# afterwards, so it must outlive the run. $tmp is the run's own scratch —
# state dir, engine log, browser profile — and the exit trap removes it;
# the artifacts defaulted *into* $tmp, so every successful walk printed
# the path of a directory it was about to delete.
# They get their own directory now, kept, and PODARO_WALK_OUT
# still chooses the place.
OUT="${PODARO_WALK_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/podaro-walk-XXXXXXXX")}"
mkdir -p "$OUT"
case "$OUT" in
  "$tmp"|"$tmp"/*)
    echo "FAIL the artifact directory $OUT is inside the run's scratch $tmp, which is removed on exit"
    exit 1 ;;
esac
ENGINE_PID=""; CHROME_PID=""
cleanup() {
  [ -n "$CHROME_PID" ] && { kill "$CHROME_PID" 2>/dev/null || true; wait "$CHROME_PID" 2>/dev/null || true; }
  # Chromium's helpers (renderers, the crash handler) outlive the main
  # process by a moment and keep writing the profile; an `rm -rf` that
  # raced them failed a run after every check had passed ("Directory not empty").
  # Wait, bounded, for every process still
  # naming the profile, then remove with one retry, and never let a
  # leftover temp dir fail a walk that passed: the dir is disposable.
  for _ in $(seq 1 50); do pgrep -f "$tmp/chrome" >/dev/null 2>&1 || break; sleep 0.1; done
  [ -n "$ENGINE_PID" ] && { kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; }
  rm -rf "$tmp" 2>/dev/null || { sleep 1; rm -rf "$tmp" 2>/dev/null || echo "(left $tmp behind: a browser helper was still writing it)"; }
}
trap cleanup EXIT
fail() { echo "FAIL $*"; echo "--- engine log"; tail -40 "$tmp/engine.log" 2>/dev/null || true; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}" PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-500ms}"
mkdir -p "$XDG_STATE_HOME/podaro/catalog" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME"
# The catalog the engine serves templates from (INSTALL §3), as
# `podaro system install` would place it: the small template, which
# ships a playbook for the rail to walk.
cp -R scenarios/grafana-prometheus-intro "$XDG_STATE_HOME/podaro/catalog/"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
DOMAIN=lab.test
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')"
CDP_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')"
export no_proxy="${no_proxy:+$no_proxy,}$DOMAIN,.$DOMAIN,127.0.0.1" NO_PROXY="${NO_PROXY:+$NO_PROXY,}$DOMAIN,.$DOMAIN,127.0.0.1"

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

"$bin" setup --domain "$DOMAIN" --port "$PORT" --ip 203.0.113.10 >"$tmp/setup.out" 2>&1 || { cat "$tmp/setup.out"; fail "setup"; }
printf 'walk-password-long-enough\n' >"$tmp/pw"
chmod 0600 "$tmp/pw"
"$bin" auth setup --username walker --password-file "$tmp/pw" >"$tmp/auth.out" 2>&1 || { cat "$tmp/auth.out"; fail "auth setup"; }

# A template with a playbook, so the rail has steps to walk.
"$bin" up grafana-prometheus-intro --name walk >"$tmp/up.out" 2>&1 || { cat "$tmp/up.out"; fail "up"; }

# A second lab, driven to UX §5's regression (plan S14): a fall *from*
# ready, which is the only thing the amber bar means. It has to be an
# authoring instance — one that tracks a directory — because a delivery
# instance pins its snapshot and its checkpoints cannot be made to fail
# after the fact. Up to ready first, so the ladder has somewhere to fall
# from; then the baseline is edited red and re-verified.
FALLEN=fallen
mkdir -p "$tmp/$FALLEN"
cat >"$tmp/$FALLEN/lab.yaml" <<'LAB'
apiVersion: lab.podaro.dev/v1alpha1
kind: Template
metadata: { name: fallen, version: 1.0.0 }
services:
  web:
    image: docker.io/library/nginx@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609
    endpoints: [ { purpose: ui, port: 80 } ]
    readiness: { probe: { port: 80 }, typical: 100ms, budget: 10s }
checkpoints:
  - id: web-answers
    adapter: http
    params: { url: http://web:80/ }
    expect: { status: 200 }
    retries: { attempts: 1 }
LAB
"$bin" up "$tmp/$FALLEN" --name "$FALLEN" >"$tmp/fallen-up.out" 2>&1 || { cat "$tmp/fallen-up.out"; fail "up $FALLEN"; }
stage="$("$bin" status "$FALLEN" --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance"]["ladder"]["stage"])')"
[ "$stage" = "ready" ] || fail "$FALLEN must reach ready before it can fall from it (stage: $stage)"
# The same checkpoint, now asking for something the page does not say.
sed -i 's/    expect: { status: 200 }/    expect: { body_contains: "not in the page" }/' "$tmp/$FALLEN/lab.yaml"
"$bin" verify "$FALLEN" >"$tmp/fallen-verify.out" 2>&1 || true
stage="$("$bin" status "$FALLEN" --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["instance"]["ladder"]["stage"])')"
[ "$stage" = "seeded" ] || { cat "$tmp/fallen-verify.out"; fail "$FALLEN must have fallen to seeded (stage: $stage)"; }

# Chromium's own update and variations pings would be external requests
# the walk then reports; they are the browser's, not the console's, so
# they are switched off rather than explained away.
"$CHROME" --headless --disable-gpu --no-sandbox --no-first-run \
  --disable-background-networking --disable-component-update --disable-domain-reliability \
  --disable-sync --disable-features=Translate,OptimizationHints,MediaRouter \
  --host-resolver-rules="MAP *.$DOMAIN 127.0.0.1, MAP $DOMAIN 127.0.0.1" \
  --ignore-certificate-errors \
  --remote-debugging-port="$CDP_PORT" --user-data-dir="$tmp/chrome" about:blank \
  >"$tmp/chrome.log" 2>&1 &
CHROME_PID=$!
# A cold first start on a loaded runner takes longer than a warm one on a
# workstation: the profile directory is new, the page cache is empty, and
# the machine is sharing itself with the rest of the job. Sixty seconds is
# the wait, and a start that dies is reported at once rather than waited
# out — with the browser's own words, so the next failure is diagnosable
# instead of being a sentence about a port.
for _ in $(seq 1 600); do
  curl -sS "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1 && break
  kill -0 "$CHROME_PID" 2>/dev/null || break
  sleep 0.1
done
if ! curl -sS "http://127.0.0.1:$CDP_PORT/json/version" >/dev/null 2>&1; then
  echo "--- chromium ($CHROME)"
  tail -30 "$tmp/chrome.log" 2>/dev/null || true
  kill -0 "$CHROME_PID" 2>/dev/null || echo "(the process exited)"
  fail "chromium did not open its debugging port"
fi

echo "== the console, walked in Chromium (runtime: $PODARO_RUNTIME)"
CDP_PORT="$CDP_PORT" node hack/console_walk.mjs "https://$DOMAIN:$PORT" walk walker walk-password-long-enough "$OUT" "$FALLEN" || fail "browser walk"
echo "screenshots and DOM dumps, kept (set PODARO_WALK_OUT to choose the place): $OUT"
ls "$OUT"
echo "all S7 acceptance checks passed (runtime: $PODARO_RUNTIME)"
