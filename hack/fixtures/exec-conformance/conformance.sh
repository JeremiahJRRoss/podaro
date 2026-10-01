#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
#
# Spec 0002 conformance behaviors, selected by the first argument (the
# checkpoint's args[0]); the contract input arrives on stdin, the verdict
# leaves on stdout, diagnostics on stderr, exit 0 whenever a judgment was
# reached (§4, §7). POSIX sh on busybox: the input is read with sed and
# grep, which is enough for the flat shapes the fixture needs.
set -u
mode="${1:-pass}"
input="$(cat)"

# field NAME → the string value of a top-level-ish "NAME":"…" pair.
field() { printf '%s' "$input" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -n 1; }
kind="$(field kind)"
run_id="$(field run_id)"
endpoints="$(printf '%s' "$input" | grep -o '"purpose"' | wc -l | tr -d ' ')"
granted="$(printf '%s' "$input" | sed -n 's/.*"granted":\(\[[^]]*\]\).*/\1/p' | head -n 1)"
[ -n "$granted" ] || granted='[]'
expect="$(printf '%s' "$input" | sed -n 's/.*"expect":\({[^{}]*}\).*/\1/p' | head -n 1)"
[ -n "$expect" ] || expect='{"ran":true}'
capture="{\"run_id\":\"$run_id\",\"endpoints\":$endpoints,\"secrets\":$granted}"

verdict() { # status observed message
  printf '{"contract":"podaro.dev/exec/v1","status":"%s","observed":%s,"message":"%s","evidence":{"capture":%s}}\n' "$1" "$2" "$3" "$capture"
}

case "$mode" in
  crash)
    echo "conformance: crashing on purpose (exit 2)" >&2
    exit 2 ;;
  garbage)
    echo "this is not contract json"
    exit 0 ;;
  sleep)
    echo "conformance: sleeping past any timeout" >&2
    sleep 3600
    exit 0 ;;
  secret)
    # A granted secret is read from its file, never echoed: only its
    # length is observed.
    n=0
    for f in /run/podaro/secrets/*; do
      [ -f "$f" ] || continue
      n="$(tr -d '\n\r' <"$f" | wc -c | tr -d ' ')"
      break
    done
    verdict pass "{\"secret_bytes\":$n}" "read the granted secret as a file"
    exit 0 ;;
  claim)
    # A misbehaving adapter of the second kind: it writes the engine's own
    # capture keys, claiming another image and another grant set. The
    # engine reserves those names; this row exists to prove that on a real
    # runtime.
    capture="{\"run_id\":\"$run_id\",\"image\":\"docker.io/attacker/other@sha256:0000000000000000000000000000000000000000000000000000000000000000\",\"secrets\":[\"never-granted\"]}"
    verdict pass '{"ok":true}' "claimed the engine's keys"
    exit 0 ;;
  leak)
    # A misbehaving adapter: the granted secret echoed into every place a
    # verdict can carry a value. The engine's redaction filter keeps it
    # out of evidence; this row exists to prove that on a real runtime.
    v="no-secret-granted"
    for f in /run/podaro/secrets/*; do
      [ -f "$f" ] || continue
      v="$(tr -d '\n\r' <"$f")"
      break
    done
    echo "leak: $v" >&2
    capture="{\"run_id\":\"$run_id\",\"leaked\":{\"token\":\"$v\",\"list\":[\"$v\",{\"deep\":\"$v\"}]}}"
    if [ "$kind" = "seed" ]; then
      printf '{"contract":"podaro.dev/exec/v1","status":"ok","sent":{"events":1,"echo":"%s","nested":[{"deep":"%s"}]},"message":"leaked %s"}\n' "$v" "$v" "$v"
      exit 0
    fi
    verdict pass "{\"echo\":\"$v\",\"nested\":{\"deep\":[\"$v\"]}}" "leaked $v"
    exit 0 ;;
esac

if [ "$kind" = "seed" ]; then
  count="$(printf '%s' "$input" | sed -n 's/.*"count":\([0-9]*\).*/\1/p' | head -n 1)"
  seed_value="$(field seed_value)"
  printf '{"contract":"podaro.dev/exec/v1","status":"ok","sent":{"events":%s},"message":"%s events, seeded rng %s"}\n' "${count:-0}" "${count:-0}" "$seed_value"
  exit 0
fi

if [ "$mode" = "fail" ]; then
  echo "diagnostic chatter on stderr" >&2
  verdict fail '{"lag":3}' "conformance fail: lag 3 above 0"
  exit 0
fi

verdict pass "$expect" "conformance pass"
exit 0
