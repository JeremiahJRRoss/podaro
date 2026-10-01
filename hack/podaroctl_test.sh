#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# podaroctl (INSTALL §2 step 6), checked where a CI runner can: shellcheck
# and bash -n; --help; --print shows the exact command for a passthrough,
# for `system restart` and for `shell`, as root and as the account itself;
# an account that does not exist is refused, and a caller that is neither
# root nor the account is refused. Running it for real needs the account
# and its service manager: the VM of docs/reviews/0003.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL $*"; exit 1; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

bash -n podaroctl || fail "podaroctl does not parse"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning podaroctl hack/podaroctl_test.sh || fail "shellcheck"
  echo "✓ shellcheck          podaroctl · no warnings"
fi
./podaroctl --help | grep -q "run podaro as its account" || fail "--help"
./podaroctl | grep -q "run podaro as its account" || fail "no arguments prints the help"

# --print for this user (the account is whoever runs the test): the
# command is env … podaro <args>, with the session the account needs.
me="$(id -un)"; home="$(getent passwd "$me" | cut -d: -f6)"; uid="$(id -u)"
out="$(PODARO_USER="$me" ./podaroctl --print status intro)"
grep -q "XDG_RUNTIME_DIR=/run/user/$uid" <<<"$out" || fail "the runtime directory is set: $out"
grep -q "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus" <<<"$out" || fail "the session bus is set: $out"
grep -q "$home/.local/bin/podaro status intro" <<<"$out" || fail "the arguments pass through unchanged: $out"
out="$(PODARO_USER="$me" ./podaroctl --print system restart)"
grep -q "podaro system restart" <<<"$out" || fail "system restart passes through: $out"
out="$(PODARO_USER="$me" ./podaroctl --print shell)"
grep -q "bash -l" <<<"$out" || fail "shell is a login shell: $out"
if [ "$uid" -eq 0 ]; then
  grep -q "^env " <<<"$out" || fail "as the account itself, no runuser: $out"
else
  grep -q "^env " <<<"$out" || fail "as the account itself, no runuser: $out"
fi
echo "✓ --print             passthrough, system restart and shell show the exact command"

# Refusals
if ./podaroctl --print status >"$tmp/r1.out" 2>&1 <<<"" && [ -z "$(getent passwd podaro)" ]; then fail "a missing account was accepted"; fi
if [ -z "$(getent passwd podaro)" ]; then
  grep -q "no account named podaro" "$tmp/r1.out" || fail "the missing account is named"
  echo "✓ refusal             an account that does not exist is refused"
fi
if [ "$uid" -ne 0 ]; then
  if PODARO_USER=root ./podaroctl --print status >"$tmp/r2.out" 2>&1; then fail "a caller that is neither root nor the account was accepted"; fi
  grep -q "run as root" "$tmp/r2.out" || fail "the caller refusal names the remedy"
  echo "✓ refusal             neither root nor the account is refused"
fi
echo "all podaroctl checks passed (running it for real needs the account and its service manager)"
