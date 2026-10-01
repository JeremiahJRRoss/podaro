#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The installer (INSTALL §2), checked where a CI runner can check it:
#
#   1. shellcheck and bash -n on install.sh (shellcheck skipped honestly
#      when the runner has none);
#   2. --help prints the header; --check reports and changes nothing;
#   3. --answers: the shipped install.test.yaml resolves to the documented
#      defaults, the environment wins over the file, an unknown key and a
#      bad port are refused before anything runs;
#   4. the refusals that keep the stages honest: the user stage never runs
#      as root, never as the wrong account, and never without a service
#      manager to reach; --yes without a password file is refused before
#      any act;
#   5. the log export answers: off by default, the endpoint and host
#      attribute resolved and shown, the token never shown, a bad endpoint
#      and a credential in the URL refused, and --yes without a token file
#      refused before any act (root only: the host stage is what asks);
#   7. a source checkout is not the package: beside go.mod with no binary,
#      --check says so and the install stops at its first row, both naming
#      ./build.sh --install.
#
# What this does NOT exercise is the host stage — useradd, subordinate
# IDs, lingering, and the hand-over to the account — nor the
# steps the account then runs, because both need a systemd host with
# root, which is the VM of docs/reviews/0003, not a runner. The packaged
# tarball's entries are checked by hack/release_package.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $*"; exit 1; }

# 1. static checks
bash -n install.sh || fail "install.sh does not parse"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning install.sh hack/install_sh_test.sh || fail "shellcheck"
  echo "✓ shellcheck          install.sh · no warnings"
else
  echo "○ shellcheck          not on this runner · skipped"
fi

# A package directory: the built binary beside a copy of the script, as
# the tarball lays them out.
pkg="$tmp/pkg"; mkdir -p "$pkg"
go build -o "$pkg/podaro" ./cmd/podaro
cp install.sh install.test.yaml podaroctl "$pkg/"
chmod +x "$pkg/install.sh" "$pkg/podaroctl"

# 2. --help and --check change nothing
"$pkg/install.sh" --help | grep -q "Podaro installer" || fail "--help"
before="$(find "$pkg" -printf '%p %s %m\n' | sort)"
"$pkg/install.sh" --check >"$tmp/check.out" 2>&1 || fail "--check exited $? (it reports, never fails)"
grep -q "^✓ package" "$tmp/check.out" || { cat "$tmp/check.out"; fail "--check did not see the package"; }
grep -q "podaroctl" "$tmp/check.out" || { cat "$tmp/check.out"; fail "--check has no podaroctl row"; }
[ "$before" = "$(find "$pkg" -printf '%p %s %m\n' | sort)" ] || fail "--check changed the package directory"
echo "✓ --check             reports the host and changes nothing"

# 3. answers
PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$pkg/install.test.yaml" >"$tmp/ans.out" 2>&1 || { cat "$tmp/ans.out"; fail "--print-answers"; }
grep -q "^domain          lab.example.test$" "$tmp/ans.out" || fail "domain from the file"
grep -q "^gateway port    7777$" "$tmp/ans.out" || fail "port 7777 from the file"
grep -q "^operator        podaro-admin$" "$tmp/ans.out" || fail "operator from the file"
grep -q "^first lab       no$" "$tmp/ans.out" || fail "the first lab is off by default"
grep -q "^tls             local-ca$" "$tmp/ans.out" || fail "tls from the file"
grep -q "^install podman  yes" "$tmp/ans.out" || fail "install_podman from the file (the line may go on to say Podman is already installed)"
grep -q "prompted by podaro auth setup" "$tmp/ans.out" || fail "no password in the file means the CLI prompts"
grep -q "^log export      no$" "$tmp/ans.out" || fail "log export is off by default"
grep -qi "password.*not shown\|password.*from file" "$tmp/ans.out" && fail "a password value leaked" || true
PODARO_IP=203.0.113.10 PODARO_PORT=8443 PODARO_DOMAIN=lab.example.com "$pkg/install.sh" --print-answers --answers "$pkg/install.test.yaml" >"$tmp/ans2.out" 2>&1
grep -q "^gateway port    8443$" "$tmp/ans2.out" && grep -q "^domain          lab.example.com$" "$tmp/ans2.out" || fail "the environment must win over the file"
echo "✓ answers             install.test.yaml resolves; the environment wins"

printf 'domain: lab.example.test\nflavour: mint\n' >"$tmp/bad1.yaml"
if "$pkg/install.sh" --print-answers --answers "$tmp/bad1.yaml" >"$tmp/bad1.out" 2>&1; then fail "an unknown key was accepted"; fi
grep -q "unknown key 'flavour'" "$tmp/bad1.out" || fail "the unknown key is named"
printf 'domain: lab.example.test\nport: 70000\n' >"$tmp/bad2.yaml"
if PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/bad2.yaml" >"$tmp/bad2.out" 2>&1; then fail "port 70000 was accepted"; fi
grep -q "port must be 1–65535" "$tmp/bad2.out" || fail "the bad port is named"
printf 'domain: not_a_domain\n' >"$tmp/bad3.yaml"
if PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/bad3.yaml" >"$tmp/bad3.out" 2>&1; then fail "a bad domain was accepted"; fi
grep -q "is not a domain name" "$tmp/bad3.out" || fail "the bad domain is named"
echo "✓ answers             an unknown key, a bad port and a bad domain are refused"

# 4. the refusals
home="$tmp/home"; mkdir -p "$home" "$tmp/xdg"
if [ "$(id -u)" -eq 0 ]; then
  if "$pkg/install.sh" --stage user --home "$home" >"$tmp/r1.out" 2>&1; then fail "the user stage ran as root"; fi
  grep -q "never runs as root" "$tmp/r1.out" || { cat "$tmp/r1.out"; fail "the root refusal names itself"; }
  echo "✓ refusal             the user stage never runs as root"
else
  # As a non-root user that is not the account: refused before any act.
  if HOME="$home" "$pkg/install.sh" --stage user --user podaro --home "$home" >"$tmp/r2.out" 2>&1; then fail "the user stage ran as the wrong account"; fi
  grep -q "runs as podaro, not $(id -un)" "$tmp/r2.out" || { cat "$tmp/r2.out"; fail "the wrong-account refusal names both"; }
  # As the account (this user, by name) but with no service manager to
  # reach: refused with the lingering remedy, and nothing installed.
  if HOME="$home" XDG_RUNTIME_DIR="$tmp/xdg" DBUS_SESSION_BUS_ADDRESS="unix:path=$tmp/xdg/bus" \
     "$pkg/install.sh" --stage user --user "$(id -un)" --home "$home" --yes --answers "$pkg/install.test.yaml" >"$tmp/r3.out" 2>&1; then
    fail "the user stage ran without a service manager"
  fi
  grep -q "cannot reach" "$tmp/r3.out" || { cat "$tmp/r3.out"; fail "the session refusal names the manager"; }
  grep -q "enable-linger" "$tmp/r3.out" || fail "the session refusal names the remedy"
  [ ! -e "$home/.local/bin/podaro" ] || fail "a refused run installed the binary"
  echo "✓ refusal             wrong account, and no service manager, both refused before any act"
fi
# --yes without a password file is an answers error, before any act, in
# either stage (the check runs while collecting answers).
printf 'domain: lab.example.test\n' >"$tmp/nopass.yaml"
if PODARO_IP=203.0.113.10 HOME="$home" "$pkg/install.sh" --print-answers --answers "$tmp/nopass.yaml" >/dev/null 2>&1; then :; else fail "--print-answers must not require a password"; fi
echo "✓ answers             --print-answers never asks for a password"

# 5. the log export answers
printf '%s' 's3cr3t-hec-token-value' >"$tmp/hec.token"; chmod 0600 "$tmp/hec.token"
printf 'domain: lab.example.test\nexport_logs: yes\nhec_endpoint: https://collector.example.test:8088\nhec_token_file: %s\nhost_attribute: lab-01\ncreate_lab: yes\n' "$tmp/hec.token" >"$tmp/export.yaml"
PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/export.yaml" >"$tmp/exp.out" 2>&1 || { cat "$tmp/exp.out"; fail "--print-answers with export"; }
grep -q "^log export      hec · https://collector.example.test:8088 · host lab-01 · token provided (never shown)$" "$tmp/exp.out" || { cat "$tmp/exp.out"; fail "the export answers are shown"; }
grep -q "s3cr3t" "$tmp/exp.out" && fail "the HEC token leaked into the answers" || true
grep -q "^first lab       grafana-prometheus-intro as intro$" "$tmp/exp.out" || { cat "$tmp/exp.out"; fail "create_lab yes is shown"; }
printf 'domain: lab.example.test\ncreate_lab: maybe\n' >"$tmp/bad6.yaml"
if PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/bad6.yaml" >"$tmp/bad6.out" 2>&1; then fail "create_lab maybe was accepted"; fi
grep -q "create_lab must be yes or no" "$tmp/bad6.out" || fail "the bad create_lab value is named"
printf 'domain: lab.example.test\nexport_logs: yes\nhec_endpoint: ftp://collector\nhec_token_file: %s\n' "$tmp/hec.token" >"$tmp/bad4.yaml"
if PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/bad4.yaml" >"$tmp/bad4.out" 2>&1; then fail "a non-http endpoint was accepted"; fi
grep -q "is not an http(s) URL" "$tmp/bad4.out" || fail "the bad endpoint is named"
printf 'domain: lab.example.test\nexport_logs: yes\nhec_endpoint: https://user:secret@collector.example.test:8088\nhec_token_file: %s\n' "$tmp/hec.token" >"$tmp/bad5.yaml"
if PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/bad5.yaml" >"$tmp/bad5.out" 2>&1; then fail "a credential in the endpoint was accepted"; fi
grep -q "carries a credential" "$tmp/bad5.out" || fail "the credential in the URL is named"
grep -q "secret@" "$tmp/bad5.out" && fail "the refusal echoed the credential" || true
grep -q "^podaroctl       not on PATH" "$tmp/ans.out" || { cat "$tmp/ans.out"; fail "podaroctl stays off PATH by default"; }
PODARO_IP=203.0.113.10 PODARO_LINK_PODAROCTL=yes "$pkg/install.sh" --print-answers --answers "$pkg/install.test.yaml" >"$tmp/link.out" 2>&1 || { cat "$tmp/link.out"; fail "--print-answers with link_podaroctl"; }
grep -q "^podaroctl       root-owned copy in /usr/local/bin/podaroctl$" "$tmp/link.out" || { cat "$tmp/link.out"; fail "link_podaroctl yes is shown"; }
printf 'domain: lab.example.test\nlink_podaroctl: maybe\n' >"$tmp/bad7.yaml"
if PODARO_IP=203.0.113.10 "$pkg/install.sh" --print-answers --answers "$tmp/bad7.yaml" >"$tmp/bad7.out" 2>&1; then fail "link_podaroctl maybe was accepted"; fi
grep -q "link_podaroctl must be yes or no" "$tmp/bad7.out" || fail "the bad link_podaroctl value is named"
echo "✓ answers             log export, the first lab and podaroctl on PATH: off by default; shown when asked for; bad values refused"
if [ "$(id -u)" -eq 0 ]; then
  # The host stage asks; with --yes and no token file it stops while
  # collecting answers — before podman, the account, anything.
  printf '%s' 'pw' >"$tmp/pw"; chmod 0600 "$tmp/pw"
  printf 'domain: lab.example.test\npassword_file: %s\nexport_logs: yes\nhec_endpoint: https://collector.example.test:8088\n' "$tmp/pw" >"$tmp/notoken.yaml"
  if PODARO_IP=203.0.113.10 "$pkg/install.sh" --yes --answers "$tmp/notoken.yaml" --home "$home" >"$tmp/r4.out" 2>&1; then fail "--yes with export and no token file ran"; fi
  grep -q "needs hec_token_file" "$tmp/r4.out" || { cat "$tmp/r4.out"; fail "the missing token file is named"; }
  id podaro >/dev/null 2>&1 && [ ! -d "$home/.config" ] || true
  echo "✓ refusal             --yes with export_logs yes and no hec_token_file stops before any act"
fi

# 6. the profile block: appended once, parses, sets PATH when sourced, and
# names the runtime directory only when it exists.
home6="$tmp/home6"; mkdir -p "$home6"; printf '# skel\n' >"$home6/.profile"
(
  set -euo pipefail
  row() { :; }
  # shellcheck disable=SC2034  # read by the eval'd function
  PODARO_USER=podaro
  HOME="$home6"
  eval "$(sed -n '/^ensure_profile() {/,/^}/p' "$pkg/install.sh")"
  ensure_profile; ensure_profile
)
[ "$(grep -c '^# >>> podaro session' "$home6/.profile")" = 1 ] || fail "the profile block is appended exactly once"
bash -n "$home6/.profile" || fail "the profile with the block does not parse"
out="$(env -i HOME="$home6" PATH=/usr/bin:/bin bash -c 'source "$HOME/.profile"; echo "$PATH"; echo "${XDG_RUNTIME_DIR:-unset}"')"
grep -q "^$home6/.local/bin:" <<<"$out" || fail "sourcing the profile puts ~/.local/bin first on PATH"
echo "✓ profile             the session block is appended once, parses, and puts ~/.local/bin on PATH"

# 7. a source checkout: install.sh beside go.mod, no binary.
src="$tmp/src"; mkdir -p "$src"; cp install.sh "$src/"; : >"$src/go.mod"
"$src/install.sh" --check >"$tmp/src.out" 2>&1 || fail "--check in a checkout exited $? (it reports, never fails)"
grep -q "^✗ package.*source checkout" "$tmp/src.out" || { cat "$tmp/src.out"; fail "--check names the source checkout"; }
grep -q "build.sh --install" "$tmp/src.out" || fail "--check names the build"
if [ "$(id -u)" -eq 0 ]; then
  if "$src/install.sh" --home "$tmp/home7" >"$tmp/src2.out" 2>&1; then fail "the host stage ran in a source checkout"; fi
  grep -q "source checkout" "$tmp/src2.out" || { cat "$tmp/src2.out"; fail "the refusal names the source checkout"; }
  grep -q "build.sh --install" "$tmp/src2.out" || fail "the refusal names the build"
  [ ! -e "$tmp/home7" ] || fail "a refused run created the home"
fi
echo "✓ refusal             a source checkout (go.mod, no binary) is refused and names ./build.sh --install"

echo "all installer checks passed (the host stage is the VM's, docs/reviews/0003)"
