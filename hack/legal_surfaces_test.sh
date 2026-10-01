#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The reconciliation plan's R5, task 5 (the reconciliation §7.1–§7.2):
# every path a Podaro binary reaches someone by carries its licence, its
# notices and the offer of its exact source — tested on the release's own
# artifacts, built fresh from this commit.
#
#   1. the release: hack/release_package.sh for this host's architecture,
#      into a temporary directory;
#   2. the tarball, extracted: every entry TARBALL_ENTRIES names is there;
#      LICENSE, NOTICE, TRADEMARKS.md, THIRD-PARTY-NOTICES.md, LICENSES/
#      and SOURCE-AND-BUILD.md are the tree's bytes; RELEASE-MANIFEST.json
#      names the version, the Go release and the binaries' digests — the
#      extracted binary's among them, as SHA256SUMS lists it — and no
#      commit; the AGPL text and the notices are there (the mission's check
#      11, asked here so that the published snapshot, which leaves the
#      mission's harness out, still asks it);
#   3. the bare binary where INSTALL §5 puts it, with nothing beside it:
#      `podaro legal` prints the licence, NOTICE's two statements and the
#      source offer, and `--licenses` every licence text, from the binary;
#   4. install.sh's binary step, run on its own as install_sh_test.sh runs
#      the profile step: the four notices land beside the binary;
#   5. the public routes, through the real gateway with real TLS and the
#      attendee matrix's harness (hack/attendee_matrix.sh: the engine on the
#      fake runtime, setup, the operator, a lab, a joined access link):
#      /legal and GET /system/legal answer a visitor with no session on the
#      apex and on the lab's hostname, and the attendee on the lab's
#      hostname and on the apex — the public routes read no session to
#      bind — while every other path still refuses; the sign-in page and
#      the attendee's lab page link to /legal; and the route's JSON is what
#      `podaro legal --json` of the same binary prints.
#
# Needs a clean checkout (the release script refuses any other), Go,
# python3 and curl. Nothing outside a temporary directory is written, and
# `podaro system install` is not run — it installs a real user service;
# <state>/legal/ is internal/system's unit test.
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
version="$(tr -d '[:space:]' <VERSION)"
arch="$(go env GOHOSTARCH)"
source_url="$(tr -d '[:space:]' <SOURCE)"
formulation1="Copyright © 2026 Jeremiah Ross, to the extent copyright subsists in first-party material and such copyright is owned by Jeremiah Ross. No copyright is claimed in AI-generated material that is not eligible for copyright protection under applicable law."
formulation2="To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only."

echo "== 1. the release, built from this commit (linux/$arch)"
PODARO_RELEASE_ARCHES="$arch" hack/release_package.sh "$version" "$tmp/out" >"$tmp/release.out" 2>&1 || { cat "$tmp/release.out"; fail "hack/release_package.sh"; }
rel="$tmp/out/download/v$version"
tarball="$rel/podaro_v${version}_linux_${arch}.tar.gz"
bare="$rel/podaro-${version}-linux-${arch}"
[ -f "$tarball" ] && [ -f "$bare" ] && [ -f "$rel/SHA256SUMS" ] || fail "the release directory lacks its artifacts"
grep '^✓ tarball' "$tmp/release.out"

echo "== 2. the tarball: every entry, the tree's bytes, the manifest"
pkg="$tmp/pkg"; mkdir -p "$pkg"
tar -xzf "$tarball" -C "$pkg"
tar -tzvf "$tarball" | awk '{print $1, $6}'
entries="$(sed -n 's/^TARBALL_ENTRIES="\(.*\)"$/\1/p' hack/release_package.sh)"
[ -n "$entries" ] || fail "no TARBALL_ENTRIES in hack/release_package.sh"
for e in $entries; do
  [ -e "$pkg/${e%/}" ] || fail "the tarball lacks $e"
done
for f in LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md SOURCE-AND-BUILD.md LICENSES/Apache-2.0.txt; do
  cmp -s "$f" "$pkg/$f" || fail "the tarball's $f is not the tree's"
done
[ "$(ls "$pkg/LICENSES")" = "$(ls LICENSES)" ] || fail "the tarball's LICENSES/ is not the tree's"
python3 - "$pkg/RELEASE-MANIFEST.json" "$version" "$arch" "$(sha256sum <"$pkg/podaro" | cut -d' ' -f1)" "$rel/SHA256SUMS" "$source_url" <<'EOF' || fail "RELEASE-MANIFEST.json"
import json, re, sys
path, version, arch, digest, sums, source = sys.argv[1:7]
raw = open(path).read()
m = json.loads(raw)
assert m["version"] == version, m
assert re.fullmatch(r"go1\.\d+(\.\d+)?", m["go"]), m["go"]
assert m["architectures"] == [arch], m["architectures"]
name = "podaro-%s-linux-%s" % (version, arch)
assert m["binaries"] == {name: "sha256:" + digest}, m["binaries"]
listed = dict(reversed(line.split()) for line in open(sums) if line.strip())
assert listed[name] == digest, "SHA256SUMS and the manifest disagree"
assert m["source"] == source, m["source"]
assert not re.search(r"\b[0-9a-f]{40}\b", raw.replace(digest, "")), "a commit hash in the manifest"
print("✓ RELEASE-MANIFEST.json: v%s · %s · %s · %s = the extracted binary's digest, as SHA256SUMS lists it · no commit" % (version, m["go"], arch, name))
EOF
for need in LICENSE NOTICE THIRD-PARTY-NOTICES.md; do
  [ -f "$pkg/$need" ] || fail "the extracted release lacks $need, which every recipient of the binary is owed"
done
echo "✓ the extracted release carries LICENSE, NOTICE and THIRD-PARTY-NOTICES.md (the mission's check 11)"
echo "✓ $(echo $entries | wc -w) entries · the legal files are the tree's bytes"

echo "== 3. the bare binary, alone where INSTALL §5 puts it"
export HOME="$tmp/home" XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config"
mkdir -p "$HOME/.local/bin" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME"
install -m 0755 "$bare" "$HOME/.local/bin/podaro"
bin="$HOME/.local/bin/podaro"
[ "$(ls "$HOME/.local/bin")" = "podaro" ] || fail "the bare install holds more than the binary"
"$bin" legal >"$tmp/legal.out" 2>"$tmp/legal.err" || { cat "$tmp/legal.err"; fail "podaro legal"; }
squashed="$(tr -s ' \n' ' ' <"$tmp/legal.out")"
for want in "AGPL-3.0-only" "$formulation1" "$formulation2" "$source_url" "sha256sum --ignore-missing -c SHA256SUMS" "TRADEMARKS.md" "podaro system install writes them to"; do
  case "$squashed" in *"$want"*) ;; *) fail "podaro legal on a bare install printed no \"$want\"";; esac
done
case "$version" in
  *-dev) grep -q "obtain its source from whoever gave you this binary" "$tmp/legal.out" || fail "an unreleased build's offer" ;;
  *) grep -q "$source_url/tree/v$version" "$tmp/legal.out" || fail "a release build's offer names its tag" ;;
esac
sed -n '1,9p' "$tmp/legal.out"
"$bin" legal --licenses >"$tmp/licenses.out"
for f in LICENSE NOTICE LICENSES/Apache-2.0.txt THIRD-PARTY-NOTICES.md; do
  grep -qx "==> $f <==" "$tmp/licenses.out" || fail "podaro legal --licenses printed no $f"
done
grep -q "GNU AFFERO GENERAL PUBLIC LICENSE" "$tmp/licenses.out" && grep -q "SIL OPEN FONT LICENSE" "$tmp/licenses.out" || fail "the licence texts"
python3 - "$tmp/licenses.out" <<'EOF' || fail "--licenses does not carry the files whole"
import sys
out = open(sys.argv[1], encoding="utf-8").read()
for name in ("LICENSE", "NOTICE", "LICENSES/Apache-2.0.txt", "THIRD-PARTY-NOTICES.md"):
    text = open(name, encoding="utf-8").read()
    assert ("==> %s <==\n%s" % (name, text)) in out, name
print("✓ podaro legal --licenses: LICENSE, NOTICE, LICENSES/Apache-2.0.txt and THIRD-PARTY-NOTICES.md, whole (%d bytes)" % len(out.encode()))
EOF

echo "== 4. install.sh's binary step: the notices land beside the binary"
home2="$tmp/home2"; mkdir -p "$home2"
(
  set -euo pipefail
  row() { printf '%s %-22s %s\n' "$1" "$2" "${3:-}"; }
  # shellcheck disable=SC2034  # read by the eval'd function
  SCRIPT_DIR="$pkg"
  # shellcheck disable=SC2034
  NOTICE_FILES="$(sed -n 's/^NOTICE_FILES="\(.*\)"$/\1/p' "$pkg/install.sh")"
  HOME="$home2"
  podman() { :; }
  eval "$(sed -n '/^install_binary() {/,/^}/p' "$pkg/install.sh")"
  install_binary
) | tee "$tmp/install.out"
grep -q "^✓ notices .*beside the binary" "$tmp/install.out" || fail "install.sh's notices row"
for f in LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md; do
  cmp -s "$f" "$home2/.local/bin/$f" || fail "install.sh did not put $f beside the binary"
done
echo "✓ LICENSE · NOTICE · TRADEMARKS.md · THIRD-PARTY-NOTICES.md beside $home2/.local/bin/podaro"

echo "== 5. the public routes, as a visitor and as an attendee (the attendee matrix's harness)"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
mkdir -p "$XDG_STATE_HOME/podaro/catalog"
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
printf 'correct horse battery staple\n' >"$tmp/pw"; chmod 600 "$tmp/pw"
"$bin" auth setup --username jross --password-file "$tmp/pw" >/dev/null 2>&1 || fail "auth setup"
"$bin" up grafana-prometheus-intro --name one >"$tmp/up.out" 2>&1 || { cat "$tmp/up.out"; fail "up one"; }
"$bin" access create one --name alice --json >"$tmp/grant.json" 2>&1 || { cat "$tmp/grant.json"; fail "access create"; }
TOKEN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' "$tmp/grant.json")"
c() { local host="$1" path="$2"; shift 2; curl -sS --cacert "$CA" --resolve "$host:$PORT:127.0.0.1" "$@" "https://$host:$PORT$path"; }
code() { c "$@" -o /dev/null -w '%{http_code}'; }
c "one.$DOMAIN" "$API/join/$TOKEN" -H 'Accept: application/json' -c "$tmp/jar" >/dev/null || fail "join"
grep -q podaro_session "$tmp/jar" || fail "the join set no session"

"$bin" legal --json >"$tmp/cli.json"
for who in visitor attendee; do
  for host in "$DOMAIN" "one.$DOMAIN"; do
    args=(); [ "$who" = attendee ] && args=(-b "$tmp/jar")
    got="$(code "$host" /legal "${args[@]}")"
    [ "$got" = 200 ] || fail "$who: $host/legal answered $got"
    c "$host" /legal "${args[@]}" >"$tmp/page.html"
    grep -q "Licence and source" "$tmp/page.html" && grep -q "Copyright © 2026 Jeremiah Ross, to the extent copyright subsists" "$tmp/page.html" \
      && grep -q "$source_url" "$tmp/page.html" || fail "$who: $host/legal lacks the licence, the statement or the source location"
    grep -q "signed in as" "$tmp/page.html" && fail "$who: the public page carries session chrome"
    got="$(code "$host" "$API/system/legal" "${args[@]}")"
    [ "$got" = 200 ] || fail "$who: $host$API/system/legal answered $got"
    c "$host" "$API/system/legal" "${args[@]}" >"$tmp/route.json"
    python3 - "$tmp/route.json" "$tmp/cli.json" <<'EOF' || fail "$who on $host: the route and podaro legal --json disagree"
import json, sys
assert json.load(open(sys.argv[1]))["legal"] == json.load(open(sys.argv[2]))["legal"]
EOF
    echo "   ✓ $who · $host: /legal 200 · $API/system/legal 200, what podaro legal --json prints"
  done
done
# Everything else still refuses: a visitor gets 401, the attendee off its host 403.
[ "$(code "$DOMAIN" "$API/system")" = 401 ] || fail "a visitor reached $API/system"
[ "$(code "$DOMAIN" "$API/instances")" = 401 ] || fail "a visitor reached $API/instances"
[ "$(code "$DOMAIN" "$API/instances" -b "$tmp/jar")" = 403 ] || fail "the attendee reached the apex's API"
[ "$(code "one.$DOMAIN" "$API/instances/one/services/prometheus/logs" -b "$tmp/jar")" = 403 ] || fail "the attendee reached the logs"
echo "   ✓ everything else still refuses: 401 for a visitor, 403 for the attendee off its grant"
c "$DOMAIN" /login >"$tmp/login.html"
grep -q '<a href="/legal">Licence and source</a>' "$tmp/login.html" || fail "the sign-in page does not link to /legal"
if grep -Eo 'https?://[^"'"'"' ]+' "$tmp/login.html" | grep -v "$DOMAIN"; then fail "the sign-in page carries a URL off the gateway"; fi
c "one.$DOMAIN" / -b "$tmp/jar" >"$tmp/lab.html"
grep -q '<a href="/legal">Licence and source</a>' "$tmp/lab.html" || fail "the attendee's lab page does not link to /legal"
echo "   ✓ the sign-in page and the attendee's lab page link to /legal; the sign-in page carries no URL off the gateway"

hack/secret_leak_scan.sh "$XDG_STATE_HOME/podaro" "$tmp/engine.log" "$tmp/legal.out" "$tmp/licenses.out" >/dev/null || fail "a secret value appeared outside the store"
echo "all legal-surface checks passed: tarball, bare binary, installer, and the public routes for a visitor and an attendee (runtime: $PODARO_RUNTIME)"
