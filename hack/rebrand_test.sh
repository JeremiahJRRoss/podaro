#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# The reconciliation plan's R5, task 2 (the reconciliation §6.5;
# TRADEMARKS.md, "Rebranding a build"): an independently named build is
# one build flag away, and the flag reaches the display name and nothing
# else — not the licence, not NOTICE's statements, not the source offer,
# not one identifier a fork must keep.
#
#   1. the same commit built twice: as it is, and with a neutral name and
#      title (-ldflags -X <module>/internal/brand.Name=… -X …Title=…);
#   2. `podaro version` prints `podaro v<version>` from both — the command is
#      an identifier — while `version --json` names each build's product;
#   3. `podaro --help` describes the neutral product;
#   4. `podaro legal --json`: every field but the product line is what the
#      unbranded build says — AGPL-3.0-only, NOTICE's two statements, the
#      name policy, the third-party components, the files — and the source
#      offer points at the same repository, tag and release location;
#   5. the neutral build's engine on the fake runtime, behind the real
#      gateway with real TLS: the sign-in page's eyebrow, title and
#      wordmark, the legal page's title and eyebrow, and the evidence
#      report's title and footer carry the neutral name, while the legal
#      page still carries the AGPL notice, NOTICE's statement and the offer;
#   6. no identifier moved: the `podaro_session` cookie, the /api/v1alpha1
#      path, the X-Podaro-CSRF header, the `pdr-` container names, the state
#      directory's `podaro`, and the schema `$id`s under schemas.podaro.dev
#      that `lab init` writes.
#
# The systemd unit's description reads the same package; writing the unit
# needs a systemd user manager, so it is internal/system's unit test, not
# this script's. Nothing outside a temporary directory is written.
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="Workbench"
TITLE="Workbench Studio"

tmp="$(mktemp -d)"
ENGINE_PID=""
cleanup() {
  if [ -n "$ENGINE_PID" ]; then kill "$ENGINE_PID" 2>/dev/null || true; wait "$ENGINE_PID" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; echo "--- engine log"; tail -30 "$tmp/engine.log" 2>/dev/null || true; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
module="$(go list -m)"
version="$(tr -d '[:space:]' <VERSION)"

echo "== 1. the same commit, built as it is and with a neutral name"
go build -o "$tmp/podaro" ./cmd/podaro
go build -ldflags "-X '$module/internal/brand.Name=$NAME' -X '$module/internal/brand.Title=$TITLE'" -o "$tmp/rebranded" ./cmd/podaro
echo "✓ built · the neutral build: Name=$NAME · Title=$TITLE"

export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
mkdir -p "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME"

echo "== 2. podaro version: the command is an identifier, the product is the build's"
for b in podaro rebranded; do
  [ "$("$tmp/$b" version)" = "podaro v$version" ] || fail "$b version prints $("$tmp/$b" version)"
done
python3 - "$("$tmp/podaro" version --json)" "$("$tmp/rebranded" version --json)" "$NAME" "$TITLE" <<'EOF' || fail "version --json"
import json, sys
plain, neutral = json.loads(sys.argv[1]), json.loads(sys.argv[2])
assert plain == {"version": plain["version"], "product": "Podaro", "title": "Podaro Community"}, plain
assert neutral == {"version": plain["version"], "product": sys.argv[3], "title": sys.argv[4]}, neutral
print("✓ podaro v%s from both · version --json names %r and %r" % (plain["version"], plain["product"], neutral["product"]))
EOF

echo "== 3. podaro --help describes the neutral product"
"$tmp/rebranded" --help >"$tmp/help.out"
head -1 "$tmp/help.out" | grep -q "^$NAME: verified lab environments" || { head -3 "$tmp/help.out"; fail "the neutral help"; }
grep -q "Podaro:" "$tmp/help.out" && fail "the neutral help still names Podaro as the product"
grep -q "^  podaro \[command\]" "$tmp/help.out" || fail "the command is still podaro"
echo "✓ $(head -1 "$tmp/help.out")"

echo "== 4. podaro legal: the licence, the statements and the source offer did not move"
"$tmp/podaro" legal --json >"$tmp/legal-plain.json"
"$tmp/rebranded" legal --json >"$tmp/legal-neutral.json"
python3 - "$tmp/legal-plain.json" "$tmp/legal-neutral.json" "$NAME" "$TITLE" "$(tr -d '[:space:]' <SOURCE)" <<'EOF' || fail "podaro legal differs beyond the product line"
import json, sys
plain = json.load(open(sys.argv[1]))["legal"]
neutral = json.load(open(sys.argv[2]))["legal"]
name, title, source = sys.argv[3], sys.argv[4], sys.argv[5]
assert neutral["product"] == name and neutral["title"] == title, (neutral["product"], neutral["title"])
assert plain["product"] == "Podaro" and plain["title"] == "Podaro Community"
for key in plain:
    if key in ("product", "title", "source"):
        continue
    assert plain[key] == neutral[key], "%s moved with the brand: %r → %r" % (key, plain[key], neutral[key])
ps, ns = plain["source"], neutral["source"]
for key in ("build", "url", "tag", "repository", "operator"):
    assert ps.get(key) == ns.get(key), "source.%s moved with the brand" % key
assert ns["repository"] == source, ns
assert ns["offer"].replace(name, "Podaro") == ps["offer"], (ps["offer"], ns["offer"])
assert neutral["license"] == "AGPL-3.0-only"
assert neutral["copyright"].startswith("Copyright © 2026 Jeremiah Ross, to the extent copyright subsists"), neutral["copyright"]
assert neutral["licensing"] == "To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only."
print("✓ licence %s · copyright and licensing statements · name policy · %d third-party components · %d files: identical"
      % (neutral["license"], len(neutral["third_party"]), len(neutral["files"])))
print("✓ the source offer, rebranded: %s" % ns["offer"])
print("✓ the repository it points at: %s (the SOURCE file)" % ns["repository"])
EOF
"$tmp/rebranded" legal --licenses >"$tmp/licenses-neutral.txt"
"$tmp/podaro" legal --licenses >"$tmp/licenses-plain.txt"
cmp -s "$tmp/licenses-plain.txt" "$tmp/licenses-neutral.txt" || fail "podaro legal --licenses differs between the builds"
echo "✓ podaro legal --licenses: byte for byte the same ($(wc -c <"$tmp/licenses-neutral.txt") bytes)"

echo "== 5. the neutral build's pages, through the real gateway"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
bin="$tmp/rebranded"
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
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
c() { local host="$1" path="$2"; shift 2; curl -sS --cacert "$CA" --resolve "$host:$PORT:127.0.0.1" "$@" "https://$host:$PORT$path"; }
API=/api/v1alpha1

c $DOMAIN /login >"$tmp/login.html"
grep -q "<p class=\"eyebrow\">$NAME</p>" "$tmp/login.html" || fail "the sign-in eyebrow is not the neutral name"
grep -q "<title>Sign in · $NAME</title>" "$tmp/login.html" || fail "the sign-in title"
grep -q "<a class=\"brand\" href=\"[^\"]*\">$NAME</a>" "$tmp/login.html" || fail "the status bar's wordmark"
grep -q '<a href="/legal">Licence and source</a>' "$tmp/login.html" || fail "the sign-in page links to /legal"
grep -Eq '>Podaro<' "$tmp/login.html" && fail "the sign-in page still shows Podaro as the product"
echo "✓ /login: eyebrow, title and wordmark read $NAME · the page links to /legal"

c $DOMAIN /legal >"$tmp/legal.html"
grep -q "<title>Licence and source · $NAME</title>" "$tmp/legal.html" || fail "the legal page's title"
grep -q "<p class=\"eyebrow\">$NAME v$version</p>" "$tmp/legal.html" || fail "the legal page's product line"
grep -q '<span class="mono">AGPL-3.0-only</span>' "$tmp/legal.html" || fail "the legal page lost the AGPL notice"
grep -q "Copyright © 2026 Jeremiah Ross, to the extent copyright subsists in first-party material" "$tmp/legal.html" || fail "the legal page lost NOTICE's statement"
grep -q "To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only." "$tmp/legal.html" || fail "the legal page lost the licensing grant"
grep -q "$(tr -d '[:space:]' <SOURCE)" "$tmp/legal.html" || fail "the legal page lost the source location"
grep -qi "official $NAME\|$NAME official" "$tmp/legal.html" && fail "the neutral build calls itself official"
echo "✓ /legal: title and product line read $NAME; AGPL-3.0-only, NOTICE's two statements and the source location unchanged"
c $DOMAIN $API/system/legal >"$tmp/legal-api.json"
cmp -s <(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["legal"], sort_keys=True))' "$tmp/legal-api.json") \
       <(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["legal"], sort_keys=True))' "$tmp/legal-neutral.json") \
  || fail "GET /system/legal and podaro legal --json disagree"
echo "✓ GET /system/legal (no credential) is what podaro legal --json prints"

echo "== 6. no identifier moved"
c $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' \
  -d '{"username":"jross","password":"correct horse battery staple"}' -D "$tmp/login.h" -c "$tmp/jar" >/dev/null
grep -qi "^set-cookie: podaro_session=" "$tmp/login.h" || fail "the session cookie is not podaro_session"
CSRF="$(c $DOMAIN $API/auth/session -b "$tmp/jar" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["csrf"])')"
"$bin" up hack/fixtures/hello-nginx --name t1 >"$tmp/up.out" 2>&1 || { cat "$tmp/up.out"; fail "up"; }
c "web-t1.$DOMAIN" /hello -b "$tmp/jar" | grep -q "fake pdr-t1-web ok" || fail "the container is not pdr-t1-web"
curl -sS --unix-socket "$sock" "http://podaro$API/instances/t1/evidence/report.html" >"$tmp/report.html"
grep -q "<title>$NAME evidence · t1</title>" "$tmp/report.html" || fail "the evidence report's title"
grep -q "^$TITLE · evidence is append-only" "$tmp/report.html" || fail "the evidence report's footer"
[ "$(curl -sS --cacert "$CA" --resolve "$DOMAIN:$PORT:127.0.0.1" -o /dev/null -w '%{http_code}' -b "$tmp/jar" -X DELETE \
     -H "X-Podaro-CSRF: $CSRF" "https://$DOMAIN:$PORT$API/auth/session")" = 204 ] || fail "the CSRF header is not X-Podaro-CSRF"
[ -d "$XDG_STATE_HOME/podaro" ] || fail "the state directory is not …/podaro"
"$bin" lab init --from grafana-prometheus-intro "$tmp/scaffold" >"$tmp/init.out" 2>&1 || { cat "$tmp/init.out"; fail "lab init"; }
grep -q 'schemas.podaro.dev/lab/v1alpha2.json' "$tmp/scaffold/lab.yaml" || fail "the scaffold's schema \$id moved"
echo "✓ podaro_session · /api/v1alpha1 · X-Podaro-CSRF · pdr-t1-web · \$XDG_STATE_HOME/podaro · schemas.podaro.dev — unchanged"
echo "✓ the evidence report: <title>$NAME evidence · t1</title> · footer \"$TITLE · evidence is append-only…\""

echo "all rebrand checks passed: the name moved, the licence, the notices, the source offer and every identifier did not (runtime: $PODARO_RUNTIME)"
