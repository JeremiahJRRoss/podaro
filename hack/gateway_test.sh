#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S5 acceptance, scripted (INSTALL §2 steps 4–5; API §1–§2; threat
# model B1–B3): the curl matrix against a real engine with the gateway
# open on a local port.
#   1. setup → CA, wildcard leaf, gateway listening; the printed block;
#   2. unknown hostnames are dropped (no HTTP answer at all);
#   3. deny until authenticated: /api and /healthz are 401 on the network —
#      all but the two public routes, /legal and GET /system/legal (the
#      reconciliation plan's R5), which answer anyone and nothing else;
#   4. auth setup → login sets the documented cookie; CSRF enforced on
#      cookie writes; logout;
#   5. the console: login page, empty state, security headers, assets, and
#      not one external reference;
#   6. an instance's console and its product vhost proxied with the
#      framing headers rewritten and forwarding headers set;
#   7. bearer tokens: read scope reads, cannot create (403 names admin);
#   8. socket-only endpoints are absent on the network;
#   9. the engine's only non-loopback listener is the gateway port;
#  10. login throttle and lockout, audited.
# Runs against the fake runtime (PODARO_RUNTIME=fake); the gateway, TLS,
# and auth paths are the real ones.
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

# Go's caches follow HOME: pin the real ones first, or the build below
# re-downloads every module into the temporary home — read-only files a
# non-root runner's cleanup cannot remove, failing the run after every
# check has passed.
export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_RUNTIME_DIR="$tmp/run" XDG_CONFIG_HOME="$tmp/config" HOME="$tmp/home"
export PODARO_RUNTIME="${PODARO_RUNTIME:-fake}"
export PODARO_FAKE_READY_DELAY="${PODARO_FAKE_READY_DELAY:-1s}"
mkdir -p "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$HOME"
bin="$tmp/podaro"
go build -o "$bin" ./cmd/podaro
sock="$XDG_RUNTIME_DIR/podaro/api.sock"
DOMAIN=lab.test
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')"
# The lab hostnames resolve to loopback here; keep any HTTPS proxy of the
# environment out of the way for them.
export no_proxy="${no_proxy:+$no_proxy,}$DOMAIN,.$DOMAIN,127.0.0.1" NO_PROXY="${NO_PROXY:+$NO_PROXY,}$DOMAIN,.$DOMAIN,127.0.0.1"

"$bin" engine serve >"$tmp/engine.log" 2>&1 &
ENGINE_PID=$!
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || fail "engine did not open its socket"

echo "== 1. setup: config, local CA, wildcard leaf, gateway"
"$bin" setup --domain "$DOMAIN" --port "$PORT" --ip 203.0.113.10 >"$tmp/setup.out" 2>&1 || { cat "$tmp/setup.out"; fail "setup"; }
cat "$tmp/setup.out"
grep -q "certificate authority   Podaro Local CA · valid 10 years" "$tmp/setup.out" || fail "CA row"
grep -q "wildcard certificate    \*.$DOMAIN · valid 1 year · auto-renews" "$tmp/setup.out" || fail "leaf row"
grep -q "gateway                 listening on :$PORT (TLS)" "$tmp/setup.out" || fail "gateway row"
grep -q "^  \*.$DOMAIN *A    203.0.113.10" "$tmp/setup.out" || fail "DNS block"
grep -q "→ next: podaro auth setup" "$tmp/setup.out" || fail "next action"
CA="$XDG_STATE_HOME/podaro/ca/ca.crt"
[ -f "$CA" ] || fail "no ca.crt"
[ "$(stat -c %a "$XDG_STATE_HOME/podaro/ca/ca.key")" = "600" ] || fail "ca.key mode"
[ "$(stat -c %a "$XDG_CONFIG_HOME/podaro/config.yaml")" = "600" ] || fail "config.yaml mode"
# The leaf covers the wildcard and the apex and obeys the 825-day rule.
openssl x509 -in "$XDG_STATE_HOME/podaro/ca/wildcard.pem" -noout -ext subjectAltName | grep -q "DNS:\*.$DOMAIN" || fail "leaf SAN"
[ "$(stat -c %a "$XDG_STATE_HOME/podaro/ca/wildcard.pem")" = "600" ] || fail "wildcard.pem mode (the key rides in it)"
echo "✓ setup block, CA (0600 key), leaf, gateway on :$PORT"

# curl helpers: a real TLS client trusting the local CA, resolving the
# hostnames to loopback as a wildcard DNS record would.
c() { # host path [curl args]
  local host="$1" path="$2"; shift 2
  curl -sS --cacert "$CA" --resolve "$host:$PORT:127.0.0.1" "$@" "https://$host:$PORT$path"
}
code() { c "$@" -o /dev/null -w '%{http_code}'; }
API=/api/v1alpha1

echo "== 2. unknown hostnames are dropped"
if curl -sS -k --resolve "nope.example:$PORT:127.0.0.1" -o /dev/null "https://nope.example:$PORT/" 2>"$tmp/drop.err"; then fail "unknown SNI answered"; fi
if curl -sS -k -o /dev/null -H "Host: nope.example" "https://127.0.0.1:$PORT/" 2>"$tmp/drop2.err"; then fail "unknown Host answered"; fi
grep -qi "empty reply\|connection reset\|closed" "$tmp/drop2.err" || { cat "$tmp/drop2.err"; fail "expected a dropped connection"; }
if curl -sS -k -o /dev/null --resolve "nope-x.$DOMAIN:$PORT:127.0.0.1" "https://nope-x.$DOMAIN:$PORT/" 2>"$tmp/drop3.err"; then fail "unknown instance hostname answered"; fi
echo "✓ wrong SNI, wrong Host, and unknown instance hostnames drop"

echo "== 3. deny until authenticated"
[ "$(code $DOMAIN $API/instances)" = "401" ] || fail "instances without credentials"
[ "$(code $DOMAIN $API/healthz)" = "401" ] || fail "healthz is authenticated on the network"
[ "$(code $DOMAIN $API/system)" = "401" ] || fail "system without credentials"
[ "$(code $DOMAIN $API/system/errors/PDR-E300)" = "401" ] || fail "system/errors without credentials"
[ "$(code $DOMAIN $API/auth/tokens)" = "401" ] || fail "auth/tokens without credentials"
# The two public routes (API §2; threat model B1; the reconciliation plan's
# R5): the licence, the notices and the offer of this binary's source, for
# anyone who can reach the gateway — static, stateless, GET only, and
# rate-limited per source like the login form. Nothing else answers.
[ "$(code $DOMAIN /legal)" = "200" ] || fail "the /legal page must answer without credentials"
[ "$(code $DOMAIN $API/system/legal)" = "200" ] || fail "GET /system/legal must answer without credentials"
c $DOMAIN $API/system/legal | grep -q '"license":"AGPL-3.0-only"' || fail "the legal route's body"
# The page is read into a file first: piped straight into grep -q, which exits
# at its first match, curl can be left writing into a closed pipe (exit 23),
# and pipefail would call that a failure of the page.
c $DOMAIN /legal >"$tmp/legal-public.html"
grep -q "To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only." "$tmp/legal-public.html" || fail "the legal page's licensing grant"
[ "$(code $DOMAIN $API/system/legal -X POST)" = "405" ] || fail "the legal route is GET only"
[ "$(code $DOMAIN /legal -X POST)" = "405" ] || fail "the legal page is GET only"
c $DOMAIN $API/instances | grep -q '"code":"PDR-E300"' || fail "401 envelope"
[ "$(code $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' -d '{"username":"jross","password":"whatever-it-is-long"}')" = "401" ] || fail "login before auth setup"
c $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' -d '{"username":"jross","password":"whatever-it-is-long"}' | grep -q '"code":"PDR-E306"' || fail "E306 before auth setup"
echo "✓ 401 everywhere on the network but /legal and GET /system/legal; E306 before an operator exists"

echo "== 4. auth setup, login cookie, CSRF, logout"
printf 'correct horse battery staple\n' >"$tmp/pw"; chmod 600 "$tmp/pw"
"$bin" auth setup --username jross --password-file "$tmp/pw" >"$tmp/auth.out" 2>&1 || { cat "$tmp/auth.out"; fail "auth setup"; }
cat "$tmp/auth.out"
grep -q "✓ operator account created" "$tmp/auth.out" || fail "auth setup row"
grep -q "✓ audit               recorded to system evidence" "$tmp/auth.out" || fail "audit row"
tail -1 "$tmp/auth.out" | grep -q "^console: https://$DOMAIN:$PORT$" || fail "console URL last"
[ "$(stat -c %a "$XDG_STATE_HOME/podaro/auth.json")" = "600" ] || fail "auth.json mode"
grep -q "correct horse" "$XDG_STATE_HOME/podaro/auth.json" && fail "password stored in clear"
if "$bin" auth setup --username jross --password-file "$tmp/pw" >"$tmp/auth2.out" 2>&1; then fail "second auth setup accepted"; fi
grep -q "PDR-E310" "$tmp/auth2.out" || fail "E310 on second setup"
printf 'short\n' >"$tmp/pw-short"
if "$bin" auth setup --username jross --password-file "$tmp/pw-short" >"$tmp/auth3.out" 2>&1; then fail "short password accepted"; fi
grep -q "PDR-E307" "$tmp/auth3.out" || fail "E307 for a short password"

c $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' -d '{"username":"jross","password":"correct horse battery staple"}' -D "$tmp/login.h" -c "$tmp/jar" >"$tmp/login.json"
grep -q '"subject":"jross"' "$tmp/login.json" || { cat "$tmp/login.json"; fail "login body"; }
grep -i "^set-cookie: podaro_session=" "$tmp/login.h" | tr -d '\r' >"$tmp/cookie"
for attr in "Domain=$DOMAIN" "Secure" "HttpOnly" "SameSite=Lax" "Path=/"; do
  grep -q "$attr" "$tmp/cookie" || { cat "$tmp/cookie"; fail "cookie lacks $attr"; }
done
CSRF="$(c $DOMAIN $API/auth/session -b "$tmp/jar" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["csrf"])')"
[ -n "$CSRF" ] || fail "no csrf"
[ "$(code $DOMAIN $API/auth/session -b "$tmp/jar" -X DELETE)" = "403" ] || fail "logout without CSRF must be 403"
c $DOMAIN $API/auth/session -b "$tmp/jar" -X DELETE | grep -q '"code":"PDR-E305"' || fail "E305 envelope"
[ "$(code $DOMAIN $API/auth/session -b "$tmp/jar" -X DELETE -H "X-Podaro-CSRF: $CSRF")" = "204" ] || fail "logout with CSRF"
[ "$(code $DOMAIN $API/instances -b "$tmp/jar")" = "401" ] || fail "session survives logout"
# The subdomain cookie reaches instance hostnames too (one login, every tab).
c $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' -d '{"username":"jross","password":"correct horse battery staple"}' -c "$tmp/jar" >/dev/null
CSRF="$(c $DOMAIN $API/auth/session -b "$tmp/jar" | python3 -c 'import json,sys; print(json.load(sys.stdin)["session"]["csrf"])')"
echo "✓ auth setup (0600, hashed), cookie attributes, CSRF on writes, logout"

echo "== 5. the console shell"
[ "$(code $DOMAIN / -o /dev/null -w '%{http_code}' 2>/dev/null)" = "302" ] || fail "unauthenticated / must redirect to login"
c $DOMAIN / -D "$tmp/root.h" -o /dev/null; grep -qi "^location: /login" "$tmp/root.h" || fail "redirect target"
c $DOMAIN /login -D "$tmp/login-page.h" >"$tmp/login-page.html"
grep -qi "^content-security-policy: .*frame-ancestors 'none'" "$tmp/login-page.h" || fail "console CSP frame-ancestors 'none'"
grep -qi "^strict-transport-security:" "$tmp/login-page.h" || fail "HSTS"
grep -q 'name="password"' "$tmp/login-page.html" || fail "login form"
grep -q "Sign in" "$tmp/login-page.html" || fail "login copy"
c $DOMAIN / -b "$tmp/jar" >"$tmp/home.html"
grep -q "No instances yet" "$tmp/home.html" || { cat "$tmp/home.html"; fail "empty state"; }
grep -q "podaro up grafana-prometheus-intro" "$tmp/home.html" || fail "empty state names the action"
grep -q 'signed in as <span class="mono">jross' "$tmp/home.html" || fail "session in the status bar"
if grep -Eo 'https?://[^"'"'"' ]+' "$tmp/home.html" "$tmp/login-page.html" | grep -v "$DOMAIN"; then fail "console references an external URL"; fi
# Both pages link to the licence and source page, and the link is relative:
# the source URL is printed on /legal alone, so the rule above still holds.
grep -q '<a href="/legal">Licence and source</a>' "$tmp/login-page.html" || fail "the login page links to /legal"
grep -q '<a href="/legal">Licence and source</a>' "$tmp/home.html" || fail "the home page links to /legal"
for asset in console.css theme.js htmx.min.js alpine-csp.min.js fonts/inter-latin-400-normal.woff2 fonts/poppins-latin-600-normal.woff2 fonts/IBMPlexMono-Regular-Latin1.woff2; do
  [ "$(code $DOMAIN /assets/$asset)" = "200" ] || fail "asset $asset"
done
[ "$(code $DOMAIN /assets/../embed.go)" != "200" ] || fail "asset traversal"
# The asset URLs' cache key is the bundle's content revision (twelve hex
# characters), never the release number: assets are cached for a day, and
# an in-place upgrade changes the bundles without changing the number.
grep -Eq 'console\.js\?v=[0-9a-f]{12}"' "$tmp/home.html" || fail "asset URLs carry the bundle's content revision"
# And the stylesheet's own subresources: every font URL carries its
# font's pinned digest, since the stylesheet's key cannot reach them.
c $DOMAIN /assets/console.css -o "$tmp/console.css"
grep -Eq 'fonts/[^"?]+\.woff2\?v=[0-9a-f]{12}"' "$tmp/console.css" || fail "the stylesheet keys its fonts by their pins"
if grep -Eq 'fonts/[^"?]+\.woff2"' "$tmp/console.css"; then fail "a font URL in the stylesheet carries no key"; fi
if grep -q "?v=$(cat VERSION | tr -d '[:space:]')\"" "$tmp/home.html"; then fail "asset URLs keyed by the release number"; fi
# The shell carries no inline script and no inline style (plan S12): the
# CSP is script-src 'self' and style-src 'self', so either would be dead
# on arrival, and the theme is applied by an external file.
if grep -Eo '<script[^>]*>' "$tmp/login-page.html" "$tmp/home.html" | grep -v 'src=' >/dev/null; then fail "inline script in the shell"; fi
if grep -q ' style="' "$tmp/login-page.html" "$tmp/home.html"; then fail "inline style in the shell"; fi
c $DOMAIN $API/instances -b "$tmp/jar" -H 'Accept: text/html' | grep -q '<section class="empty">' || fail "instances fragment"
c $DOMAIN $API/system -b "$tmp/jar" -H 'Accept: text/html' | grep -q "listening on :$PORT (TLS)" || fail "system fragment"
c $DOMAIN $API/system -b "$tmp/jar" | grep -q '"listening":true' || fail "system JSON gateway posture"
echo "✓ login page → empty state; CSP/HSTS; vendored assets only; both link to /legal; fragments negotiate"

echo "== 6. an instance's console and its product vhost"
"$bin" up hack/fixtures/hello-nginx --name t1 >"$tmp/up.out" 2>&1 || { cat "$tmp/up.out"; fail "up"; }
tail -1 "$tmp/up.out" | grep -q "^https://t1.$DOMAIN:$PORT$" || { cat "$tmp/up.out"; fail "console URL last, alone"; }
c "t1.$DOMAIN" / -b "$tmp/jar" >"$tmp/t1.html"
grep -q "<span class=\"instance-name\">t1</span>" "$tmp/t1.html" || fail "instance page"
grep -q "healthy" "$tmp/t1.html" || fail "instance ladder"
c "t1.$DOMAIN" / -D "$tmp/t1anon.h" -o /dev/null; grep -qi "^location: /login?next=https%3A%2F%2Ft1.$DOMAIN%3A$PORT%2F" "$tmp/t1anon.h" || { cat "$tmp/t1anon.h"; fail "instance login redirect carries next"; }
[ "$(code "web-t1.$DOMAIN" /)" = "401" ] || fail "product vhost without credentials (API client)"
c "web-t1.$DOMAIN" / -H 'Accept: text/html' -D "$tmp/web-anon.h" -o /dev/null; grep -qi "^location: https://$DOMAIN:$PORT/login?next=" "$tmp/web-anon.h" || fail "product vhost browser redirect"
c "web-t1.$DOMAIN" /hello -b "$tmp/jar" -D "$tmp/web.h" >"$tmp/web.html"
grep -q "fake pdr-t1-web ok · path /hello" "$tmp/web.html" || { cat "$tmp/web.html"; fail "proxied body"; }
grep -qi "^x-frame-options" "$tmp/web.h" && fail "X-Frame-Options not stripped on the product vhost"
grep -qi "^content-security-policy: default-src 'self'; frame-ancestors https://t1.$DOMAIN:$PORT" "$tmp/web.h" || { cat "$tmp/web.h"; fail "frame-ancestors not rewritten to the instance console"; }
grep -qi "^x-fake-host: web-t1.$DOMAIN:$PORT" "$tmp/web.h" || fail "Host preserved to the product"
grep -qi "^x-fake-forwarded-proto: https" "$tmp/web.h" || fail "X-Forwarded-Proto"
grep -qi "^x-fake-forwarded-for: 127.0.0.1" "$tmp/web.h" || fail "X-Forwarded-For"
if curl -sS -k -o /dev/null --resolve "db-t1.$DOMAIN:$PORT:127.0.0.1" "https://db-t1.$DOMAIN:$PORT/" 2>/dev/null; then fail "unknown service hostname answered"; fi
echo "✓ instance console; product vhost proxied with framing headers rewritten, forwarding set; unknown service drops"

echo "== 7. bearer tokens and scopes"
TOKEN="$("$bin" auth token create --name ci --scope read --show)"
case "$TOKEN" in pdr_*) ;; *) fail "token prefix: $TOKEN";; esac
[ "$(code $DOMAIN $API/instances -H "Authorization: Bearer $TOKEN")" = "200" ] || fail "read token reads"
[ "$(code $DOMAIN $API/healthz -H "Authorization: Bearer $TOKEN")" = "200" ] || fail "healthz with a token"
c $DOMAIN $API/instances -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"template":"x"}' -D "$tmp/tok.h" >"$tmp/tok.json"
grep -q "^HTTP/1.1 403" "$tmp/tok.h" || { cat "$tmp/tok.h"; fail "read token must not create"; }
grep -q '"code":"PDR-E304"' "$tmp/tok.json" && grep -q '"required_scope","hint":"admin"' "$tmp/tok.json" || { cat "$tmp/tok.json"; fail "403 names the required scope"; }
[ "$(code $DOMAIN $API/instances -H "Authorization: Bearer pdr_not-a-real-token")" = "401" ] || fail "bogus bearer"
"$bin" auth token create --name ci2 --scope operate >"$tmp/tok2.out"
grep -q "token written to .*/tokens/ci2.token (0600)" "$tmp/tok2.out" || { cat "$tmp/tok2.out"; fail "token file line"; }
[ "$(stat -c %a "$XDG_STATE_HOME/podaro/tokens/ci2.token")" = "600" ] || fail "token file mode"
"$bin" auth token list | grep -q "^ci " || fail "token list"
"$bin" auth token revoke ci >/dev/null
[ "$(code $DOMAIN $API/instances -H "Authorization: Bearer $TOKEN")" = "401" ] || fail "revoked token still works"
echo "✓ tokens: read reads, cannot create (403 names admin), revoke is immediate, files 0600"

echo "== 8. socket-only endpoints are absent on the network"
[ "$(code $DOMAIN $API/auth/operator -b "$tmp/jar" -X POST -H "X-Podaro-CSRF: $CSRF" -H 'Content-Type: application/json' -d '{"username":"x","password":"y"}')" = "404" ] || fail "auth/operator on the network"
[ "$(code $DOMAIN $API/system/reload -b "$tmp/jar" -X POST -H "X-Podaro-CSRF: $CSRF")" = "404" ] || fail "system/reload on the network"
[ "$(code $DOMAIN $API/system/audit -b "$tmp/jar")" = "404" ] || fail "system/audit on the network"
echo "✓ operator, reload, audit exist only at the socket"

echo "== 9. the engine's only network listener is the gateway port"
if command -v ss >/dev/null 2>&1; then
  listeners="$(ss -tlnpH 2>/dev/null | grep "pid=$ENGINE_PID," | grep -v '127\.0\.0\.1:' || true)"
  echo "$listeners"
  [ "$(echo "$listeners" | grep -c ":$PORT ")" = "1" ] || fail "gateway port not the single non-loopback listener"
  [ "$(echo "$listeners" | grep -vc ":$PORT ")" = "0" ] || fail "extra non-loopback listener"
  echo "✓ ss: :$PORT and nothing else"
else
  echo "○ ss not available; listener check skipped"
fi

echo "== 10. login throttle and lockout, audited (last: it locks 127.0.0.1 out)"
attempt() { c $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' -d '{"username":"jross","password":"wrong-password-here"}' -D "$tmp/att.h" -o "$tmp/att.json" -w '%{http_code}'; }
# The first of the five failures is a plain form post: it re-renders the
# sign-in page around the error, and that page is keyed like every other
# — it framed its own shell and carried an empty asset cache key, which a
# browser would have kept for a day.
s="$(c $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/x-www-form-urlencoded' -H 'Accept: text/html' -d 'username=jross&password=wrong-password-here' -o "$tmp/login-failed.html" -w '%{http_code}')"
[ "$s" = "401" ] || fail "a failed form sign-in answers $s, not 401"
grep -q "<!doctype html>" "$tmp/login-failed.html" || fail "a failed form sign-in re-renders the page"
grep -Eq 'console\.js\?v=[0-9a-f]{12}"' "$tmp/login-failed.html" || fail "the failed sign-in page carries the bundle's content revision"
n=1
while [ $n -lt 5 ]; do
  s="$(attempt)"
  case "$s" in
    401) n=$((n+1));;
    429) ra="$(grep -i '^retry-after:' "$tmp/att.h" | tr -dc '0-9')"; [ -n "$ra" ] || fail "429 without Retry-After"; sleep "$ra";;
    *) fail "unexpected status $s";;
  esac
done
s="$(attempt)"; [ "$s" = "429" ] || fail "sixth attempt should be locked (got $s)"
grep -q '"code":"PDR-E303"' "$tmp/att.json" || { cat "$tmp/att.json"; fail "lockout envelope"; }
# The right password is refused too while locked.
[ "$(code $DOMAIN $API/auth/session -X POST -H 'Content-Type: application/json' -d '{"username":"jross","password":"correct horse battery staple"}')" = "429" ] || fail "lockout must refuse the right password"
audit="$(curl -sS --unix-socket "$sock" "http://podaro$API/system/audit")"
for action in operator-created login logout token-created token-revoked login-failed lockout; do
  echo "$audit" | grep -q "\"action\":\"$action\"" || { echo "$audit"; fail "audit lacks $action"; }
done
echo "✓ backoff (Retry-After), lockout after 5 failures (E303), audit stream complete"

echo "all S5 acceptance checks passed (runtime: $PODARO_RUNTIME)"
