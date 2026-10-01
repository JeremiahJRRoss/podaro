#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S9 acceptance (INSTALL §6): `podaro system upgrade` against a real
# release mirror this script fills — a real binary, a real SHA256SUMS,
# real HTTP, and the real command.
#
#   1. a download that does not match its manifest is refused: the
#      running binary is untouched and the download is not left behind;
#   2. a version older than the running one is refused, naming the way
#      back rather than performing half of it;
#   3. the release the mirror calls latest is fetched, verified, the
#      state database is backed up, and the binary is replaced — and the
#      replacement is a working binary that reports the new version;
#   4. with no --from at all, the same upgrade from the location the binary
#      asks by default (the reconciliation plan's R7): the releases of the
#      repository the root SOURCE file names, answered at that very address.
#
# The mirror is laid out at the default location's path — the destination
# the owner gave on 2026-09-23, <SOURCE>/releases, read from SOURCE at run
# time — so every request in steps 1–3 names the path the destination
# serves. Step 4 goes further: the binary's own default is asked for, as
# https://github.com/…, and a local TLS server answers for that host with a
# certificate from a throwaway CA that only the upgrade's process trusts
# (SSL_CERT_FILE), reached through a local CONNECT proxy (HTTPS_PROXY) that
# tunnels that host and refuses every other. `latest` answers as GitHub
# answers it — a redirect to the tag — and the script checks every request
# made: the destination's host, its path, nothing else. Nothing leaves the
# host. Needs python3, curl and openssl.
#
# What this does NOT exercise is the systemd restart: there is no user
# service here, so the command reports that the new binary is in place
# and the operator must restart it, which is the documented behaviour for
# exactly that case. The restart itself is covered where it can be: the
# unit tests assert it runs after the replacement and never before.
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
MIRROR_PID=""
DEST_PID=""
VERSION_SAVED=""
cleanup() {
  if [ -n "$MIRROR_PID" ]; then kill "$MIRROR_PID" 2>/dev/null || true; wait "$MIRROR_PID" 2>/dev/null || true; fi
  if [ -n "$DEST_PID" ]; then kill "$DEST_PID" 2>/dev/null || true; wait "$DEST_PID" 2>/dev/null || true; fi
  # The release binary is built from a bumped VERSION, so this script
  # edits a tracked file for one command. Restoring it belongs here, not
  # only after the build: a build that fails, or a signal, otherwise
  # leaves the tree claiming to be version 9.9.9 — which makes every
  # later upgrade read as "already current", the unit tests included
  # (a gate interrupted mid-build left exactly that behind).
  if [ -n "$VERSION_SAVED" ] && [ -f "$VERSION_SAVED" ]; then cp "$VERSION_SAVED" VERSION; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
fail() { echo "FAIL $*"; exit 1; }

export GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export XDG_STATE_HOME="$tmp/state" XDG_CONFIG_HOME="$tmp/config" XDG_RUNTIME_DIR="$tmp/run" HOME="$tmp/home"
export no_proxy="${no_proxy:+$no_proxy,}127.0.0.1,localhost" NO_PROXY="${NO_PROXY:+$NO_PROXY,}127.0.0.1,localhost"
command -v openssl >/dev/null || fail "openssl is needed: step 4 answers the default location over TLS"

# The location the binary asks by default: the releases of the repository
# SOURCE names (internal/system/r7_coordinates_test.go holds
# DefaultReleaseBase to it). The mirror is laid out at its path.
DEST="$(tr -d '[:space:]' <SOURCE)/releases"    # https://<host>/<owner>/<name>/releases
DEST_HOST="${DEST#https://}"
DEST_HOST="${DEST_HOST%%/*}"
DEST_PATH="/${DEST#https://*/}"
case "$DEST" in https://*/*/*/releases) ;; *) fail "SOURCE gave no https://<host>/<owner>/<name> location: $DEST" ;; esac
MIRROR="$tmp/mirror$DEST_PATH"
mkdir -p "$XDG_STATE_HOME/podaro" "$XDG_CONFIG_HOME" "$XDG_RUNTIME_DIR" "$HOME" "$tmp/bin" "$MIRROR/download"

# The running install: the current version, in its own bin directory.
CURRENT="$(cat VERSION)"
go build -o "$tmp/bin/podaro" ./cmd/podaro
cp "$tmp/bin/podaro" "$tmp/podaro.running"   # step 4 starts again from it
# The binary names the default it asks, and it is SOURCE's releases.
help="$("$tmp/bin/podaro" system upgrade --help)"
grep -q -F "(default: $DEST," <<<"$help" \
  || fail "system upgrade --help does not name $DEST as its default: $(grep -F -e "--from string" <<<"$help")"
# A real database holding a row, because the backup the upgrade takes is
# SQLite's own and a file of prose is not a database — and because a
# backup is only a backup if it holds what the state held. The engine's
# own WAL case (rows committed but not yet checkpointed) is pinned by the
# unit test, which can keep the store open across the upgrade.
python3 - "$XDG_STATE_HOME/podaro/state.db" <<'EOF'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute("pragma journal_mode=wal")
db.execute("create table marker (id text primary key)")
db.execute("insert into marker values ('the row the backup must carry')")
db.commit()
db.close()
EOF
chmod 600 "$XDG_STATE_HOME/podaro/state.db"

# The release: a genuinely different binary, built from a bumped VERSION,
# with the manifest a release publishes beside it.
NEXT="9.9.9"
ARCH="$(go env GOARCH)"
ASSET="podaro-$NEXT-linux-$ARCH"
cp VERSION "$tmp/VERSION.orig"
VERSION_SAVED="$tmp/VERSION.orig"
printf '%s\n' "$NEXT" >VERSION
go build -o "$MIRROR/download/$ASSET" ./cmd/podaro
cp "$tmp/VERSION.orig" VERSION
VERSION_SAVED=""
mkdir -p "$MIRROR/download/v$NEXT"
mv "$MIRROR/download/$ASSET" "$MIRROR/download/v$NEXT/$ASSET"
( cd "$MIRROR/download/v$NEXT" && sha256sum "$ASSET" >SHA256SUMS )
printf '/tag/v%s\n' "$NEXT" >"$MIRROR/latest"

PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')"
( cd "$tmp/mirror" && python3 -m http.server "$PORT" --bind 127.0.0.1 >"$tmp/mirror.log" 2>&1 ) &
MIRROR_PID=$!
BASE="http://127.0.0.1:$PORT$DEST_PATH"
for _ in $(seq 1 100); do curl -fsS "$BASE/latest" >/dev/null 2>&1 && break; sleep 0.1; done
curl -fsS "$BASE/latest" >/dev/null || fail "the mirror did not start"
echo "✓ mirror serving v$NEXT · $ASSET · SHA256SUMS, laid out at the default location's path: $DEST_PATH"

running_sum() { sha256sum "$tmp/bin/podaro" | cut -d' ' -f1; }
BEFORE="$(running_sum)"

# ------------------------------------------- 1. a corrupt manifest
BAD="$tmp/bad$DEST_PATH"
mkdir -p "$BAD/download/v$NEXT"
cp "$MIRROR/download/v$NEXT/$ASSET" "$BAD/download/v$NEXT/$ASSET"
printf '%s  %s\n' "$(printf '0%.0s' $(seq 1 64))" "$ASSET" >"$BAD/download/v$NEXT/SHA256SUMS"
printf '/tag/v%s\n' "$NEXT" >"$BAD/latest"
BADPORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1])')"
( cd "$tmp/bad" && python3 -m http.server "$BADPORT" --bind 127.0.0.1 >>"$tmp/mirror.log" 2>&1 ) &
BAD_PID=$!
for _ in $(seq 1 100); do curl -fsS "http://127.0.0.1:$BADPORT$DEST_PATH/latest" >/dev/null 2>&1 && break; sleep 0.1; done
set +e
"$tmp/bin/podaro" system upgrade --from "http://127.0.0.1:$BADPORT$DEST_PATH" >"$tmp/bad.out" 2>&1
rc=$?
set -e
kill "$BAD_PID" 2>/dev/null || true
[ "$rc" -ne 0 ] || fail "a corrupt download exited 0: $(cat "$tmp/bad.out")"
grep -q "PDR-E025" "$tmp/bad.out" || fail "the refusal does not carry its code: $(cat "$tmp/bad.out")"
grep -q "does not match the release manifest" "$tmp/bad.out" || fail "the refusal does not say why: $(cat "$tmp/bad.out")"
[ "$(running_sum)" = "$BEFORE" ] || fail "the binary was replaced by a download that failed its checksum"
[ -z "$(find "$tmp/bin" -name '.podaro-upgrade-*' -print -quit)" ] || fail "a refused download was left beside the binary"
[ ! -e "$XDG_STATE_HOME/podaro/state.db.bak-v$CURRENT" ] || fail "the state was backed up before the download was verified"
echo "✓ a corrupt download is refused · binary untouched · nothing left behind · no backup taken"

# ------------------------------------------------ 2. a downgrade
set +e
"$tmp/bin/podaro" system upgrade --from "$BASE" --to 0.0.0 >"$tmp/down.out" 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] || fail "a downgrade exited 0: $(cat "$tmp/down.out")"
grep -q "older than the running" "$tmp/down.out" || fail "the downgrade refusal: $(cat "$tmp/down.out")"
grep -q "state.db.bak-v" "$tmp/down.out" || fail "the refusal does not name the way back: $(cat "$tmp/down.out")"
[ "$(running_sum)" = "$BEFORE" ] || fail "a downgrade replaced the binary"
echo "✓ a downgrade is refused · the refusal names the rollback pair"

# --------------------------------------------- 3. the real upgrade
set +e
"$tmp/bin/podaro" system upgrade --from "$BASE" >"$tmp/up.out" 2>&1
rc=$?
set -e
grep -q "checksum verified" "$tmp/up.out" || fail "no checksum row: $(cat "$tmp/up.out")"
grep -q "state backed up" "$tmp/up.out" || fail "no backup row: $(cat "$tmp/up.out")"
[ -s "$XDG_STATE_HOME/podaro/state.db.bak-v$CURRENT" ] || fail "the state backup was not written"
# SQLite's backup is a logical copy, not a byte copy — it is written
# through the same snapshot a reader sees, which is the point — so what
# is checked is that the rows are there.
python3 - "$XDG_STATE_HOME/podaro/state.db.bak-v$CURRENT" <<'EOF' || fail "the backup does not hold what the state held"
import sqlite3, sys
db = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
rows = [r[0] for r in db.execute("select id from marker")]
assert rows == ["the row the backup must carry"], rows
EOF
[ "$(running_sum)" != "$BEFORE" ] || fail "the binary was not replaced"
[ "$(running_sum)" = "$(sha256sum "$MIRROR/download/v$NEXT/$ASSET" | cut -d' ' -f1)" ] \
  || fail "the binary in place is not the release that was verified"
# It is a working binary, and it is the new version.
got="$("$tmp/bin/podaro" version 2>&1 | head -1)"
case "$got" in
  *"$NEXT"*) ;;
  *) fail "the replaced binary reports $got, want $NEXT" ;;
esac
# There is no user service here, so the restart step reports what the
# operator must do; the exit is non-zero and says so, which is right.
if [ "$rc" -ne 0 ]; then
  grep -q "the new binary is in place" "$tmp/up.out" \
    || fail "the restart failure does not say the binary is in place: $(cat "$tmp/up.out")"
  echo "✓ replaced and verified · no user service here, so the restart is reported, not pretended"
else
  echo "✓ replaced, verified and restarted"
fi

# ------------------------- 4. the default location, with no --from at all
# The reconciliation plan's R7: the location the binary asks by itself is
# the destination's releases. The running install starts again from the
# current version, and a local TLS server answers for $DEST_HOST: its
# certificate comes from a CA made here, which the upgrade's process alone
# trusts, and the process reaches it through a local CONNECT proxy that
# tunnels $DEST_HOST:443 and refuses anything else. Nothing leaves the host.
cp "$tmp/podaro.running" "$tmp/bin/podaro"
rm -f "$XDG_STATE_HOME/podaro/state.db.bak-v$CURRENT"
[ "$(running_sum)" = "$BEFORE" ] || fail "the running install was not restored for step 4"
mkdir -p "$tmp/tls/none"
cat >"$tmp/tls/openssl.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = podaro upgrade test CA
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF
printf 'basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = DNS:%s\n' \
  "$DEST_HOST" >"$tmp/tls/leaf.ext"
(
  cd "$tmp/tls"
  openssl req -x509 -config openssl.cnf -extensions ca -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2
  openssl req -new -config openssl.cnf -newkey rsa:2048 -nodes -keyout leaf.key -out leaf.csr -subj "/CN=$DEST_HOST"
  openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 2 -extfile leaf.ext
) >"$tmp/tls/openssl.log" 2>&1 || { cat "$tmp/tls/openssl.log"; fail "openssl could not make the test certificates"; }
cat >"$tmp/destination.py" <<'EOF'
# The destination, answered locally: a TLS server for the host the release
# location names, serving the mirror at its path, with `latest` answered as
# GitHub answers it (a redirect to the tag), and a CONNECT proxy that
# tunnels that host alone. Every request line is written to the log.
import http.server, os, select, socket, socketserver, ssl, sys, threading
mirror, cert, key, host, path, version, log, ready = sys.argv[1:9]
lock = threading.Lock()
def record(line):
    with lock, open(log, "a") as f:
        f.write(line + "\n")
class Destination(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=mirror, **kw)
    def log_message(self, *a):
        pass
    def do_GET(self):
        record(f"GET {self.headers.get('Host')} {self.path}")
        if self.path == path + "/latest":
            self.send_response(302)
            self.send_header("Location", f"https://{host}{path}/tag/v{version}")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_GET()
tls = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Destination)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            head += chunk
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        record(line)
        if line.split(" ")[:2] != ["CONNECT", f"{host}:443"]:
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        upstream = socket.create_connection(("127.0.0.1", tls.server_address[1]))
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        rest = head.split(b"\r\n\r\n", 1)[1]
        if rest:
            upstream.sendall(rest)
        ends = [self.request, upstream]
        while True:
            readable, _, _ = select.select(ends, [], [], 30)
            if not readable:
                break
            for end in readable:
                data = end.recv(65536)
                if not data:
                    upstream.close()
                    return
                (upstream if end is self.request else self.request).sendall(data)
        upstream.close()
class Proxy(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
proxy = Proxy(("127.0.0.1", 0), Tunnel)
threading.Thread(target=tls.serve_forever, daemon=True).start()
with open(ready + ".tmp", "w") as f:
    f.write(f"{proxy.server_address[1]}\n")
os.rename(ready + ".tmp", ready)
proxy.serve_forever()
EOF
python3 "$tmp/destination.py" "$tmp/mirror" "$tmp/tls/leaf.pem" "$tmp/tls/leaf.key" "$DEST_HOST" "$DEST_PATH" "$NEXT" \
  "$tmp/asked.log" "$tmp/destination.ready" >"$tmp/destination.log" 2>&1 &
DEST_PID=$!
for _ in $(seq 1 100); do [ -s "$tmp/destination.ready" ] && break; sleep 0.1; done
[ -s "$tmp/destination.ready" ] || { cat "$tmp/destination.log"; fail "the local destination did not start"; }
PROXY="http://127.0.0.1:$(cat "$tmp/destination.ready")"
set +e
env HTTPS_PROXY="$PROXY" https_proxy="$PROXY" HTTP_PROXY= http_proxy= ALL_PROXY= all_proxy= \
  NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost \
  SSL_CERT_FILE="$tmp/tls/ca.pem" SSL_CERT_DIR="$tmp/tls/none" \
  "$tmp/bin/podaro" system upgrade >"$tmp/default.out" 2>&1
rc=$?
set -e
kill "$DEST_PID" 2>/dev/null || true
wait "$DEST_PID" 2>/dev/null || true
DEST_PID=""
grep -q "checksum verified" "$tmp/default.out" || fail "no checksum row from the default location: $(cat "$tmp/default.out")"
[ -s "$XDG_STATE_HOME/podaro/state.db.bak-v$CURRENT" ] || fail "the state backup was not written from the default location"
[ "$(running_sum)" = "$(sha256sum "$MIRROR/download/v$NEXT/$ASSET" | cut -d' ' -f1)" ] \
  || fail "the binary in place is not the release the default location served"
got="$("$tmp/bin/podaro" version 2>&1 | head -1)"
case "$got" in
  *"$NEXT"*) ;;
  *) fail "the replaced binary reports $got, want $NEXT" ;;
esac
if [ "$rc" -ne 0 ]; then
  grep -q "the new binary is in place" "$tmp/default.out" \
    || fail "the restart failure does not say the binary is in place: $(cat "$tmp/default.out")"
fi
# What was asked, and of whom: tunnels to the destination's host alone, and
# three requests at its path, in the order the upgrade makes them.
tunnels="$(grep -c '^CONNECT ' "$tmp/asked.log" || true)"
[ "$tunnels" -ge 1 ] || fail "the upgrade opened no tunnel through the proxy: $(cat "$tmp/asked.log" 2>/dev/null)"
if grep -v -x -F "CONNECT $DEST_HOST:443 HTTP/1.1" "$tmp/asked.log" | grep -q -v '^GET '; then
  fail "the upgrade asked the proxy for something else: $(grep -v '^GET ' "$tmp/asked.log")"
fi
want="GET $DEST_HOST $DEST_PATH/latest
GET $DEST_HOST $DEST_PATH/download/v$NEXT/$ASSET
GET $DEST_HOST $DEST_PATH/download/v$NEXT/SHA256SUMS"
asked="$(grep '^GET ' "$tmp/asked.log")"
[ "$asked" = "$want" ] || fail "the upgrade asked:
$asked
want:
$want"
echo "✓ no --from: asked $DEST — the redirect GitHub gives for latest, then $ASSET and SHA256SUMS from"
echo "  …/download/v$NEXT/, all at $DEST_HOST through $tunnels tunnel(s), nothing else · verified, backed up, replaced"

echo
echo "S9 system upgrade: a corrupt download is refused before anything is replaced · a downgrade is"
echo "refused with the rollback pair named · a verified release is backed up behind and swapped in."
echo "R7: the location asked with no --from is the destination's releases, $DEST, and the mirror"
echo "laid out at its path is what an air-gapped host fills."
