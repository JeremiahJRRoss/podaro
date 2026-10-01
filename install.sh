#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Podaro installer — from an extracted release package to a running engine
# (INSTALL §2). Ships inside the release tarball beside the binary.
#
#   sudo mkdir -p /opt/podaro
#   sudo tar -xzf podaro_v<version>_linux_<arch>.tar.gz -C /opt/podaro
#   cd /opt/podaro && chmod +x install.sh && sudo ./install.sh
#
# A checkout of the repository is not the package: there is no binary in
# it, and run there this script stops at its first row and names
# `./build.sh --install`, which builds the release and then runs it
# (INSTALL §5).
#
# Two stages, one command. Run under sudo it prepares the host once — the
# `podaro` account whose home is this directory, its subordinate ID ranges,
# session lingering, and Podman from your distribution if you say yes —
# each act printed as its own row, and
# then drops to that account for everything else: the binary into
# ~/.local/bin, `podaro system install`, `doctor`, `setup`, `auth setup`,
# a self-check and a summary card. Run as the podaro account it performs
# the second stage alone and prints, never runs, any privileged command
# doctor still asks for. The engine never runs as root.
#
#   --yes                take every answer from PODARO_* variables or --answers;
#                        never prompt (sudo strips your environment, so pass
#                        answers with --answers <file> or sudo --preserve-env)
#   --answers <file>     flat `key: value` YAML: domain, port, ip, tls
#                        (local-ca | own), cert_file, key_file, operator,
#                        password_file, install_podman (yes | no),
#                        export_logs (yes | no), hec_endpoint,
#                        hec_token_file, host_attribute, create_lab (yes | no),
#                        link_podaroctl (yes | no)
#   --check              report what is already done; change nothing
#   --uninstall          podaro system uninstall, as the podaro account
#   --purge              with --uninstall: also remove the account and its home
#   --user <name>        the account (default podaro) · --home <dir> its home
#                        (default: this directory)
#   --print-answers      resolve the answers and print them (no secrets)
#
# The password is never a flag value: interactively `podaro auth setup`
# prompts for it with echo off; with --yes, password_file names a 0600
# file the script hands to that account on a private tmpfs and removes.
#
# Log export (Manual §4): answer yes and the script asks for the endpoint
# of a collector that speaks the HTTP Event Collector protocol, the token —
# read with echo off, never printed, kept in ~/.config/podaro/hec.token
# (0600) — and a
# host attribute; it writes the `observability:` block, restarts the
# engine so the export starts, and runs `podaro observe test`. With --yes,
# hec_token_file names a 0600 file. The default is no: nothing leaves the
# host unless you asked.
#
# The console login defaults to podaro-admin; the Linux account that owns
# the service is podaro, and the two are never the same thing. Say yes to
# create_lab and the script ends by creating the open-source lab as
# `intro` (podaro up grafana-prometheus-intro --name intro — two image
# pulls) and prints every hostname a browsing machine must resolve for it,
# read from the engine, beside the one wildcard record that covers them.
#
# podaroctl, beside this script in the package, runs any podaro command
# as the account from any shell (sudo /opt/podaro/podaroctl status). Say
# yes to link_podaroctl and the root stage puts a root-owned copy of it
# in /usr/local/bin, so `sudo podaroctl …` works without the path —
# root-owned, so the account cannot change what root runs (threat model
# B8). The default is no: nothing outside the account's home unless you
# ask.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PODARO_USER="${PODARO_USER:-podaro}"
PODARO_HOME="${PODARO_HOME:-$SCRIPT_DIR}"
DEFAULT_PORT=7777
DEFAULT_OPERATOR=podaro-admin
# An earlier installer wrote this file for the retired golden lab's kernel
# value; this one writes nothing there, and --purge names it if it is
# still present (the reconciliation plan's D-R6).
SYSCTL_FILE=/etc/sysctl.d/99-podaro.conf
PODMAN_PACKAGES="podman uidmap slirp4netns passt fuse-overlayfs dbus-user-session"

MODE=install      # install | check | uninstall | print-answers
STAGE=auto        # auto | user
YES=0
YES_FLAG=()       # (--yes) when --yes was given, so a hand-over can pass it on
PURGE=0
ANSWERED=0
ANSWERED_BY_FLAG=0
REQUIRE_PASSWORD=1
ANSWERS_FILE=""
LOG="${PODARO_INSTALL_LOG:-}"

A_DOMAIN="${PODARO_DOMAIN:-}"
A_PORT="${PODARO_PORT:-}"
A_IP="${PODARO_IP:-}"
A_TLS="${PODARO_TLS:-}"
A_CERT="${PODARO_TLS_CERT:-}"
A_KEY="${PODARO_TLS_KEY:-}"
A_OPERATOR="${PODARO_OPERATOR:-}"
A_PASSFILE="${PODARO_PASSWORD_FILE:-}"
A_PODMAN="${PODARO_INSTALL_PODMAN:-}"
A_EXPORT="${PODARO_EXPORT_LOGS:-}"
A_HEC_ENDPOINT="${PODARO_HEC_ENDPOINT:-}"
A_HEC_TOKEN_FILE="${PODARO_HEC_TOKEN_FILE:-}"
A_HOST_ATTR="${PODARO_HOST_ATTRIBUTE:-}"
A_LAB="${PODARO_CREATE_LAB:-}"
A_LINK="${PODARO_LINK_PODAROCTL:-}"
PODAROCTL_PATH=/usr/local/bin/podaroctl
PASSFILE_TMP="${PODARO_INSTALL_PASSFILE_TMP:-0}"
TOKEN_TMP="${PODARO_INSTALL_TOKEN_TMP:-0}"
RESTART_FOR_EXPORT=0
# The product's display name, as the binary this script installs was built
# with (internal/brand; `podaro version --json`): read_brand sets them once
# the package's binary is found. These are the project's own name until then.
PKG_PRODUCT="Podaro"
PKG_TITLE="Podaro Community"
# The legal files a release carries beside the binary (the reconciliation
# plan's R5): install_binary puts these four beside ~/.local/bin/podaro, where
# INSTALL §5's by-hand path puts them too; `podaro system install` writes the
# full set, LICENSES/ and SOURCE-AND-BUILD.md included, to the state directory.
NOTICE_FILES="LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md"

# ---------------------------------------------------------------- output
# The UX Guide's CLI grammar (§7): glyph, label, one clause; colour only on
# a terminal without NO_COLOR; the error anatomy is code-free here because
# the CLI's own errors carry the PDR codes.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\e[32m'; C_BAD=$'\e[31m'; C_WARN=$'\e[33m'; C_DIM=$'\e[2m'; C_0=$'\e[0m'
else
  C_OK=""; C_BAD=""; C_WARN=""; C_DIM=""; C_0=""
fi
row() { # glyph label [detail]
  local g="$1" c=""
  case "$g" in ✓) c="$C_OK";; ✗) c="$C_BAD";; !) c="$C_WARN";; ○|◐) c="$C_DIM";; esac
  printf '%s%s%s %-22s %s\n' "$c" "$g" "$C_0" "$2" "${3:-}"
}
say()  { printf '%s\n' "$*"; }
nxt()  { printf '→ next: %s\n' "$*"; }
die() { # label cause [next] [exit]
  row ✗ "$1"
  printf '  cause     %s\n' "$2"
  [ -n "${3:-}" ] && printf '  next      %s\n' "$3"
  exit "${4:-1}"
}
have() { command -v "$1" >/dev/null 2>&1; }

usage() { sed -n '3,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- answers
load_answers() {
  local f="$1" line k v
  [ -r "$f" ] || die "answers" "cannot read $f" "" 2
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    [[ "$line" =~ ^[[:space:]]*$ ]] && continue
    [[ "$line" =~ ^[[:space:]]*([A-Za-z_]+)[[:space:]]*:[[:space:]]*(.*)$ ]] || continue
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    v="${v%"${v##*[![:space:]]}"}"; v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    # The environment wins over the file: only blanks are filled here.
    case "$k" in
      domain)         : "${A_DOMAIN:=$v}" ;;
      port)           : "${A_PORT:=$v}" ;;
      ip)             : "${A_IP:=$v}" ;;
      tls)            : "${A_TLS:=$v}" ;;
      cert_file)      : "${A_CERT:=$v}" ;;
      key_file)       : "${A_KEY:=$v}" ;;
      operator)       : "${A_OPERATOR:=$v}" ;;
      password_file)  : "${A_PASSFILE:=$v}" ;;
      install_podman) : "${A_PODMAN:=$v}" ;;
      export_logs)    : "${A_EXPORT:=$v}" ;;
      hec_endpoint)   : "${A_HEC_ENDPOINT:=$v}" ;;
      hec_token_file) : "${A_HEC_TOKEN_FILE:=$v}" ;;
      host_attribute) : "${A_HOST_ATTR:=$v}" ;;
      create_lab)     : "${A_LAB:=$v}" ;;
      link_podaroctl) : "${A_LINK:=$v}" ;;
      *) die "answers" "unknown key '$k' in $f" "keys: domain port ip tls cert_file key_file operator password_file install_podman export_logs hec_endpoint hec_token_file host_attribute create_lab link_podaroctl" 2 ;;
    esac
  done <"$f"
}

default_domain() {
  local f; f="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo podaro)"
  case "$f" in *.*) echo "lab.$f" ;; *) echo "lab.${f}.test" ;; esac
}
default_ip() {
  local a=""
  have ip && a="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [ -z "$a" ] && a="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "${a:-}"
}

ask() { # var prompt default
  local var="$1" prompt="$2" def="$3" v
  [ -n "${!var}" ] && return 0
  if [ "$YES" = 1 ]; then
    [ -n "$def" ] && { printf -v "$var" '%s' "$def"; return 0; }
    die "answers" "no value for '$prompt' and --yes given" "set PODARO_$(tr '[:lower:]' '[:upper:]' <<<"${var#A_}") or put it in --answers <file>" 2
  fi
  [ -r /dev/tty ] || die "answers" "no terminal to ask '$prompt' on" "use --yes with --answers <file>" 2
  read -r -p "? ${prompt} [${def}]: " v </dev/tty || v=""
  printf -v "$var" '%s' "${v:-$def}"
}

ask_optional() { # var prompt default — an empty answer is allowed (setup detects the address itself)
  local var="$1" prompt="$2" def="$3" v
  [ -n "${!var}" ] && return 0
  if [ "$YES" = 1 ] || [ ! -r /dev/tty ]; then printf -v "$var" '%s' "$def"; return 0; fi
  read -r -p "? ${prompt} [${def:-detected by setup}]: " v </dev/tty || v=""
  printf -v "$var" '%s' "${v:-$def}"
}

collect_answers() {
  [ "$ANSWERED" = 1 ] && return 0
  ask A_DOMAIN   "domain instances live under" "$(default_domain)"
  ask A_PORT     "gateway port"                "$DEFAULT_PORT"
  ask_optional A_IP "address for the DNS block" "$(default_ip)"
  ask A_TLS      "TLS: local-ca or own"        "local-ca"
  case "$A_TLS" in
    local-ca) A_CERT=""; A_KEY="" ;;
    own) ask A_CERT "certificate file (covers *.$A_DOMAIN and $A_DOMAIN)" ""; ask A_KEY "key file" "" ;;
    *) die "answers" "tls must be local-ca or own, not '$A_TLS'" "" 2 ;;
  esac
  ask A_OPERATOR "operator username"           "$DEFAULT_OPERATOR"
  ask_export
  ask_lab
  ask_link
  [[ "$A_PORT" =~ ^[0-9]+$ ]] && [ "$A_PORT" -ge 1 ] && [ "$A_PORT" -le 65535 ] || die "answers" "port must be 1–65535, not '$A_PORT'" "" 2
  [[ "$A_DOMAIN" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] || die "answers" "'$A_DOMAIN' is not a domain name" "lowercase labels joined by dots, e.g. lab.example.com" 2
  if [ -n "$A_PASSFILE" ]; then
    [ -r "$A_PASSFILE" ] || die "answers" "password_file $A_PASSFILE is not readable" "" 2
  elif [ "$REQUIRE_PASSWORD" = 1 ] && [ "$YES" = 1 ] && [ ! -f "${HOME:-/nonexistent}/.local/state/podaro/auth.json" ]; then
    die "answers" "--yes needs password_file for the operator password" "a 0600 file holding the password; never a flag value" 2
  fi
  ANSWERED=1
}

# The log export (Manual §4): off unless asked for. The token is the one
# answer that is a secret, so it travels like the password — never as a
# value in a file the script prints, only in a 0600 file or typed with
# echo off — and is never shown again.
ask_export() {
  ask A_EXPORT "export Podaro's logs over the HTTP Event Collector protocol? yes/no" "no"
  case "$A_EXPORT" in
    y|yes|Y|YES) A_EXPORT=yes ;;
    n|no|N|NO) A_EXPORT=no; return 0 ;;
    *) die "answers" "export_logs must be yes or no, not '$A_EXPORT'" "" 2 ;;
  esac
  ask A_HEC_ENDPOINT "HEC endpoint (https://host:8088; the collector path is added)" ""
  local url_re='^https?://[^[:space:]]+$' cred_re='^https?://[^/]*@' host_re='^[A-Za-z0-9][A-Za-z0-9._-]*$'
  [[ "$A_HEC_ENDPOINT" =~ $url_re ]] || die "answers" "'$A_HEC_ENDPOINT' is not an http(s) URL" "e.g. https://collector.example.com:8088" 2
  case "$A_HEC_ENDPOINT" in *\"*|*\'*) die "answers" "the endpoint holds a quote character" "" 2 ;; esac
  [[ "$A_HEC_ENDPOINT" =~ $cred_re ]] && die "answers" "the endpoint carries a credential" "the token belongs in the token file, never in the URL (Manual §4)" 2
  ask A_HOST_ATTR "host attribute on every exported record" "$(hostname -s 2>/dev/null || hostname)"
  [[ "$A_HOST_ATTR" =~ $host_re ]] || die "answers" "'$A_HOST_ATTR' is not a host attribute" "letters, digits, dots, dashes, underscores" 2
  if [ -n "$A_HEC_TOKEN_FILE" ]; then
    [ -r "$A_HEC_TOKEN_FILE" ] || die "answers" "hec_token_file $A_HEC_TOKEN_FILE is not readable" "" 2
    [ -s "$A_HEC_TOKEN_FILE" ] || die "answers" "hec_token_file $A_HEC_TOKEN_FILE is empty" "" 2
    return 0
  fi
  if [ "$YES" = 1 ]; then
    [ "$REQUIRE_PASSWORD" = 1 ] && die "answers" "--yes with export_logs yes needs hec_token_file" "a 0600 file holding the HEC token; never a flag value" 2
    return 0   # --print-answers: the token would be prompted for
  fi
  [ -r /dev/tty ] || die "answers" "no terminal to ask for the HEC token on" "use --yes with hec_token_file" 2
  local t
  read -r -s -p "? HEC token (echo off): " t </dev/tty || t=""
  printf '\n'
  [ -n "$t" ] || die "answers" "no HEC token given" "" 2
  local f; f="$(umask 077 && mktemp)"
  printf '%s' "$t" >"$f"; t=""
  A_HEC_TOKEN_FILE="$f"; TOKEN_TMP=1
}

# The first lab (INSTALL §2): off unless asked for, and the open-source
# lab — the one template the starter catalog holds.
ask_lab() {
  ask A_LAB "create the open-source lab now (grafana-prometheus-intro as 'intro'; two image pulls)? yes/no" "no"
  case "$A_LAB" in
    y|yes|Y|YES) A_LAB=yes ;;
    n|no|N|NO) A_LAB=no ;;
    *) die "answers" "create_lab must be yes or no, not '$A_LAB'" "" 2 ;;
  esac
}

ask_link() {
  ask A_LINK "put podaroctl on PATH (a root-owned copy in /usr/local/bin, so sudo podaroctl works from any shell)? yes/no" "no"
  case "$A_LINK" in
    y|yes|Y|YES) A_LINK=yes ;;
    n|no|N|NO) A_LINK=no ;;
    *) die "answers" "link_podaroctl must be yes or no, not '$A_LINK'" "" 2 ;;
  esac
}

print_answers() {
  say "domain          $A_DOMAIN"
  say "gateway port    $A_PORT"
  say "dns address     ${A_IP:-(detected at setup)}"
  say "tls             $A_TLS${A_CERT:+ · $A_CERT}"
  say "operator        $A_OPERATOR"
  say "password        $([ -n "$A_PASSFILE" ] && echo "from file (not shown)" || echo "prompted by podaro auth setup")"
  if [ "$A_EXPORT" = yes ]; then
    say "log export      hec · $A_HEC_ENDPOINT · host $A_HOST_ATTR · token $([ -n "$A_HEC_TOKEN_FILE" ] && echo "provided (never shown)" || echo "prompted, echo off")"
  else
    say "log export      no"
  fi
  say "first lab       $([ "$A_LAB" = yes ] && echo "grafana-prometheus-intro as intro" || echo "no")"
  say "podaroctl       $([ "$A_LINK" = yes ] && echo "root-owned copy in $PODAROCTL_PATH" || echo "not on PATH · sudo $SCRIPT_DIR/podaroctl <command>")"
  say "account         $PODARO_USER · home $PODARO_HOME"
  local pod="${A_PODMAN:-asked if missing}"
  have podman && pod="$pod · not needed: $(podman --version 2>/dev/null | awk '{print $3}') already installed"
  say "install podman  $pod"
}

confirm_plan() {
  say; print_answers; say
  [ "$YES" = 1 ] && return 0
  local v; read -r -p "proceed? [Y/n]: " v </dev/tty || v=""
  case "${v:-Y}" in y|Y|yes|YES) ;; *) say "stopped; nothing changed"; exit 0 ;; esac
}

# ---------------------------------------------------------------- package
read_brand() { # sets PKG_PRODUCT and PKG_TITLE from the package's binary, when there is one that runs
  [ -x "$SCRIPT_DIR/podaro" ] || return 0
  local js p t
  js="$("$SCRIPT_DIR/podaro" version --json 2>/dev/null || true)"
  p="$(printf '%s' "$js" | sed -n 's/.*"product":"\([^"\\]*\)".*/\1/p')"
  t="$(printf '%s' "$js" | sed -n 's/.*"title":"\([^"\\]*\)".*/\1/p')"
  [ -n "$p" ] && PKG_PRODUCT="$p"
  [ -n "$t" ] && PKG_TITLE="$t"
  return 0
}

package_row() { # sets PKG_VERSION
  if [ ! -x "$SCRIPT_DIR/podaro" ]; then
    [ -f "$SCRIPT_DIR/go.mod" ] && die "package" "this is a source checkout, not the release package: no 'podaro' binary beside install.sh in $SCRIPT_DIR" "./build.sh --install builds the release from this checkout and runs the installer (INSTALL §5) · or extract a release tarball into a directory of its own" 2
    die "package" "no executable 'podaro' beside install.sh in $SCRIPT_DIR" "extract the release tarball here: tar -xzf podaro_v<version>_linux_<arch>.tar.gz -C $SCRIPT_DIR" 2
  fi
  local out
  if ! out="$("$SCRIPT_DIR/podaro" version 2>&1)"; then
    die "package" "$out" "the binary must be built for this machine ($(uname -m)); the release has amd64 and arm64" 2
  fi
  PKG_VERSION="${out#podaro }"
  local note="SHA256SUMS not beside the package · unverified"
  if [ -f "$SCRIPT_DIR/SHA256SUMS" ]; then
    local d; d="$(sha256sum <"$SCRIPT_DIR/podaro" | cut -d' ' -f1)"
    grep -q "^$d " "$SCRIPT_DIR/SHA256SUMS" && note="digest listed in SHA256SUMS" || die "package" "the binary's digest is not in SHA256SUMS" "download the release again; a mismatch is never installed" 1
  fi
  row ◐ "package" "podaro $PKG_VERSION · linux/$(uname -m) · $note"
}

# ---------------------------------------------------------------- host stage (root)
ensure_podman() {
  if have podman && have newuidmap; then
    row ✓ "podman" "$(podman --version 2>/dev/null | awk '{print $3}') · already installed"
    return 0
  fi
  have apt-get || die "podman" "Podman is not installed and this is not an apt system" "install Podman ≥ 4.4 and uidmap from your distribution, then re-run" 2
  ask A_PODMAN "install Podman from the distribution (apt)? yes/no" "yes"
  case "$A_PODMAN" in
    y|yes|Y|YES)
      row ◐ "podman" "apt-get install $PODMAN_PACKAGES"
      DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $PODMAN_PACKAGES >/dev/null
      row ✓ "podman" "$(podman --version 2>/dev/null | awk '{print $3}') · installed from the distribution" ;;
    *) die "podman" "Podman is required and you chose not to install it" "sudo apt-get install -y $PODMAN_PACKAGES, then re-run" 2 ;;
  esac
}

ensure_account() {
  if id "$PODARO_USER" >/dev/null 2>&1; then
    local h; h="$(getent passwd "$PODARO_USER" | cut -d: -f6)"
    [ "$h" = "$PODARO_HOME" ] || die "account" "$PODARO_USER exists with home $h, not $PODARO_HOME" "extract the package into $h, or pass --home $h" 2
    row ✓ "account $PODARO_USER" "exists · home $PODARO_HOME"
  else
    local err
    if ! err="$(useradd --create-home --home-dir "$PODARO_HOME" --shell /bin/bash --comment "$PKG_TITLE" "$PODARO_USER" 2>&1 >/dev/null)"; then
      die "account $PODARO_USER" "useradd: $err" "" 1
    fi
    local f
    for f in /etc/skel/.profile /etc/skel/.bashrc; do
      [ -f "$f" ] && [ ! -e "$PODARO_HOME/$(basename "$f")" ] && cp "$f" "$PODARO_HOME/"
    done
    row ✓ "account $PODARO_USER" "created · home $PODARO_HOME · no password (use sudo -iu $PODARO_USER)"
  fi
  chown -R "$PODARO_USER:$PODARO_USER" "$PODARO_HOME"
  chmod 0750 "$PODARO_HOME"
  PODARO_UID="$(id -u "$PODARO_USER")"
}

# podaroctl on PATH (INSTALL §2 step 6): a root-owned copy, never a link
# into the account's home — root would then execute a file the account
# can replace (threat model B8).
ensure_podaroctl() {
  if [ "$A_LINK" != yes ]; then
    row ○ "podaroctl" "not on PATH · sudo $SCRIPT_DIR/podaroctl <command> works as is"
    return 0
  fi
  [ -f "$SCRIPT_DIR/podaroctl" ] || die "podaroctl" "no podaroctl beside install.sh in $SCRIPT_DIR" "extract the release tarball again; it holds one" 2
  install -o root -g root -m 0755 "$SCRIPT_DIR/podaroctl" "$PODAROCTL_PATH"
  row ✓ "podaroctl" "$PODAROCTL_PATH · root-owned copy of $SCRIPT_DIR/podaroctl"
}

ensure_subids() {
  if ! grep -q "^${PODARO_USER}:" /etc/subuid 2>/dev/null || ! grep -q "^${PODARO_USER}:" /etc/subgid 2>/dev/null; then
    local start
    start="$(cat /etc/subuid /etc/subgid 2>/dev/null | awk -F: 'NF==3 {e=$2+$3; if (e>m) m=e} END {if (m<100000) m=100000; print m}')"
    usermod --add-subuids "${start}-$((start + 65535))" --add-subgids "${start}-$((start + 65535))" "$PODARO_USER"
  fi
  local r; r="$(grep "^${PODARO_USER}:" /etc/subuid | head -1 | awk -F: '{print $2"-"$2+$3-1}')"
  row ✓ "subuid / subgid" "$r mapped for $PODARO_USER"
}

ensure_linger() {
  loginctl enable-linger "$PODARO_USER" 2>/dev/null || die "lingering" "loginctl enable-linger $PODARO_USER failed" "is systemd-logind running on this host?" 1
  local i
  for i in $(seq 1 40); do
    [ -S "/run/user/$PODARO_UID/bus" ] && break
    [ "$i" -eq 10 ] && systemctl start "user@${PODARO_UID}.service" 2>/dev/null || true
    sleep 0.5
  done
  [ -S "/run/user/$PODARO_UID/bus" ] || die "lingering" "the service manager for $PODARO_USER did not start (/run/user/$PODARO_UID/bus missing)" "systemctl status user@${PODARO_UID}.service" 1
  row ✓ "lingering" "enabled for $PODARO_USER · service manager running"
}

stage_private_files() {
  # The account must be able to read what setup and auth setup will read;
  # copies land on its own tmpfs (the password) or in its config dir (a
  # bring-your-own certificate), owned by it, 0600.
  if [ -n "$A_PASSFILE" ]; then
    local t="/run/user/$PODARO_UID/podaro-install.pass"
    install -o "$PODARO_USER" -g "$PODARO_USER" -m 0600 "$A_PASSFILE" "$t"
    A_PASSFILE="$t"; PASSFILE_TMP=1
  fi
  if [ "$A_EXPORT" = yes ]; then
    local t="/run/user/$PODARO_UID/podaro-install.hec"
    install -o "$PODARO_USER" -g "$PODARO_USER" -m 0600 "$A_HEC_TOKEN_FILE" "$t"
    [ "$TOKEN_TMP" = 1 ] && rm -f "$A_HEC_TOKEN_FILE"
    A_HEC_TOKEN_FILE="$t"; TOKEN_TMP=1
  fi
  if [ "$A_TLS" = own ]; then
    local d="$PODARO_HOME/.config/podaro/tls"
    install -o "$PODARO_USER" -g "$PODARO_USER" -m 0700 -d "$PODARO_HOME/.config" "$PODARO_HOME/.config/podaro" "$d"
    install -o "$PODARO_USER" -g "$PODARO_USER" -m 0600 "$A_CERT" "$d/cert.pem"
    install -o "$PODARO_USER" -g "$PODARO_USER" -m 0600 "$A_KEY" "$d/key.pem"
    A_CERT="$d/cert.pem"; A_KEY="$d/key.pem"
    row ✓ "certificate" "copied to $d (0600, owned by $PODARO_USER)"
  fi
}

reexec_user_stage() {
  say "→ continuing as $PODARO_USER"
  exec runuser -u "$PODARO_USER" -- env -i \
    HOME="$PODARO_HOME" USER="$PODARO_USER" LOGNAME="$PODARO_USER" SHELL=/bin/bash \
    PATH="$PODARO_HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    XDG_RUNTIME_DIR="/run/user/$PODARO_UID" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$PODARO_UID/bus" \
    TERM="${TERM:-dumb}" NO_COLOR="${NO_COLOR:-}" LANG="${LANG:-C.UTF-8}" \
    PODARO_USER="$PODARO_USER" PODARO_HOME="$PODARO_HOME" PODARO_INSTALL_LOG="$LOG" \
    PODARO_DOMAIN="$A_DOMAIN" PODARO_PORT="$A_PORT" PODARO_IP="$A_IP" PODARO_TLS="$A_TLS" \
    PODARO_TLS_CERT="$A_CERT" PODARO_TLS_KEY="$A_KEY" PODARO_OPERATOR="$A_OPERATOR" \
    PODARO_PASSWORD_FILE="$A_PASSFILE" PODARO_INSTALL_PASSFILE_TMP="$PASSFILE_TMP" \
    PODARO_EXPORT_LOGS="$A_EXPORT" PODARO_HEC_ENDPOINT="$A_HEC_ENDPOINT" PODARO_HEC_TOKEN_FILE="$A_HEC_TOKEN_FILE" \
    PODARO_HOST_ATTRIBUTE="$A_HOST_ATTR" PODARO_INSTALL_TOKEN_TMP="$TOKEN_TMP" PODARO_CREATE_LAB="$A_LAB" PODARO_LINK_PODAROCTL="$A_LINK" \
    bash "$SCRIPT_DIR/install.sh" --stage user --answered ${YES_FLAG[@]+"${YES_FLAG[@]}"}
}

host_stage() {
  read_brand
  package_row
  collect_answers
  confirm_plan
  ensure_podman
  ensure_account
  ensure_subids
  ensure_linger
  ensure_podaroctl
  stage_private_files
  reexec_user_stage
}

# ---------------------------------------------------------------- user stage (the podaro account)
user_session_row() {
  [ "$(id -un)" = "$PODARO_USER" ] || die "account" "this stage runs as $PODARO_USER, not $(id -un)" "sudo $SCRIPT_DIR/install.sh (prepares the host, then continues as $PODARO_USER) · or as that account: sudo -iu $PODARO_USER $SCRIPT_DIR/install.sh" 2
  : "${XDG_RUNTIME_DIR:=/run/user/$(id -u)}"; export XDG_RUNTIME_DIR
  [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"
  systemctl --user show-environment >/dev/null 2>&1 || die "user session" "systemctl --user cannot reach $PODARO_USER's service manager" "sudo loginctl enable-linger $PODARO_USER, then re-run" 2
  row ✓ "user session" "$PODARO_USER · $XDG_RUNTIME_DIR"
}

install_binary() {
  BIN="$HOME/.local/bin/podaro"
  mkdir -p "$HOME/.local/bin"
  if [ -x "$BIN" ] && [ "$(sha256sum <"$BIN" | cut -d' ' -f1)" = "$(sha256sum <"$SCRIPT_DIR/podaro" | cut -d' ' -f1)" ]; then
    row ✓ "binary" "$BIN · already this release"
  else
    install -m 0755 "$SCRIPT_DIR/podaro" "$BIN"
    row ✓ "binary" "$BIN (0755)"
  fi
  # The notices travel with the binary they cover: the release's own copies,
  # from the package, beside it (the reconciliation §7.1).
  local f missing=""
  for f in $NOTICE_FILES; do
    if [ -f "$SCRIPT_DIR/$f" ]; then install -m 0644 "$SCRIPT_DIR/$f" "$HOME/.local/bin/$f"; else missing="$missing $f"; fi
  done
  if [ -z "$missing" ]; then
    row ✓ "notices" "$(printf '%s · ' $NOTICE_FILES | sed 's/ · $//') beside the binary"
  else
    row ! "notices" "not in the package:$missing · podaro legal prints them from the binary"
  fi
  podman system migrate >/dev/null 2>&1 || true
}

# A `sudo -iu podaro` shell is a login shell with no logind session: no
# XDG_RUNTIME_DIR, no session bus, so systemctl --user, journalctl --user
# and podman all lose the account's session (acceptance log 0002,
# deviation 1). The block below gives the profile what the session would
# have given, guarded on the runtime directory lingering keeps alive, and
# puts ~/.local/bin on PATH. Appended once; a profile that has it is kept.
ensure_profile() {
  local f="$HOME/.profile" marker='# >>> podaro session'
  if grep -qs "^$marker" "$f"; then
    row ✓ "profile" "$f · session block present"
    return 0
  fi
  {
    printf '\n%s (INSTALL §2): the runtime directory, session bus and PATH a sudo -iu shell lacks\n' "$marker"
    printf '%s\n' 'if [ -z "${XDG_RUNTIME_DIR:-}" ] && [ -d "/run/user/$(id -u)" ]; then export XDG_RUNTIME_DIR="/run/user/$(id -u)"; fi'
    printf '%s\n' 'if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "${XDG_RUNTIME_DIR:-/nonexistent}/bus" ]; then export DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus"; fi'
    printf '%s\n' 'case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac'
    printf '# <<< podaro session\n'
  } >>"$f"
  row ✓ "profile" "$f · session variables and PATH for sudo -iu $PODARO_USER shells"
}

doctor_loop() {
  local rc j need fail
  while :; do
    set +e; "$BIN" doctor; rc=$?; set -e
    [ "$rc" -eq 0 ] && return 0
    j="$("$BIN" doctor --json 2>/dev/null || echo '{}')"
    need="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("summary",{}).get("need_root",0))' <<<"$j" 2>/dev/null || echo 0)"
    fail="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("summary",{}).get("fail",0))' <<<"$j" 2>/dev/null || echo 0)"
    if [ "$need" -gt 0 ]; then
      if [ "$YES" = 1 ] || [ ! -r /dev/tty ]; then
        die "doctor" "$need item(s) need root, and this run cannot wait for you" "run the printed sudo command(s), then re-run install.sh" 2
      fi
      say; say "! run the printed sudo command(s) in another terminal, then press Enter to re-check (Ctrl-C stops)"
      read -r _ </dev/tty
      continue
    fi
    [ "$fail" -gt 0 ] && die "doctor" "$fail item(s) fail and root cannot fix them" "fix the causes doctor printed, then re-run install.sh" 2
    return 0   # only pending rows (dns before setup)
  done
}

write_own_tls() {
  [ "$A_TLS" = own ] || return 0
  local cfg="$HOME/.config/podaro/config.yaml"
  mkdir -p "$HOME/.config/podaro"; chmod 0700 "$HOME/.config/podaro"
  if [ -f "$cfg" ] && grep -q '^tls:' "$cfg"; then
    row ✓ "tls" "config already names a certificate · kept"
    return 0
  fi
  { [ -f "$cfg" ] && cat "$cfg"; printf 'tls:\n  cert_file: %s\n  key_file: %s\n' "$A_CERT" "$A_KEY"; } >"$cfg.tmp"
  chmod 0600 "$cfg.tmp"; mv "$cfg.tmp" "$cfg"
  row ✓ "tls" "bringing your own certificate · $A_CERT"
}

# The export block goes into config.yaml before `setup`, which rewrites the
# file from what it loaded and keeps every block it does not own; the
# engine builds its exporter at start, so the service is restarted once
# the account is in place, and `observe test` says whether the probe landed.
write_log_export() {
  [ "$A_EXPORT" = yes ] || return 0
  local cfg="$HOME/.config/podaro/config.yaml" dest="$HOME/.config/podaro/hec.token"
  mkdir -p "$HOME/.config/podaro"; chmod 0700 "$HOME/.config/podaro"
  if [ "$A_HEC_TOKEN_FILE" != "$dest" ]; then
    install -m 0600 "$A_HEC_TOKEN_FILE" "$dest"
    [ "$TOKEN_TMP" = 1 ] && rm -f "$A_HEC_TOKEN_FILE"
  fi
  chmod 0600 "$dest"
  if [ -f "$cfg" ] && grep -q '^observability:' "$cfg"; then
    row ✓ "log export" "config already names an export · kept · token refreshed in $dest"
    RESTART_FOR_EXPORT=1
    return 0
  fi
  { [ -f "$cfg" ] && cat "$cfg"
    printf 'observability:\n  logs:\n    exporter: hec\n    endpoint: "%s"\n    token_file: "%s"\n  attributes:\n    host: "%s"\n' "$A_HEC_ENDPOINT" "$dest" "$A_HOST_ATTR"
  } >"$cfg.tmp"
  chmod 0600 "$cfg.tmp"; mv "$cfg.tmp" "$cfg"
  RESTART_FOR_EXPORT=1
  row ✓ "log export" "hec · $A_HEC_ENDPOINT · host $A_HOST_ATTR · token in $dest (0600)"
}

export_check() {
  [ "$A_EXPORT" = yes ] || return 0
  if [ "$RESTART_FOR_EXPORT" = 1 ]; then
    systemctl --user restart podaro
    local i
    for i in $(seq 1 60); do [ -S "$XDG_RUNTIME_DIR/podaro/api.sock" ] && break; sleep 0.5; done
    [ -S "$XDG_RUNTIME_DIR/podaro/api.sock" ] || { row ✗ "service" "did not come back after the restart · journalctl --user -u podaro"; return 0; }
    row ✓ "service" "restarted to start the export"
  fi
  "$BIN" observe status || true
  if "$BIN" observe test; then
    row ✓ "export probe" "landed at $A_HEC_ENDPOINT"
  else
    row ! "export probe" "did not land · check the destination and the token, then: podaro observe test"
  fi
}

auth_setup() {
  if [ -f "$HOME/.local/state/podaro/auth.json" ]; then
    row ✓ "operator account" "exists · replace with: podaro auth reset"
  elif [ -n "$A_PASSFILE" ]; then
    "$BIN" auth setup --username "$A_OPERATOR" --password-file "$A_PASSFILE"
  else
    "$BIN" auth setup --username "$A_OPERATOR"
  fi
  [ "$PASSFILE_TMP" = 1 ] && [ -n "$A_PASSFILE" ] && rm -f "$A_PASSFILE"
  return 0
}

# The first lab, when asked for: the same `podaro up` the summary would
# have offered, run now so the summary can print what the engine says the
# lab's hostnames are — the console's and one per product with a UI —
# for the DNS or hosts-file work the browsing machine needs.
create_lab() {
  [ "$A_LAB" = yes ] || return 0
  if "$BIN" status intro >/dev/null 2>&1; then
    row ✓ "lab intro" "exists · kept"
    return 0
  fi
  say; say "creating the open-source lab as 'intro' (two image pulls; minutes on a cold cache)"
  if "$BIN" up grafana-prometheus-intro --name intro; then
    row ✓ "lab intro" "grafana-prometheus-intro · created"
  else
    row ✗ "lab intro" "create did not finish · podaro status intro · then podaro up grafana-prometheus-intro --name intro"
  fi
}

lab_urls() { # one "label  url" per line — the console first, then each product with a UI; empty when the lab is not there
  "$BIN" status intro --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin).get("instance") or {}
if d.get("console_url"): print("%-12s %s" % ("console", d["console_url"]))
for s in d.get("services") or []:
    if s.get("url"): print("%-12s %s" % (s.get("name", "?"), s["url"]))
' 2>/dev/null || true
}

hosts_of() { # the bare hostnames of "label  url" lines, space-separated
  printf '%s\n' "$1" | sed -E 's#.*https?://([^/:[:space:]]+).*#\1#' | tr '\n' ' '
}

self_check() {
  say
  "$BIN" status || true
  systemctl --user is-active --quiet podaro && row ✓ "service" "podaro.service active" || row ✗ "service" "podaro.service is not active · journalctl --user -u podaro"
  if have ss && ss -tln 2>/dev/null | grep -qE "[:.]${A_PORT}[[:space:]]"; then
    row ✓ "listener" ":$A_PORT (TLS) · the only network port $PKG_PRODUCT opens"
  else
    row ! "listener" ":$A_PORT not seen in ss -tln"
  fi
  if have curl; then
    local ca="$HOME/.local/state/podaro/ca/ca.crt" code opts
    opts=(-s -o /dev/null -w '%{http_code}' --resolve "$A_DOMAIN:$A_PORT:127.0.0.1" --max-time 10)
    [ "$A_TLS" = local-ca ] && [ -f "$ca" ] && opts+=(--cacert "$ca") || opts+=(-k)
    code="$(curl "${opts[@]}" "https://$A_DOMAIN:$A_PORT/api/v1alpha1/instances" 2>/dev/null || echo 000)"
    if [ "$code" = 401 ]; then
      row ✓ "gateway" "https://$A_DOMAIN:$A_PORT answers 401 until you log in$([ "$A_TLS" = local-ca ] && echo " · trusted through the local CA")"
    else
      row ! "gateway" "expected 401 from https://$A_DOMAIN:$A_PORT, got $code"
    fi
  fi
}

summary() {
  local ca="$HOME/.local/state/podaro/ca/ca.crt"
  say
  say "installed · engine running as $PODARO_USER · log: ${LOG:-none}"
  say
  [ "$A_TLS" = local-ca ] && {
    say "trust the CA on machines that will browse labs (never copy ca.key):"
    say "  sudo install -m 0644 $ca /tmp/podaro-ca.crt   # then copy /tmp/podaro-ca.crt to the workstation"
    say
  }
  local urls=""
  [ "$A_LAB" = yes ] && urls="$(lab_urls)"
  say "point dns at this host (one wildcard record covers every lab):"
  say "  *.$A_DOMAIN    A    ${A_IP:-<this host>}"
  if [ -n "$urls" ]; then
    say "  or, on the browsing machine's hosts file, one line with every name this lab uses:"
    say "    ${A_IP:-<this host>}  $A_DOMAIN $(hosts_of "$urls")"
    say
    say "lab intro (grafana-prometheus-intro):"
    while IFS= read -r u; do say "  $u"; done <<<"$urls"
    say "  the product names are loaded by the console's tabs and answer only to a signed-in session"
  else
    say "  or, on the browsing machine's hosts file, one line per hostname the console shows you"
  fi
  say
  local ctl="sudo $SCRIPT_DIR/podaroctl"; [ "$A_LINK" = yes ] && ctl="sudo podaroctl"
  say "operate as the account:  sudo -iu $PODARO_USER   ·   from any shell: $ctl <podaro command>   ·   console login: $A_OPERATOR"
  [ "$A_EXPORT" = yes ] && say "logs export to $A_HEC_ENDPOINT (hec):  podaro observe status · podaro observe test"
  if [ -n "$urls" ]; then
    nxt "open the lab: $(head -1 <<<"$urls" | awk '{print $2}')"
  else
    nxt "podaro up grafana-prometheus-intro --name intro      # 4 GB · all open source"
  fi
  say
  say "console: https://$A_DOMAIN:$A_PORT"
}

user_stage() {
  read_brand
  user_session_row
  # After a hand-over the root stage has already verified and printed the package.
  if [ "$ANSWERED_BY_FLAG" != 1 ]; then package_row; fi
  collect_answers
  if [ "$ANSWERED_BY_FLAG" != 1 ]; then confirm_plan; fi
  install_binary
  ensure_profile
  # As the account there is no root: the one privileged act asked for is printed, never run.
  if [ "$A_LINK" = yes ] && [ "$ANSWERED_BY_FLAG" != 1 ]; then row ○ "podaroctl" "needs root · sudo install -o root -g root -m 0755 $SCRIPT_DIR/podaroctl $PODAROCTL_PATH"; fi
  "$BIN" system install
  doctor_loop
  write_own_tls
  write_log_export
  if [ -n "$A_IP" ]; then
    "$BIN" setup --domain "$A_DOMAIN" --port "$A_PORT" --ip "$A_IP"
  else
    "$BIN" setup --domain "$A_DOMAIN" --port "$A_PORT"
  fi
  auth_setup
  export_check
  create_lab
  self_check
  summary
}

# ---------------------------------------------------------------- check / uninstall
as_account() { # run a command as the account, with its session environment
  local uid; uid="$(id -u "$PODARO_USER")"
  runuser -u "$PODARO_USER" -- env HOME="$PODARO_HOME" XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$@"
}

check() {
  local me; me="$(id -un)"
  read_brand
  if [ -x "$SCRIPT_DIR/podaro" ]; then row ✓ "package" "$("$SCRIPT_DIR/podaro" version 2>/dev/null || echo 'podaro (not runnable here)') · $SCRIPT_DIR"
  elif [ -f "$SCRIPT_DIR/go.mod" ]; then row ✗ "package" "a source checkout, not the package: no podaro binary in $SCRIPT_DIR · ./build.sh --install builds and installs it (INSTALL §5)"
  else row ✗ "package" "no podaro binary in $SCRIPT_DIR"; fi
  if [ -x "$PODAROCTL_PATH" ]; then row ✓ "podaroctl" "$PODAROCTL_PATH · sudo podaroctl <command> from any shell"
  elif [ -f "$SCRIPT_DIR/podaroctl" ]; then row ○ "podaroctl" "not on PATH · sudo $SCRIPT_DIR/podaroctl <command>"
  else row ✗ "podaroctl" "not beside install.sh in $SCRIPT_DIR"; fi
  have podman && row ✓ "podman" "$(podman --version 2>/dev/null | awk '{print $3}')" || row ✗ "podman" "not installed"
  if id "$PODARO_USER" >/dev/null 2>&1; then row ✓ "account $PODARO_USER" "home $(getent passwd "$PODARO_USER" | cut -d: -f6)"; else row ✗ "account $PODARO_USER" "does not exist"; fi
  grep -qs "^${PODARO_USER}:" /etc/subuid && grep -qs "^${PODARO_USER}:" /etc/subgid && row ✓ "subuid / subgid" "mapped" || row ✗ "subuid / subgid" "not mapped for $PODARO_USER"
  [ "$(loginctl show-user "$PODARO_USER" -p Linger --value 2>/dev/null)" = yes ] && row ✓ "lingering" "enabled" || row ✗ "lingering" "not enabled"
  [ -x "$PODARO_HOME/.local/bin/podaro" ] && row ✓ "binary" "$PODARO_HOME/.local/bin/podaro" || row ✗ "binary" "not installed at $PODARO_HOME/.local/bin/podaro"
  if [ -f "$PODARO_HOME/.local/bin/NOTICE" ]; then row ✓ "notices" "beside the binary in $PODARO_HOME/.local/bin"
  elif [ -f "$SCRIPT_DIR/NOTICE" ]; then row ○ "notices" "in the package · not yet beside an installed binary"
  else row ○ "notices" "not in the package · podaro legal prints them from the binary"; fi
  local cfg="$PODARO_HOME/.config/podaro/config.yaml"
  if [ -r "$cfg" ]; then row ✓ "setup" "$(awk '/^domain:/{d=$2} /^ *port:/{p=$2} END{print d " · port " (p?p:"'"$DEFAULT_PORT"'")}' "$cfg")"; elif [ -e "$cfg" ]; then row ○ "setup" "config exists · not readable as $me"; else row ✗ "setup" "not run (no config)"; fi
  if [ -r "$cfg" ] && grep -q '^observability:' "$cfg"; then row ✓ "log export" "$(awk '/^ *endpoint:/{gsub(/"/,"",$2); print $2; exit}' "$cfg")"; elif [ -r "$cfg" ]; then row ○ "log export" "off (Manual §4)"; fi
  local auth="$PODARO_HOME/.local/state/podaro/auth.json"
  if [ -r "$auth" ] || { [ -e "$auth" ] && [ "$me" != "$PODARO_USER" ]; }; then row ✓ "operator account" "created"; else row ✗ "operator account" "not created"; fi
  if [ "$me" = root ] && ! id "$PODARO_USER" >/dev/null 2>&1; then
    row ✗ "service" "no account, so no service"
  elif [ "$me" = root ]; then
    as_account systemctl --user is-active --quiet podaro 2>/dev/null && row ✓ "service" "active" || row ✗ "service" "not active"
  elif [ "$me" = "$PODARO_USER" ]; then
    systemctl --user is-active --quiet podaro 2>/dev/null && row ✓ "service" "active" || row ✗ "service" "not active"
  else
    row ○ "service" "run --check as root or as $PODARO_USER to see it"
  fi
  local port; port="$(awk '/^ *port:/{print $2}' "$cfg" 2>/dev/null || true)"; port="${port:-$DEFAULT_PORT}"
  have ss && ss -tln 2>/dev/null | grep -qE "[:.]${port}[[:space:]]" && row ✓ "listener" ":$port" || row ○ "listener" ":$port not seen"
}

uninstall() {
  local bin="$PODARO_HOME/.local/bin/podaro"
  if [ "$(id -un)" = root ]; then
    id "$PODARO_USER" >/dev/null 2>&1 || die "uninstall" "no account $PODARO_USER on this host" "" 2
    if [ -x "$bin" ]; then
      as_account "$bin" system uninstall ${YES_FLAG[@]+"${YES_FLAG[@]}"}
    else
      row ○ "uninstall" "no binary at $bin · nothing to ask the engine"
    fi
    [ "$PURGE" = 1 ] || { nxt "sudo $SCRIPT_DIR/install.sh --uninstall --purge   # also removes the account and $PODARO_HOME"; return 0; }
    if [ "$YES" != 1 ]; then
      say "this removes the account $PODARO_USER and everything under $PODARO_HOME, this package included"
      local v; read -r -p "type the account name to confirm: " v </dev/tty || v=""
      [ "$v" = "$PODARO_USER" ] || { say "stopped; nothing removed"; exit 1; }
    fi
    loginctl disable-linger "$PODARO_USER" 2>/dev/null || true
    pkill -u "$PODARO_USER" 2>/dev/null || true
    userdel -r "$PODARO_USER" 2>/dev/null || userdel "$PODARO_USER"
    rm -rf "$PODARO_HOME"
    row ✓ "account $PODARO_USER" "removed with $PODARO_HOME"
    if [ -e "$PODAROCTL_PATH" ]; then rm -f "$PODAROCTL_PATH"; row ✓ "podaroctl" "removed from $PODAROCTL_PATH"; fi
    [ -e "$SYSCTL_FILE" ] && say "left in place: $SYSCTL_FILE (written by an earlier installer; inert; remove it and run sysctl --system to revert)"
    say "left in place: podman images (podman rmi --all as any remaining user)"
  elif [ "$(id -un)" = "$PODARO_USER" ]; then
    [ -x "$bin" ] || die "uninstall" "no binary at $bin" "" 2
    "$bin" system uninstall ${YES_FLAG[@]+"${YES_FLAG[@]}"}
    [ "$PURGE" = 1 ] && say "removing the account needs root: sudo $SCRIPT_DIR/install.sh --uninstall --purge"
  else
    die "uninstall" "run as root or as $PODARO_USER" "" 2
  fi
}

# ---------------------------------------------------------------- main
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1; YES_FLAG=(--yes) ;;
    --answers) ANSWERS_FILE="${2:-}"; shift ;;
    --check) MODE=check ;;
    --uninstall) MODE=uninstall ;;
    --purge) PURGE=1 ;;
    --print-answers) MODE=print-answers ;;
    --stage) STAGE="${2:-}"; shift ;;
    --answered) ANSWERED=1; ANSWERED_BY_FLAG=1 ;;
    --user) PODARO_USER="${2:-}"; shift ;;
    --home) PODARO_HOME="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "usage" "unknown argument: $1" "install.sh --help" 2 ;;
  esac
  shift
done
[ -n "$ANSWERS_FILE" ] && load_answers "$ANSWERS_FILE"

case "$MODE" in
  check) check; exit 0 ;;
  print-answers) YES=1; REQUIRE_PASSWORD=0; collect_answers; print_answers; exit 0 ;;
  uninstall) uninstall; exit 0 ;;
esac

if [ -z "$LOG" ]; then
  LOG="$PODARO_HOME/install-$(date -u +%Y%m%dT%H%M%SZ).log"
  if ( : >>"$LOG" ) 2>/dev/null; then
    exec > >(tee -a "$LOG") 2>&1
  else
    LOG=""
  fi
fi

if [ "$(id -u)" -eq 0 ]; then
  [ "$STAGE" = user ] && die "stage" "the user stage never runs as root" "sudo $SCRIPT_DIR/install.sh runs both stages in order" 2
  host_stage
else
  user_stage
fi
