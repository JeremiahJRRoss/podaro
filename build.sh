#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Podaro — build the release artifacts from this checkout (INSTALL §5,
# "From source"). A git clone or a GitHub zip both work: the packager
# tolerates a tree without .git, and refuses a dirty one.
#
#   ./build.sh              check the tools, build the release into dist/,
#                           print the install commands
#   ./build.sh --check      report the tools and versions; build nothing
#   ./build.sh --quick      one `go build` of this machine's binary into
#                           dist/quick/ — unverified, for iteration
#   ./build.sh --install    build, then extract into /opt/podaro and run
#                           install.sh under sudo (the prompts are yours)
#   ./build.sh --yes        install a missing or too-old Go without asking:
#                           the distribution's package when it is new
#                           enough, else the official tarball from go.dev,
#                           checksum verified, into /usr/local/go
#
# Every missing dependency is a row with its remedy; nothing is installed
# on this machine unless --yes says so. PODARO_BUILD_OUT overrides dist/.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
OUT="${PODARO_BUILD_OUT:-dist}"
INSTALL_DIR=/opt/podaro
GO_DL=https://go.dev/dl
MODE=build   # build | check | quick
DO_INSTALL=0
YES=0

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_OK=$'\e[32m'; C_BAD=$'\e[31m'; C_WARN=$'\e[33m'; C_DIM=$'\e[2m'; C_0=$'\e[0m'
else
  C_OK=""; C_BAD=""; C_WARN=""; C_DIM=""; C_0=""
fi
row() { # glyph label [detail]
  local g="$1" c=""
  case "$g" in ✓) c="$C_OK";; ✗) c="$C_BAD";; !) c="$C_WARN";; ○|◐) c="$C_DIM";; esac
  printf '%s%s%s %-14s %s\n' "$c" "$g" "$C_0" "$2" "${3:-}"
}
say() { printf '%s\n' "$*"; }
nxt() { printf '→ next: %s\n' "$*"; }
die() { # label cause [next] [exit]
  row ✗ "$1"
  printf '  cause     %s\n' "$2"
  [ -n "${3:-}" ] && printf '  next      %s\n' "$3"
  exit "${4:-1}"
}
have() { command -v "$1" >/dev/null 2>&1; }
usage() { sed -n '3,24p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check ;;
    --quick) MODE=quick ;;
    --install) DO_INSTALL=1 ;;
    --yes|-y) YES=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "usage" "unknown argument: $1" "build.sh --help" 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- the checkout
[ -f go.mod ] && [ -f VERSION ] && [ -x hack/release_package.sh ] || die "checkout" "this is not a Podaro source tree (go.mod, VERSION and hack/release_package.sh expected beside build.sh)" "" 2
VERSION="$(tr -d '[:space:]' <VERSION)"
NEED_GO="$(awk '/^go /{print $2; exit}' go.mod)"
row ◐ "checkout" "podaro $VERSION · needs go ≥ $NEED_GO"

# ---------------------------------------------------------------- host
case "$(uname -s)" in Linux) ;; *) die "host" "$(uname -s) is not Linux" "Podaro builds and runs on Linux (User Manual §3)" 2 ;; esac
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "host" "$(uname -m) is not an architecture a release is built for" "amd64 or arm64" 2 ;;
esac
row ✓ "host" "linux/$ARCH"

# ---------------------------------------------------------------- tools
missing=""
for t in tar gzip sha256sum realpath; do have "$t" || missing="$missing $t"; done
if [ -n "$missing" ]; then
  die "tools" "missing:$missing" "apt-get install -y tar gzip coreutils" 2
fi
row ✓ "tools" "tar gzip sha256sum realpath"
if have git && git rev-parse --git-dir >/dev/null 2>&1; then
  dirty="$(git status --porcelain --untracked-files=all | { grep -v -E "^\?\? ${OUT%/}/" || true; } | wc -l | tr -d ' ')"
  if [ "$dirty" -gt 0 ] && [ "$MODE" = build ]; then
    die "checkout" "$dirty uncommitted or untracked file(s); the packager refuses a dirty tree, because an artifact must name a commit" "commit or stash them (git status --short) · or --quick for an unverified build of the tree as it is" 2
  fi
  row ✓ "git" "$(git rev-parse --short HEAD) · $([ "$dirty" -gt 0 ] && echo "$dirty change(s), --quick build" || echo clean)"
else
  row ○ "git" "no .git (a GitHub zip): the packager builds it unstamped"
fi

# ---------------------------------------------------------------- go
go_version() { go version 2>/dev/null | sed -n 's/^go version go\([0-9][0-9.]*\).*/\1/p'; }
version_ge() { # a b — true when a ≥ b, numerically per dotted field
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]
}
install_go() {
  [ "$YES" = 1 ] || die "go" "$1" "install Go ≥ $NEED_GO (https://go.dev/dl, or apt-get install golang-go when the distribution's is new enough) · or re-run with --yes to let this script do it" 2
  local cand=""
  if have apt-cache; then
    cand="$(apt-cache policy golang-go 2>/dev/null | awk '/Candidate:/{print $2}' | sed -n 's/^[0-9]*://p; t; p' | sed 's/^\([0-9][0-9.]*\).*/\1/')"
  fi
  if [ -n "$cand" ] && [ "$cand" != "(none)" ] && version_ge "$cand" "$NEED_GO"; then
    row ◐ "go" "apt-get install golang-go ($cand)"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq golang-go >/dev/null
    return 0
  fi
  have curl || die "go" "curl is needed to fetch Go from $GO_DL" "apt-get install -y curl" 2
  local latest
  latest="$(curl -fsSL "$GO_DL/../VERSION?m=text" | head -1)"
  [ -n "$latest" ] || die "go" "could not read the current Go version from go.dev" "check the network (HTTPS_PROXY) · or install Go by hand" 2
  local tgz="${latest}.linux-${ARCH}.tar.gz" tmp
  tmp="$(mktemp -d)"
  row ◐ "go" "fetching $GO_DL/$tgz and its checksum"
  curl -fsSL -o "$tmp/$tgz" "$GO_DL/$tgz"
  curl -fsSL -o "$tmp/$tgz.sha256" "$GO_DL/$tgz.sha256"
  ( cd "$tmp" && echo "$(cat "$tgz.sha256")  $tgz" | sha256sum -c --quiet ) || die "go" "the checksum of $tgz does not match go.dev's" "download it again; a mismatch is never installed" 1
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf "$tmp/$tgz"
  rm -rf "$tmp"
  export PATH="/usr/local/go/bin:$PATH"
  row ✓ "go" "$latest installed into /usr/local/go · add /usr/local/go/bin to PATH for your shell"
}
if ! have go; then
  [ -x /usr/local/go/bin/go ] && export PATH="/usr/local/go/bin:$PATH"
fi
if ! have go; then
  install_go "Go is not installed"
elif ! version_ge "$(go_version)" "$NEED_GO"; then
  install_go "go $(go_version) is older than the $NEED_GO go.mod declares"
fi
row ✓ "go" "$(go version | awk '{print $3, $4}')"

[ "$MODE" = check ] && { say; say "nothing built (--check)"; exit 0; }

# ---------------------------------------------------------------- modules
# The first build needs the module set: a download over the network, or a
# warm module cache. Fetched here so a network problem is its own row,
# not a wall of compiler output.
if ! out="$(go mod download 2>&1)"; then
  printf '%s\n' "$out" | tail -5
  die "modules" "go mod download failed" "the build needs the modules go.sum lists: check the network and HTTPS_PROXY / GOPROXY, or reuse a warm module cache (GOMODCACHE)" 1
fi
row ✓ "modules" "$(go list -m all 2>/dev/null | wc -l | tr -d ' ') modules present"

# ---------------------------------------------------------------- build
if [ "$MODE" = quick ]; then
  mkdir -p "$OUT/quick"
  CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o "$OUT/quick/podaro" ./cmd/podaro
  cp install.sh install.test.yaml podaroctl "$OUT/quick/"
  row ✓ "quick build" "$OUT/quick/podaro · $("$OUT/quick/podaro" version) · unverified (no double build, no SHA256SUMS)"
  say
  nxt "sudo mkdir -p $INSTALL_DIR && sudo cp $OUT/quick/podaro $OUT/quick/install.sh $OUT/quick/install.test.yaml $OUT/quick/podaroctl $INSTALL_DIR/ && cd $INSTALL_DIR && chmod +x install.sh && sudo ./install.sh"
  exit 0
fi

say
say "building the release with hack/release_package.sh (each artifact built twice and compared)"
PODARO_RELEASE_ARCHES="${PODARO_RELEASE_ARCHES:-$ARCH}" hack/release_package.sh "$VERSION" "$OUT"
DIR="$OUT/download/v$VERSION"
TARBALL="$DIR/podaro_v${VERSION}_linux_${ARCH}.tar.gz"
[ -f "$TARBALL" ] && [ -f "$DIR/SHA256SUMS" ] || die "build" "the packager did not leave $TARBALL and SHA256SUMS behind" "read its output above" 1
say
row ✓ "release" "$TARBALL · $DIR/SHA256SUMS"

if [ "$DO_INSTALL" = 1 ]; then
  [ "$(id -u)" -ne 0 ] || die "install" "run build.sh as yourself, not root: it builds as you and asks sudo for the install alone" "" 2
  say; say "installing: the package into $INSTALL_DIR, then install.sh as root (its prompts are yours to answer)"
  sudo mkdir -p "$INSTALL_DIR"
  sudo tar -xzf "$TARBALL" -C "$INSTALL_DIR"
  sudo install -m 0644 "$DIR/SHA256SUMS" "$INSTALL_DIR/SHA256SUMS"
  cd "$INSTALL_DIR" && sudo chmod +x install.sh && exec sudo ./install.sh
fi

say
nxt "sudo mkdir -p $INSTALL_DIR && sudo tar -xzf $TARBALL -C $INSTALL_DIR && sudo cp $DIR/SHA256SUMS $INSTALL_DIR/"
nxt "cd $INSTALL_DIR && chmod +x install.sh && sudo ./install.sh"
nxt "or, in one go:  ./build.sh --install"
