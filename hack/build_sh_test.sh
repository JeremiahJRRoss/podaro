#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# build.sh (INSTALL §5, "From source"), checked where a CI runner can:
#
#   1. shellcheck and bash -n;
#   2. --check reports the tools and builds nothing;
#   3. in a copy of the tree without .git — a GitHub zip — --quick builds
#      a binary that prints its version, and the full build packages the
#      release for this architecture through hack/release_package.sh,
#      leaving the tarball and SHA256SUMS the install commands name;
#   4. the refusals: not a source tree; a dirty git tree refused for the
#      packaged build and allowed for --quick.
#
# What this does NOT do is install Go (--yes) or run --install: both need
# root on a host, which is the VM of docs/reviews/0003.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { echo "FAIL $*"; exit 1; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# 1. static checks
bash -n build.sh || fail "build.sh does not parse"
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -S warning build.sh hack/build_sh_test.sh || fail "shellcheck"
  echo "✓ shellcheck          build.sh · no warnings"
else
  echo "○ shellcheck          not installed here · skipped"
fi

# 2. --check builds nothing
./build.sh --check >"$tmp/check.out" 2>&1 || { cat "$tmp/check.out"; fail "--check"; }
grep -q "^✓ go " "$tmp/check.out" || { cat "$tmp/check.out"; fail "--check reports go"; }
grep -q "nothing built" "$tmp/check.out" || fail "--check says it built nothing"
[ ! -e dist/quick ] || fail "--check must not build"
echo "✓ --check             reports the tools and builds nothing"

# 3. a tree without .git, as a GitHub zip unpacks it
mkdir -p "$tmp/zip"
git archive HEAD | tar -x -C "$tmp/zip"
( cd "$tmp/zip" && PODARO_BUILD_OUT="$tmp/out" ./build.sh --quick >"$tmp/quick.out" 2>&1 ) || { cat "$tmp/quick.out"; fail "--quick in a zip"; }
grep -q "^○ git " "$tmp/quick.out" || fail "the zip case is named"
[ -x "$tmp/out/quick/podaro" ] || fail "--quick left no binary"
[ "$("$tmp/out/quick/podaro" version)" = "podaro v$(tr -d '[:space:]' <VERSION)" ] || fail "the quick binary prints its version"
echo "✓ --quick             a zip builds a binary that prints its version"

arch="$(go env GOHOSTARCH)"
( cd "$tmp/zip" && PODARO_BUILD_OUT="$tmp/out" PODARO_RELEASE_ARCHES="$arch" ./build.sh >"$tmp/build.out" 2>&1 ) || { tail -20 "$tmp/build.out"; fail "the packaged build in a zip"; }
v="$(tr -d '[:space:]' <VERSION)"
[ -f "$tmp/out/download/v$v/podaro_v${v}_linux_${arch}.tar.gz" ] || fail "no tarball"
[ -f "$tmp/out/download/v$v/SHA256SUMS" ] || fail "no SHA256SUMS"
grep -q "^✓ release " "$tmp/build.out" || fail "the release row"
grep -q "^→ next: sudo mkdir -p /opt/podaro" "$tmp/build.out" || fail "the install commands are printed"
( cd "$tmp/out/download/v$v" && sha256sum -c --quiet SHA256SUMS ) || fail "SHA256SUMS does not verify"
echo "✓ build               a zip packages the release: tarball, SHA256SUMS, the install commands"

# 4. refusals
mkdir -p "$tmp/notatree"; cp build.sh "$tmp/notatree/"
if ( cd "$tmp/notatree" && ./build.sh --check >"$tmp/r1.out" 2>&1 ); then fail "a directory that is not a source tree was accepted"; fi
grep -q "not a Podaro source tree" "$tmp/r1.out" || fail "the refusal names the tree"
if git rev-parse --git-dir >/dev/null 2>&1; then
  git -C "$tmp" init -q "$tmp/dirty" && git archive HEAD | tar -x -C "$tmp/dirty"
  ( cd "$tmp/dirty" && git add -A >/dev/null && git -c user.name=t -c user.email=t@t commit -qm x && echo x >untracked.txt )
  if ( cd "$tmp/dirty" && PODARO_BUILD_OUT="$tmp/out2" ./build.sh >"$tmp/r2.out" 2>&1 ); then fail "a dirty tree was packaged"; fi
  grep -q "refuses a dirty tree" "$tmp/r2.out" || { cat "$tmp/r2.out"; fail "the dirty refusal names itself"; }
  ( cd "$tmp/dirty" && PODARO_BUILD_OUT="$tmp/out2" ./build.sh --quick >"$tmp/r3.out" 2>&1 ) || { cat "$tmp/r3.out"; fail "--quick must build a dirty tree"; }
  echo "✓ refusal             not a source tree, and a dirty tree for the packaged build; --quick still builds it"
fi

echo "all build.sh checks passed (Go installation and --install are the VM's, docs/reviews/0003)"
