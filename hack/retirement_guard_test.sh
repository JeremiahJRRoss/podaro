#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# hack/retirement_guard.py, tested the way it must fail (the reconciliation
# plan's R6; CI's `retirement` job runs it after the guard). The tree — its
# tracked files and any new ones not yet committed — is copied into a
# throwaway git repository, and each probe below changes one thing and
# asserts the guard's verdict: a retired module re-added, a retired name in
# the catalog, a session prompt or a registry, a maintained surface covered
# by a row, a stale row, a malformed row, a real digest in a negative
# fixture, a retired digest outside the manifest, a retired name in the
# tarball or the binary, an embedded
# listing the directives do not give, a failing TestEmbedded — each must
# fail; the tree as it is, and a history note with its own row, must pass.
# The retired names the probes plant are read from hack/retirement.json at
# run time, so this file spells none. The probes call the guard's judging
# half with --no-self-test: the self-test proves check 5, and the CI job's
# guard run has already run it. A probe whose edit changes nothing — the
# row, line or artifact it edits having moved or gone — fails as such, so
# no probe passes for a reason it did not test: update it to the tree as it
# stands, never drop it.
#
#   hack/retirement_guard_test.sh     exit 0 only when every probe comes out as stated
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export GOMODCACHE GOCACHE GOPATH
export PYTHONDONTWRITEBYTECODE=1

# What the guard judges besides the tree, made once from this tree: a binary,
# TestEmbedded's listing, and the tarball's entries (the binary beside the
# release's other files, as hack/release_package.sh packs them).
go build -trimpath -ldflags='-s -w -buildid=' -o "$tmp/podaro" ./cmd/podaro
go test -count=1 -run '^TestEmbedded$' -v . >"$tmp/embedded.log" 2>&1 || { cat "$tmp/embedded.log"; exit 1; }
mkdir -p "$tmp/tarball"
cp "$tmp/podaro" "$tmp/tarball/podaro"
cp install.sh install.test.yaml podaroctl LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md SOURCE-AND-BUILD.md "$tmp/tarball/"
cp -R LICENSES "$tmp/tarball/LICENSES"

tree="$tmp/tree"
mkdir -p "$tree"
git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -t "$tree" 2>/dev/null || true
cd "$tree"
git init -q
git add -A
git -c user.name=probe -c user.email=probe@example.invalid commit -q -m base

manifest() { python3 -c "import json; m = json.load(open('hack/retirement.json')); print($1)"; }
module="$(manifest 'm["modules"][0]["name"]')"
adapter="$(manifest 'm["adapters"]["product"][0]')"
generator="$(manifest 'm["generators"][0]')"
scenario="$(manifest 'm["scenarios"][0]["name"]')"
digest="$(manifest 'm["modules"][0]["image"]["digest"]')"
kept="$(sed -n 's/.*\(sha256:[0-9a-f]\{64\}\).*/\1/p' modules/prometheus/module.yaml | head -1)"
[ -n "$module" ] && [ -n "$adapter" ] && [ -n "$digest" ] && [ -n "$kept" ] || { echo "✗ the manifest or the prometheus module did not give the probes their names"; exit 1; }
row() { printf '%s\t%s\t%s\n' "$1" "$2" "a probe's row" >> hack/retirement_allow.txt; }
line_of() { grep -n -F "$2" "$1" | tail -1 | cut -d: -f1; }

failures=0
stale=0
BIN="$tmp/podaro"
TAR="$tmp/tarball"
LOG="$tmp/embedded.log"
probe() {  # probe <must: pass|fail> <label> <mutation function> [the finding the failure must name]
  local must="$1" label="$2" mutate="$3" want="${4:-}" out got
  BIN="$tmp/podaro"; TAR="$tmp/tarball"; LOG="$tmp/embedded.log"
  "$mutate"
  git add -A
  if [ "$mutate" != nothing ] && ! edited; then
    echo "✗ $label: the probe's edit changed nothing — what it edits has moved or gone; update the probe"
    stale=$((stale + 1))
  else
    if out="$(python3 hack/retirement_guard.py --embedded-log "$LOG" --binary "$BIN" --tarball-dir "$TAR" --no-self-test 2>&1)"; then got=pass; else got=fail; fi
    if [ "$got" = "$must" ] && { [ -z "$want" ] || printf '%s\n' "$out" | grep -q -F -- "$want"; }; then
      echo "✓ $label: $got (must $must)"
    else
      echo "✗ $label: $got (must $must${want:+, naming \"$want\"})"
      failures=$((failures + 1))
    fi
    printf '%s\n' "$out" | grep '^✗' | head -2 | cut -c1-220 | sed 's/^/      /' || true
  fi
  git reset -q --hard HEAD
  git clean -qfd
}
edited() {  # did the edit change the tree, or put an artifact in place that differs from the original?
  ! git diff --cached --quiet && return 0
  if [ "$BIN" != "$tmp/podaro" ] && ! cmp -s "$BIN" "$tmp/podaro"; then return 0; fi
  if [ "$TAR" != "$tmp/tarball" ] && ! diff -rq "$TAR" "$tmp/tarball" >/dev/null 2>&1; then return 0; fi
  if [ "$LOG" != "$tmp/embedded.log" ] && ! cmp -s "$LOG" "$tmp/embedded.log"; then return 0; fi
  return 1
}

nothing()           { :; }
module_readded()    { mkdir -p "modules/$module"; printf 'apiVersion: lab.podaro.dev/v1alpha2\nkind: Module\nmetadata:\n  name: %s\n' "$module" > "modules/$module/module.yaml"; }
catalog_adapter()   { printf '# adapter: %s\n' "$adapter" >> scenarios/grafana-prometheus-intro/lab.yaml; }
prompt_names()      { mkdir -p docs/code-execution; printf 'Restore %s.\n' "$scenario" > docs/code-execution/probe.prompt.md; }  # a new session prompt, at the path the guard treats as a maintained surface
registry_names()    { printf '\n// %s\n' "$generator" >> internal/seed/seed.go; }
laundered()         { printf '# %s\n' "$adapter" >> install.sh; row "install.sh:$(line_of install.sh "$adapter")" evidence_and_history; }
history_row()       { printf '\nThe %s adapter was retired.\n' "$adapter" >> public-docs/concepts.md; row "public-docs/concepts.md:$(line_of public-docs/concepts.md "$adapter")" evidence_and_history; }
history_unrowed()   { printf '\nThe %s adapter was retired.\n' "$adapter" >> public-docs/concepts.md; }
stale_line()        { sed -i 's/^internal\/observe\/sinks\.go:/internal\/observe\/sinks.go:1,/' hack/retirement_allow.txt; }
stale_file()        { row public-docs/ARCHITECTURE.md evidence_and_history; }  # a page that holds no retired term
whole_narrative()   { sed -i 's/^internal\/console\/s7_test\.go:[0-9,]*\t/internal\/console\/s7_test.go\t/' hack/retirement_allow.txt; }
bad_category()      { sed -i 's/^hack\/retirement_allow\.txt\tharness\t/hack\/retirement_allow.txt\tmisc\t/' hack/retirement_allow.txt; }
fixture_digest()    { sed -i "s/sha256:0\{64\}/$kept/" "hack/fixtures/retired-catalog/$scenario/lab.yaml"; }
loose_digest()      { printf '\nimage: %s\n' "$digest" >> public-docs/concepts.md; row "public-docs/concepts.md:$(line_of public-docs/concepts.md "$digest")" evidence_and_history; }
tarball_entry()     { cp -R "$tmp/tarball" "$tmp/tarball2"; printf '%s\n' "$module" >> "$tmp/tarball2/NOTICE"; TAR="$tmp/tarball2"; }
binary_appended()   { { cat "$tmp/podaro"; printf '\0adapter: %s\0' "$adapter"; } > "$tmp/podaro2"; BIN="$tmp/podaro2"; }
listing_extra()     { { cat "$tmp/embedded.log"; printf '    embed_test.go:137: modules/%s/module.yaml\n' "$module"; } > "$tmp/embedded2.log"; LOG="$tmp/embedded2.log"; }
embedded_failed()   { sed 's/^--- PASS: TestEmbedded/--- FAIL: TestEmbedded/' "$tmp/embedded.log" > "$tmp/embedded3.log"; LOG="$tmp/embedded3.log"; }

probe pass "the tree as it is"                                             nothing
probe fail "a retired module re-added"                                     module_readded   "modules/$module exists"
probe fail "a retired adapter named in the catalog template"               catalog_adapter  "(maintained surface)"
probe fail "a retired template named in a session prompt"                  prompt_names     "docs/code-execution/probe.prompt.md"
probe fail "a retired generator named in a registry"                       registry_names   "internal/seed/seed.go"
probe fail "a maintained surface covered by a row"                         laundered        "install.sh is a maintained surface"
probe pass "a history note in a document, with its row"                    history_row
probe fail "the same note without a row"                                   history_unrowed  "public-docs/concepts.md"
probe fail "a row naming a line that holds nothing"                        stale_line       "internal/observe/sinks.go:1 holds no retired term"
probe fail "a whole-file row for a file that holds nothing"                stale_file       "public-docs/ARCHITECTURE.md holds no retired term"
probe fail "a whole-file row outside the whole-file roles"                 whole_narrative  "a whole-file row only for"
probe fail "a row whose category is no manifest role"                      bad_category     "is none of the manifest's roles"
probe fail "a real digest in a negative fixture"                           fixture_digest   "a negative fixture with a real digest"
probe fail "a retired image digest outside the manifest, even with a row"  loose_digest     "a retired image digest outside the manifest"
probe fail "a retired name in a tarball entry"                             tarball_entry    "NOTICE"
probe fail "a retired adapter name added to the binary"                    binary_appended  "outside the manifest's in_a_binary allowance"
probe fail "an embedded listing the directives do not give"                listing_extra    "which no //go:embed directive here embeds"
probe fail "TestEmbedded failing"                                          embedded_failed  "TestEmbedded did not pass"

if [ "$stale" -gt 0 ]; then
  echo "FAIL $stale probe(s) whose edit changed nothing: the probe, not the guard, needs updating to the tree as it stands"
fi
if [ "$failures" -gt 0 ]; then
  echo "FAIL $failures probe(s) did not come out as stated: the retirement guard is broken"
fi
[ "$stale" -eq 0 ] && [ "$failures" -eq 0 ] || exit 1
echo "all probes came out as stated: the retirement guard fails where it must"
