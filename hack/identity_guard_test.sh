#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# hack/identity_guard.py, tested the way it must fail (the reconciliation
# plan's R6; CI's `identity` job runs it after the guard). The tree — its
# tracked files and any new ones not yet committed — is copied into a
# throwaway git repository, and each probe below changes one thing and
# asserts the guard's verdict, in three parts:
#
#   1. the ledger's form, where the residual-identity ledger is in the tree:
#      the former organization's name written into a footer, a CLI output,
#      the rendered console, the binary or a compendium line that mirrors
#      nothing; a blanket row — a whole file, a directory or a glob without a
#      literal, or a literal that is barely a detector; a row moved off its
#      occurrence; a review-only row that gains one; a narrowed detectors
#      line; a row with no blocks-publication value; the detector hashes
#      stale or missing — each must fail, and the tree as it is, and a
#      history line with its own row, must pass. The name these probes plant
#      is read from the ledger's Detectors line at run time, so this file
#      spells none. Where the ledger does not travel (the published snapshot)
#      this part does not apply, and says so.
#   2. the destination's form (the plan's D-R17), always: on a copy without
#      the ledger whose hack/identity_detectors.txt holds the hashes of a
#      made-up detector, hashed here at run time — never a real spelling —
#      the detector in a footer, inside a word, in NOTICE's first-party part,
#      a CLI output, the rendered console, the binary or a tarball entry, a
#      malformed or empty hash file, and neither the ledger nor the hashes,
#      each must fail; the tree as it is, and the detector inside a
#      third-party credit (listed, never failing), must pass.
#   3. the snapshot mode, on synthetic archives and destinations: a clean one
#      passes, and a first-party leak, detectors kept inside the snapshot or
#      a second identity in the destination's commits fail. Its detectors
#      are made-up words.
#
# Given neither the ledger nor the hashes, the script fails at once: the
# guard would have nothing to search for, and it never skips. A probe whose
# edit changes nothing — the row, line or artifact it edits having moved or
# gone — fails as such, so no probe passes for a reason it did not test:
# update it to the tree as it stands, never drop it.
#
#   hack/identity_guard_test.sh     exit 0 only when every probe comes out as stated
# shellcheck disable=SC2016  # the backticks below are the ledger's own, written literally
set -euo pipefail
cd "$(dirname "$0")/.."

ledger=docs/reconciliation/RESIDUAL_IDENTITY_LEDGER.md
hashes=hack/identity_detectors.txt
if [ ! -f "$ledger" ] && [ ! -f "$hashes" ]; then
  echo "✗ neither $ledger nor $hashes is in this tree: the identity guard has no detectors, and its probes fail rather than skip"
  exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
GOMODCACHE="$(go env GOMODCACHE)" GOCACHE="$(go env GOCACHE)" GOPATH="$(go env GOPATH)"
export GOMODCACHE GOCACHE GOPATH
export PYTHONDONTWRITEBYTECODE=1
unset PODARO_IDENTITY_DETECTORS

# What the guard judges besides the tree, made once from this tree: a binary,
# the tarball's entries, two of the CLI's outputs and a walk's dumps.
go build -trimpath -ldflags='-s -w -buildid=' -o "$tmp/podaro" ./cmd/podaro
mkdir -p "$tmp/tarball" "$tmp/cli" "$tmp/walk"
cp "$tmp/podaro" "$tmp/tarball/podaro"
cp install.sh install.test.yaml podaroctl LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md SOURCE-AND-BUILD.md "$tmp/tarball/"
{ echo '$ podaro --help'; "$tmp/podaro" --help; } >"$tmp/cli/001.txt"
{ echo '$ podaro legal'; "$tmp/podaro" legal; } >"$tmp/cli/002.txt"
printf '==> https://lab.test/login <==\ntitle: Sign in\naddress: https://lab.test/login\nSign in to Podaro\n' >"$tmp/walk/page-text.txt"
printf '<html><body><footer><a href="/legal">Licence and source</a></footer></body></html>\n' >"$tmp/walk/01-signed-in.html"

src="$PWD"
copy_tree() {  # copy_tree <dir>: this tree, tracked and new files, as a throwaway repository with one commit
  mkdir -p "$1"
  (cd "$src" && git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -t "$1" 2>/dev/null) || true
  (cd "$1" && git init -q && git add -A && git -c user.name=probe -c user.email=probe@example.invalid commit -q -m base)
}
line_of() { grep -n -F "$2" "$1" | tail -1 | cut -d: -f1; }

failures=0
stale=0
probe() {  # probe <must: pass|fail> <label> <mutation function> [the finding the failure must name]
  local must="$1" label="$2" mutate="$3" want="${4:-}" out got
  BIN="$tmp/podaro"; TAR="$tmp/tarball"; CLI="$tmp/cli"; WALK="$tmp/walk"
  "$mutate"
  git add -A
  if [ "$mutate" != nothing ] && ! edited; then
    echo "✗ $label: the probe's edit changed nothing — what it edits has moved or gone; update the probe"
    stale=$((stale + 1))
  else
    if out="$(python3 hack/identity_guard.py --binary "$BIN" --tarball-dir "$TAR" --cli-dir "$CLI" --walk-dir "$WALK" 2>&1)"; then got=pass; else got=fail; fi
    verdict "$must" "$label" "$want" "$got" "$out"
  fi
  git reset -q --hard HEAD
  git clean -qfd
}
edited() {  # did the edit change the tree, or put an artifact in place that differs from the original?
  ! git diff --cached --quiet && return 0
  if [ "$BIN" != "$tmp/podaro" ] && ! cmp -s "$BIN" "$tmp/podaro"; then return 0; fi
  if [ "$TAR" != "$tmp/tarball" ] && ! diff -rq "$TAR" "$tmp/tarball" >/dev/null 2>&1; then return 0; fi
  if [ "$CLI" != "$tmp/cli" ] && ! diff -rq "$CLI" "$tmp/cli" >/dev/null 2>&1; then return 0; fi
  if [ "$WALK" != "$tmp/walk" ] && ! diff -rq "$WALK" "$tmp/walk" >/dev/null 2>&1; then return 0; fi
  return 1
}
verdict() {
  local must="$1" label="$2" want="$3" got="$4" out="$5"
  if [ "$got" = "$must" ] && { [ -z "$want" ] || printf '%s\n' "$out" | grep -q -F -- "$want"; }; then
    echo "✓ $label: $got (must $must)"
  else
    echo "✗ $label: $got (must $must${want:+, naming \"$want\"})"
    failures=$((failures + 1))
  fi
  printf '%s\n' "$out" | grep '^✗' | head -2 | cut -c1-220 | sed 's/^/      /' || true
}
nothing() { :; }

# --- 1. the ledger's form ------------------------------------------------------
if [ -f "$ledger" ]; then
  copy_tree "$tmp/tree"
  cd "$tmp/tree"
  org="$(sed -n 's/^\*\*Detectors\*\*.*): `\([^`]*\)`.*/\1/p' "$ledger")"
  [ -n "$org" ] || { echo "✗ the ledger's Detectors line gave the probes no name"; exit 1; }
  harness_lines="$(sed -n 's/^| 10 | `hack\/reconciliation_check\.py:\([0-9,]*\)`.*/\1/p' "$ledger")"
  [ -n "$harness_lines" ] || { echo "✗ the ledger's row 10 gave the probes no lines"; exit 1; }
  notice_line="$(sed -n 's/^| 12 | .*`NOTICE:\([0-9]*\)[,`].*/\1/p' "$ledger")"
  [ -n "$notice_line" ] || { echo "✗ the ledger's row 12 gave the probes no NOTICE line"; exit 1; }
  addrow() { sed -i "/^| 13 | /a $1" "$ledger"; }

  footer()         { printf '\n— a %s project\n' "$org" >> public-docs/concepts.md; }
  history_row()    { printf '\nThe project was once called %s here.\n' "$org" >> public-docs/concepts.md
                     addrow "| 14 | \`public-docs/concepts.md:$(line_of public-docs/concepts.md "$org")\` | a probe's history line | history | a probe | no | — |"; }
  blanket_notice() { printf '\n%s\n' "$org" >> NOTICE; addrow '| 14 | `NOTICE` | the whole file | history | a probe | no | — |'; }
  blanket_dir()    { printf '\n%s\n' "$org" >> public-docs/concepts.md; addrow '| 14 | `docs/` | the whole directory | history | a probe | no | — |'; }
  blanket_glob()   { printf '\n%s\n' "$org" >> public-docs/concepts.md; addrow '| 14 | `**/*.md` | every document | history | a probe | no | — |'; }
  bare_literal()   { sed -i "/^| 4 | /s#\`https://github.com/[^\`]*\`#\`$org\`#" "$ledger"; }
  moved_row()      { sed -i "s|hack/reconciliation_check.py:$harness_lines|hack/reconciliation_check.py:1,$harness_lines|" "$ledger"; }
  review_only()    { sed -i "${notice_line}s/\$/ ($org)/" NOTICE; }
  narrowed()       { sed -i "s/^\(\*\*Detectors\*\*.*): \)\`[^\`]*\` · /\1/" "$ledger"; }
  no_blocks()      { sed -i 's/^| 9 | \(.*\) | no — the snapshot (D-R14) carries the curated set the owner chooses | R8 (curation list) |$/| 9 | \1 |  | R8 (curation list) |/' "$ledger"; }
  hashes_stale()   { sed -i '$d' "$hashes"; }
  hashes_missing() { rm "$hashes"; }
  in_cli()         { cp -R "$tmp/cli" "$tmp/cli2"; printf '$ podaro version\npodaro, by %s\n' "$org" > "$tmp/cli2/003.txt"; CLI="$tmp/cli2"; }
  in_walk()        { cp -R "$tmp/walk" "$tmp/walk2"; printf '\nA %s project\n' "$org" >> "$tmp/walk2/page-text.txt"; WALK="$tmp/walk2"; }
  in_binary()      { { cat "$tmp/podaro"; printf '\0Published by %s\0' "$org"; } > "$tmp/podaro2"; BIN="$tmp/podaro2"; TAR="$tmp/tarball"; }
  unmirrored()     { printf '%s\n' "$org" >> docs/PODARO_COMPENDIUM.md; }

  probe pass "the tree as it is"                                              nothing
  probe fail "a footer naming the former organization"                        footer         "public-docs/concepts.md"
  probe pass "a history line with its own row"                                history_row
  probe fail "a whole NOTICE without a literal"                               blanket_notice "a whole file without a literal is a blanket exclusion"
  probe fail "a directory outside the evidence"                               blanket_dir    "a directory outside the reconciliation's evidence"
  probe fail "a glob without a literal"                                       blanket_glob   "a glob allows only through a literal"
  probe fail "a literal that is barely a detector"                            bare_literal   "is little more than a detector"
  probe fail "a row naming a line that holds no occurrence"                   moved_row      "hack/reconciliation_check.py:1\` holds no detector"
  probe fail "a review-only row whose line gains the name"                    review_only    "says no former-organization occurrence"
  probe fail "the Detectors line narrowed"                                    narrowed       "lacks a spelling the reconciliation §5.6.3 names"
  probe fail "a row with no blocks-publication value"                         no_blocks      "says neither yes nor no"
  probe fail "the detector hashes, one line short of the ledger's detectors"  hashes_stale   "is not the ledger's **Detectors** line, hashed"
  probe fail "the detector hashes missing"                                    hashes_missing "hack/identity_detectors.txt is missing"
  probe fail "the name in the CLI's output"                                   in_cli         "podaro version"
  probe fail "the name in the rendered console"                               in_walk        "page-text.txt"
  probe fail "the name added to the binary's strings"                         in_binary      "Published by"
  probe fail "a compendium line that mirrors nothing"                         unmirrored     "docs/PODARO_COMPENDIUM.md"
  cd "$src"
else
  echo "○ the ledger's form: not in this tree — $ledger does not travel with the published snapshot; the destination's form below is what its identity job runs"
fi

# --- 2. the destination's form ------------------------------------------------------
# A made-up detector, hashed by the guard's own function: the tree carries its hashes and never its spelling. It is
# composed at run time, because the copy the probes judge holds this file too.
word="quokka""soft"
test_org="${word^} Labs"
copy_tree "$tmp/dest"
cd "$tmp/dest"
rm -f "$ledger"
{ echo "# a probe's detector hashes: a made-up name, hashed at run time"
  python3 -c 'import sys; sys.path.insert(0, "hack"); import identity_guard as g; [print(g.hash_line(d)) for d in sys.argv[1:]]' \
    "$test_org" "$word"; } > "$hashes"
git add -A
git -c user.name=probe -c user.email=probe@example.invalid commit -q -m "the destination's form, with a made-up detector"

d_footer()       { printf '\n— a %s project\n' "${test_org^^}" >> public-docs/concepts.md; }
d_in_word()      { printf '\nsee xx%sxx for details\n' "$word" >> public-docs/concepts.md; }
d_credit()       { printf '\nThanks to %s for the fonts.\n' "${word^}" >> THIRD-PARTY-NOTICES.md; }
d_notice_first() { sed -i "1s/\$/ — a ${word^} project/" NOTICE; }
d_in_cli()       { cp -R "$tmp/cli" "$tmp/cli3"; printf '$ podaro version\npodaro, by %s\n' "$test_org" > "$tmp/cli3/003.txt"; CLI="$tmp/cli3"; }
d_in_walk()      { cp -R "$tmp/walk" "$tmp/walk3"; printf '\nA %s project\n' "$test_org" >> "$tmp/walk3/page-text.txt"; WALK="$tmp/walk3"; }
d_in_binary()    { { cat "$tmp/podaro"; printf '\0Published by %s\0' "$test_org"; } > "$tmp/podaro3"; BIN="$tmp/podaro3"; }
d_in_tarball()   { cp -R "$tmp/tarball" "$tmp/tarball3"; printf '# by %s\n' "$test_org" >> "$tmp/tarball3/install.test.yaml"; TAR="$tmp/tarball3"; }
d_malformed()    { printf 'not a hash\n' >> "$hashes"; }
d_empty()        { sed -i '/^[0-3]* [0-9a-f]\{64\}$/d' "$hashes"; }
d_neither()      { rm "$hashes"; }

probe pass "destination: the tree as it is, a made-up detector's hashes, no ledger"   nothing
probe fail "destination: the detector in a footer, in capitals"                        d_footer       "public-docs/concepts.md"
probe fail "destination: the detector inside a word"                                   d_in_word      "xx${word}xx"
probe pass "destination: the detector in a third-party credit (listed, never failing)" d_credit
probe fail "destination: the detector in NOTICE's first-party part"                    d_notice_first "NOTICE:1"
probe fail "destination: the detector in the CLI's output"                             d_in_cli       "podaro version"
probe fail "destination: the detector in the rendered console"                         d_in_walk      "page-text.txt"
probe fail "destination: the detector in the binary"                                   d_in_binary    "Published by"
probe fail "destination: the detector in a tarball entry"                              d_in_tarball   "install.test.yaml"
probe fail "destination: a malformed hash line"                                        d_malformed    "not \`<fold> <sha256>\`"
probe fail "destination: a hash file with no detector"                                 d_empty        "holds no detector"
probe fail "destination: neither the ledger nor the hashes (never a skip)"             d_neither      "neither"
cd "$src"

# --- 3. the snapshot mode: synthetic archives and destinations, made-up detectors ------------
printf 'zebracorp\nold-handle-zz\n' >"$tmp/detectors.txt"
archive() {  # archive <dir>: a clean first-party page and a third-party notices file
  mkdir -p "$1/docs"
  printf 'a first-party page\n' >"$1/docs/page.md"
  printf 'Third-party notices: Example Holder\n' >"$1/THIRD-PARTY-NOTICES.md"
}
destination() {  # destination <dir>: one commit, the owner's, signed off
  git init -q "$1"
  printf 'Podaro\n' >"$1/README.md"
  git -C "$1" add -A
  git -C "$1" -c "user.name=Jeremiah Ross" -c "user.email=dev@podaro.dev" commit -q -m "Podaro" \
    -m "Signed-off-by: Jeremiah Ross <dev@podaro.dev>"
}
snapshot() {  # snapshot <must> <label> <the finding a failure must name, or ""> -- <the guard's arguments>
  local must="$1" label="$2" want="$3" out got
  shift 4
  if out="$(python3 hack/identity_guard.py --snapshot "$@" 2>&1)"; then got=pass; else got=fail; fi
  verdict "$must" "$label" "$want" "$got" "$out"
}
archive "$tmp/s1"; destination "$tmp/d1"
snapshot pass "snapshot: a clean archive, a one-identity destination" "" -- "$tmp/s1" --destination "$tmp/d1" --detectors "$tmp/detectors.txt"
archive "$tmp/s2"; printf 'Thanks to old-handle-zz\n' >>"$tmp/s2/THIRD-PARTY-NOTICES.md"
snapshot pass "snapshot: a detector inside a third-party credit (listed, never failing)" "" -- "$tmp/s2" --detectors "$tmp/detectors.txt"
archive "$tmp/s3"; printf 'published by ZebraCorp\n' >>"$tmp/s3/docs/page.md"
snapshot fail "snapshot: a detector in a first-party file" "docs/page.md:2" -- "$tmp/s3" --detectors "$tmp/detectors.txt"
archive "$tmp/s4"; cp "$tmp/detectors.txt" "$tmp/s4/detectors.txt"
snapshot fail "snapshot: the detectors kept inside the snapshot" "is inside the snapshot" -- "$tmp/s4" --detectors "$tmp/s4/detectors.txt"
archive "$tmp/s5"
snapshot fail "snapshot: no detectors given" "no detectors" -- "$tmp/s5"
archive "$tmp/s6"; destination "$tmp/d6"
printf 'x\n' >"$tmp/d6/x"
git -C "$tmp/d6" add x
git -C "$tmp/d6" -c user.name=Someone -c user.email=someone@example.org commit -q -m "a change" -m "Signed-off-by: Someone <someone@example.org>"
snapshot fail "snapshot: a second identity in the destination's commits" "author Someone <someone@example.org>" -- "$tmp/s6" --destination "$tmp/d6" --detectors "$tmp/detectors.txt"

if [ "$stale" -gt 0 ]; then
  echo "FAIL $stale probe(s) whose edit changed nothing: the probe, not the guard, needs updating to the tree as it stands"
fi
if [ "$failures" -gt 0 ]; then
  echo "FAIL $failures probe(s) did not come out as stated: the identity guard is broken"
fi
[ "$stale" -eq 0 ] && [ "$failures" -eq 0 ] || exit 1
echo "all probes came out as stated: the identity guard fails where it must"
