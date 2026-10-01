#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# hack/link_check.py, tested the way it must fail (the reconciliation plan's
# R7; CI's `schemas` job runs it after the check). The tree — its tracked
# files and any new ones not yet committed — is copied into a throwaway git
# repository, and each probe below changes one thing and asserts the check's
# verdict: a relative link to nothing, to a heading that does not exist or out
# of the repository; an absolute link with no host, with a credential, to a
# scheme no reader can follow, or a mailto: with no address; the
# destination's URL spelled in another letter case, over http, or at a place
# GitHub does not serve; a module path spelled as the URL is; go.mod no
# longer following SOURCE — each must fail. The tree as it is must pass, and so must a link to a real
# heading, the destination's releases spelled as SOURCE spells them, a URL
# that ends a sentence, a broken link inside code, which is not a link, and a
# misspelled coordinate quoted in the reconciliation's evidence, which quotes
# what the checks found.
# The coordinates the probes plant are read from SOURCE and go.mod at run
# time. A probe whose edit changes nothing — the file or line it edits having
# moved or gone — fails as such: update it, never drop it.
#
#   hack/link_check_test.sh     exit 0 only when every probe comes out as stated
# shellcheck disable=SC2016  # the backticks below are Markdown's own, written literally
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export PYTHONDONTWRITEBYTECODE=1
git ls-files -z --cached --others --exclude-standard | xargs -0 cp --parents -t "$tmp" 2>/dev/null || true
cd "$tmp"
git init -q
git add -A
git -c user.name=probe -c user.email=probe@example.invalid commit -q -m base

source_url="$(tr -d '[:space:]' <SOURCE)"                 # https://github.com/<Owner>/<name>
repo="${source_url#https://github.com/}"                  # <Owner>/<name>
lower="$(printf '%s' "$repo" | tr '[:upper:]' '[:lower:]')"
if [ -z "$repo" ] || [ "$repo" = "$source_url" ]; then echo "✗ SOURCE gave the probes no GitHub repository"; exit 1; fi
if [ "$lower" = "$repo" ]; then echo "✗ SOURCE's owner is all lower case: the casing probe needs a letter to change"; exit 1; fi

failures=0
stale=0
probe() {  # probe <must: pass|fail> <label> <mutation function> [the finding a failure must name]
  local must="$1" label="$2" mutate="$3" want="${4:-}" out got
  "$mutate"
  git add -A
  if [ "$mutate" != nothing ] && git diff --cached --quiet; then
    echo "✗ $label: the probe's edit changed nothing — what it edits has moved or gone; update the probe"
    stale=$((stale + 1))
  else
    if out="$(python3 hack/link_check.py 2>&1)"; then got=pass; else got=fail; fi
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
page=public-docs/concepts.md   # a guide beside INSTALL.md
add() { printf '\n%s\n' "$1" >> "$page"; }

nothing()          { :; }
to_nothing()       { add '[a page](no-such-page.md)'; }
no_heading()       { add '[upgrading](INSTALL.md#no-such-heading)'; }
real_heading()     { add '[upgrading](INSTALL.md#6-upgrading)'; }
out_of_tree()      { add '[outside](../../outside.md)'; }
no_host()          { add '[nowhere](https:///releases)'; }
credential()       { add '[a mirror](https://someone@mirror.example.com/releases)'; }
file_scheme()      { add '[notes](file:///tmp/notes.txt)'; }
empty_mailto()     { add '[write](mailto:)'; }
in_code()          { printf '\n```\n[a page](no-such-page.md)\n```\n\nand `[a page](no-such-page.md)` in a span\n' >> "$page"; }
releases()         { add "The releases: \`$source_url/releases/tag/v0.1.0\`."; }
sentence_end()     { add "The source is at $source_url."; }
other_case()       { add "The releases: \`https://github.com/$lower/releases\`."; }
case_at_end()      { add "The source is at https://github.com/$lower."; }
repo_root()        { add '[the repository root](../)'; }
over_http()        { add "The source: \`http://github.com/$repo\`."; }
no_place()         { add "The releases: \`$source_url/relases\`."; }
module_as_url()    { add "The module path: \`github.com/$repo\`."; }
go_mod_elsewhere() { sed -i '1s#^module .*#module github.com/someone-else/elsewhere#' go.mod; }
in_evidence()      { mkdir -p docs/reconciliation/evidence  # the published snapshot carries no evidence: the probe makes the place
                     printf '%s\n' "the probe planted https://github.com/$lower/releases" >> docs/reconciliation/evidence/A17-coordinates.txt; }

probe pass "the tree as it is (the control)"                               nothing
probe fail "a relative link to no file"                                    to_nothing       "no tracked file or directory public-docs/no-such-page.md"
probe fail "a relative link to a heading that does not exist"              no_heading       "has no heading or anchor #no-such-heading"
probe pass "a relative link to a real heading (GitHub's anchor)"           real_heading
probe pass "a relative link to the repository's root"                      repo_root
probe fail "a relative link out of the repository"                         out_of_tree      "leaves the repository"
probe fail "an absolute link with no host"                                 no_host          "no host"
probe fail "an absolute link carrying a credential"                        credential       "a credential in a link"
probe fail "a file: link"                                                  file_scheme      "file: is not a link"
probe fail "a mailto: link with no address"                                empty_mailto     "names one address"
probe pass "a broken link inside code, which is not a link"                in_code
probe pass "the destination's releases, spelled as SOURCE spells them"     releases
probe pass "the destination's URL ending a sentence"                       sentence_end
probe fail "the destination's URL in another letter case"                  other_case       "spelled otherwise than SOURCE"
probe fail "the same, ending a sentence"                                   case_at_end      "spelled otherwise than SOURCE"
probe fail "the destination's URL over http"                               over_http        "the destination is https"
probe fail "the destination's URL at a place GitHub does not serve"        no_place         "is no place GitHub serves"
probe fail "a module path spelled as the URL is"                           module_as_url    "a module path is spelled as go.mod's"
probe fail "go.mod's module no longer following SOURCE"                    go_mod_elsewhere "does not follow SOURCE"
probe pass "a misspelled coordinate quoted in the reconciliation's evidence" in_evidence

if [ "$stale" -gt 0 ]; then
  echo "FAIL $stale probe(s) whose edit changed nothing: the probe, not the check, needs updating to the tree as it stands"
fi
if [ "$failures" -gt 0 ]; then
  echo "FAIL $failures probe(s) did not come out as stated: the link check is broken"
fi
[ "$stale" -eq 0 ] && [ "$failures" -eq 0 ] || exit 1
echo "all probes came out as stated: the link check fails where it must"
