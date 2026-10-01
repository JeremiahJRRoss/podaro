#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# hack/spdx_check.py, tested the way it must fail (the reconciliation plan's
# R4; CI's licenses job runs it after the check itself). The tracked tree is
# copied into a throwaway git repository, and each probe below changes one
# thing — a relabelled file, a copyright tag, a bare copyright line naming
# the owner, a missing or doubled REUSE.toml annotation, a replaced third-party
# holder, a third-party file the allowlist does not name — and asserts that
# the check fails; the tree as it is, and ADR-0004 D2's qualified statement,
# must pass. Nothing outside the temporary directory is touched.
#
#   hack/spdx_check_test.sh     exit 0 only when every probe comes out as stated
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git ls-files -z | xargs -0 cp --parents -t "$tmp"
cd "$tmp"
git init -q
git add -A
git -c user.name=probe -c user.email=probe@example.invalid commit -q -m base

failures=0
probe() {  # probe <must: pass|fail> <label> <mutation function>
  local must="$1" label="$2" mutate="$3" out got
  "$mutate"
  git add -A
  if out="$(python3 hack/spdx_check.py 2>&1)"; then got=pass; else got=fail; fi
  if [ "$got" = "$must" ]; then
    echo "✓ $label: $got (must $must)"
  else
    echo "✗ $label: $got (must $must)"
    failures=$((failures + 1))
  fi
  printf '%s\n' "$out" | grep '^✗' | head -2 | sed 's/^/      /' || true
  git reset -q --hard HEAD
  git clean -qfd
}

# The lines the probes plant are assembled here, at run time, so that this file
# carries no copyright line of its own for the check (or a REUSE parser) to read.
tag="SPDX-File""CopyrightText"
owner="Jeremiah"" Ross"
notice="Copyright © 2026 $owner"
reserved="All rights"" reserved."

nothing()             { :; }
go_apache()           { sed -i '1s/AGPL-3.0-only/Apache-2.0/' version.go; }
doc_ccby()            { sed -i '1s/AGPL-3.0-only/CC-BY-4.0/' public-docs/ARCHITECTURE.md; }
owner_tag()           { sed -i "1a // $tag: 2026 $owner" version.go; }
other_tag()           { sed -i "1a # $tag: 2026 Someone Else" install.test.yaml; }
owner_line()          { printf '\n%s\n' "$notice" >> README.md; }
owner_reserved()      { printf '\n%s. %s\n' "$notice" "$reserved" >> public-docs/ARCHITECTURE.md; }
qualified()           { printf '\n%s, to the extent copyright subsists in first-party material and such copyright is owned by %s.\n' "$notice" "$owner" >> public-docs/ARCHITECTURE.md; }
uncovered()           { printf 'plain\n' > public-docs/new-note.txt; }
annotation_removed()  { sed -i 's/path = \["VERSION", /path = [/' REUSE.toml; }
third_relabelled()    { sed -i '/^path = "console\/assets\/htmx.min.js"$/,/^SPDX-License-Identifier/ s/"0BSD"/"AGPL-3.0-only"/' REUSE.toml; }
holder_replaced()     { sed -i "s/2020 Big Sky Software/2026 $owner/" REUSE.toml; }
coc_relabelled()      { sed -i '1s/CC-BY-4.0/AGPL-3.0-only/' CODE_OF_CONDUCT.md; }
passwords_relabelled(){ sed -i '1s/MIT/AGPL-3.0-only/' internal/auth/common-passwords.txt; }
stale_annotation()    { printf '\n[[annotations]]\npath = "no/such/file"\nSPDX-License-Identifier = "AGPL-3.0-only"\n' >> REUSE.toml; }
double_annotation()   { printf '\n[[annotations]]\npath = "VERSION"\nSPDX-License-Identifier = "AGPL-3.0-only"\n' >> REUSE.toml; }
first_party_holder()  { sed -i "0,/^SPDX-License-Identifier = \"AGPL-3.0-only\"\$/s//$tag = \"2026 Someone\"\nSPDX-License-Identifier = \"AGPL-3.0-only\"/" REUSE.toml; }
unlisted_third()      { printf '# SPDX-License-Identifier: MIT\nx\n' > hack/vendored.sh; }
schema_copyright()    { sed -i '0,/SPDX-License-Identifier: AGPL-3.0-only · /s//SPDX-License-Identifier: AGPL-3.0-only · Copyright 2026 Someone · /' schemas/module.v1alpha1.json; }

probe pass "the tree as it is (the control)" nothing
probe fail "a first-party Go file relabelled Apache-2.0" go_apache
probe fail "a first-party document relabelled CC-BY-4.0" doc_ccby
probe fail "a copyright tag naming the owner added to a first-party header" owner_tag
probe fail "a copyright tag naming someone else added to a first-party file" other_tag
probe fail "a bare copyright line naming the owner in README" owner_line
probe fail "an all-rights-reserved line naming the owner in a document" owner_reserved
probe pass "ADR-0004 D2's qualified statement in a document" qualified
probe fail "a first-party file with no header and no annotation" uncovered
probe fail "VERSION's annotation removed" annotation_removed
probe fail "a third-party script relabelled AGPL-3.0-only in REUSE.toml" third_relabelled
probe fail "a third-party holder replaced by the owner in REUSE.toml" holder_replaced
probe fail "the Code of Conduct relabelled AGPL-3.0-only" coc_relabelled
probe fail "the password list's header relabelled AGPL-3.0-only" passwords_relabelled
probe fail "an annotation for a file that is not tracked" stale_annotation
probe fail "a file named by two annotations" double_annotation
probe fail "a first-party annotation carrying a copyright line" first_party_holder
probe fail "a new MIT file the third-party allowlist does not name" unlisted_third
probe fail "a schema \$comment with a copyright statement beside its identifier" schema_copyright

if [ "$failures" -ne 0 ]; then
  echo "$failures probe(s) did not come out as stated: hack/spdx_check.py is broken"
  exit 1
fi
echo "all probes came out as stated"
