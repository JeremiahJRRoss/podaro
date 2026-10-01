#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The SPDX check (docs/DEVELOPMENT_PLAN_RECONCILIATION.md, R4 task 2): the second step of CI's `licenses` job.

Every tracked file is judged by what it is:

1. Covered. It carries its own SPDX header — a `SPDX-License-Identifier:` tag within its first lines, in its
   own comment syntax — or exactly one REUSE.toml annotation names it. Every annotation names at least one
   tracked file, so REUSE.toml cannot keep a row for a file that is gone.
2. First-party — every file the third-party allowlist below does not name. Its identifier, from its header and
   from its annotation when it has one, is exactly `AGPL-3.0-only`, and it carries no copyright line: no
   `SPDX-FileCopyrightText` tag in the file or in its annotation, and no copyright statement on its header line
   (ADR-0004 D1–D2; the owner's Amendment 1: an identifier declares terms and claims no ownership).
3. Third-party — the allowlist below, from the license ledger's rows (docs/reconciliation/LICENSE_LEDGER.md).
   Its identifier is exactly the one it is known by, and where the allowlist names a holder, its annotation
   still names that holder. Nothing third-party is relabelled (ADR-0004 D3).
4. No copyright line names the owner, anywhere: no `SPDX-FileCopyrightText` naming the owner in a file or an
   annotation, and no copyright notice naming the owner except the qualified statement of ADR-0004 D2, which reads
   on "…, to the extent copyright subsists". Two roles are exempt from this rule and from rule 2's tag search,
   each for its reason: the evidence set (docs/reconciliation/ and the plan) quotes the retired forms as what
   not to do, and the two detectors (this file and hack/reconciliation_check.py) spell what they detect.

The `reuse` tool is not adopted: REUSE compliance requires a copyright notice on every file, which the owner's
decision declines for first-party material. REUSE.toml is read as the REUSE specification 3.2 writes it: `*`
stays within one directory, `**` crosses directories, and a backslash escapes an asterisk.

Usage: hack/spdx_check.py [-v]
  -v  list every tracked file with its class, its identifier and where the identifier comes from.
Exit 0 when every file passes; 1 naming each file that does not, and why.
"""
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python before 3.11
    sys.exit("spdx_check: needs Python 3.11 or later, whose standard library reads REUSE.toml (tomllib)")

ROOT = Path(__file__).resolve().parent.parent
FIRST_PARTY = "AGPL-3.0-only"
HEADER_LINES = 12  # an SPDX tag further down a file is content (a quotation, a fixture), not the file's header

# Third-party material: (path glob, the identifier it is known by, the holder its annotation names — a tuple when it
# names several, as the Alpine build does with the Vue code it bundles — or None, what it is). The ledger's rows 5–9, 18, 19 and 21; the holders are the ones NOTICE and console/VENDOR.md
# record. A file added under a third-party licence joins this list, with its row, or it is judged first-party.
THIRD_PARTY = [
    ("CODE_OF_CONDUCT.md", "CC-BY-4.0", None, "the Contributor Covenant 2.1, its attribution kept (row 18)"),
    ("console/assets/htmx.min.js", "0BSD", "Big Sky Software", "htmx 2.0.10, vendored unmodified (row 5)"),
    ("console/assets/sse.min.js", "0BSD", "Alexander Petros", "htmx-ext-sse 2.2.4, vendored unmodified (row 5)"),
    ("console/assets/alpine-csp.min.js", "MIT", ("Caleb Porzio", "Yuxi (Evan) You"),
     "Alpine.js, CSP build 3.17.1, vendored unmodified, with the Vue reactivity code 3.5.41 its build bundles (row 6)"),
    ("console/assets/fonts/IBMPlexMono-*.woff2", "OFL-1.1", "IBM Corp.", "IBM Plex Mono 2.5.0, reserved name \"Plex\" (row 7)"),
    ("console/assets/fonts/poppins-*.woff2", "OFL-1.1", "The Poppins Project Authors", "Poppins, @fontsource 5.3.0 (row 7)"),
    ("console/assets/fonts/inter-*.woff2", "OFL-1.1", "The Inter Project Authors", "Inter, @fontsource 5.3.0 (row 7)"),
    ("console/assets/LICENSES/htmx.txt", "0BSD", "Big Sky Software", "htmx's licence text (row 8)"),
    ("console/assets/LICENSES/htmx-ext-sse.txt", "0BSD", "Alexander Petros", "htmx-ext-sse's licence text (row 8)"),
    ("console/assets/LICENSES/ibm-plex-mono.txt", "OFL-1.1", "IBM Corp.", "IBM Plex Mono's licence text (row 8)"),
    ("console/assets/LICENSES/poppins.txt", "OFL-1.1", "The Poppins Project Authors", "Poppins' licence text (row 8)"),
    ("console/assets/LICENSES/inter.txt", "OFL-1.1", "The Inter Project Authors", "Inter's licence text (row 8)"),
    ("console/assets/LICENSES/vue.txt", "MIT", "Yuxi (Evan) You", "the licence text of @vue/reactivity and @vue/shared, which the Alpine build bundles (row 8)"),
    ("internal/auth/common-passwords.txt", "MIT", "Daniel Miessler", "the NCSC list as redistributed in SecLists, filtered (row 9)"),
    ("LICENSE", "AGPL-3.0-only", "Free Software Foundation", "the GNU AGPL v3 text itself, verbatim (row 19)"),
    ("LICENSES/Apache-2.0.txt", "Apache-2.0", None, "the Apache License 2.0 text itself, verbatim (row 19; LICENSE-APACHE until R5)"),
]

# Rule 4's two exempt roles, and the reason for each.
EVIDENCE = ("docs/reconciliation/", "docs/DEVELOPMENT_PLAN_RECONCILIATION.md")  # quotes the retired forms as removal targets
DETECTORS = ("hack/spdx_check.py", "hack/reconciliation_check.py")  # their patterns spell what they detect

TAG = re.compile(r"SPDX-License-Identifier:\s*(.+?)\s*(?:-->|\*/|·|\"|$)")
COPYRIGHT_TAG_LINE = re.compile(r"^\s*(?:#|//|<!--|/?\*|\{\{/\*|--|;|>)?\s*SPDX-FileCopyrightText\s*:", re.M)
OWNER = r"Jeremiah\s+Ross"
OWNER_TAG = re.compile(r"SPDX-FileCopyrightText\s*[:=][^\n]*" + OWNER, re.I)
OWNER_NOTICE = re.compile(r"(?:\bCopyright\b|©|\(c\))\s*(?:©\s*)?(?:\d{4}(?:\s*[-–]\s*\d{4})?\s*,?\s*)?" + OWNER, re.I)
QUALIFIED = ", to the extent copyright subsists"  # ADR-0004 D2's statement goes on so, and only so
HEADER_COPYRIGHT = re.compile(r"\bCopyright\b|©|SPDX-FileCopyrightText", re.I)


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def reuse_regex(glob):
    """A REUSE.toml path glob as a regular expression (REUSE 3.2: `*` within a directory, `**` across)."""
    out, i = "", 0
    while i < len(glob):
        c = glob[i]
        if c == "\\" and i + 1 < len(glob):
            out += re.escape(glob[i + 1])
            i += 2
        elif glob.startswith("**", i):
            out += ".*"
            i += 2
        elif c == "*":
            out += "[^/]*"
            i += 1
        else:
            out += re.escape(c)
            i += 1
    return re.compile(out + r"\Z")


def annotations():
    data = tomllib.loads((ROOT / "REUSE.toml").read_text(encoding="utf-8"))
    anns = []
    for i, a in enumerate(data.get("annotations", []), 1):
        paths = a.get("path", [])
        paths = [paths] if isinstance(paths, str) else list(paths)
        holders = a.get("SPDX-FileCopyrightText", [])
        holders = [holders] if isinstance(holders, str) else list(holders)
        anns.append({"n": i, "paths": paths, "rx": [reuse_regex(p) for p in paths],
                     "license": a.get("SPDX-License-Identifier"), "holders": holders})
    return data, anns


def header(text):
    """The file's own licence identifier (the first tag within its first lines) and that line, or (None, None)."""
    for line in text.splitlines()[:HEADER_LINES]:
        m = TAG.search(line)
        if m:
            return m.group(1), line
    return None, None


def third_party(path):
    for entry in THIRD_PARTY:
        if fnmatch.fnmatchcase(path, entry[0]):
            return entry
    return None


def owner_lines(text):
    """Lines that carry a copyright line naming the owner, other than ADR-0004 D2's qualified statement."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        if OWNER_TAG.search(line):
            found.append(n)
            continue
        for m in OWNER_NOTICE.finditer(line):
            if not line[m.end():].startswith(QUALIFIED):
                found.append(n)
                break
    return found


def main(argv):
    verbose = "-v" in argv[1:]
    files = tracked()
    problems = []
    try:
        data, anns = annotations()
    except FileNotFoundError:
        print("✗ REUSE.toml is missing: the files that cannot carry a header are covered by nothing")
        return 1
    if data.get("version") != 1:
        problems.append(f"REUSE.toml: version {data.get('version')!r}, want 1 (REUSE 3.2)")
    for a in anns:
        if not a["license"]:
            problems.append(f"REUSE.toml annotation {a['n']} ({', '.join(a['paths'])}) names no SPDX-License-Identifier")
        for glob, rx in zip(a["paths"], a["rx"]):
            if not any(rx.match(p) for p in files):
                problems.append(f"REUSE.toml annotation {a['n']}: {glob!r} names no tracked file")
        for h in a["holders"]:
            if re.search(OWNER, h, re.I):
                problems.append(f"REUSE.toml annotation {a['n']}: a copyright line naming the owner ({h!r})")
    for entry in THIRD_PARTY:
        if not any(fnmatch.fnmatchcase(p, entry[0]) for p in files):
            problems.append(f"the third-party allowlist names {entry[0]!r}, which is not a tracked file")

    counts = {"first-party header": 0, "first-party REUSE.toml": 0, "first-party both": 0,
              "third-party header": 0, "third-party REUSE.toml": 0, "third-party both": 0}
    listing = []
    for p in files:
        raw = (ROOT / p).read_bytes()
        text = raw.decode("utf-8", errors="replace")
        ident, head_line = header(text)
        matched = [a for a in anns if any(rx.match(p) for rx in a["rx"])]
        if len(matched) > 1:
            problems.append(f"{p}: {len(matched)} REUSE.toml annotations name it (annotations "
                            f"{', '.join(str(a['n']) for a in matched)}); exactly one may")
        ann = matched[0] if matched else None
        source = "both" if (ident and ann) else "header" if ident else "REUSE.toml" if ann else None
        if source is None:
            problems.append(f"{p}: not covered — no SPDX header in its first {HEADER_LINES} lines and no REUSE.toml annotation")
            listing.append(f"{p}\t-\tnot covered")
            continue
        declared = [x for x in (ident, ann["license"] if ann else None) if x]
        entry = third_party(p)
        exempt = p.startswith(EVIDENCE) or p in DETECTORS
        if entry:
            glob, want, holder, what = entry
            counts[f"third-party {source}"] += 1
            for got in declared:
                if got != want:
                    problems.append(f"{p}: third-party, known as {want} ({what}), but declares {got}")
            for one in (holder if isinstance(holder, tuple) else (holder,) if holder else ()):
                if ann and not any(one in h for h in ann["holders"]):
                    problems.append(f"{p}: its REUSE.toml annotation no longer names its holder, {one}")
            listing.append(f"{p}\tthird-party\t{want}\t{source}")
        else:
            counts[f"first-party {source}"] += 1
            for got in declared:
                if got != FIRST_PARTY:
                    problems.append(f"{p}: first-party, declares {got} (want {FIRST_PARTY}; a third-party file "
                                    "belongs in this script's allowlist, with its ledger row)")
            if ann and ann["holders"]:
                problems.append(f"{p}: first-party, its REUSE.toml annotation carries a copyright line "
                                f"({'; '.join(ann['holders'])})")
            if head_line and HEADER_COPYRIGHT.search(head_line):
                problems.append(f"{p}: first-party, its header line carries a copyright statement")
            if not exempt and COPYRIGHT_TAG_LINE.search(text):
                problems.append(f"{p}: first-party, carries an SPDX-FileCopyrightText tag")
            listing.append(f"{p}\tfirst-party\t{FIRST_PARTY}\t{source}")
        if not exempt:
            for n in owner_lines(text):
                problems.append(f"{p}:{n}: a copyright line naming the owner — only ADR-0004 D2's qualified "
                                "statement may name the owner, in NOTICE, README and the legal surfaces")

    if verbose:
        print("path\tclass\tidentifier\tfrom")
        for line in listing:
            print(line)
        print()
    first = counts["first-party header"] + counts["first-party REUSE.toml"] + counts["first-party both"]
    third = counts["third-party header"] + counts["third-party REUSE.toml"] + counts["third-party both"]
    print(f"spdx_check: {len(files)} tracked files · REUSE.toml: {len(anns)} annotations")
    print(f"  first-party {first:>4} — {FIRST_PARTY}: {counts['first-party header']} by their own header, "
          f"{counts['first-party REUSE.toml']} by REUSE.toml, {counts['first-party both']} by both")
    print(f"  third-party {third:>4} — their own licences: {counts['third-party header']} by their own header, "
          f"{counts['third-party REUSE.toml']} by REUSE.toml, {counts['third-party both']} by both")
    if problems:
        for pr in problems:
            print(f"✗ {pr}")
        print(f"{len(problems)} problem(s)")
        return 1
    print("✓ every tracked file is covered by its own SPDX header or exactly one REUSE.toml annotation")
    print(f"✓ every first-party file declares {FIRST_PARTY} and carries no copyright line")
    print(f"✓ every third-party file in the allowlist ({len(THIRD_PARTY)} entries) declares exactly its known identifier")
    print("✓ no copyright line names the owner outside ADR-0004 D2's qualified statement (evidence and detectors exempt)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
