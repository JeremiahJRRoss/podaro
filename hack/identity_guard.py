#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The identity guard's judgement; hack/identity_guard.sh gathers what it judges and calls it.

The reconciliation plan's R6, task 2 (the reconciliation §5.6.3–§5.6.5 and §9.4; the owner's
mission of 2026-09-23, §9): no current attribution to the former organization comes back
unnoticed — not in the tree, the built binary, the extracted release, the CLI's output or the
rendered console. Every match of a detector, in any letter case, must be a row of the
residual-identity ledger (docs/reconciliation/RESIDUAL_IDENTITY_LEDGER.md), path by path.

This file spells no detector. The public snapshot of the plan's D-R14 carries the guard, and
must carry no former identity, so the tree mode reads its detectors from the ledger's
**Detectors** line — the ledger is the record of the name, and stays with the provenance
record — and the snapshot mode takes them at run time, from a file outside the snapshot
(--detectors) or the environment (PODARO_IDENTITY_DETECTORS, one per line or comma-separated).

Where the ledger does not travel — the published snapshot, where CI's `identity` job runs as it
runs here (the plan's D-R16, D-R17) — the tree mode takes the destination's form: its detectors
are hack/identity_detectors.txt, hashes kept in the tree and never a spelling, and it judges the
tree, every architecture's binary and tarball, the CLI's output and the rendered console against
an empty ledger — no detector anywhere, third-party credits aside (listed, never failing, as the
snapshot mode lists them). A hash file line is a detector's fold — each code point of the
detector, case-folded, modulo 4, one digit each: a prefilter the guard finds with str.find —
and the SHA-256 of "podaro-identity-detector:" and the case-folded detector, which decides.
With the ledger in the tree, the hash file must be exactly the ledger's detectors, hashed
(`identity_guard.py --write-hashes` writes it); given neither the ledger nor the hash file, the
guard fails — it never skips.

The ledger, read row by row:

  * a row's Location cell names its places in backticks: a file (`path`), its lines
    (`path:6,22`), a path abbreviated to the one file it begins (`docs/reviews/0003…:411`), a
    glob (`**/*.go`), a directory (`dir/`), the compendium's mirror of the row's other lines
    (`docs/PODARO_COMPENDIUM.md`), or a built artifact (`<binary>`, `<tarball>/<entry>`,
    `<cli>`, `<walk>`); a row with no place is outside the tree (history, accounts);
  * its Occurrence cell's backticked tokens that contain a detector are its literals: what
    stays, exactly, letter case included — a literal ending in "…" is a prefix, taking the rest
    of its token — and a match counts only where it sits inside one;
  * an Occurrence that begins "no former-organization occurrence" marks a row listed for
    review, not for allowance: the guard checks that its lines hold no detector;
  * a Closed-by cell that begins "Closed" marks a row whose occurrence has gone: it allows
    nothing and must match nothing.

A blanket exclusion is refused by construction (the reconciliation §9.4): a whole file, a
directory or a glob allows only through a literal, save the reconciliation's own evidence
(docs/reconciliation/ and the plan, which have to name what they remove); a literal must name
more than a detector alone; a compendium line counts only when it is byte-equal to an allowed
line of its own source part; an artifact place allows only through a literal. And every row
must still match: its places exist, and every line it names holds a detector.

The report ends with the line "identity migration: pending" while a row of category
"migration compatibility" is open — the reconciliation §5.6.4's honest state until the plan's
R7 moves the coordinates in the tree and the snapshot's push (R8) retires the old account.

Snapshot mode (the plan's R8, D-R14) judges an extracted archive, or a tarball of one, against
an empty ledger: no detector anywhere, third-party credits aside — THIRD-PARTY-NOTICES.md,
LICENSES/, the vendored assets and their licence texts, console/VENDOR.md, the password list,
the prototype's MIT licence, the Code of Conduct, LICENSE and NOTICE's third-party block,
which are other people's names and stay (listed, never failing). With --destination, a clone
of the destination after the snapshot's push, it reads every commit and tag: each author,
committer, tagger and sign-off must be Jeremiah Ross <dev@podaro.dev>, no message may carry a
detector, and no message may name another e-mail address.

Usage:
  identity_guard.py (--binary FILE --tarball-dir DIR)... --cli-dir DIR (--walk-dir DIR | --walk-skipped WHY)
      one --binary and one --tarball-dir per architecture the release ships, paired in order; the CLI's
      outputs and the walk come from the first
  identity_guard.py --snapshot DIR-OR-TARBALL [--destination CLONE] [--detectors FILE]
  identity_guard.py --write-hashes      rewrite hack/identity_detectors.txt from the ledger's Detectors line
"""
import argparse
import collections
import fnmatch
import hashlib
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
LEDGER = "docs/reconciliation/RESIDUAL_IDENTITY_LEDGER.md"
# The detectors as hashes, for the tree the ledger does not travel to (the plan's D-R17): never a spelling.
HASHES = "hack/identity_detectors.txt"
SALT = "podaro-identity-detector:"
FOLD = {c: "0123"[c % 4] for c in range(128)}
BYTE_FOLD = bytes(b"0123"[c % 4] if c < 128 else 0xFF for c in range(256))
HASH_LINE = re.compile(r"([0-3]+) ([0-9a-f]{64})")
COMPENDIUM = "docs/PODARO_COMPENDIUM.md"
# The owner's reconciliation, §5.6.3: its detection line names the spellings the ledger's detectors must include.
RECONCILIATION = "docs/reconciliation/PODARO-RECONCILIATION-v1.1.md"
ANCHOR = "Search case-insensitively for "
# The reconciliation's evidence: the owner's verbatim documents, the ledgers, the step evidence and the plan
# cannot say what is removed without naming it. The one place a whole file may stand without a literal.
EVIDENCE = ("docs/reconciliation/", "docs/DEVELOPMENT_PLAN_RECONCILIATION.md")
# The categories a residual occurrence may have (the reconciliation §5.6.5; the ledger's header).
CATEGORIES = ("required legal or provenance record", "pinned historical source URL", "history", "evidence",
              "retirement or negative-test marker", "migration compatibility", "factual reference")
PENDING = "migration compatibility"
OWNER = ("Jeremiah Ross", "dev@podaro.dev")
# Other people's names and notices: not project identity, and they stay (the plan's R6 task 2).
THIRD_PARTY = ("THIRD-PARTY-NOTICES.md", "LICENSE", "CODE_OF_CONDUCT.md", "console/VENDOR.md",
               "internal/auth/common-passwords.txt",
               "console/assets/htmx.min.js", "console/assets/sse.min.js", "console/assets/alpine-csp.min.js")
THIRD_PARTY_DIRS = ("LICENSES/", "console/assets/LICENSES/", "console/assets/fonts/")
BINARY_SUFFIXES = (".woff2", ".png", ".ico", ".gz")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SHOWN = 12


def text(path):
    """A file's text, or None for a binary one (a NUL in its first 8000 bytes, as git decides)."""
    p = Path(path)
    if str(path).endswith(BINARY_SUFFIXES) or not p.is_file():
        return None
    data = p.read_bytes()
    return None if b"\0" in data[:8000] else data.decode("utf-8", "replace")


def tree_files(root):
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=root, capture_output=True, text=True)
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() == Path(root).resolve():
        out = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=True).stdout
        return sorted(p for p in out.decode("utf-8").split("\0") if p and (Path(root) / p).is_file()), "git's tracked files"
    files = []
    for d, dirs, names in os.walk(root):
        dirs[:] = [x for x in dirs if x != ".git"]
        files += [str((Path(d) / n).relative_to(root)) for n in names]
    return sorted(files), "every file under the root (no .git)"


def listed(items):
    items = list(items)
    return "; ".join(items[:SHOWN]) + (f"; … and {len(items) - SHOWN} more" if len(items) > SHOWN else "")


def detector_regex(detectors):
    return re.compile("|".join(re.escape(d) for d in sorted(detectors, key=len, reverse=True)), re.I)


def fold(s):
    """A string's fold: each code point, modulo 4, as a digit — the prefilter a hash file line carries."""
    return s.translate(FOLD)


def digest(s):
    return hashlib.sha256((SALT + s).encode("utf-8")).hexdigest()


def hash_line(detector):
    t = detector.casefold()
    if not t.isascii():
        raise ValueError("a detector the hash file can carry is ASCII once case-folded")
    return f"{fold(t)} {digest(t)}"


class Hashed:
    """Detectors known by their hashes alone: a match is a window of the case-folded text whose fold is a detector's
    fold (found with str.find, in C) and whose salted SHA-256 is that detector's hash."""

    def __init__(self, lines):
        self.groups = collections.defaultdict(set)
        for f, h in lines:
            self.groups[f].add(h)

    def __len__(self):
        return sum(len(v) for v in self.groups.values())

    def search(self, s):
        t = s.casefold()
        f = t.translate(FOLD)
        for pat, hashes in self.groups.items():
            i = f.find(pat)
            while i != -1:
                if digest(t[i:i + len(pat)]) in hashes:
                    return True
                i = f.find(pat, i + 1)
        return None

    def byte_spans(self, data):
        """Every span of bytes where a detector sits, ASCII letter case ignored (a binary's strings are ASCII)."""
        low = data.lower()
        f = low.translate(BYTE_FOLD)
        spans = []
        for pat, hashes in self.groups.items():
            b = pat.encode()
            i = f.find(b)
            while i != -1:
                if digest(low[i:i + len(b)].decode("ascii")) in hashes:
                    spans.append((i, i + len(b)))
                i = f.find(b, i + 1)
        return spans


class AnyOf:
    """Several detector sets as one: hashed ones and spelled ones given at run time."""

    def __init__(self, *dets):
        self.dets = [d for d in dets if d is not None]

    def search(self, s):
        return any(d.search(s) for d in self.dets)

    def byte_spans(self, data):
        spans = []
        for d in self.dets:
            if isinstance(d, Hashed):
                spans += d.byte_spans(data)
            else:
                rx = re.compile(d.pattern.encode("utf-8"), re.I)
                spans += [m.span() for m in rx.finditer(data)]
        return spans


def read_hashes(root, problems):
    """The hash file's lines, (fold, sha256); a malformed line or an empty file is a problem."""
    raw = text(Path(root) / HASHES)
    if raw is None:
        return None
    lines = []
    for n, line in enumerate(raw.split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        m = HASH_LINE.fullmatch(line.strip())
        if not m:
            problems.append(f"{HASHES}:{n}: not `<fold> <sha256>` — a fold of digits 0–3 and 64 hex digits")
            continue
        lines.append((m.group(1), m.group(2)))
    if not lines and not problems:
        problems.append(f"{HASHES} holds no detector")
    return lines


def hash_file_text(detectors):
    head = (text(ROOT / HASHES) or "").split("\n")
    comments = [x for x in head if x.startswith("#")]
    return "\n".join(comments + sorted({hash_line(d) for d in detectors})) + "\n"


def given_detectors(opts, problems, outside=None):
    """The detectors given at run time: a file (never inside the tree judged) and the environment."""
    terms, whence = [], []
    if opts.detectors:
        f = Path(opts.detectors).resolve()
        if outside is not None and (f == outside or outside in f.parents):
            problems.append(f"--detectors {opts.detectors} is inside the snapshot; it must stay outside what is published")
        elif not f.is_file():
            problems.append(f"--detectors {opts.detectors}: no such file")
        else:
            terms += [t.strip() for t in f.read_text(encoding="utf-8").split("\n") if t.strip() and not t.startswith("#")]
            whence.append(f"{len(terms)} from --detectors")
    env = [t.strip() for t in re.split(r"[\n,]", os.environ.get("PODARO_IDENTITY_DETECTORS", "")) if t.strip()]
    if env:
        whence.append(f"{len(env)} from PODARO_IDENTITY_DETECTORS")
    return list(dict.fromkeys(terms + env)), " and ".join(whence)


# --- the ledger ----------------------------------------------------------------

def read_ledger(problems):
    raw = text(ROOT / LEDGER)
    if raw is None:
        problems.append(f"{LEDGER} is missing: the tree mode reads its detectors and its rows from it")
        return [], []
    detectors, rows = [], []
    for line in raw.split("\n"):
        if line.startswith("**Detectors**"):
            # `**Detectors** (what they are): `a` · `b` …` — the list is what follows the explanation.
            detectors = re.findall(r"`([^`]+)`", line.rsplit("): ", 1)[-1])
        cells = [c.strip() for c in line.split("|")[1:-1]]
        if len(cells) < 2 or not cells[0].isdigit():
            continue
        if len(cells) != 7:
            problems.append(f"ledger row {cells[0]}: {len(cells)} cells, not the seven columns")
            continue
        n, loc, occ, cat, reason, blocks, closed = cells
        rows.append({"n": int(n), "loc": loc, "occ": occ, "category": cat, "blocks": blocks, "closed": closed,
                     "tokens": re.findall(r"`([^`]+)`", loc), "backticked": re.findall(r"`([^`]+)`", occ),
                     "review_only": occ.lower().startswith("no former-organization occurrence"),
                     "is_closed": closed.lower().startswith("closed")})
    return detectors, rows


def glob_match(path, pat):
    return fnmatch.fnmatchcase(path, pat) or (pat.startswith("**/") and fnmatch.fnmatchcase(path, pat[3:]))


def resolve(row, files, problems):
    """A row's places: (kind, path, lines). Kinds: file, dir, glob, mirror, artifact."""
    places = []
    for tok in row["tokens"]:
        if tok.startswith("<"):
            places.append(("artifact", tok, None))
            continue
        path, sep, nums = tok.partition(":")
        lines = None
        if sep:
            if not re.fullmatch(r"[1-9]\d*(,[1-9]\d*)*", nums):
                problems.append(f"ledger row {row['n']}: `{tok}` — the lines are comma-separated numbers")
                continue
            lines = {int(x) for x in nums.split(",")}
        if path.endswith("…"):
            begun = [f for f in files if f.startswith(path[:-1])]
            if len(begun) != 1:
                problems.append(f"ledger row {row['n']}: `{tok}` begins {len(begun)} files, not one")
                continue
            path = begun[0]
        if path == COMPENDIUM:
            places.append(("mirror", path, lines))
        elif "*" in path:
            places.append(("glob", path, lines))
        elif path.endswith("/"):
            places.append(("dir", path, lines))
        else:
            places.append(("file", path, lines))
    return places


def covers(place, path, n):
    kind, p, lines = place
    hit = ((kind == "file" and path == p) or (kind == "dir" and path.startswith(p))
           or (kind == "glob" and glob_match(path, p)))
    return hit and (lines is None or n in lines)


def strip_literals(s, literals):
    for lit in literals:
        if lit.endswith("…"):
            s = re.sub(re.escape(lit[:-1]) + r"[^\s)\]>`'\"]*", "", s)
        else:
            s = s.replace(lit, "")
    return s


def validate(rows, files, det, problems):
    """Each row's shape, and the refusals that keep the ledger per path (the reconciliation §9.4)."""
    fileset = set(files)
    for r in rows:
        at = f"ledger row {r['n']}"
        if r["category"].lower() not in [c.lower() for c in CATEGORIES]:
            problems.append(f"{at}: category {r['category']!r} is none of: {', '.join(CATEGORIES)}")
        if not re.match(r"(yes|no)\b", r["blocks"].strip("*").lower()):
            problems.append(f"{at}: its Blocks-publication cell says neither yes nor no")
        if not r["closed"]:
            problems.append(f"{at}: its Closed-by cell is empty (— when nothing closes it)")
        r["literals"] = [t for t in r["backticked"] if det.search(t)]
        r["places"] = resolve(r, files, problems)
        for lit in r["literals"] if r["places"] else []:
            if len(re.sub(r"\s", "", det.sub("", lit.rstrip("…")))) < 6:
                problems.append(f"{at}: the literal `{lit}` is little more than a detector — a blanket, not an occurrence")
        for kind, p, lines in r["places"]:
            evidence = p.startswith(EVIDENCE)
            if kind == "artifact":
                if not re.fullmatch(r"<(binary|cli|walk)>|<tarball>/\S+", p):
                    problems.append(f"{at}: `{p}` is no artifact the guard reads (<binary>, <tarball>/<entry>, <cli>, <walk>)")
                elif not r["literals"] and not r["review_only"]:
                    problems.append(f"{at}: `{p}` allows only through a literal")
                continue
            if kind in ("file", "mirror") and p not in fileset:
                problems.append(f"{at}: `{p}` is not in the tree")
            if kind == "dir" and not evidence:
                problems.append(f"{at}: `{p}` — a directory outside the reconciliation's evidence is a blanket exclusion")
            if kind == "glob" and not r["literals"]:
                problems.append(f"{at}: `{p}` — a glob allows only through a literal")
            if kind == "file" and lines is None and not r["literals"] and not evidence and not r["review_only"]:
                problems.append(f"{at}: `{p}` — a whole file without a literal is a blanket exclusion outside the evidence")


# --- the tree -------------------------------------------------------------------

def judge_tree(root, files, rows, det, cc_parts):
    """Every detector match in the tree, and the row that accounts for it (None: unaccounted)."""
    hits = {}
    for p in files:
        t = text(Path(root) / p)
        if t is None:
            continue
        for n, line in enumerate(t.split("\n"), 1):
            if det.search(line):
                hits[(p, n)] = line
    live = [r for r in rows if not r["review_only"] and not r["is_closed"]]
    account, used = {}, collections.defaultdict(set)
    for (p, n), line in hits.items():
        if p == COMPENDIUM:
            continue
        over = [(r, pl) for r in live for pl in r["places"] if pl[0] in ("file", "dir", "glob") and covers(pl, p, n)]
        if not over:
            continue
        free = [r for r, (kind, pp, lines) in over if not r["literals"] and (lines is not None or pp.startswith(EVIDENCE))]
        if free:
            account[(p, n)] = free[0]["n"]
            used[free[0]["n"]].add((p, n))
            continue
        lits = [lit for r, _ in over for lit in r["literals"]]
        if not det.search(strip_literals(line, lits)):
            owners = [r["n"] for r, _ in over if any((lit[:-1] if lit.endswith("…") else lit) in line for lit in r["literals"])]
            account[(p, n)] = owners[0] if owners else over[0][0]["n"]
            for o in owners or [over[0][0]["n"]]:
                used[o].add((p, n))
    # The compendium: byte-equal to an allowed line of its own source part, for a row that names the mirror.
    mirror_rows = [r["n"] for r in live if any(pl[0] == "mirror" for pl in r["places"])]
    allowed_text = collections.defaultdict(set)
    for (p, n) in account:
        allowed_text[p].add(hits[(p, n)])
    for (p, n), line in hits.items():
        if p != COMPENDIUM:
            continue
        for first, last, source in cc_parts:
            if first <= n <= last and line in allowed_text[source] and mirror_rows:
                account[(p, n)] = mirror_rows[0]
                used[mirror_rows[0]].add((p, n))
    return hits, account, used


def compendium_parts(root):
    try:
        sys.path.insert(0, str(Path(root) / "hack"))
        import compendium_check as cc  # noqa: E402 — a sibling script, for its part map
    except ImportError:
        return []
    finally:
        sys.path.pop(0)
    lines = (text(Path(root) / COMPENDIUM) or "").split("\n")
    heads = []
    for part, source in cc.PARTS:
        at = next((i + 1 for i, x in enumerate(lines) if x.startswith(f"# ━━━ Part {part} · ")), None)
        if at is not None:
            heads.append((at, source))
    return [(at + 2, (heads[k + 1][0] - 1 if k + 1 < len(heads) else len(lines)), source)
            for k, (at, source) in enumerate(heads)]


def stale_rows(rows, hits, used, binary_used, binary_scanned):
    """A row that matches nothing is stale; a review-only row whose lines hold a detector is wrong; a closed row
    whose places still match has not closed."""
    out = []
    by_path = collections.defaultdict(dict)
    for (p, n), line in hits.items():
        by_path[p][n] = line
    for r in rows:
        at = f"ledger row {r['n']}"
        for kind, p, lines in r["places"]:
            if kind == "artifact":
                if p == "<binary>" and binary_scanned and not r["review_only"] and not r["is_closed"] and r["n"] not in binary_used:
                    out.append(f"{at}: `<binary>` — no string of the binary is this row's")
                continue
            if r["review_only"] or r["is_closed"]:
                found = [f"{f}:{n}" for (f, n) in hits if covers((kind if kind != "mirror" else "file", p, lines), f, n)]
                if found:
                    out.append(f"{at}: {'says no former-organization occurrence' if r['review_only'] else 'is closed'}, "
                               f"but {listed(found)} holds one")
                if r["review_only"] and kind == "file" and lines:
                    have = len((text(ROOT / p) or "").split("\n"))
                    out += [f"{at}: `{p}:{n}` — the file has {have} lines" for n in sorted(lines) if n > have]
                continue
            mine = [k for k in used[r["n"]] if (kind == "mirror" and k[0] == COMPENDIUM)
                    or (kind != "mirror" and covers((kind, p, None), k[0], k[1]))]
            if lines is not None and kind == "file":
                out += [f"{at}: `{p}:{n}` holds no detector" for n in sorted(lines) if n not in by_path.get(p, {})]
            elif not mine:
                out.append(f"{at}: `{p}` — nothing there is this row's")
    return out


def scan_text_files(paths, det):
    """Detector matches in files outside the tree (the tarball's entries, the CLI's output, the walk's dumps); a file
    whose first line reads `$ <command>` is named by its command."""
    found = []
    for path, name in paths:
        t = text(path)
        if t is None:
            continue
        head = t.split("\n", 1)[0]
        for n, line in enumerate(t.split("\n"), 1):
            if det.search(line):
                found.append((name if not head.startswith("$ ") else head[2:], n, line))
    return found


def binary_strings(data):
    for mt in re.finditer(rb"[\x20-\x7e]{4,}", data):
        yield mt.group().decode("ascii")


def judge_binary(data, rows, det):
    """Every printable string of the binary with a detector, and the rows whose literals account for it."""
    binary_rows = [r for r in rows if not r["review_only"] and not r["is_closed"]
                   and any(pl[0] == "artifact" and pl[1] == "<binary>" for pl in r["places"])]
    lits = [lit for r in binary_rows for lit in r["literals"]]
    counted, bad, used = collections.Counter(), [], set()
    for s in binary_strings(data):
        if not det.search(s):
            continue
        if det.search(strip_literals(s, lits)):
            bad.append(s[:160])
            continue
        for r in binary_rows:
            if any((lit[:-1] if lit.endswith("…") else lit) in s for lit in r["literals"]):
                counted[r["n"]] += 1
                used.add(r["n"])
    return counted, bad, used


# --- the modes --------------------------------------------------------------------

def tree_mode(opts):
    """The ledger's form where the ledger is in the tree; the destination's form where only the hashes are; a failure
    where neither is."""
    if (ROOT / LEDGER).is_file():
        return ledger_form(opts)
    if (ROOT / HASHES).is_file():
        return destination_form(opts)
    print(f"✗ the detectors: neither {LEDGER} nor {HASHES} is in this tree — the identity guard has nothing to search "
          "for, and it fails rather than skip")
    print()
    print("identity guard: FAIL — no detectors: the residual-identity ledger, or the detector hashes the destination keeps")
    return 1


def artifacts(opts):
    """The binaries and extracted tarballs, one pair per architecture, and their bytes."""
    return [(Path(b), Path(t), Path(b).read_bytes()) for b, t in zip(opts.binary, opts.tarball_dir)]


def ledger_form(opts):
    failures = []

    def verdict(title, problems, good):
        print(f"{'✓' if not problems else '✗'} {title}: {good if not problems else listed(problems)}")
        failures.extend(f"{title}: {p}" for p in problems)

    shape = []
    detectors, rows = read_ledger(shape)
    # The ledger's detectors must take in every spelling the owner's reconciliation names (§5.6.3), so that the list
    # can grow but never quietly narrow; the anchor is the owner's verbatim record, which is never edited.
    named = re.findall(r"`([^`]+)`", next((x for x in (text(ROOT / RECONCILIATION) or "").split("\n")
                                           if x.startswith(ANCHOR)), ""))
    missing = [t for t in named if t.lower() not in [d.lower() for d in detectors]]
    if not named:
        shape.append(f"{RECONCILIATION} §5.6.3's detection line ({ANCHOR!r}) is gone: the detectors have no anchor")
    shape += [f"the ledger's **Detectors** line lacks a spelling the reconciliation §5.6.3 names (its {k + 1}. of {len(named)})"
              for k, t in enumerate(named) if t in missing]
    # The destination's guard searches for what the hash file holds: exactly the ledger's detectors, hashed.
    hashed = []
    try:
        want = {hash_line(d) for d in detectors}
    except ValueError as e:
        want = set()
        shape.append(f"the ledger's **Detectors** line: {e}")
    have = read_hashes(ROOT, hashed)
    if have is None:
        hashed.append(f"{HASHES} is missing: the destination's identity job reads it where the ledger does not travel")
    elif not hashed and {f"{f} {h}" for f, h in have} != want:
        hashed.append(f"{HASHES} is not the ledger's **Detectors** line, hashed ({len(have)} lines for {len(want)} "
                      "detectors) — rewrite it: python3 hack/identity_guard.py --write-hashes")
    extra, whence = given_detectors(opts, shape)
    detectors = list(dict.fromkeys(detectors + extra))
    if not detectors:
        shape.append(f"no detectors: {LEDGER} has no **Detectors** line and none was given at run time")
        verdict("the ledger", shape, "")
        return 1
    det = detector_regex(detectors)
    files, how = tree_files(ROOT)
    validate(rows, files, det, shape)
    print(f"== the residual-identity ledger, {LEDGER}: {len(rows)} rows · {len(detectors)} detectors in any letter case — "
          f"its **Detectors** line, every spelling of the reconciliation §5.6.3 among them"
          f"{', and ' + whence if whence else ''} (this guard spells none)")
    verdict(f"the detector hashes the destination keeps, {HASHES}", hashed,
            f"{len(want)} lines, the ledger's detectors hashed — what the identity job searches for where the ledger "
            "does not travel")

    print(f"== 1. the tree: {len(files)} files ({how})")
    hits, account, used = judge_tree(ROOT, files, rows, det, compendium_parts(ROOT))
    unaccounted = [f"{p}:{n}: {line.strip()[:120]}" for (p, n), line in sorted(hits.items()) if (p, n) not in account]
    per_row = collections.Counter(account.values())
    verdict(f"{len(hits)} lines with a detector, in {len({p for p, _ in hits})} files", unaccounted,
            "every one a row of the ledger — " + ", ".join(f"row {k}: {v}" for k, v in sorted(per_row.items())))

    arts = artifacts(opts)
    binary_used = set()
    print(f"== 2. the binaries' strings: {', '.join(f'{b.name} ({len(d):,} bytes)' for b, _, d in arts)}")
    for b, _, data in arts:
        counted, bad, u = judge_binary(data, rows, det)
        binary_used |= u
        verdict(f"{b.name}: {sum(counted.values()) + len(bad)} strings with a detector", bad,
                ("every one inside a literal of a `<binary>` row — " + ", ".join(f"row {k}: {v}" for k, v in sorted(counted.items())))
                if counted else "no string of the binary carries one")

    print("== 3. the ledger's rows: well formed, and every one still matching")
    verdict(f"{len(rows)} rows", shape, "each with a category and a blocks-publication value; no blanket exclusion; "
            f"rows {', '.join(str(r['n']) for r in rows if r['review_only'])}, listed for review, hold no detector")
    verdict(f"{len(rows)} rows match something", stale_rows(rows, hits, used, binary_used, True), "none stale")

    for b, tdir, data in arts:
        entries = sorted(p for p in tdir.rglob("*") if p.is_file())
        print(f"== 4. the release tarball of {b.name}, extracted: {len(entries)} entries")
        tar, same = [], False
        for e in entries:
            name = str(e.relative_to(tdir))
            if name == "podaro":
                inner = e.read_bytes()
                same = inner == data
                if not same:
                    _, inner_bad, _ = judge_binary(inner, rows, det)
                    tar += [f"podaro: {x}" for x in inner_bad]
                continue
            tar += [f"{n}:{k}: {line.strip()[:100]}" for n, k, line in scan_text_files([(e, name)], det)]
        verdict(f"{len(entries)} entries beside {b.name}", tar,
                ("its podaro is that binary, byte for byte" if same else "its podaro's strings are all rows'")
                + f"; the other {len(entries) - 1} carry no detector")

    cli_and_walk(opts, det, verdict)

    print()
    status = 1 if failures else 0
    if failures:
        print(f"identity guard: FAIL — {len(failures)} finding(s); every former-organization occurrence must be a row of "
              f"{LEDGER}, path by path")
    else:
        print("identity guard: PASS — every former-organization occurrence in the tree, the binaries, the release, the CLI's "
              "output and the rendered console is a row of the ledger")
    pending = [r for r in rows if r["category"].lower() == PENDING and not r["is_closed"]]
    if len(pending) == 1:
        print(f"identity migration: pending — ledger row {pending[0]['n']} ({PENDING}) is open; "
              "it closes as its Closed-by cell says")
    elif pending:
        print("identity migration: pending — ledger rows " + ", ".join(str(r["n"]) for r in pending)
              + f" ({PENDING}) are open; each closes as its Closed-by cell says")
    else:
        print(f"identity migration: no {PENDING} row is open")
    return status


def cli_and_walk(opts, det, verdict):
    """Steps 5 and 6, the same in both forms: the CLI's outputs and the rendered console, from the first binary."""
    cli = sorted(Path(opts.cli_dir).glob("*.txt"))
    print(f"== 5. the CLI: {len(cli)} outputs — podaro --help for every command, hidden ones too; podaro legal, "
          "legal --licenses, legal --json; podaro version")
    found = scan_text_files([(p, p.name) for p in cli], det)
    verdict(f"{len(cli)} outputs", [f"{name}: line {n}: {line.strip()[:100]}" for name, n, line in found], "no detector")

    print("== 6. the rendered console: the walk's page-text dump and its DOM dumps")
    if opts.walk_skipped:
        print(f"○ not scanned: {opts.walk_skipped}")
    else:
        walk = sorted(p for p in Path(opts.walk_dir).glob("*") if p.suffix in (".txt", ".html"))
        dump = text(Path(opts.walk_dir) / "page-text.txt")
        problems = [] if dump else ["page-text.txt is missing from the walk's output"]
        found = scan_text_files([(p, p.name) for p in walk], det)
        problems += [f"{name}:{n}: {line.strip()[:100]}" for name, n, line in found]
        pages = (dump or "").count("==> ")
        verdict(f"{len(walk)} files, page-text.txt holding {pages} {'page or state' if pages == 1 else 'pages and states'}",
                problems, "no detector")


def credit_spans(data, root, files, block_text):
    """Where the binary embeds a third-party credit byte for byte — a whole third-party file, or NOTICE's third-party
    block — so that a detector inside another holder's notice is listed, as in the tree, and never fails."""
    bodies = [(Path(root) / p).read_bytes() for p in files if third_party(p, 0, None)]
    bodies += [block_text.encode("utf-8")] if block_text else []
    spans = []
    for body in bodies:
        if len(body) < 64:
            continue
        i = data.find(body)
        while i != -1:
            spans.append((i, i + len(body)))
            i = data.find(body, i + 1)
    return spans


def destination_form(opts):
    """The tree without the ledger — the published snapshot (the plan's D-R17): the hashes are the detectors, and the
    target is an empty ledger. Third-party credits are listed and never fail."""
    failures = []

    def verdict(title, problems, good):
        print(f"{'✓' if not problems else '✗'} {title}: {good if not problems else listed(problems)}")
        failures.extend(f"{title}: {p}" for p in problems)

    shape = []
    lines = read_hashes(ROOT, shape)
    extra, whence = given_detectors(opts, shape)
    if shape:
        verdict("the detectors", shape, "")
        print()
        print(f"identity guard: FAIL — the detector hashes, {HASHES}, cannot be read; the guard never skips")
        return 1
    det = AnyOf(Hashed(lines), detector_regex(extra) if extra else None)
    files, how = tree_files(ROOT)
    notice = (text(ROOT / "NOTICE") or "").split("\n")
    block = next((i + 1 for i, x in enumerate(notice) if x.startswith("Third-party")), None)
    block_text = "\n".join(notice[block - 1:]) if block else ""
    print(f"== the destination's form: no residual-identity ledger in this tree — the target is an empty ledger · "
          f"{len(lines)} detectors from {HASHES}, as hashes (never a spelling){', and ' + whence if whence else ''}")

    print(f"== 1. the tree: {len(files)} files ({how})")
    found, credits = [], []
    for p in files:
        t = text(ROOT / p)
        for n, line in enumerate((t or "").split("\n"), 1):
            if t is not None and det.search(line):
                (credits if third_party(p, n, block) else found).append(f"{p}:{n}: {line.strip()[:100]}")
    verdict(f"{len(files)} files", found, "no detector outside third-party credits")
    if credits:
        print(f"○ third-party credits, other people's names, not project identity (they stay): {listed(credits)}")

    def binary_findings(data):
        """A binary's detector matches outside an embedded third-party credit, each shown in its string; and how many
        sit inside one."""
        allowed = credit_spans(data, ROOT, files, block_text)
        bad, inside = [], 0
        for a, z in det.byte_spans(data):
            if any(x <= a and z <= y for x, y in allowed):
                inside += 1
                continue
            lo = max(data.rfind(b"\0", 0, a) + 1, a - 60)
            hi = data.find(b"\0", z)
            hi = min(hi if hi != -1 else len(data), z + 60)
            bad.append(data[lo:hi].decode("ascii", "replace"))
        return bad, inside

    arts = artifacts(opts)
    print(f"== 2. the binaries: {', '.join(f'{b.name} ({len(d):,} bytes)' for b, _, d in arts)}")
    for b, _, data in arts:
        bad, inside = binary_findings(data)
        verdict(f"{b.name}", bad, "no detector outside an embedded third-party credit"
                + (f" ({inside} inside one, listed)" if inside else ""))

    print("== 3. the ledger's rows: none — this tree carries no residual-identity ledger, and none is allowed")

    for b, tdir, data in arts:
        entries = sorted(p for p in tdir.rglob("*") if p.is_file())
        print(f"== 4. the release tarball of {b.name}, extracted: {len(entries)} entries")
        tar, same = [], False
        for e in entries:
            name = str(e.relative_to(tdir))
            if name == "podaro":
                inner = e.read_bytes()
                same = inner == data
                if not same:
                    tar += [f"podaro: {x}" for x in binary_findings(inner)[0]]
                continue
            tar += [f"{n}:{k}: {line.strip()[:100]}" for n, k, line in scan_text_files([(e, name)], det)
                    if not third_party(n, k, block if n == "NOTICE" else None)]
        verdict(f"{len(entries)} entries beside {b.name}", tar,
                ("its podaro is that binary, byte for byte" if same else "its podaro carries no detector either")
                + f"; the other {len(entries) - 1} carry no detector outside third-party credits")

    cli_and_walk(opts, det, verdict)

    print()
    if failures:
        print(f"identity guard: FAIL — {len(failures)} finding(s); this tree carries no residual-identity ledger, so no "
              "former identity may stand in it")
        return 1
    print("identity guard: PASS — no former identity in the tree, the binaries, the release, the CLI's output or the "
          "rendered console (the destination's form)")
    print("identity migration: none pending in this tree — it carries no residual-identity ledger, and none is allowed")
    return 0


def third_party(path, n, notice_block):
    return path in THIRD_PARTY or path.startswith(THIRD_PARTY_DIRS) or (path == "NOTICE" and notice_block and n >= notice_block)


def snapshot_mode(opts):
    failures = []

    def verdict(title, problems, good):
        print(f"{'✓' if not problems else '✗'} {title}: {good if not problems else listed(problems)}")
        failures.extend(f"{title}: {p}" for p in problems)

    src = Path(opts.snapshot).resolve()
    tmp = None
    if src.is_file():
        tmp = tempfile.TemporaryDirectory()
        with tarfile.open(src) as t:
            t.extractall(tmp.name, filter="data")
        tops = [p for p in Path(tmp.name).iterdir()]
        root = tops[0] if len(tops) == 1 and tops[0].is_dir() else Path(tmp.name)
    elif src.is_dir():
        root = src
    else:
        print(f"✗ --snapshot {opts.snapshot}: no such archive or directory")
        return 1
    problems = []
    detectors, whence = given_detectors(opts, problems, outside=src if src.is_dir() else None)
    if not detectors and not problems:
        problems.append("no detectors: give them at run time, --detectors FILE (outside the snapshot) or PODARO_IDENTITY_DETECTORS")
    if problems:
        verdict("the detectors", problems, "")
        return 1
    det = detector_regex(detectors)
    files, how = tree_files(root)
    print(f"== snapshot mode: {opts.snapshot} — {len(files)} files ({how}); {len(detectors)} detectors given at run time "
          f"({whence}); the target is an empty ledger")

    print("== 1. the archive's text: no project identity but Jeremiah Ross <dev@podaro.dev>")
    notice = (text(root / "NOTICE") or "").split("\n")
    block = next((i + 1 for i, x in enumerate(notice) if x.startswith("Third-party")), None)
    found, credits = [], []
    for p in files:
        t = text(root / p)
        for n, line in enumerate((t or "").split("\n"), 1):
            if t is not None and det.search(line):
                (credits if third_party(p, n, block) else found).append(f"{p}:{n}: {line.strip()[:100]}")
    verdict(f"{len(files)} files", found, "no detector outside third-party credits")
    if credits:
        print(f"○ third-party credits, other people's names, not project identity (they stay): {listed(credits)}")

    print("== 2. the destination's commit metadata")
    if not opts.destination:
        print("○ not read: run again after the snapshot's commit is pushed, with --destination <a clone of the destination>")
    else:
        g = ["git", "-C", opts.destination]
        log = subprocess.run(g + ["log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"],
                             capture_output=True, text=True)
        tags = subprocess.run(g + ["for-each-ref", "refs/tags", "--format=%(refname:short)%1f%(taggername)%1f%(taggeremail)%1f%(contents)%1e"],
                              capture_output=True, text=True)
        bad = []
        if log.returncode != 0:
            bad.append(f"git log: {log.stderr.strip()}")
        commits = [c.strip("\n") for c in log.stdout.split("\x1e") if c.strip()]
        for c in commits:
            h, an, ae, cn, ce, body = (c.split("\x1f") + [""] * 6)[:6]
            who = f"commit {h[:12]}"
            for role, name, mail in (("author", an, ae), ("committer", cn, ce)):
                if (name, mail) != OWNER:
                    bad.append(f"{who}: {role} {name} <{mail}>")
            bad += message_problems(who, body, det)
        tagged = [t.strip("\n") for t in tags.stdout.split("\x1e") if t.strip()]
        for t in tagged:
            ref, tn, te, body = (t.split("\x1f") + [""] * 4)[:4]
            if tn and (tn, te.strip("<>")) != OWNER:
                bad.append(f"tag {ref}: tagger {tn} {te}")
            bad += message_problems(f"tag {ref}", body, det)
        verdict(f"{len(commits)} commits and {len(tagged)} tags", bad,
                "every author, committer, tagger and sign-off Jeremiah Ross <dev@podaro.dev>; no detector and no other address in any message")

    print()
    if failures:
        print(f"snapshot identity: FAIL — {len(failures)} finding(s)")
    elif opts.destination:
        print("snapshot identity: clean — the archive's text and the destination's commits carry one project identity, "
              "Jeremiah Ross <dev@podaro.dev>")
    else:
        print("snapshot identity: the archive's text is clean — the destination's commits are still to be read, after the push")
    if tmp:
        tmp.cleanup()
    return 1 if failures else 0


def message_problems(who, body, det):
    out = []
    for line in body.split("\n"):
        if det.search(line):
            out.append(f"{who}: a detector in its message: {line.strip()[:100]}")
        if line.lower().startswith("signed-off-by:") and line.strip() != f"Signed-off-by: {OWNER[0]} <{OWNER[1]}>":
            out.append(f"{who}: {line.strip()}")
        out += [f"{who}: the address {a} in its message" for a in EMAIL.findall(line) if a.lower() != OWNER[1]]
    return out


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", action="append", default=[],
                    help="tree mode: a podaro binary built from this tree; once per architecture the release ships")
    ap.add_argument("--tarball-dir", action="append", default=[],
                    help="tree mode: that architecture's release tarball, extracted; paired with the --binary in its place")
    ap.add_argument("--cli-dir", help="tree mode: the CLI's outputs, one file each, its first line `$ <command>`")
    ap.add_argument("--walk-dir", help="tree mode: the console walk's output (page-text.txt and the DOM dumps)")
    ap.add_argument("--walk-skipped", help="tree mode: why the walk did not run (reported, never a pass)")
    ap.add_argument("--snapshot", help="snapshot mode: an extracted archive, or the archive itself")
    ap.add_argument("--destination", help="snapshot mode: a clone of the destination, after the snapshot's push")
    ap.add_argument("--detectors", help="a file of detectors, one per line (the snapshot mode's must lie outside it)")
    ap.add_argument("--write-hashes", action="store_true",
                    help=f"rewrite {HASHES} from the ledger's Detectors line, and exit")
    opts = ap.parse_args(argv[1:])
    if opts.write_hashes:
        problems = []
        detectors, _ = read_ledger(problems)
        if problems or not detectors:
            sys.exit(f"✗ {LEDGER}: " + ("; ".join(problems) or "no **Detectors** line"))
        (ROOT / HASHES).write_text(hash_file_text(detectors), encoding="utf-8")
        print(f"✓ wrote {HASHES}: {len(detectors)} detectors, as hashes")
        return 0
    if opts.snapshot:
        return snapshot_mode(opts)
    if not (opts.binary and opts.tarball_dir and opts.cli_dir and (opts.walk_dir or opts.walk_skipped)):
        ap.error("the tree mode needs --binary, --tarball-dir, --cli-dir and --walk-dir (or --walk-skipped)")
    if len(opts.binary) != len(opts.tarball_dir):
        ap.error(f"{len(opts.binary)} --binary and {len(opts.tarball_dir)} --tarball-dir: one of each per architecture")
    return tree_mode(opts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
