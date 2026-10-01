#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The retirement guard's judgement; hack/retirement_guard.sh builds what it judges and calls it.

The reconciliation plan's R6, task 1 (the reconciliation §9.1–§9.2; the owner's mission of
2026-09-23, §7; ADR-0004 D9): nothing the owner retired comes back unnoticed — not in the tree,
the embedded filesystem, the binary or the extracted release. It reads hack/retirement.json and
judges every match by the role of the file it is in, against hack/retirement_allow.txt; it is
never a substring ban across the repository (the reconciliation §9.1).

The search is everything the manifest records by name — the scenario, the modules, their images
and digests, the adapter ids, the generator ids, the playbooks, the licence ids, the pack — and
the vendors whose images it retired (each image repository's path below its registry), in any
letter case: the retired-name search of R2's acceptance, which the allowlist answers, taken from
the manifest so that this file spells no retired name. The rules, each failure named where found:

  1. nothing the manifest retired by path exists: the scenario, its pack, the modules, the
     script, the code files, the withdrawn prompt;
  2. every line of the tree the search returns is a row of the allowlist, by path or by
     path:line — the reconciliation's evidence aside (docs/reconciliation/ and the plan), which
     R2's search leaves out because it cannot say what is removed without naming it;
  3. a maintained surface is never a row — the catalog, the module library, the current schemas,
     the installer and its answers, the wrapper, the registries, the session prompts, the
     release's files and every file a //go:embed directive puts in the binary — except the
     instruction that forbids restoring the lab (CLAUDE.md and AGENTS.md, retirement_instruction,
     by line) and the embedded files the manifest's in_a_binary roles name, under their role;
  4. every row is well formed: a category the manifest's allowed_locations define; a whole file
     only for the manifest, the harness, a history or evidence document, or the compendium, whose
     lines count only as byte-equal copies of an allowed line of their own source part; a role the
     manifest names by path (this_manifest, frozen_schemas, negative_fixtures) only on its paths;
  5. every row matches something: its path is in the tree, a whole-file row's file holds a match,
     and every line a row names holds one — a row that matches nothing is removed, never kept in
     case;
  6. no allowed location holds runnable provisioning content: a retired image digest appears in
     the manifest alone, and the negative fixtures carry no real digest, only all-zero ones;
  7. the embedded filesystem: TestEmbedded passed, listing the retained catalog alone, every file
     it lists is one a directive here embeds, and check 5's source half holds — no retired template
     or module is embedded, and each allowed file carries exactly what the manifest records;
  8. every binary the release ships — one per architecture — and each tarball's: check 5's
     in_a_binary allowance, called from hack/retirement_scan.py rather than repeated (the plan's
     Q-R5; the module the published snapshot keeps, D-R17), whose self-test probes must come out
     as stated against the first binary as built;
  9. each tarball's other entries carry no retired term at all.

It judges the tree it lives in: git's tracked files in a checkout, every file under the root in
an extracted archive (the snapshot of the plan's R8 has no .git).

Usage: retirement_guard.py --embedded-log FILE (--binary FILE --tarball-dir DIR [--tarball-name NAME])...
  one --binary and one --tarball-dir per architecture the release ships, paired in order
"""
import argparse
import collections
import contextlib
import fnmatch
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "hack/retirement.json"
ALLOWLIST = "hack/retirement_allow.txt"
COMPENDIUM = "docs/PODARO_COMPENDIUM.md"
# R2's search leaves out the reconciliation's evidence — the owner's verbatim documents, the ledgers,
# the step evidence and the plan cannot say what is removed without naming it (the manifest's
# evidence_and_history role) — and the allowlist, which answers that search, has no row for them.
EVIDENCE = ("docs/reconciliation/", "docs/DEVELOPMENT_PLAN_RECONCILIATION.md")
# allowed_locations entries that are not categories of a row: the binary's allowance, and a note
# (the diagnostics' codes spell no retired name, so internal/pdr/pdr.go needs no row).
NOT_CATEGORIES = ("in_a_binary", "diagnostics")
# The roles a row may cover a whole file for (the allowlist's header).
WHOLE_FILE = ("this_manifest", "harness", "evidence_and_history", "compendium_mirror")
# The roles the manifest names by path: a row of one of them is on one of its paths.
BY_PATH = ("this_manifest", "frozen_schemas", "negative_fixtures")
# The maintained surfaces, by role (the plan's R6 task 1), besides every embedded file and every file
# the release tarball carries, which are read from the tree itself.
MAINTAINED = ("scenarios/*", "modules/*", "schemas/*.v1alpha2.json", "docs/code-execution/*.prompt.md",
              "install.sh", "install.test.yaml", "podaroctl", "CLAUDE.md", "AGENTS.md",
              "internal/lab/model.go", "internal/verify/verify.go", "internal/seed/seed.go",
              "internal/runtime/fake.go", "internal/system/install.go")
# The instruction that forbids restoring the lab has to name it.
INSTRUCTION = ("CLAUDE.md", "AGENTS.md")
BINARY_SUFFIXES = (".woff2", ".png", ".ico", ".gz")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.I)
ZERO_DIGEST = "sha256:" + "0" * 64
SHOWN = 12  # matches listed per failure before "… and N more"


def load(name, optional=False):
    """A sibling script, imported: check 5's scan; the compendium's part map, where a compendium is kept."""
    spec = importlib.util.spec_from_file_location(name, ROOT / "hack" / f"{name}.py")
    if spec is None or not (ROOT / "hack" / f"{name}.py").is_file():
        if optional:
            return None
        sys.exit(f"✗ hack/{name}.py is missing, and the guard reads it")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tree_files():
    """The tree the guard lives in, and how its file list was taken."""
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, capture_output=True, text=True)
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() == ROOT:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        return sorted(p for p in out.decode("utf-8").split("\0") if p and (ROOT / p).is_file()), "git's tracked files"
    files = []
    for d, dirs, names in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x != ".git"]
        files += [str((Path(d) / n).relative_to(ROOT)) for n in names]
    return sorted(files), "every file under the root (no .git: an extracted archive)"


def text(path, root=ROOT):
    """A file's text, or None for a binary one (a NUL in its first 8000 bytes, as git decides)."""
    p = Path(root) / path
    if str(path).endswith(BINARY_SUFFIXES) or not p.is_file():
        return None
    data = p.read_bytes()
    return None if b"\0" in data[:8000] else data.decode("utf-8", "replace")


def search_terms(m, rs):
    """Everything the manifest records by name, and the vendors whose images it retired."""
    terms = list(rs.retired_identifiers(m))
    for x in m["modules"]:
        terms += x["image"]["repository"].split("/")[1:]
    return list(dict.fromkeys(terms))


def role_paths(m, role):
    v = m["allowed_locations"].get(role)
    return [v] if isinstance(v, str) else [x for x in (v or []) if isinstance(x, str)]


def named_by(m, role, path):
    return any(path == x or (x.endswith("/") and path.startswith(x)) for x in role_paths(m, role))


def embedded_files(files):
    """Every file a //go:embed directive of non-test Go code puts in a binary, resolved as the toolchain
    resolves it: from the directive's package directory; a directory takes every file below it but those
    whose names begin with '.' or '_' (unless the pattern says all:)."""
    out = set()
    for f in files:
        if not f.endswith(".go") or f.endswith("_test.go") or "/testdata/" in f:
            continue
        for line in (text(f) or "").split("\n"):
            d = re.match(r"\s*//go:embed\s+(.*\S)", line)
            if not d:
                continue
            for pat in d.group(1).split():
                hidden = pat.startswith("all:")
                full = os.path.normpath(os.path.join(os.path.dirname(f), pat.removeprefix("all:")))
                for g in files:
                    if fnmatch.fnmatchcase(g, full):
                        out.add(g)
                    elif g.startswith(full + "/"):
                        below = g[len(full) + 1:].split("/")
                        if hidden or not any(x.startswith((".", "_")) for x in below):
                            out.add(g)
    return out


def tarball_sources(files):
    """The tree's files the release tarball carries (hack/release_package.sh's TARBALL_ENTRIES)."""
    m = re.search(r'^TARBALL_ENTRIES="([^"]*)"', text("hack/release_package.sh") or "", re.M)
    out = set()
    for e in (m.group(1).split() if m else []):
        e = e.rstrip("/")
        out |= {f for f in files if f == e or f.startswith(e + "/")}
    return out


def allow_rows(problems):
    """The allowlist's rows: path, the lines it names (None: the whole file), category, reason."""
    raw = text(ALLOWLIST)
    if raw is None:
        problems.append(f"{ALLOWLIST} is missing")
        return []
    rows = []
    for i, line in enumerate(raw.split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cells = line.split("\t")
        if len(cells) != 3 or not all(c.strip() for c in cells):
            problems.append(f"{ALLOWLIST}:{i}: not `path[:line,…]<TAB>category<TAB>reason`")
            continue
        loc, category, reason = cells
        path, sep, nums = loc.partition(":")
        if sep and not re.fullmatch(r"[1-9]\d*(,[1-9]\d*)*", nums):
            problems.append(f"{ALLOWLIST}:{i}: {loc!r} — the lines are comma-separated numbers")
            continue
        rows.append({"at": f"{ALLOWLIST}:{i}", "loc": loc, "path": path, "category": category, "reason": reason,
                     "lines": sorted({int(n) for n in nums.split(",")}) if sep else None})
    return rows


def compendium_parts(cc):
    """(first line, last line, source) of each part of the compendium, 1-based, from its banners."""
    lines = (text(COMPENDIUM) or "").split("\n")
    heads = []
    for part, source in cc.PARTS:
        at = next((i + 1 for i, x in enumerate(lines) if x.startswith(f"# ━━━ Part {part} · ")), None)
        if at is not None:
            heads.append((at, source))
    return [(at + 2, (heads[k + 1][0] - 1 if k + 1 < len(heads) else len(lines)), source)
            for k, (at, source) in enumerate(heads)]


def listed(items):
    items = list(items)
    return "; ".join(items[:SHOWN]) + (f"; … and {len(items) - SHOWN} more" if len(items) > SHOWN else "")


def binary_report(rs, m, files, data):
    """Where the retired identifiers sit in a binary — which allowance holds each, or 'outside' — in one pass."""
    loc = m["allowed_locations"]["in_a_binary"]
    spans = {p: rs.occurrences(data, (ROOT / p).read_bytes()) for p in rs.binary_roles(m) if p in files}
    spans.update({f"the protocol string {s['bytes']!r}": rs.occurrences(data, s["bytes"].encode())
                  for s in loc.get("protocol_strings", [])})
    ids = sorted((i.encode() for i in rs.retired_identifiers(m)), key=len, reverse=True)
    where = collections.Counter()
    for mt in re.finditer(b"|".join(re.escape(i) for i in ids), data, re.I):
        a, z = mt.span()
        inside = [n for n, sp in spans.items() if any(x <= a and z <= y for x, y in sp)]
        where[inside[0] if inside else "outside"] += 1
    return where


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--embedded-log", required=True, help="the output of `go test -v -run '^TestEmbedded$' .`")
    ap.add_argument("--binary", action="append", required=True,
                    help="a podaro binary built from this tree; once per architecture the release ships")
    ap.add_argument("--tarball-dir", action="append", required=True,
                    help="that architecture's release tarball, extracted; paired with the --binary in the same place")
    ap.add_argument("--tarball-name", action="append", default=[], help="each tarball's file name, for the report")
    ap.add_argument("--no-self-test", action="store_true",
                    help="skip check 5's self-test: for hack/retirement_guard_test.sh alone, whose probes prove this "
                         "guard's rules; hack/retirement_guard.sh, the CI job, always runs it")
    opts = ap.parse_args(argv[1:])
    if len(opts.binary) != len(opts.tarball_dir):
        ap.error(f"{len(opts.binary)} --binary and {len(opts.tarball_dir)} --tarball-dir: one of each per architecture")
    names = opts.tarball_name + [f"the release tarball of {Path(b).name}" for b in opts.binary[len(opts.tarball_name):]]

    rs = load("retirement_scan")
    cc = load("compendium_check", optional=True)  # None where no compendium is kept: a mirror row is then stale
    m = json.loads((ROOT / MANIFEST).read_text(encoding="utf-8"))
    files, how = tree_files()
    fileset = set(files)
    terms = search_terms(m, rs)
    rx = re.compile("|".join(re.escape(t) for t in sorted(terms, key=len, reverse=True)), re.I)
    failures = []

    def verdict(title, problems, good):
        print(f"{'✓' if not problems else '✗'} {title}: {good if not problems else listed(problems)}")
        failures.extend(f"{title}: {p}" for p in problems)

    digests = {x["image"]["digest"].lower() for x in m["modules"]}
    print(f"== the retirement manifest, {MANIFEST} — retired on {m['retired_on']}")
    print(f"   {len(terms)} search terms, from its scenario, modules, images and digests, adapters, generators, "
          f"playbooks, licence ids and pack, and the vendors of its images (in any letter case; spelled nowhere here)")
    print(f"   the tree: {len(files)} files ({how})")

    # 1. What the manifest retired by path.
    print("== 1. nothing the manifest retired by path exists")
    gone = [s["path"] for s in m["scenarios"]] + [a for s in m["scenarios"] for a in s["assets"]]
    gone += [x["path"] for x in m["modules"]] + list(m["scripts"]) + list(m["code"]["delete"])
    gone += [m["records"]["prompt_withdrawn"]]
    present = [p for p in gone if (ROOT / p).exists()]
    verdict(f"{len(gone)} retired paths", [f"{p} exists" for p in present], "every one absent")

    # 2–5. The tree, against the allowlist.
    problems = []
    rows = allow_rows(problems)
    hits = {}
    for p in files:
        if p.startswith(EVIDENCE):
            continue
        t = text(p)
        for n, line in enumerate((t or "").split("\n"), 1):
            if t is not None and rx.search(line):
                hits.setdefault(p, {})[n] = line
    embedded = embedded_files(files)
    shipped = tarball_sources(files)
    binary_roles = {p: role for role in m["allowed_locations"]["in_a_binary"]["roles"] for p in role_paths(m, role)}
    categories = [k for k, v in m["allowed_locations"].items()
                  if not k.startswith("$") and k not in NOT_CATEGORIES and isinstance(v, (str, list))]

    def maintained(p):
        return any(fnmatch.fnmatchcase(p, g) for g in MAINTAINED) or p in embedded or p in shipped

    print(f"== 2–5. the tree against {ALLOWLIST}: every match a row (the reconciliation's evidence aside), "
          "no maintained surface a row, every row well formed and matching something")
    malformed, laundering, stale, account = [], [], [], {}
    mirror_rows = []
    for r in rows:
        p, cat, where = r["path"], r["category"], r["at"]
        bad = []
        if cat not in categories:
            bad.append(f"{where}: category {cat!r} is none of the manifest's roles ({', '.join(categories)})")
        if r["lines"] is None and cat not in WHOLE_FILE:
            bad.append(f"{where}: {p} — a whole-file row only for {', '.join(WHOLE_FILE)}; name its lines")
        if (p == COMPENDIUM) != (cat == "compendium_mirror") or (cat == "compendium_mirror" and r["lines"] is not None):
            bad.append(f"{where}: the compendium is one whole-file compendium_mirror row, and that category is its alone")
        if cat in BY_PATH and not named_by(m, cat, p):
            bad.append(f"{where}: {p} is not a path the manifest's {cat} role names")
        if p.startswith(EVIDENCE):
            bad.append(f"{where}: {p} is evidence, which the search leaves out; the row accounts for nothing")
        malformed += bad
        if maintained(p) and not ((p in INSTRUCTION and cat == "retirement_instruction" and r["lines"] is not None)
                                  or binary_roles.get(p) == cat):
            laundering.append(f"{where}: {p} is a maintained surface, and no row may cover it"
                              + (" but retirement_instruction, by line" if p in INSTRUCTION else ""))
            bad.append(p)
        if bad:
            continue
        if p not in fileset:
            stale.append(f"{where}: {p} is not in the tree")
            continue
        if cat == "compendium_mirror":
            mirror_rows.append(r)
            continue
        found = hits.get(p, {})
        if r["lines"] is None:
            if not found:
                stale.append(f"{where}: {p} holds no retired term")
            for n in found:
                account.setdefault((p, n), r)
        else:
            for n in r["lines"]:
                if n in found:
                    account.setdefault((p, n), r)
                else:
                    stale.append(f"{where}: {p}:{n} holds no retired term")
    # The compendium: a line counts when it is byte-equal to an allowed line of its own source part.
    if mirror_rows and cc is None:
        stale.append(f"{mirror_rows[0]['at']}: {COMPENDIUM} has no checker (hack/compendium_check.py) in this tree")
    elif mirror_rows:
        allowed_text = collections.defaultdict(set)
        for (p, n), _ in account.items():
            allowed_text[p].add(hits[p][n])
        mirrored = 0
        for first, last, source in compendium_parts(cc):
            for n, line in hits.get(COMPENDIUM, {}).items():
                if first <= n <= last and line in allowed_text[source]:
                    account[(COMPENDIUM, n)] = mirror_rows[0]
                    mirrored += 1
        if not mirrored:
            stale.append(f"{mirror_rows[0]['at']}: no line of {COMPENDIUM} mirrors an allowed line")
    unaccounted = [f"{p}:{n}{' (maintained surface)' if maintained(p) else ''}: {line.strip()[:120]}"
                   for p in sorted(hits) for n, line in sorted(hits[p].items()) if (p, n) not in account]
    nlines = sum(len(v) for v in hits.values())
    by_cat = collections.Counter(r["category"] for r in rows)
    verdict(f"2. {nlines} lines in {len(hits)} files", unaccounted,
            f"every one a row of the allowlist ({len(rows)} rows: "
            + ", ".join(f"{c} {n}" for c, n in sorted(by_cat.items())) + ")")
    surfaces = sorted(p for p in files if maintained(p))
    verdict(f"3. {len(surfaces)} maintained files ({len(embedded)} embedded, {len(shipped)} in the tarball)", laundering,
            "none is a row but " + ", ".join(sorted(r["loc"] for r in rows if maintained(r["path"]))))
    verdict(f"4. {len(rows)} rows well formed", problems + malformed,
            "every category a manifest role; whole files only for the manifest, the harness, history, evidence and the mirror")
    verdict(f"5. {len(rows)} rows match something", stale, "none stale")

    # 6. No runnable provisioning content in an allowed location.
    print("== 6. no allowed location holds runnable provisioning content")
    loose, real = [], []
    for p in files:
        if p.startswith(EVIDENCE):
            continue
        t = text(p) or ""
        for n, line in enumerate(t.split("\n"), 1):
            for d in DIGEST.findall(line):
                if d.lower() in digests and p != MANIFEST:
                    loose.append(f"{p}:{n}: a retired image digest outside the manifest")
                if named_by(m, "negative_fixtures", p) and d.lower() != ZERO_DIGEST:
                    real.append(f"{p}:{n}: a negative fixture with a real digest, {d[:19]}…")
    fixtures = sorted(p for p in files if named_by(m, "negative_fixtures", p))
    verdict(f"the {len(digests)} retired image digests", loose, f"in {MANIFEST} alone")
    verdict(f"{len(fixtures)} negative-fixture files", real, "no real digest — "
            + (", ".join(sorted({d for p in fixtures for d in DIGEST.findall(text(p) or '')})) or "no digest at all")
            .replace(ZERO_DIGEST, "an all-zero digest"))

    # 7. The embedded filesystem.
    print("== 7. the embedded filesystem")
    log = Path(opts.embedded_log).read_text(encoding="utf-8", errors="replace")
    listing = re.findall(r"embed_test\.go:\d+: ((?:scenarios|modules)/\S+)", log)
    emb = []
    if not re.search(r"^--- PASS: TestEmbedded\b", log, re.M):
        said = [x.strip() for x in log.split("\n")
                if re.match(r"\s+embed_test\.go:\d+: ", x) and not re.search(r": (scenarios|modules)/\S+$", x)]
        emb.append("TestEmbedded did not pass" + (": " + "; ".join(said[:3]) if said else ""))
    emb += [f"TestEmbedded lists {x}, which no //go:embed directive here embeds" for x in listing if x not in embedded]
    emb += [f"a //go:embed directive embeds {x}, which TestEmbedded does not list" for x in sorted(embedded)
            if x.startswith(("scenarios/", "modules/")) and x not in listing]
    verdict(f"TestEmbedded's listing of the embedded catalog ({len(listing)} files)", emb, ", ".join(listing))
    verdict("check 5 over the tree (hack/retirement_scan.py)", rs.source_problems(m, files),
            "no retired template or module is embedded; each allowed file carries exactly what the manifest records")
    print(f"   {len(embedded)} embedded files, from the //go:embed directives: "
          + ", ".join(sorted({f.split('/')[0] if '/' in f else f for f in embedded})))

    # 8. The binaries, one per architecture.
    print(f"== 8. the {'binary' if len(opts.binary) == 1 else f'{len(opts.binary)} binaries'}: "
          "check 5's in_a_binary allowance (the plan's Q-R5; D-R17: every architecture the release ships)")
    datas = [Path(b).read_bytes() for b in opts.binary]
    for b, data in zip(opts.binary, datas):
        where = binary_report(rs, m, files, data)
        verdict(f"{b.rsplit('/', 1)[-1]} ({len(data):,} bytes)", rs.binary_problems(m, files, data),
                f"{sum(where.values())} occurrences of retired identifiers, every one inside the allowance — "
                + ", ".join(f"{n} in {w}" for w, n in sorted(where.items())))
    if opts.no_self_test:
        print("○ check 5's self-test: not run here (--no-self-test)")
    else:
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = rs.self_test(m, files, opts.binary[0])
        probes = re.findall(r"^([✓✗]) +\d+\. (.*)$", buf.getvalue(), re.M)
        verdict(f"check 5's self-test against {opts.binary[0].rsplit('/', 1)[-1]} ({len(probes)} probes)",
                [label for mark, label in probes if mark != "✓"] + ([] if code == 0 and probes else ["the self-test failed"]),
                "every probe came out as stated")

    # 9. The tarballs, one per architecture.
    for tarball_dir, name, data in zip(opts.tarball_dir, names, datas):
        print(f"== 9. the release tarball, extracted: {name}")
        tdir = Path(tarball_dir)
        entries = sorted(str(p.relative_to(tdir)) for p in tdir.rglob("*") if p.is_file())
        tar = [] if "podaro" in entries else ["the tarball carries no podaro"]
        for e in entries:
            if e == "podaro":
                inner = (tdir / e).read_bytes()
                tar += [f"podaro: {x}" for x in (rs.binary_problems(m, files, inner) if inner != data else [])]
                continue
            t = text(e, tdir)
            if t is None:
                tar.append(f"{e}: not text, and not the binary")
                continue
            tar += [f"{e}:{n}: {line.strip()[:100]}" for n, line in enumerate(t.split("\n"), 1) if rx.search(line)]
        same = (tdir / "podaro").is_file() and (tdir / "podaro").read_bytes() == data
        verdict(f"{len(entries)} files in {name}", tar,
                ("its podaro is its architecture's binary above, byte for byte" if same else "its podaro passes check 5")
                + f"; the other {len(entries) - 1} carry no retired term")

    print()
    if failures:
        print(f"retirement guard: FAIL — {len(failures)} finding(s); a match is judged by the role of the file it is in "
              f"(hack/retirement.json, {ALLOWLIST})")
        return 1
    print("retirement guard: PASS — nothing the owner retired is in the tree outside its allowed roles, "
          "in the embedded filesystem, in the binaries or in the release")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
