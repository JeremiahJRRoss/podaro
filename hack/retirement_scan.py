#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Check 5's scan: nothing the owner retired is embedded in what a release carries, by the manifest's allowance.

The owner's mission of 2026-09-23 lists twenty acceptance checks; its fifth — no dedicated content of the retired lab
remains embedded in release artifacts — is the one the retirement guard (hack/retirement_guard.py, CI's `retirement`
job) needs wherever the guard runs, the published snapshot included. So its functions live here, in a module the
snapshot keeps, imported by the guard and by the mission's harness (hack/reconciliation_check.py, which stays with the
reconciliation's record) alike — the reconciliation plan's D-R17(a).

Over the tree: no retired template or module sits in the embedded catalog, and each file the manifest's in_a_binary
roles name carries exactly the retired names the manifest records for it (`carries`), so retired content appended to a
frozen schema is caught, not allowed along with the file. Over a built binary (the plan's Q-R5): every file those roles
name must be embedded as the tree has it — a binary built from another tree, or a file that is not a podaro binary,
fails as such — and every retired identifier, in any letter case, must sit inside one of those byte-identical copies or
inside an exact protocol string the manifest lists. The self-test runs the scan against a real binary and against
copies of it, of the manifest and of a schema made to fail; each must come out as stated.

This file spells no retired name: everything it searches for, and everything its self-test plants, is read from
hack/retirement.json at run time.

Usage: retirement_scan.py --binary PATH [--self-test] [--manifest PATH]
  without --self-test: check 5 over the tree and the binary — exit 0 when nothing is outside the allowance;
  with it: the self-test's probes against the binary, and where each retired identifier sits in it.
"""
import argparse
import copy
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "hack" / "retirement.json"


def load_manifest(path=None):
    return json.loads(Path(path or MANIFEST).read_text(encoding="utf-8"))


def tree_files():
    """The tree this file lives in: git's tracked files in a checkout, every file under the root without one."""
    top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, capture_output=True, text=True)
    if top.returncode == 0 and Path(top.stdout.strip()).resolve() == ROOT:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        return sorted(p for p in out.decode("utf-8").split("\0") if p and (ROOT / p).is_file())
    files = []
    for d, dirs, names in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x != ".git"]
        files += [str((Path(d) / n).relative_to(ROOT)) for n in names]
    return sorted(files)


def retired_names(m):
    return [s["name"] for s in m["scenarios"]] + [x["name"] for x in m["modules"]]


def retired_paths(m):
    return [s["path"] for s in m["scenarios"]] + [x["path"] for x in m["modules"]] + list(m["scripts"]) + list(m["code"]["delete"])


def retired_identifiers(m):
    """Everything the manifest records by name: the scenario, the modules, their images, the adapters, the generators,
    the playbooks, the licence ids and the assets. Check 5 searches a binary for each, in any letter case."""
    ids = retired_names(m) + m["adapters"]["product"] + m["adapters"]["composites_over_them"] + m["generators"]
    for x in m["modules"]:
        ids += [x["image"]["repository"], x["image"]["digest"]]
    for s in m["scenarios"]:
        ids += s["playbooks"] + s["licenses"] + [Path(a).name for a in s["assets"]]
    return list(dict.fromkeys(ids))


def occurrences(data, needle, ignore_case=False):
    """Every span of `data` where `needle` (bytes) occurs."""
    return [(mt.start(), mt.end()) for mt in re.finditer(re.escape(needle), data, re.I if ignore_case else 0)]


def count_names(data, ids):
    """How many times each identifier occurs in `data` (bytes), in any letter case; identifiers that never occur are left out."""
    counts = {i: len(occurrences(data, i.encode(), ignore_case=True)) for i in ids}
    return {i: n for i, n in counts.items() if n}


def binary_roles(m):
    """The files the manifest's `in_a_binary` roles name: the only files a built binary may carry a retired identifier in."""
    loc = m["allowed_locations"]
    paths = []
    for role in loc["in_a_binary"]["roles"]:
        val = loc.get(role, f"<no role named {role}>")  # never a tracked file, so the scan reports it
        paths += [val] if isinstance(val, str) else list(val)
    return list(dict.fromkeys(paths))


def embedded_copies(data, paths):
    """Every span of `data` that is a byte-identical copy of one of the files: an allowance covers that and nothing else."""
    spans = []
    for p in paths:
        spans += occurrences(data, (ROOT / p).read_bytes())
    return spans


def carries_problems(m, path, data):
    """An allowed file must carry exactly the retired names the manifest records for it, so that retired content
    appended to a frozen schema is caught, not allowed along with the file (the review of #46/#47, E3)."""
    expected = m["allowed_locations"]["in_a_binary"].get("carries", {})
    if path not in expected:
        return [f"the manifest records no expected names for {path} (in_a_binary.carries)"]
    got = count_names(data, retired_identifiers(m))
    if got == expected[path]:
        return []
    diff = sorted(f"{i} ×{got.get(i, 0)} (recorded ×{expected[path].get(i, 0)})"
                  for i in set(got) | set(expected[path]) if got.get(i, 0) != expected[path].get(i, 0))
    return [f"{path} carries retired names the manifest does not record: " + ", ".join(diff)]


def source_problems(m, files):
    """Check 5 over the tree: no retired template or module is embedded, and each allowed file carries what is recorded."""
    names = retired_names(m)
    problems = []
    for tree in ("scenarios", "modules"):
        for d in sorted(p.name for p in (ROOT / tree).iterdir() if p.is_dir()):
            if d in names:
                problems.append(f"{tree}/{d} is embedded by embed.go")
    for p in binary_roles(m):
        if p == m["allowed_locations"].get("this_manifest") or p not in files:
            continue  # the manifest is the list itself; an untracked path is reported by the binary scan
        problems += carries_problems(m, p, (ROOT / p).read_bytes())
    return problems


def binary_problems(m, files, data):
    """Check 5 over a built binary (the plan's Q-R5). Every file the `in_a_binary` roles name must be embedded as the
    tree has it — the positive control, which a binary built from another tree, or a file that is not a podaro binary,
    fails — and every retired identifier, in any letter case, must sit inside one of those copies or inside an exact
    protocol string the manifest lists."""
    loc = m["allowed_locations"]["in_a_binary"]
    allowed = binary_roles(m)
    fileset = set(files)
    problems = [f"the manifest's in_a_binary roles name {p}, which is not a tracked file" for p in allowed if p not in fileset]
    present = [p for p in allowed if p in fileset]
    absent = [p for p in present if (ROOT / p).read_bytes() not in data]
    if absent:
        return problems + [f"the binary does not embed {p} as the tree has it — built from another commit, or not a podaro binary"
                           for p in absent]
    spans = embedded_copies(data, present)
    for s in loc.get("protocol_strings", []):
        spans += occurrences(data, s["bytes"].encode())
    for ident in retired_identifiers(m):
        for a, z in occurrences(data, ident.encode(), ignore_case=True):
            if not any(x <= a and z <= y for x, y in spans):
                seen = data[a:z].decode("utf-8", "replace")
                problems.append(f"binary carries {ident!r}" + ("" if seen == ident else f" (as {seen!r})") +
                                " outside the manifest's in_a_binary allowance")
                break
    return problems


def self_test(m, files, binary):
    """Check 5 against a real binary and against copies of it made to fail (the plan's §4 A2 row; R8b re-runs it).

    It prints where each retired identifier sits in the binary as built, then runs the probes: each modified binary,
    manifest or file must come out as stated, or check 5 itself is broken. The names it plants come from the manifest.
    Returns 0 only when every probe does."""
    data = Path(binary).read_bytes()
    loc = m["allowed_locations"]["in_a_binary"]
    present = [p for p in binary_roles(m) if p in set(files)]
    print("== the allowance: byte-identical embedded copies of the files the in_a_binary roles name ("
          + ", ".join(loc["roles"]) + "), and the exact protocol strings")
    for p in present:
        print(f"{p:<36} {len((ROOT / p).read_bytes()):>6} bytes  embedded byte-identical ×{len(occurrences(data, (ROOT / p).read_bytes()))}")
    for s in loc.get("protocol_strings", []):
        print(f"{s['bytes']!r:<36} {len(occurrences(data, s['bytes'].encode())):>6} time(s)  {s['reason']}")
    print("\n== every occurrence of a retired identifier in the binary, in any letter case, and the allowance it sits in")
    spans = {p: occurrences(data, (ROOT / p).read_bytes()) for p in present}
    spans.update({repr(s["bytes"]): occurrences(data, s["bytes"].encode()) for s in loc.get("protocol_strings", [])})
    places, outside = set(), 0
    for ident in retired_identifiers(m):
        hits = occurrences(data, ident.encode(), ignore_case=True)
        where = []
        for a, z in hits:
            inside = [name for name, sp in spans.items() if any(x <= a and z <= y for x, y in sp)]
            where.append(inside[0] if inside else "OUTSIDE")
            outside += 0 if inside else 1
            places.add(a)
        if hits:
            print(f"{ident!r:<28} ×{len(hits)}  {', '.join(sorted(set(where)))}")
    absent = [i for i in retired_identifiers(m) if not occurrences(data, i.encode(), ignore_case=True)]
    print(f"absent ({len(absent)}): " + ", ".join(absent))
    print(f"matches at {len(places)} distinct byte location(s); outside the allowance: {outside}")

    # What the probes plant, from the manifest: a retired adapter, a retired image, the protocol string.
    adapter = m["adapters"]["product"][-1].encode()
    image = m["modules"][-1]["image"]["repository"].encode()
    schemes = [s["bytes"].encode() for s in loc.get("protocol_strings", [])]
    schema = "schemas/checkpoint.v1alpha1.json"
    body = (ROOT / schema).read_bytes()
    edited = bytearray(data)
    at = data.find(body)
    if at != -1:
        edited[at + 2] ^= 0x01
    untracked = copy.deepcopy(m)
    untracked["allowed_locations"]["frozen_schemas"].append("schemas/not-tracked.v1alpha1.json")
    undefined = copy.deepcopy(m)
    undefined["allowed_locations"]["in_a_binary"]["roles"].append("no_such_role")
    probes = [
        ("the binary as built (the control)", lambda: binary_problems(m, files, data), False),
        ("binary: a retired adapter name added outside the embedded copies",
         lambda: binary_problems(m, files, data + b"\0adapter: " + adapter + b"\0"), True),
        ("binary: the same name in capitals", lambda: binary_problems(m, files, data + b"\0" + adapter.upper() + b"\0"), True),
        ("binary: a retired image reference added", lambda: binary_problems(m, files, data + b"\0" + image + b"\0"), True),
    ]
    for scheme in schemes[:1]:
        probes += [
            ("binary: the protocol string added again, exactly",
             lambda s=scheme: binary_problems(m, files, data + b"\0" + s + b"\0"), False),
            ("binary: the protocol string in another letter case",
             lambda s=scheme: binary_problems(m, files, data + b"\0" + s.swapcase() + b"\0"), True),
        ]
    probes += [
        ("binary: the embedded checkpoint schema edited by one byte", lambda: binary_problems(m, files, bytes(edited)), True),
        ("binary: a file that is not a podaro binary", lambda: binary_problems(m, files, Path(__file__).read_bytes()), True),
        ("manifest: a binary role naming a file the tree does not track", lambda: binary_problems(untracked, files, data), True),
        ("manifest: an in_a_binary role that allowed_locations does not define",
         lambda: binary_problems(undefined, files, data), True),
        ("tree: retired content appended to an allowed schema",
         lambda: carries_problems(m, schema, body + b'\n{"enum": ["' + adapter + b'"]}\n'), True),
    ]
    print("\n== probes: each must come out as stated"
          + ("" if schemes else " (the manifest lists no protocol string, so its two probes have nothing to plant)"))
    ok = True
    for i, (label, run, must_fail) in enumerate(probes):
        got = run()
        good = bool(got) == must_fail
        ok = ok and good
        print(f"{'✓' if good else '✗'} {i:2d}. {label}: {'FAIL' if got else 'PASS'} (must {'FAIL' if must_fail else 'PASS'})")
        for x in got[:3]:
            print(f"       - {x}")
    print("all probes came out as stated" if ok else "a probe did not come out as stated: check 5 is broken")
    return 0 if ok else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", required=True, help="a podaro binary built from this tree")
    ap.add_argument("--self-test", action="store_true", help="run the probes against that binary, print the evidence, and exit")
    ap.add_argument("--manifest", help="read this retirement manifest instead of hack/retirement.json")
    opts = ap.parse_args(argv[1:])
    if not Path(opts.binary).is_file():
        ap.error(f"--binary {opts.binary}: no such file")
    m = load_manifest(opts.manifest)
    files = tree_files()
    if opts.self_test:
        return self_test(m, files, opts.binary)
    problems = source_problems(m, files) + binary_problems(m, files, Path(opts.binary).read_bytes())
    for p in problems:
        print(f"✗ {p}")
    print("check 5: " + ("PASS — nothing retired is embedded outside the manifest's in_a_binary allowance" if not problems
                         else f"FAIL — {len(problems)} finding(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
