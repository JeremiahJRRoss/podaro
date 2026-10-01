#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Every link in the tree, checked offline — and the project's own coordinates, spelled as the owner gave them.

The reconciliation plan's R7 (the reconciliation §5.6.4 and its A17): the technical coordinates moved to the
destination the owner gave on 2026-09-23, and what a reader follows moves with them without breaking. Nothing is
fetched. The destination is published by the owner's own act (the plan's GR3), so a check that asked the network
would fail on a tree that is right, or pass on one that is wrong because a page happened to answer; this one asks the
tree, and asks an absolute link only for its form.

  1. Relative links. Every inline link or image, and every reference definition, in a tracked Markdown file whose
     target names no scheme resolves to a tracked file, or to a directory that holds one; a #fragment names a heading
     of its target, as GitHub derives the anchor, or an anchor written into it (id= or name=). Code — fenced blocks
     and code spans — is not a link. The compendium's parts are their sources byte for byte (hack/compendium_check.py),
     so their links are checked where they are written: in the sources.
  2. Absolute links. Form only: an http(s) link names a host and carries no whitespace and no credential; a mailto:
     link names one address; no other scheme is a link a reader can follow from a page of this repository.
  3. The project's own coordinates, in every tracked text file — prose and code alike, since the coordinates are
     usually written as code. A URL on github.com naming the destination repository (the one line of the root SOURCE
     file; owner and name compared without letter case) is https, spells the owner and the name as SOURCE does, and
     names a place GitHub serves for a repository; a Go module path naming it (github.com/<owner>/<name> with no
     scheme) is spelled as go.mod's module line spells it. The two spellings differ on purpose — the URL as the owner
     gave it, the module path in the lowercase the owner chose on 2026-09-25 — and each has one form. The
     reconciliation's evidence (docs/reconciliation/evidence/) is left out: it quotes command output verbatim, this
     check's probes' planted misspellings among it.

This file names no former coordinate: the identity guard (hack/identity_guard.sh) holds every one of those to the
residual-identity ledger, row by row.

Usage: link_check.py [--list]   (--list prints every link and coordinate checked, one per line)
Exit 0 when every link resolves and every coordinate has its form; 1 naming each one that does not.
"""
import argparse
import os
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parent.parent
COMPENDIUM = "docs/PODARO_COMPENDIUM.md"
# The reconciliation's evidence quotes what the checks printed, verbatim — this check's own probes plant misspelled
# coordinates, and their findings quote them — so the coordinates' rule leaves it out, as the SPDX check and the
# identity guard leave out the evidence they would otherwise read as claims.
EVIDENCE = "docs/reconciliation/evidence/"
BINARY_SUFFIXES = (".woff2", ".png", ".ico", ".gz", ".db")
SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(`+)(?:(?!\1).)+?\1")
# An inline link or image: [text](target "title"), the target optionally in angle brackets.
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*(<[^>]*>|[^\s()]*(?:\([^\s()]*\)[^\s()]*)*)(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?\s*\)")
# A reference definition, [label]: target — never a footnote, [^label]: text.
REFDEF = re.compile(r"^ {0,3}\[(?!\^)[^\]]+\]:\s*(<[^>]*>|\S+)")
AUTOLINK = re.compile(r"<((?:https?|mailto):[^>\s]*)>")
ANCHOR = re.compile(r"""\b(?:id|name)\s*=\s*["']([^"']+)["']""")
HEADING = re.compile(r"^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
# Any URL on github.com, in any text; and a scheme-less github.com/<owner>/<name>, as a module path is written.
GITHUB_URL = re.compile(r"(?i)\b(https?)://(?:www\.)?github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)((?:/[^\s`'\"<>)\]|,;]*)?)")
MODULE_PATH = re.compile(r"(?i)(?<![/\w.-])github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)")
# What GitHub serves under a repository: the first path segment after owner/name.
REPO_PLACES = ("releases", "issues", "pulls", "pull", "security", "tree", "blob", "commit", "commits", "compare",
               "tags", "discussions", "actions", "archive", "raw", "wiki", "labels", "milestones")


def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p and (ROOT / p).is_file())


def text(path):
    if path.endswith(BINARY_SUFFIXES):
        return None
    data = (ROOT / path).read_bytes()
    return None if b"\0" in data[:8000] else data.decode("utf-8", "replace")


def source_and_module():
    source = (ROOT / "SOURCE").read_text(encoding="utf-8").strip()
    m = re.fullmatch(r"https://github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)", source)
    module = re.search(r"(?m)^module\s+(\S+)", (ROOT / "go.mod").read_text(encoding="utf-8"))
    return source, (m.groups() if m else None), (module.group(1) if module else "")


def prose_lines(t):
    """A Markdown file's lines outside fenced code, each with its number and its code spans blanked."""
    fence = None
    for n, line in enumerate(t.split("\n"), 1):
        m = FENCE.match(line)
        if m:
            mark = m.group(1)
            if fence is None:
                fence = mark
            elif mark[0] == fence[0] and len(mark) >= len(fence) and not line.strip()[len(mark):].strip():
                fence = None
            continue
        if fence is None:
            yield n, CODE_SPAN.sub(lambda s: " " * len(s.group(0)), line)


def compendium_own_lines(t):
    """The compendium's lines outside its mirrored parts: its preamble and its banners."""
    sys.path.insert(0, str(ROOT / "hack"))
    try:
        import compendium_check as cc  # noqa: E402 — a sibling script, for its part map
    finally:
        sys.path.pop(0)
    lines = t.split("\n")
    heads = [i + 1 for i, x in enumerate(lines) for part, _ in cc.PARTS if x.startswith(f"# ━━━ Part {part} · ")]
    own = set(range(1, (heads[0] if heads else len(lines) + 1)))
    own.update(heads)
    return own


def slug(heading, seen):
    """GitHub's anchor for a heading: its rendered text, lower case, punctuation dropped, spaces as hyphens;
    a repeat gains -1, -2, …"""
    s = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)       # a link or image renders as its text
    s = re.sub(r"<[^>]+>", "", s).replace("`", "")
    s = re.sub(r"(\*\*|__|\*|~~)", "", s)
    s = "".join(c for c in unicodedata.normalize("NFC", s.lower())
                if c in " -_" or unicodedata.category(c)[0] in "LNM")
    s = s.replace(" ", "-")
    n = seen.get(s, 0)
    seen[s] = n + 1
    return s if n == 0 else f"{s}-{n}"


def anchors(path, cache):
    if path not in cache:
        t = text(path) or ""
        seen, found = {}, set()
        for _, line in prose_lines(t):
            h = HEADING.match(line)
            if h:
                found.add(slug(h.group(2), seen))
        found.update(ANCHOR.findall(t))
        cache[path] = found
    return cache[path]


def links_of(path, t):
    """(line, target) for every link a Markdown file makes."""
    own = compendium_own_lines(t) if path == COMPENDIUM else None
    for n, line in prose_lines(t):
        if own is not None and n not in own:
            continue
        for m in INLINE.finditer(line):
            yield n, m.group(1).strip("<>")
        m = REFDEF.match(line)
        if m:
            yield n, m.group(1).strip("<>")
        for m in AUTOLINK.finditer(line):
            yield n, m.group(1)


def check_relative(path, n, target, files, dirs, cache):
    raw, _, frag = target.partition("#")
    raw = unquote(raw.split("?", 1)[0])
    if raw:
        base = Path(path).parent if not raw.startswith("/") else Path(".")
        resolved = os.path.normpath(str(base / raw.lstrip("/")))
        if resolved.startswith(".."):
            return f"{path}:{n}: `{target}` leaves the repository"
        if resolved != "." and resolved not in files and resolved not in dirs:
            return f"{path}:{n}: `{target}` — no tracked file or directory {resolved}"
    else:
        resolved = path
    if frag and resolved in files and resolved.endswith(".md") and unquote(frag).lower() not in {
            a.lower() for a in anchors(resolved, cache)}:
        return f"{path}:{n}: `{target}` — {resolved} has no heading or anchor #{frag}"
    return None


def check_absolute(path, n, target):
    scheme = SCHEME.match(target).group(1).lower()
    if scheme == "mailto":
        addr = unquote(target[len("mailto:"):].split("?", 1)[0])
        return None if EMAIL.match(addr) else f"{path}:{n}: `{target}` — a mailto: link names one address"
    if scheme not in ("http", "https"):
        return f"{path}:{n}: `{target}` — {scheme}: is not a link a reader can follow from this repository's pages"
    try:
        u = urlsplit(target)
        port = u.port
    except ValueError as e:
        return f"{path}:{n}: `{target}` — {e}"
    host = u.hostname or ""
    if not host or ("." not in host and host != "localhost"):
        return f"{path}:{n}: `{target}` — no host"
    if u.username or u.password:
        return f"{path}:{n}: `{target}` — a credential in a link"
    if re.search(r"\s", target) or (port is not None and not 0 < port < 65536):
        return f"{path}:{n}: `{target}` — malformed"
    return None


def check_coordinates(path, t, dest, module):
    """The destination's URLs spelled as SOURCE spells them, at a place GitHub serves; its module path as go.mod's."""
    problems, seen = [], []
    owner, name = dest
    for n, line in enumerate(t.split("\n"), 1):
        for m in GITHUB_URL.finditer(line):
            # A name never ends in a dot: one there ends the sentence the URL ends.
            scheme, o, r, rest = m.group(1), m.group(2), m.group(3).rstrip("."), m.group(4) or ""
            bare = r[:-4] if r.lower().endswith(".git") else r
            if (o.lower(), bare.lower()) != (owner.lower(), name.lower()):
                continue
            url = m.group(0).rstrip(".:")
            seen.append((path, n, url))
            if scheme.lower() != "https":
                problems.append(f"{path}:{n}: `{url}` — the destination is https")
            if (o, bare) != (owner, name):
                problems.append(f"{path}:{n}: `{url}` — spelled otherwise than SOURCE: github.com/{owner}/{name}")
            first = rest.strip("/").split("/", 1)[0].split("#", 1)[0].split("?", 1)[0]
            if first and first.rstrip(".:…") not in REPO_PLACES:
                problems.append(f"{path}:{n}: `{url}` — /{first} is no place GitHub serves for a repository")
            if r != bare and rest.strip("/"):
                problems.append(f"{path}:{n}: `{url}` — a clone URL (.git) names nothing below it")
        for m in MODULE_PATH.finditer(line):
            o, r = m.group(1), m.group(2).rstrip(".")
            if (o.lower(), r.lower()) != (owner.lower(), name.lower()):
                continue
            seen.append((path, n, f"github.com/{o}/{r}"))
            if f"github.com/{o}/{r}" != module:
                problems.append(f"{path}:{n}: `github.com/{o}/{r}` — a module path is spelled as go.mod's: {module}")
    return problems, seen


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--list", action="store_true", help="print every link and coordinate checked")
    opts = ap.parse_args(argv[1:])
    files = tracked()
    fileset = set(files)
    dirs = {str(p) for f in files for p in Path(f).parents if str(p) != "."}
    source, dest, module = source_and_module()
    failures = []

    def verdict(title, problems, good):
        shown = "; ".join(problems[:12]) + (f"; … and {len(problems) - 12} more" if len(problems) > 12 else "")
        print(f"{'✓' if not problems else '✗'} {title}: {good if not problems else shown}")
        failures.extend(problems)

    if dest is None:
        verdict("SOURCE", [f"SOURCE reads {source!r}: not https://github.com/<owner>/<name>"], "")
        return 1
    if module.lower() != f"github.com/{dest[0]}/{dest[1]}".lower():
        verdict("go.mod", [f"go.mod's module {module!r} does not follow SOURCE's github.com/{dest[0]}/{dest[1]}"], "")

    md = [f for f in files if f.endswith(".md")]
    rel, absolute, cache, listing = [], [], {}, []
    rel_problems, abs_problems = [], []
    for f in md:
        t = text(f) or ""
        for n, target in links_of(f, t):
            listing.append(f"{f}:{n}: {target}")
            if SCHEME.match(target):
                absolute.append(target)
                p = check_absolute(f, n, target)
                if p:
                    abs_problems.append(p)
            elif target:
                rel.append(target)
                p = check_relative(f, n, target, fileset, dirs, cache)
                if p:
                    rel_problems.append(p)
    print(f"== the tree: {len(files)} tracked files, {len(md)} of them Markdown; SOURCE: {source}; go.mod: module {module}")
    verdict(f"1. {len(rel)} relative links", rel_problems,
            f"every one resolves to a tracked file or directory ({sum('#' in r for r in rel)} with a fragment, each an anchor of its target)")
    verdict(f"2. {len(absolute)} absolute links", abs_problems,
            "every one well formed — form only, nothing fetched (" + ", ".join(
                f"{k}: {v}" for k, v in sorted(_count(SCHEME.match(a).group(1).lower() for a in absolute).items())) + ")")
    coord_problems, seen = [], []
    evidence = [f for f in files if f.startswith(EVIDENCE)]
    for f in files:
        t = text(f) if not f.startswith(EVIDENCE) else None
        if t is None:
            continue
        p, s = check_coordinates(f, t, dest, module)
        coord_problems += p
        seen += s
    urls = [s for s in seen if "://" in s[2]]
    verdict(f"3. {len(urls)} URLs of the destination and {len(seen) - len(urls)} of its module path, in {len({s[0] for s in seen})} files",
            coord_problems, f"every URL spelled as SOURCE, at a place GitHub serves; every module path as go.mod's "
            f"({len(evidence)} files of the reconciliation's evidence, {EVIDENCE}, left out: they quote what the checks found)")
    if opts.list:
        print("== the links")
        print("\n".join(listing))
        print("== the coordinates")
        print("\n".join(f"{p}:{n}: {u}" for p, n, u in seen))
    print()
    if failures:
        print(f"link check: FAIL — {len(failures)} finding(s)")
        return 1
    print("link check: PASS — every relative link resolves, every absolute one is well formed (offline, form only), "
          "and the project's coordinates have their one form each")
    return 0


def _count(items):
    out = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


if __name__ == "__main__":
    sys.exit(main(sys.argv))
