#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# THIRD-PARTY-NOTICES.md, generated (the reconciliation plan's R5 task 5;
# the reconciliation §7.1, §7.3): every third-party notice and licence
# text the podaro binary compiles in or embeds, in one file that travels
# in the release tarball, is embedded in the binary (legal.go) for
# `podaro legal --licenses` and the console's /legal page, and is written
# to <state>/legal/ by `podaro system install`.
#
#   hack/third_party_notices.sh           rewrite THIRD-PARTY-NOTICES.md
#   hack/third_party_notices.sh --check   change nothing; exit 1, showing the
#                                         difference, when the committed file
#                                         is not what its sources give
#
# Its sources:
#
#   - `go-licenses report ./...` for linux/amd64 and linux/arm64, the two
#     architectures a release carries (hack/release_package.sh): the Go
#     modules linked into the binary, and the licence file go-licenses found
#     for each. Only that file's path is taken from it. Not the licence
#     name its classifier reports — it reads the modernc.org modules'
#     BSD-3-Clause texts as other licences, and its answer moves with the
#     confidence threshold — and not the licence URL, which it looks up on
#     the network and which comes back different from one machine to the
#     next. Each module's licence is the table below, written by a person
#     who read the text; a module the table does not name stops the script,
#     so a new dependency is read before it is listed.
#   - every licence, notice and copying file in each module's own root
#     (LICENSE, LICENSE-GO, SQLITE-LICENSE, NOTICE, …), reproduced as its
#     authors published it: an Apache-2.0 module's NOTICE is part of what
#     its licence asks to be passed on.
#   - the Go distribution's LICENSE, for the standard library and runtime
#     every Go binary carries (go-licenses does not list them).
#   - console/VENDOR.md's two tables and console/assets/LICENSES/*.txt, for
#     the scripts and fonts the console bundle embeds and the code a vendored
#     script bundles (the Vue reactivity code in the Alpine build — the
#     reconciliation §7.3), held to what each script's own licence comment
#     names.
#   - NOTICE's third-party block, verbatim: Alpine's MIT text, the Vue
#     packages' notice, the fonts' notices, the password list's source, the
#     prototype's licence, the Code of Conduct's attribution.
#
# What it reads is the same on every machine that builds this commit — the
# modules go.sum pins, the Go distribution's LICENSE, the tracked files —
# so the output is too, and CI holds the committed copy to it. Needs
# go-licenses (go install github.com/google/go-licenses@v1.6.0, the
# version CI's licenses job installs) and python3.
set -euo pipefail
cd "$(dirname "$0")/.."

check=0
case "${1:-}" in
  --check) check=1 ;;
  "") ;;
  *) echo "usage: hack/third_party_notices.sh [--check]" >&2; exit 2 ;;
esac

GL="$(command -v go-licenses || true)"
[ -n "$GL" ] || GL="$(go env GOPATH)/bin/go-licenses"
if [ ! -x "$GL" ]; then
  echo "✗ go-licenses is not installed" >&2
  echo "  next      go install github.com/google/go-licenses@v1.6.0   (the version CI's licenses job uses)" >&2
  exit 2
fi

module="$(go list -m)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
printf '{{range .}}{{.Name}}\t{{.LicensePath}}\n{{end}}' >"$tmp/paths.tmpl"
for arch in amd64 arm64; do
  if ! GOOS=linux GOARCH="$arch" "$GL" report ./... --ignore "$module" --confidence_threshold=0.85 \
      --template "$tmp/paths.tmpl" >"$tmp/paths-$arch" 2>"$tmp/err-$arch"; then
    cat "$tmp/err-$arch" >&2
    echo "✗ go-licenses report failed for linux/$arch" >&2
    exit 1
  fi
done

python3 - "$(go env GOMODCACHE)" "$(go env GOROOT)" "$tmp" >"$tmp/THIRD-PARTY-NOTICES.md" <<'PY'
import os
import re
import sys
from pathlib import Path

modcache, goroot, tmp = sys.argv[1:4]

# Each linked module's licence, as a person read its text (R5, 2026-09-26). The modernc.org modules are
# BSD-3-Clause ("Neither the names of the authors nor the names of the contributors…"); modernc.org/sqlite
# also carries SQLite's public-domain dedication, and gopkg.in/yaml.v3 is MIT for the files ported from
# libyaml and Apache-2.0 for the rest, with a NOTICE. A module missing here stops the script.
LICENSES = {
    "github.com/dustin/go-humanize": "MIT",
    "github.com/google/uuid": "BSD-3-Clause",
    "github.com/remyoudompheng/bigfft": "BSD-3-Clause",
    "github.com/santhosh-tekuri/jsonschema/v6": "Apache-2.0",
    "github.com/spf13/cobra": "Apache-2.0",
    "github.com/spf13/pflag": "BSD-3-Clause",
    "golang.org/x/crypto": "BSD-3-Clause",
    "golang.org/x/exp": "BSD-3-Clause",
    "golang.org/x/sys": "BSD-3-Clause",
    "golang.org/x/term": "BSD-3-Clause",
    "golang.org/x/text": "BSD-3-Clause",
    "gopkg.in/yaml.v3": "MIT AND Apache-2.0",
    "modernc.org/libc": "BSD-3-Clause",
    "modernc.org/mathutil": "BSD-3-Clause",
    "modernc.org/memory": "BSD-3-Clause",
    "modernc.org/sqlite": "BSD-3-Clause",
}
NOTICE_FILE = re.compile(r"(?i)(licen[cs]e|copying|^notice)")


def fail(msg):
    print("✗ " + msg, file=sys.stderr)
    sys.exit(1)


def unescape(path):
    # The module cache writes an upper-case letter as "!" and the letter in lower case.
    return re.sub(r"!([a-z])", lambda m: m.group(1).upper(), path)


def text_of(path):
    try:
        text = Path(path).read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{path} is not UTF-8 text; reproduce it by hand after reading it")
    text = text.replace("\r\n", "\n").rstrip("\n") + "\n"
    return text


def fenced(text):
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}text\n{text}{fence}\n"


# The linked modules, from both architectures' reports.
modules = {}
for arch in ("amd64", "arm64"):
    for line in Path(tmp, f"paths-{arch}").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        name, _, lic = line.partition("\t")
        if not lic:
            fail(f"go-licenses found no licence file for {name} (linux/{arch}); read the module and add its text by hand")
        rel = os.path.relpath(lic, modcache)
        if rel.startswith("..") or "@" not in rel:
            fail(f"the licence file of {name} is not in the module cache ({lic}); a replaced or vendored module is read by hand")
        mod, rest = rel.split("@", 1)
        version = rest.split("/", 1)[0]
        root = os.path.join(modcache, f"{mod}@{version}")
        mod = unescape(mod)
        entry = modules.setdefault(mod, {"version": version, "root": root, "extra": set(), "packages": set()})
        if entry["version"] != version:
            fail(f"{mod} is linked at two versions ({entry['version']}, {version})")
        entry["packages"].add(name)
        inner = os.path.relpath(lic, root)
        if os.sep in inner:
            entry["extra"].add(inner)  # a licence file below the module's root: reproduced too

unknown = sorted(set(modules) - set(LICENSES))
if unknown:
    fail("no licence recorded for " + ", ".join(unknown) + " — read its licence text, then add it to the table in "
         "hack/third_party_notices.sh (and check hack/allowed-licenses.txt)")
gone = sorted(set(LICENSES) - set(modules))
if gone:
    fail("the table names modules the binary no longer links: " + ", ".join(gone) + " — remove them from it")

for mod, e in modules.items():
    files = sorted(f for f in os.listdir(e["root"]) if NOTICE_FILE.search(f) and os.path.isfile(os.path.join(e["root"], f)))
    e["files"] = files + sorted(e["extra"])
    if not e["files"]:
        fail(f"no licence file in {e['root']}")

# The console's vendored assets, from console/VENDOR.md's pin table (a row ends with the file's sha256), and the
# code a vendored file bundles, from its second table (a row ends with its licence text).
vendored, bundled = [], []
for line in Path("console/VENDOR.md").read_text(encoding="utf-8").splitlines():
    m = re.match(r"^\| `([^`]+)` \| `([^`]+)` (\S+)[^|]*\| ([^|]+?) \|.*\| `[0-9a-f]{64}` \|$", line)
    if m:
        vendored.append({"file": m.group(1), "package": m.group(2), "version": m.group(3), "license": m.group(4).strip()})
    m = re.match(r"^\| `([^`]+)` \| `([^`]+)` (\S+) \| ([^|]+?) \| `[A-Za-z0-9+/]+=*` \| `(assets/LICENSES/[^`]+)` \|$", line)
    if m:
        bundled.append({"file": m.group(1), "package": m.group(2), "version": m.group(3), "license": m.group(4).strip(),
                        "text": m.group(5)})
if len(vendored) < 8:
    fail(f"console/VENDOR.md's table gave {len(vendored)} rows; it pins more")
packages = {}
for v in vendored:
    packages.setdefault((v["package"], v["version"], v["license"]), []).append(v["file"])

# What each vendored script's own "Bundled license information" comment names — the packages its build compiled
# in (the reconciliation §7.3: the Alpine build carries Vue's reactivity code) — must be exactly the rows of the
# second table for that file, each row's licence text present: a bundle upgraded with other code stops the script.
for f in sorted({v["file"] for v in vendored if v["file"].endswith(".js")}):
    src = Path("console/assets", f).read_text(encoding="utf-8")
    at = src.find("/*! Bundled license information:")
    named = set()
    if at >= 0:
        comment = src[at:src.find("*/", at)]
        named = set(re.findall(r"^\s*\* (@?[\w./-]+) v(\d[\w.+-]*)$", comment, re.M))
        if not named:
            fail(f"console/assets/{f}'s bundled licence comment names no package and version this script can read")
    rows = {(b["package"], b["version"]) for b in bundled if b["file"] == f}
    if named != rows:
        fail(f"console/assets/{f} bundles " + (", ".join(f"{p} {v}" for p, v in sorted(named)) or "nothing")
             + " by its own licence comment, and console/VENDOR.md's table of bundled code lists "
             + (", ".join(f"{p} {v}" for p, v in sorted(rows)) or "nothing") + " — make the table say what the file carries")
for b in bundled:
    if b["file"] not in {v["file"] for v in vendored}:
        fail(f"console/VENDOR.md: {b['package']} is bundled in {b['file']}, which the pin table does not pin")
    if not Path("console", b["text"]).is_file():
        fail(f"console/VENDOR.md: {b['package']}'s licence text console/{b['text']} does not exist")

notice = Path("NOTICE").read_text(encoding="utf-8")
at = notice.find("Third-party assets vendored into the console")
if at < 0:
    fail("NOTICE has no third-party block (it begins \"Third-party assets vendored into the console\")")
block = notice[at:].rstrip("\n") + "\n"
if re.search(r"Jeremiah\s+Ross", block):
    fail("NOTICE's third-party block names the owner; third-party notices never carry the owner's name")

out = []
w = out.append
w("<!-- SPDX-License-Identifier: AGPL-3.0-only -->")
w("<!-- Generated by hack/third_party_notices.sh — never edited by hand: CI runs it with --check and refuses a stale copy. -->")
w("# Third-party notices")
w("")
w("The notices and licence texts of the third-party material in the `podaro` binary: the Go standard library and the "
  "Go modules compiled into it, and the scripts, fonts and data embedded in it. Each component below is its authors' "
  "work and keeps its own licence; every text is reproduced as its authors published it. This file only gathers them. "
  "Podaro's own material and its licence are `NOTICE` and `LICENSE`, and the Podaro name is `TRADEMARKS.md`'s. "
  "`podaro legal --licenses` prints this file from the binary itself.")
w("")
w("It is an inventory of what the binary compiles in and embeds — the Go modules as `go-licenses report ./...` lists "
  "them for linux/amd64 and linux/arm64, the console's pinned assets (`console/VENDOR.md`), and `NOTICE`'s "
  "third-party block. It is not a container or virtual-machine SBOM: the images a lab pulls when it is created are "
  "not redistributed by Podaro, and each module's `license.spdx` names what the software it runs is under.")
w("")
w("## Components")
w("")
w("| Component | Version | Licence | Where it is in the binary |")
w("|---|---|---|---|")
w("| the Go standard library and runtime | — | BSD-3-Clause | compiled in, from the Go release that built the binary (a release's `RELEASE-MANIFEST.json` names it) |")
for mod in sorted(modules):
    w(f"| `{mod}` | {modules[mod]['version']} | {LICENSES[mod]} | compiled in |")
for (pkg, ver, lic), files in sorted(packages.items()):
    shown = ", ".join(f"`{f}`" for f in files)
    w(f"| `{pkg}` (npm) | {ver} | {lic} | embedded in the console bundle: {shown} |")
for b in sorted(bundled, key=lambda b: (b["package"], b["version"])):
    by = next(v for v in vendored if v["file"] == b["file"])
    w(f"| `{b['package']}` (npm) | {b['version']} | {b['license']} | embedded in the console bundle: compiled into "
      f"`{b['file']}` by `{by['package']}` {by['version']} |")
w("| the common-password list | — | MIT | embedded data, `internal/auth/common-passwords.txt`: the NCSC \"100k most used passwords\" "
  "list as redistributed in SecLists, filtered to entries of 12 or more characters; its header records the "
  "revision of the source file it reproduces from |")
w("")
w("## NOTICE's third-party block")
w("")
w("As `NOTICE` carries it:")
w("")
w(fenced(block).rstrip("\n"))
w("")
w("## Licence texts")
w("")
w("### the Go standard library and runtime — `LICENSE` of the Go distribution")
w("")
w(fenced(text_of(os.path.join(goroot, "LICENSE"))).rstrip("\n"))
for mod in sorted(modules):
    e = modules[mod]
    for f in e["files"]:
        w("")
        w(f"### `{mod}` {e['version']} — `{f}`")
        w("")
        w(fenced(text_of(os.path.join(e["root"], f))).rstrip("\n"))
for lic in sorted(Path("console/assets/LICENSES").glob("*.txt")):
    w("")
    w(f"### the console's vendored assets — `console/assets/LICENSES/{lic.name}`")
    w("")
    w(fenced(text_of(lic)).rstrip("\n"))
text = "\n".join(out) + "\n"
if re.search(r"Jeremiah\s+Ross", text):
    fail("the generated notices name the owner; third-party notices never carry the owner's name")
sys.stdout.write(text)
PY

if [ "$check" = 1 ]; then
  if cmp -s "$tmp/THIRD-PARTY-NOTICES.md" THIRD-PARTY-NOTICES.md; then
    echo "✓ THIRD-PARTY-NOTICES.md is what its sources give ($(grep -c '^### .* — `' THIRD-PARTY-NOTICES.md) licence texts)"
    exit 0
  fi
  diff -u THIRD-PARTY-NOTICES.md "$tmp/THIRD-PARTY-NOTICES.md" | head -60 >&2 || true
  echo "✗ THIRD-PARTY-NOTICES.md is stale: its sources give something else" >&2
  echo "  next      hack/third_party_notices.sh, then commit THIRD-PARTY-NOTICES.md" >&2
  exit 1
fi
cp "$tmp/THIRD-PARTY-NOTICES.md" THIRD-PARTY-NOTICES.md
echo "✓ wrote THIRD-PARTY-NOTICES.md ($(grep -c '^### .* — `' THIRD-PARTY-NOTICES.md) licence texts)"
