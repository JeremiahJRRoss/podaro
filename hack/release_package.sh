#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Plan S10: the release artifacts INSTALL §2 step 1 and §5 name, built
# from this checkout and nothing else. It tags nothing, pushes nothing,
# publishes nothing — those are the owner's acts (docs/reviews/0002).
#
#   hack/release_package.sh <version> [outdir]      # outdir default: dist
#
# It writes only the version's own directory and the `latest` line beside
# it, and refuses a checkout that is not clean: the rest of the output
# directory is the operator's. An output directory inside the repository
# may hold release files only, or be ignored by git as `dist/` is —
# anything else untracked there is a dirty checkout like any other.
#
# What it writes, laid out exactly as a release page serves it — which is
# also the mirror layout `podaro system upgrade --from` reads (INSTALL §6):
#
#   <out>/download/v<version>/podaro-<version>-linux-<arch>        the binary
#   <out>/download/v<version>/podaro_v<version>_linux_<arch>.tar.gz  the tarball
#   <out>/download/v<version>/SHA256SUMS                          both digests
#   <out>/latest                                                  /tag/v<version>
#
# Two names, because two paths fetch them: INSTALL §2 step 1's script and
# `system upgrade` download the bare binary (`podaro-<version>-linux-<arch>`,
# the name internal/system.AssetName resolves), while INSTALL §5's offline
# path carries the tarball and extracts `podaro` from it. Both exist once
# per architecture the release supports — amd64 and arm64, since the asset
# name is resolved from the *operator's* machine, not the builder's — and
# one SHA256SUMS covers all of them, in the format `sha256sum -c` reads.
# PODARO_RELEASE_ARCHES overrides the list.
#
# The version must be the one the VERSION file carries: the binary reads
# its version from that embedded file, so packaging any other version
# would ship a binary that disagrees with its own file name. Bumping
# VERSION is part of the release, and it is the owner's act.
#
# The build is deterministic — `-trimpath`, no build id, no cgo, a tar
# with sorted names and zeroed ownership and times, gzip without a
# timestamp — and the script proves it by building twice and comparing
# digests. That is the "reproducible-build instructions in the
# repository" INSTALL §2 step 1 offers in place of signing: anyone can
# re-run this script on the same commit with the same Go version and
# compare the digest to SHA256SUMS.
set -euo pipefail
cd "$(dirname "$0")/.."

version="${1:-}"
out="${2:-dist}"
if [ -z "$version" ]; then
  echo "usage: hack/release_package.sh <version> [outdir]" >&2
  exit 2
fi
declared="$(tr -d '[:space:]' <VERSION)"
if [ "$version" != "$declared" ]; then
  cat >&2 <<EOF
✗ VERSION says $declared, and you asked to package $version
  cause     the binary reads its version from the embedded VERSION file, so
            an artifact named for another version would contradict itself
  next      bump VERSION to $version in a commit of its own, then re-run
EOF
  exit 2
fi

# The *host* has to be Linux, and GOHOSTOS is what says so. The old check
# read `go env GOOS`, which is the target: a macOS builder with GOOS=linux
# configured passed it and then tried to execute a Linux binary whose
# architecture happened to match its own. This goes
# further than the execution guard, because the script needs a GNU
# userland anyway — `tar --sort=name --owner=0` and `sha256sum` are not
# BSD tar and not macOS — so a foreign host cannot finish, and a clear
# refusal beats a half-written release.
hostos="$(go env GOHOSTOS)"
if [ "$hostos" != "linux" ]; then
  cat >&2 <<EOF
✗ a release is built on a Linux host; this one is $hostos
  cause     the packaging uses GNU tar and sha256sum, and the release is
            verified by running the binary it just built — neither works here
  next      build the release on a Linux host, as CI does (Podaro is
            Linux-server software: User Manual §3)
EOF
  exit 2
fi

# The architectures a release carries, not the one this runner happens to
# be. `internal/system.AssetName` resolves the asset from the *operator's*
# runtime architecture, and INSTALL §2 step 1's install script "resolves
# your OS/architecture" — so a release that carried only the builder's
# would 404 for everyone else, which is what CI on one amd64 runner would
# have published. Go cross-compiles these
# with CGO already off, so both come from one commit on one machine.
arches="${PODARO_RELEASE_ARCHES:-amd64 arm64}"
# GOHOSTARCH, not GOARCH, for the same reason GOHOSTOS above: GOARCH is
# the *target*, so a builder who has GOARCH=arm64 configured (in the
# environment or by `go env -w`) would have the arm64 artifact classified
# as native and then executed, which ends in an exec-format error on an
# amd64 machine. With the host known to be
# Linux, the architecture is all that is left to compare.
native="$(go env GOHOSTARCH)"
dir="$out/download/v${version}"

# ── The toolchain's own settings have to be the defaults ──
#
# A release has to be what a *stock* toolchain produces, because INSTALL §2
# step 1 offers rebuild-and-compare in place of signing and the reader who
# takes that offer will have a stock one. Three settings survive everything
# the build below pins and still change what the compiler puts in the
# binary: GOEXPERIMENT, GOFLAGS and GOFIPS140. Each can be persisted with
# `go env -w`, each is inherited here, and each then leaves no trace — the
# pair of builds inherits the same setting, so the comparison agrees with
# itself, and the toolchain line this script prints cannot explain the
# difference. Measured on this branch with
# go1.24.7, same commit, same flags, amd64: the stock binary is
# 0fb8cf1d…, GOEXPERIMENT=newinliner gives a6403422…, and
# GOFIPS140=v1.0.0 gives 06e0527d….
#
# The default each is compared against is *asked*, not written down:
# `GOENV=off` disables the go env file and `env -u` drops the environment,
# so the second `go env` is this toolchain's own answer. Writing the
# defaults down would rot — GOFIPS140's is the word `off` while the other
# two are empty, and `go env` prints an empty value with status 0 for a
# name it does not know (measured), so a hardcoded `off` would refuse
# every release on a Go that has no GOFIPS140, which is any Go before 1.24
# and any Go after it is retired.
#
# Refused rather than cleared, because no value means "the default".
# GOEXPERIMENT= is ignored, since an empty environment variable does not
# override the go env file (measured: still newinliner, still a6403422…),
# and GOEXPERIMENT=none zeroes the toolchain's own baseline as well — on
# amd64 that drops the register ABI — which gives a third binary
# (faceb429…). GOENV=off does restore the default digest, but it would
# also discard the builder's proxy, toolchain and module-cache settings,
# and a release script has no business quietly changing how modules
# resolve. Unsetting it is the builder's call, and a refusal says so.
#
# Asked once per target, because a toolchain's experiment baseline is per
# GOOS/GOARCH and `go env` prints only what differs from it: empty means
# "this target's default", anything else is the builder's. GOFLAGS does
# not vary by target and is therefore asked twice on a two-architecture
# release; one loop is clearer than two, and a `go env` call costs nothing
# next to a build.
for arch in $arches; do
  for setting in GOEXPERIMENT GOFLAGS GOFIPS140; do
    value="$(GOOS=linux GOARCH="$arch" go env "$setting")"
    stock="$(GOENV=off GOOS=linux GOARCH="$arch" \
      env -u GOEXPERIMENT -u GOFLAGS -u GOFIPS140 go env "$setting")"
    if [ "$value" != "$stock" ]; then
      # What removes the value depends on where it came from. `go env -u`
      # deletes what `go env -w` persisted and nothing else (go help env),
      # so advising it for an exported variable would delete an unrelated
      # preference from the file and the next run would refuse all the
      # same — measured: with `-mod=mod` in the file and `-tags=x` in the
      # environment, `go env` reports `-tags=x`.
      # So the file's own contribution is asked for separately: same probe
      # as the baseline above, with the file left on.
      persisted="$(GOOS=linux GOARCH="$arch" \
        env -u GOEXPERIMENT -u GOFLAGS -u GOFIPS140 go env "$setting")"
      if printenv "$setting" >/dev/null; then exported=yes; else exported=no; fi
      if [ "$persisted" != "$stock" ]; then written=yes; else written=no; fi
      case "$exported/$written" in
      yes/no)
        source="the environment"
        remedy="unset $setting" ;;
      no/yes)
        source="$(go env GOENV)"
        remedy="go env -u $setting" ;;
      yes/yes)
        source="the environment, over ${persisted:-an empty value} in $(go env GOENV)"
        remedy="unset $setting; go env -u $setting" ;;
      *)
        source="the toolchain itself — neither the environment nor $(go env GOENV)"
        remedy="unset $setting; go env -u $setting" ;;
      esac
      cat >&2 <<EOF
✗ this builder's Go toolchain is configured: $setting=$value (target linux/$arch)
  cause     a release is what a stock toolchain produces — INSTALL §2 step 1
            offers rebuild-and-compare in place of signing — and $setting
            changes the binary without changing either digest this run
            compares or the toolchain line it prints; this toolchain's own
            default is ${stock:-the empty value}, and this value comes from
            $source
  next      $remedy
EOF
      exit 2
    fi
  done
done

# ── The checkout has to be clean, and the build carries no VCS stamp ──
#
# Two different reasons, one check:
# provenance, because an artifact named for a version is a claim about a
# commit and a dirty tree is not that commit — and two builds of the same
# dirty tree agree with each other, so the comparison below cannot catch
# it; and reproducibility, because Go's default `-buildvcs=auto` stamps
# the revision and the modified flag into the binary, which would make the
# digest depend on the repository's state rather than on the source. The
# build below turns stamping off, so a rebuild from a git checkout and one
# from an exported source tree give the same bytes; this check is what
# keeps the version honest about which commit that source is.
#
# What this script writes under the output directory is its own leftovers
# and is not what "dirty" means here — but the exemption is narrow in two
# ways. It covers only the release layout (`<out>/download/…` and
# `<out>/latest`), because exempting a whole caller-supplied directory
# would hide source changes whenever that directory sits inside the tree
# (`--outdir internal` would have excused a modified internal/cli/root.go)
# and the script would then have packaged them while naming a clean commit.
# And it covers only *untracked* files: a tracked
# change is a source change wherever it lives.
#
# --untracked-files=all, because porcelain otherwise collapses a whole
# untracked directory into a single line (`?? artifacts/`), and then the
# per-path exemption matches nothing: the script refused its own second
# run into any output directory inside the repository that .gitignore does
# not already cover. The default `dist/` is ignored and round 1's fixture
# was an absolute path outside the tree, which is why neither noticed.
#
# -z, because porcelain C-quotes a path holding a quote or a backslash
# (`?? "quote\"dir/latest"`) and stripping the outer quotes does not decode
# it, so such a directory's own release files read as a dirty tree.
# With NUL-terminated records the pathname arrives as
# its own bytes and needs no decoding at all.
if git rev-parse --git-dir >/dev/null 2>&1; then
  # Where the output directory sits inside the repository, if it does at
  # all. realpath normalizes what a caller may reasonably write —
  # `./dist`, `dist//`, `$PWD/dist` — without requiring the directory to
  # exist yet, since it usually does not; a directory outside the tree
  # comes back as a ../ or absolute path and exempts nothing, which is
  # right, because it cannot make the checkout dirty either. If realpath
  # is unavailable the exemption is simply off: the script then refuses
  # its own leftovers, which is the safe direction and says which paths
  # it means.
  prefix=""
  exempt=0
  rel="$(realpath -m --relative-to="$(git rev-parse --show-toplevel)" "$out" 2>/dev/null || true)"
  case "$rel" in
  "" | .. | ../* | /*) : ;;
  .) exempt=1 ;;
  *) prefix="${rel%/}/" ; exempt=1 ;;
  esac
  dirty=""
  while IFS= read -r -d '' record; do
    # A record is `XY <path>`; a rename's source path follows as a record
    # of its own, which has no status field and is not a change by itself.
    [ "${#record}" -ge 4 ] && [ "${record:2:1}" = " " ] || continue
    if [ "$exempt" = 1 ] && [ "${record:0:2}" = "??" ]; then
      path="${record:3}"
      case "$path" in
      "${prefix}download/"*|"${prefix}latest") continue ;;
      esac
    fi
    dirty="${dirty}${record}"$'\n'
  done < <(git status --porcelain -z --untracked-files=all)
  dirty="${dirty%$'\n'}"
  if [ -n "$dirty" ]; then
    {
      echo "✗ the checkout is not clean, so an artifact built from it is not v$version"
      echo "  cause     a release is a claim about a commit; these paths are not committed:"
      printf '%s\n' "$dirty" | head -5 | sed 's/^/              /'
      echo "  next      commit or set aside those changes, then re-run"
    } >&2
    exit 2
  fi
  commit="$(git rev-parse HEAD)"
else
  commit="no git checkout — the source tree as it stands"
fi

# Only the version's own directory is replaced. An operator may keep other
# releases, or anything else, in the output directory: removing the whole
# of it would delete files this script never made.
rm -rf "$dir"
mkdir -p "$dir"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# One build command, used twice per architecture. CGO off keeps the binary
# static (INSTALL §2 step 1: "one static Go binary") and is what lets one
# machine build them all; -trimpath and an empty build id remove the two
# things that would otherwise vary by checkout path; and -buildvcs=false
# keeps the repository's own state out of the binary, so the digest is a
# function of the source and the target architecture and nothing else.
#
# The target feature levels are pinned to the baselines rather than
# inherited, because a builder who has persisted `go env -w GOAMD64=v3`
# gets a *different* binary from the same commit — measured on this
# branch: 68d48d99… against the default 25ace593… — which defeats the
# rebuild-and-compare INSTALL §2 step 1 offers in place of signing, and a
# v3 binary refuses to start on an amd64 host without AVX2.
# v1 and v8.0 are the documented defaults, so pinning
# them changes no digest a default builder produces; it only stops a
# configured one from producing something else. Each variable is ignored
# when the other architecture is the target.
build() {
  CGO_ENABLED=0 GOOS=linux GOARCH="$1" GOAMD64=v1 GOARM64=v8.0 \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$2" ./cmd/podaro
}

# The tarball holds the release's four working entries — `podaro`, which
# INSTALL §5's by-hand path extracts (`tar -xzf … -C ~/.local/bin podaro …`),
# `install.sh` and `install.test.yaml`, the installer INSTALL §2 runs and
# its test-host answers, and `podaroctl`, the wrapper that runs podaro as
# the account from any shell (INSTALL §2 step 6) — and, since the
# reconciliation plan's R5, what a recipient of the binary is owed beside
# it (the reconciliation §7.1): `LICENSE`, the AGPL text; `NOTICE`, the
# project's statement and the third-party block; `TRADEMARKS.md`, the name
# policy; `THIRD-PARTY-NOTICES.md`, every third-party notice and licence
# text the binary carries (hack/third_party_notices.sh); `LICENSES/`, the
# licence texts of compiled dependencies; `SOURCE-AND-BUILD.md`, where the
# source is and how this build is reproduced; and `RELEASE-MANIFEST.json`,
# written below. Sorted names, zeroed owners and times, and gzip without a
# name or timestamp keep it byte-identical across runs.
# Each entry's mode is set explicitly rather than inherited: `cp` applies
# the builder's umask, so the same commit packed under umask 077 would
# record 0700 and hand another machine a different tarball digest.
# chmod sets an absolute mode, so the tarball records
# the same bits whatever the environment.
TARBALL_ENTRIES="install.sh install.test.yaml podaro podaroctl LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md LICENSES/ SOURCE-AND-BUILD.md RELEASE-MANIFEST.json"
pack() {
  # shellcheck disable=SC2086
  tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime='@0' -cf - -C "$1" $TARBALL_ENTRIES | gzip -n -9 >"$2"
}

# Every binary first, each built twice and compared, so that the manifest
# every tarball carries can name all of them.
manifest=()
digests=()
for arch in $arches; do
  binary="podaro-${version}-linux-${arch}"
  stage="$work/$arch"
  mkdir -p "$stage"

  echo "◐ building            $binary"
  build "$arch" "$dir/$binary"
  chmod 0755 "$dir/$binary"
  echo "◐ building again      to prove the build is reproducible"
  build "$arch" "$stage/second"
  if [ "$(sha256sum <"$dir/$binary" | cut -d' ' -f1)" != "$(sha256sum <"$stage/second" | cut -d' ' -f1)" ]; then
    echo "✗ two builds of the same tree differ ($arch) — the release is not reproducible" >&2
    exit 1
  fi
  echo "✓ binary              $(du -h "$dir/$binary" | cut -f1) · linux/$arch · built twice · identical digest"
  digests+=("$binary" "$(sha256sum <"$dir/$binary" | cut -d' ' -f1)")
done

# RELEASE-MANIFEST.json: what the release is, for anyone rebuilding it to
# compare — the version, the Go release that built it, the architectures
# and each binary's digest, and the source location the binaries name
# (the root SOURCE file). No commit hash and no time: a documents-only
# closure commit must reproduce the tested tarball byte for byte
# (docs/code-execution/P1-close-out.md, step 7), and the tag is what names
# the commit. Written by hand, keys in a fixed order, so it is the same
# bytes on every run.
json_list() { local sep="" x; for x in "$@"; do printf '%s"%s"' "$sep" "$x"; sep=", "; done; }
{
  printf '{\n'
  printf '  "version": "%s",\n' "$version"
  printf '  "go": "%s",\n' "$(go env GOVERSION)"
  printf '  "build": "CGO_ENABLED=0 GOOS=linux GOARCH=<arch> GOAMD64=v1 GOARM64=v8.0 go build -trimpath -buildvcs=false -ldflags=\x27-s -w -buildid=\x27 ./cmd/podaro",\n'
  # shellcheck disable=SC2086
  printf '  "architectures": [%s],\n' "$(json_list $arches)"
  printf '  "binaries": {\n'
  i=0
  while [ $i -lt ${#digests[@]} ]; do
    sep=","; [ $((i + 2)) -ge ${#digests[@]} ] && sep=""
    printf '    "%s": "sha256:%s"%s\n' "${digests[$i]}" "${digests[$((i + 1))]}" "$sep"
    i=$((i + 2))
  done
  printf '  },\n'
  printf '  "source": "%s"\n' "$(tr -d '[:space:]' <SOURCE)"
  printf '}\n'
} >"$work/RELEASE-MANIFEST.json"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$work/RELEASE-MANIFEST.json" \
  || { echo "✗ RELEASE-MANIFEST.json is not valid JSON" >&2; exit 1; }
echo "✓ manifest            RELEASE-MANIFEST.json · version, Go $(go env GOVERSION), $(echo $arches | wc -w) architectures, their digests · no commit"

for arch in $arches; do
  binary="podaro-${version}-linux-${arch}"
  tarball="podaro_v${version}_linux_${arch}.tar.gz"
  stage="$work/$arch"

  cp "$dir/$binary" "$stage/podaro"
  chmod 0755 "$stage/podaro"
  cp install.sh "$stage/install.sh"
  chmod 0755 "$stage/install.sh"
  cp install.test.yaml "$stage/install.test.yaml"
  chmod 0644 "$stage/install.test.yaml"
  cp podaroctl "$stage/podaroctl"
  chmod 0755 "$stage/podaroctl"
  for f in LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md SOURCE-AND-BUILD.md; do
    cp "$f" "$stage/$f"
    chmod 0644 "$stage/$f"
  done
  rm -rf "$stage/LICENSES"
  mkdir "$stage/LICENSES"
  chmod 0755 "$stage/LICENSES"
  for f in LICENSES/*; do
    cp "$f" "$stage/$f"
    chmod 0644 "$stage/$f"
  done
  cp "$work/RELEASE-MANIFEST.json" "$stage/RELEASE-MANIFEST.json"
  chmod 0644 "$stage/RELEASE-MANIFEST.json"
  pack "$stage" "$dir/$tarball"
  pack "$stage" "$stage/second.tar.gz"
  if [ "$(sha256sum <"$dir/$tarball" | cut -d' ' -f1)" != "$(sha256sum <"$stage/second.tar.gz" | cut -d' ' -f1)" ]; then
    echo "✗ two packings of the same binary differ ($arch) — the tarball is not reproducible" >&2
    exit 1
  fi
  listed=" $(tar -tzf "$dir/$tarball" | tr '\n' ' ')"
  for entry in $TARBALL_ENTRIES; do
    case "$listed" in
    *" $entry "*) ;;
    *) echo "✗ the tarball lacks $entry ($arch)" >&2; exit 1 ;;
    esac
  done
  echo "✓ tarball             $(du -h "$dir/$tarball" | cut -f1) · entries: ${TARBALL_ENTRIES// /, } · packed twice · identical digest"

  # The artifact is only a release if it runs and agrees about its version —
  # which this host can only ask of its own architecture. A foreign binary
  # is reported as unverified rather than silently assumed good.
  mkdir -p "$stage/extracted"
  tar -xzf "$dir/$tarball" -C "$stage/extracted" podaro
  if [ "$arch" = "$native" ]; then
    got="$("$stage/extracted/podaro" version)"
    want="podaro v${version}"
    if [ "$got" != "$want" ]; then
      echo "✗ the packaged binary prints \"$got\", not \"$want\"" >&2
      exit 1
    fi
    echo "✓ extracted binary    $got · linux/$arch"
  else
    echo "○ extracted binary    linux/$arch · not run here (this host is linux/$native)"
  fi

  manifest+=("$binary" "$tarball")
done

# One manifest for the whole release, in the order sha256sum reads it.
( cd "$dir" && sha256sum "${manifest[@]}" >SHA256SUMS )
( cd "$dir" && sha256sum -c SHA256SUMS >/dev/null )
echo "✓ SHA256SUMS          ${#manifest[@]} artifacts · verified with sha256sum -c"

# A release host redirects /releases/latest to /releases/tag/v<version>;
# a mirror answers the same line in a file (INSTALL §6), so an air-gapped
# upgrade reads this directory as it would read the release page.
printf '/tag/v%s\n' "$version" >"$out/latest"

echo
echo "built from            $commit"
echo "built with            $(go version | cut -d' ' -f3) · GOAMD64=v1 · GOARM64=v8.0"
echo
# Only what this run wrote: the output directory may hold other releases,
# or anything else the operator keeps there, and none of it is part of
# this release or of the three files below.
echo "release artifacts in $dir — nothing was tagged, pushed or published"
for f in SHA256SUMS $(printf '%s\n' "${manifest[@]}" | sort); do
  echo "  download/v${version}/${f}"
done
echo "  latest"
echo
echo "→ next: the owner's acts — git tag v${version}, then upload these $((${#manifest[@]} + 1)) files"
