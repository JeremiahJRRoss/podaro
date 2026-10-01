<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Source and build

Podaro is free software under the GNU Affero General Public License, version 3 (`LICENSE`). Whoever runs a copy — the operator at the shell, an attendee in a lab, a visitor at the sign-in page — can reach its licence, its notices and the offer of its exact source from the copy itself: `podaro legal` prints them, `podaro legal --licenses` prints every licence text, and the console's `/legal` page shows the same to anyone who can reach the console, signed in or not. This file says where that source is, how a release is built from it, and what a modified build has to publish. It travels in every release tarball and inside the binary, and `podaro system install` writes it to `~/.local/state/podaro/legal/` with the other legal files.

This is a description of how the project lays out its source and builds; the licence itself says what it requires, and nothing here adds to it or replaces it.

## Where the source of a release is

The `SOURCE` file at the root of the repository names the canonical source location — today `https://github.com/JeremiahJRRoss/podaro` — and the build embeds that line. A release `v<version>` is the tag `v<version>` of that repository: its complete source is the tree at that tag, `<SOURCE>/tree/v<version>`, and the release page `<SOURCE>/releases/tag/v<version>` carries the binaries, the tarballs and `SHA256SUMS` beside it. For a release build, `podaro legal` offers exactly that: the source of Podaro v`<version>` at `<SOURCE>/tree/v<version>`.

A build whose `VERSION` ends in `-dev` — anything built from the development line between releases — is **unreleased**: no tag holds its exact source, and `podaro legal` says so and tells the person holding it to obtain its source from whoever gave them the binary. An operator who runs such a build, or any other build whose source is not at a tag of `SOURCE`, sets `legal.source_url` in `~/.config/podaro/config.yaml` to where its source is published; `podaro legal` and `/legal` then print that location as the operator's statement, beside the build's own.

The binary does not embed the commit it was built from, and that is deliberate. A release is reproducible byte for byte from its tag, and the documents-only commits that may land on a release branch between the acceptance run and the tag leave the artifact's bytes unchanged — a commit hash inside the binary would change them. The version and `SOURCE` are what bind a binary to its source; the tag is what fixes the source.

## How a release is built

`hack/release_package.sh <version>` on a clean checkout of the tag builds everything a release publishes, for linux/amd64 and linux/arm64:

```
hack/release_package.sh "$(tr -d '[:space:]' <VERSION)"
```

For each architecture it builds the binary twice with

```
CGO_ENABLED=0 GOOS=linux GOARCH=<arch> GOAMD64=v1 GOARM64=v8.0 \
  go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o podaro ./cmd/podaro
```

and refuses to finish unless both builds are identical; packs the tarball twice (sorted names, zeroed owners and times, gzip without a name or timestamp) and compares those too; refuses a version that `VERSION` does not carry and a checkout with uncommitted changes; and refuses a builder whose toolchain reports a non-default `GOEXPERIMENT`, `GOFLAGS` or `GOFIPS140`. It writes `SHA256SUMS` over every artifact and `RELEASE-MANIFEST.json` (the version, the Go release it used, the architectures and each binary's digest), and it tags, pushes and publishes nothing — those are the owner's acts.

The tarball holds `podaro`, `install.sh`, `install.test.yaml`, `podaroctl`, `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `THIRD-PARTY-NOTICES.md`, `LICENSES/`, `SOURCE-AND-BUILD.md` and `RELEASE-MANIFEST.json`.

To verify a release: download its `SHA256SUMS` with the artifacts and run `sha256sum --ignore-missing -c SHA256SUMS`. To go further, check out the tag, run the script above with the Go release `RELEASE-MANIFEST.json` names, and compare the digests. That comparison, and the tag's source, are what make a release the project's; no page or command of Podaro calls a build "official".

From a checkout without the release tooling in mind, `./build.sh` builds the same release for the machine it runs on (`public-docs/INSTALL.md` §5), and `./build.sh --quick` builds one binary of the tree as it stands — unverified, and never a release.

## A modified build

Changing Podaro is what the licence is for. A modified build keeps doing what the AGPL asks of the version it came from, and in particular it offers its own source to its users, including the users who interact with it over a network — which for Podaro means anyone the console serves. In practice:

1. **Publish the modified source**, the build scripts included, where its users can get it.
2. **Point the binary at it.** Change `SOURCE` to that location before building, and give the build a `VERSION` of its own — a tag in your repository, or a `-dev` version — so that `podaro legal` never offers the upstream tag's source for a binary that is not built from it. An installation running a modified build it did not build itself can say where the source is with `legal.source_url`.
3. **Keep the notices.** `LICENSE`, `NOTICE`, `THIRD-PARTY-NOTICES.md` and `LICENSES/` stay in the tree and in what you distribute; add your own notices for your changes, and regenerate `THIRD-PARTY-NOTICES.md` (`hack/third_party_notices.sh`) when the dependencies change. Rebranding is not a reason to remove legal provenance.
4. **Choose the name.** If the modified build should not be presented as Podaro (`TRADEMARKS.md`), set its display name at build time — `-ldflags "-X $(go list -m)/internal/brand.Name=<name> -X $(go list -m)/internal/brand.Title=<title>"` — which changes the console's titles, the CLI's description, the evidence report and the service's description, and nothing else: the licence, the notices, the source offer and every compatibility identifier (the `podaro` command, the API path, the schema `$id`s, the state paths) stay as they are.
