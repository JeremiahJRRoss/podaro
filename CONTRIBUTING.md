<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Contributing to Podaro

Podaro Community is built documentation-first: the manuals are binding
acceptance specs, and code is written until they stop being fiction. Start
with the [User Manual](public-docs/USERMANUAL.md) and the
[Installation Manual](public-docs/INSTALL.md), then the development workflow below.

**We need testers now.** Install by the [Installation Manual](public-docs/INSTALL.md), run the starter lab by the [User Manual](public-docs/USERMANUAL.md), and report what happened with the test-report issue template. A report of a clean install on a fresh machine is a contribution. So is a report that explains why you could not reach the first lab.

This is first-draft guidance for the Developer Preview. Release and security decisions remain maintainer decisions; opening or merging a documentation change does not itself certify the software.

## Choose a contribution

| You want to help with… | Start here |
|---|---|
| A first-run experience | The [User Manual](public-docs/USERMANUAL.md)'s quickstart (§6), reported with the test-report issue template |
| A bug or confusing instruction | The bug-report or documentation-issue template; [Support](SUPPORT.md) says what a report needs |
| A new or improved lab | The manual's authoring basics (§11), the starter template in `scenarios/` and the schemas in `schemas/` |
| Code, tests, or automation | The development workflow below |
| A suspected security problem | [Private security reporting](SECURITY.md) |

For changes to public interfaces, security boundaries, licensing, or major dependencies, discuss the approach before implementing it. Small documentation corrections and focused regression tests do not need a large proposal.

## Sign your commits (DCO — everywhere)

Every commit on every path requires a Developer Certificate of Origin
sign-off (**DCO everywhere** — engine and content alike, one policy for the
whole repository; there is no CLA):

```
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer, which
certifies you wrote the change or otherwise have the right to submit it
under the project license, per the [Developer Certificate of Origin
1.1](https://developercertificate.org). Use your real name and a reachable
address; unsigned commits fail the DCO check on pull requests.

## Contribution attestation

The maintainer and project contact is Jeremiah Ross, `dev@podaro.dev`. What a sign-off means:

- A DCO sign-off attests that you have the right to submit the contribution under the applicable project license — `AGPL-3.0-only` for first-party paths; a third-party file keeps its own terms.
- A sign-off is not a copyright assignment, not a transfer of ownership, not a Contributor License Agreement, and not evidence that the maintainer owns your contribution. You keep whatever copyright you hold.
- No assignment process exists here, and none is implied. Should centralized ownership ever be wanted, that would be a separately considered decision, not something a sign-off does.
- The maintainer attests the same way: `Signed-off-by: Jeremiah Ross <dev@podaro.dev>`.
- A commit's author and sign-off record who submitted a change; they do not by themselves determine who holds copyright in it. Contributor credits and sign-offs stay as they are: history is not rewritten.

Questions about contributing, or about this section, go to `dev@podaro.dev`.

## What license your change lands under

Every first-party file is `AGPL-3.0-only`. It carries the SPDX header
`SPDX-License-Identifier: AGPL-3.0-only` in its own comment syntax and no
copyright line: a licence identifier declares terms and claims no
ownership; the project's copyright statement is `NOTICE`'s. A new file
does the same.

| Paths | License |
|---|---|
| Everything first-party: `cmd/`, `internal/`, the root Go files, `console/` but its vendored assets, `schemas/`, `scenarios/`, `modules/`, `hack/`, `public-docs/`, the root documents, `.github/` | `AGPL-3.0-only` |
| Third-party material: the vendored scripts and fonts under `console/assets/` and their licence texts, `internal/auth/common-passwords.txt`, `CODE_OF_CONDUCT.md`, the licence texts `LICENSE` and `LICENSES/` | its own terms, kept exactly — never relabelled |

`REUSE.toml` names every file that cannot carry a header (`VERSION`,
`go.mod`, `go.sum`, `NOTICE`, the test goldens) and every third-party
file, with the real holders and licences of the third-party ones.
`hack/spdx_check.py` holds the tree to all of this in CI (the `licenses`
job, which also runs `hack/spdx_check_test.sh`, its probes) — run it
before you push. Earlier grants are not revoked: current
first-party releases use AGPL-3.0-only, subject to disclosed upstream and
historical rights.

Lab content **you** author yourself — templates, modules, playbooks,
checkpoints for your own products — does not become AGPL merely because
Podaro reads, stores, renders or executes it; copying protected expression
from a Podaro example is a different situation, assessed under the AGPL
(`NOTICE`).

## Dependency policy (engine imports)

Code compiled into the engine may only carry `MIT`, `BSD-2-Clause`,
`BSD-3-Clause`, `ISC`, `Apache-2.0`, `Zlib`, or file-level `MPL-2.0`
**No GPL or AGPL imports** — invoking GPL-family tools as
subprocesses (Podman et al.) is fine; compiling them in is not. The
allowlist lives in `hack/allowed-licenses.txt` and is enforced on every
pull request by the `licenses` CI job (`go-licenses check`).

## How this repository gets built (and what PRs look like)

The manuals under `public-docs/` are the specification the software is
built to: a change is built until the documents it touches are true of the
product, proved by the scripts in `hack/`, with any drifted document
updated in the same commits. One change lands as one pull request.

Outside contributions are welcome — issues, doc fixes, and (after `v0.1.0`)
templates and modules. For anything larger, [open an issue](https://github.com/JeremiahJRRoss/podaro/issues)
first so the work can be placed. Every PR needs:

- a DCO sign-off on every commit (above);
- on every new first-party file, the header `SPDX-License-Identifier:
  AGPL-3.0-only` and no copyright line (or a `REUSE.toml` annotation where
  the file cannot carry one); third-party material only under its own
  terms, with its notice and a row in `hack/spdx_check.py`'s allowlist;
- green CI: `build-test`, `licenses`, `schemas`, `scenarios-yaml`, `templates`, `retirement`, `identity`;
- if the change makes any governing document false, the document updated in
  the same PR — the docs are the acceptance; drift is a bug.

## Nothing retired, no former identity: the two guards

Two CI jobs keep what was retired before the release, and the project's
former identity, from coming back. Both build the release for every
architecture it ships (amd64 and arm64) and judge each binary and each
tarball, so run them on a clean checkout.

- `retirement` (`hack/retirement_guard.sh`) fails when anything
  `hack/retirement.json` records — the retired lab, its modules, adapters,
  generators, images and digests, its playbook, licence ids and pack — shows
  up where its role does not allow it. Every mention in the tree must be a
  row of `hack/retirement_allow.txt` — `path` or `path:line,…`, a tab, the
  file's role (a category the manifest defines), a tab, the reason — and no
  row may cover a maintained surface: the catalog, the modules, the current
  schemas, the installer, the registries, the session prompts, what the
  binary embeds or the release carries. Every binary is judged by the
  manifest's `in_a_binary` allowance: check 5's scan, `hack/retirement_scan.py`,
  which spells no retired name and runs on its own too (`--binary`,
  `--self-test`).
- `identity` (`hack/identity_guard.sh`) fails when a former project
  identity appears — in the tree, the binary, the release, the CLI's output
  or the console as the browser walk renders it. It searches for the
  detectors by their hashes, `hack/identity_detectors.txt`, never a
  spelling, and no occurrence may stand outside a third-party credit; given
  no hash file it fails rather than skip.

When a guard fails, read its finding — it names the file and the line —
and remove the mention, or, for a genuine history note outside a maintained
surface, add its row with the reason in the same pull request. A row that no
longer matches anything fails too: move it with its line, or remove it.
Each guard's probes (`hack/retirement_guard_test.sh`,
`hack/identity_guard_test.sh`) plant one restoration at a time on a
throwaway copy of the tree and prove the guard fails. Some probes edit a
row or a line by its text; when that row or line changes, the probe
says its edit changed nothing — update the probe in the same pull request,
never drop it.

## The console's vendored assets

The console makes zero external requests, so htmx, Alpine
(its CSP build), and the IBM Plex fonts are checked in under `console/assets/`
and pinned — package, version, license, tarball integrity, file digest — in
`console/VENDOR.md`; `TestVendoredAssetsMatchManifest` fails when a file and
its row disagree. Updating one means updating the row in the same commit and
copying the file unmodified from the named tarball. Licenses for vendored
assets follow the engine's dependency allowlist (0BSD counts as BSD), plus
OFL-1.1 for fonts, which are content embedded in the binary rather than code
compiled into it; every license text ships in
`console/assets/LICENSES/`, `NOTICE` names each asset, and `REUSE.toml`
names each file's holder and licence.

## Building

Go ≥ 1.24. From a clean checkout, `go build ./... && go vet ./... && go
test ./...` must pass. The schema and scenario checks run locally with
`python3 hack/validate_schemas.py` and `python3 hack/validate_scenarios.py`
(needs `jsonschema` and `pyyaml`); the lab gate — `podaro lab validate` and
`lab plan` green and deterministic on every catalog template — is
`hack/lab_gate.sh` (builds the binary itself, or uses `$PODARO`). The runtime
core's acceptance — kill -9 mid-create then resume, reboot then reconcile,
create-twice identity, destroy-leaves-nothing — is `hack/interrupt_test.sh`;
the gateway's (setup, unknown-host drop, deny-until-authenticated, the cookie
and CSRF, the console shell, a proxied product vhost, tokens and scopes, the
login throttle and lockout) is `hack/gateway_test.sh`, a curl matrix against
a real gateway on a local port;
it runs against the on-disk **fake runtime** (`PODARO_RUNTIME=fake`, no
Podman needed; its containers answer real HTTP on loopback) and against
rootless Podman with `PODARO_RUNTIME=podman`.

The rest of the acceptance runs the same way, each a script in `hack/` that
CI runs on every pull request: `ready_test.sh` with `secret_leak_scan.sh`
(the create path), `exec_conformance.sh` (the exec contract's fixture under
rootless Podman, skipped honestly without it), `console_walk.sh` (the
console in Chromium over the DevTools protocol), `license_gate_test.sh`,
`w101_test.sh` and `conformance_lab.sh` (the licence gate, `PDR-W101` and
every built-in adapter and generator, each on a first-party fixture under
`hack/fixtures/`), `attendee_matrix.sh`, `observe_export.sh` and
`upgrade_test.sh`, `retirement_migration_test.sh` (what an earlier build
left of the retired lab is kept, never offered, reconciled or run,
reported, and removed only by `destroy`), `legal_surfaces_test.sh` and
`rebrand_test.sh` (the release's tarball and bare binary carry the licence,
the notices and the source offer, and `/legal` and `GET /system/legal`
answer a visitor and an attendee; a neutral-name build moves the display
name and nothing else), `retirement_guard.sh` and `identity_guard.sh` (the
two guards, a CI job each — `retirement` and `identity` — each followed by
its probes, `retirement_guard_test.sh` and `identity_guard_test.sh`;
below), `link_check.py` (every relative link in the Markdown resolves and
every absolute one is well formed — offline, form only — and the
repository's URLs and module path are spelled as `SOURCE` and `go.mod`
spell them; its probes, `link_check_test.sh`, run after it in the `schemas`
job), and `release_package.sh <version>` (the release binary, tarball and
`SHA256SUMS`, each built twice and compared — it tags nothing and
publishes nothing, and it refuses a version `VERSION` does not carry; the
tarball carries `LICENSE`, `NOTICE`, `TRADEMARKS.md`,
`THIRD-PARTY-NOTICES.md`, `LICENSES/`, `SOURCE-AND-BUILD.md` and
`RELEASE-MANIFEST.json` beside the binary and the scripts).

`THIRD-PARTY-NOTICES.md` is generated, never edited by hand:
`hack/third_party_notices.sh` rebuilds it from `go-licenses report` for both
release architectures, `console/VENDOR.md`, the vendored assets' licence
texts and `NOTICE`'s third-party block, and the `licenses` job runs it with
`--check`. A new Go dependency stops the script until its licence is read
and recorded in the script's table (and allowed by
`hack/allowed-licenses.txt`); commit the regenerated file with the
dependency.

`./build.sh` at the root wraps that packaging for a checkout (INSTALL §5,
"From source"): `--check` reports the tools and versions — Go at least what
`go.mod` declares — and builds nothing; the default builds the release for
this machine through `hack/release_package.sh` and prints the install
commands; `--quick` is one unverified `go build` into `dist/quick/` for
iterating; `--install` hands the result to `install.sh` under `sudo`; and
`--yes` lets it install a missing Go. `hack/build_sh_test.sh` checks it in
CI: `--check`, a zip's `--quick` and packaged builds, its refusals.
`hack/podaroctl_test.sh` checks `podaroctl` the same way — `--help`,
`--print`, its refusals; running it for real needs the account, which is
the VM's.
