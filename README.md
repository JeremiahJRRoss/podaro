<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Podaro Community

## Hands-on labs. Real systems. Verifiable outcomes.

Podaro is an application for designing and distributing multi-application training labs, product demonstrations, and bug reproduction demonstrations. It combines guided walkthroughs and multimedia instructional content with a single interface for interacting with applications and is designed for interoperability with Learning Management Systems. It uses Podman to orchestrate containers within a Linux virtual machine and includes checkpoints for verifying lab readiness and learner objectives.

You define a lab once, in YAML. Podaro creates disposable instances of it on a Linux host you control; users open a browser, work in the lab's actual products, follow the guided walkthrough, and check their results against live system state.

The environment, instructions, verification, and evidence belong together. Podaro brings them into one console.

> **Developer Preview — we need testers.** Help us establish which environments work, where the instructions need improvement, and which behaviors still need correction. Start with the [Installation Manual](public-docs/INSTALL.md) and the [User Manual](public-docs/USERMANUAL.md). A useful report can describe a successful run, a failure, or the exact point where you became stuck. You do not need to write Go to help.

[Install](public-docs/INSTALL.md) · [User Manual](public-docs/USERMANUAL.md) · [Architecture](public-docs/ARCHITECTURE.md) · [Licence and notices](NOTICE) · [Get help](SUPPORT.md)

## What you can do

**Run a guided lab.** Open the products and the playbook together. Complete a task, press Verify, and see what the checkpoint actually checked.

**Present a technical demo.** Use the same playbook in Presenter mode, with speaker notes and quiet checkpoint indicators. Rehearse the exact environment before sharing it.

**Build a lab for your own stack.** Start with an installed template, edit YAML, validate the definition, and preview what Podaro will create. Extend verification with a container-based adapter when the built-in checks do not fit your product.

**Leave with evidence.** Download an HTML report or consume JSON and JUnit results. Export anything you need to keep before destroying its instance.

```text
YAML template + playbook
           │
           ▼
      Create an instance
           │
           ▼
   Baselines establish readiness
           │
           ▼
    A user works in real products
           │
           ▼
   Objectives check the outcome
           │
           ▼
      Evidence → reset or destroy
```

## One page, every application

A lab is a handful of applications — a dashboard tool, a search engine, a data pipeline, whatever the template names — each running as one or more containers on a private network that exists only for that instance. Nothing inside is reachable from outside the host; the one way in is Podaro's gateway, a single TLS port, and what it serves is one web page per lab. That page is the console. The status bar, the Overview tab and the Evidence tab are Podaro's; every other tab is one application, shown as itself; and the playbook rail beside them holds the step you are on, its actions and its Verify button. You switch applications by switching tabs, and you never need to know an application beforehand: the step says what to do in which tab, and the checkpoint says whether it worked.

```text
┌──────────────────────────────────────────────────────────────────────┐
│ intro   ●●●●●●● ready                  [Evidence] [Reset…]           │  ← status bar: Podaro's
├──────────┬─────────┬────────────┬──────────┬─────────────────────────┤
│ Overview │ Grafana │ Prometheus │ Evidence │ PLAYBOOK ▸              │  ← one tab per application
├──────────┴─────────┴────────────┴──────────┤                         │
│                                            │ Step 3 of 4             │
│                                            │ Build a dashboard the   │
│      the application itself, served        │ system can find         │
│      into this tab through Podaro's        │ ─────────────────────── │
│      gateway from its container on the     │ Save it as Lab Overview │
│      lab's private network                 │                         │
│                                            │ [Verify ✓]              │
│                                            │ ✗ hint: is the title    │
│                                            │   exactly Lab Overview? │
└────────────────────────────────────────────┴─────────────────────────┘
```

The applications are ordinary containers with deliberately permissive lab settings; the platform around them is the hardened part. Podaro's own documents call the applications *products* and their containers *services*, and the guides keep those words.

## Ready is not the same as finished

Podaro separates two questions:

| Question | Checkpoint class |
|---|---|
| Is the environment ready to use? | **Baseline** |
| Has the user accomplished the exercise? | **Objective** |

A lab can be ready while its objectives are still red. That is normally the starting point, not a failure to install. A human attestation is recorded as an attestation, not promoted to a machine-verified pass.

A checkpoint proves only the condition its author specified. Read its evidence; do not treat a green indicator as a broader certification of correctness, security, or learning.

## Start small

The starter lab, and the first evaluation, is `grafana-prometheus-intro`: two applications, Grafana (a dashboard tool) and Prometheus (a metrics store), and a four-step playbook. Its declared host envelope is 4 GB RAM; real-host compatibility and timings are still being collected.

Installation is one script: download the release tarball from the project's releases, `https://github.com/JeremiahJRRoss/podaro/releases`, extract it into `/opt/podaro` and run `sudo ./install.sh`. It prompts for what you may want to change — the domain, the gateway port (7777 by default), the certificate — with useful defaults, creates the dedicated `podaro` account, and hands over to it for everything the engine does. Once the [installation](public-docs/INSTALL.md) is complete, as that account (`sudo -iu podaro`):

```bash
podaro up grafana-prometheus-intro --name intro
podaro status intro
```

Open the console URL printed by Podaro and follow the [User Manual](public-docs/USERMANUAL.md)'s quickstart (§6). Do not run these commands on a host that serves live applications or an account that already contains important Podaro state.

The starter catalog is this one template, all open source, with no third-party licence to accept. The lab retired on 2026-09-23, before any release, is not in the catalog or the binary and is not offered in any form. To build a lab for your own stack, start from this one: `podaro lab init --from grafana-prometheus-intro ./my-lab`, then the manual's authoring basics (§11).

## What to expect from this preview

The source includes the engine, CLI, browser console, the starter template, schemas, and automated tests. The complete real-host MVP acceptance run is not established by this documentation. Implementation, automation and recorded acceptance are different things, and this page claims only the first two.

Use a dedicated Linux test VM, rootless Podman, synthetic data, and one active lab at a time for initial evaluation. The server runs on Linux; attendees use a browser. No model or AI service is required by the runtime.

Portable lab bundles, full Repro mode, certified concurrency, visual authoring, fleet management, and several other capabilities are **not** part of the current preview. Consult the [User Manual](public-docs/USERMANUAL.md), §16, before relying on a feature mentioned in a design discussion.

## We need testers

The most valuable contribution right now is a reproducible first-run experience on a machine we did not prepare.

Install by the [Installation Manual](public-docs/INSTALL.md), run the starter lab by the [User Manual](public-docs/USERMANUAL.md)'s quickstart, and record the actual result as an issue with the test-report template. Document individual defects with the bug-report template, as [Support](SUPPORT.md) describes.

Please report missing prerequisites and confusing instructions too. A clean run is useful; a precisely described blocked run is equally useful. Never post credentials, attendee join links, raw state directories, or sensitive customer data in an issue.

## Control and responsibility

Podaro is self-hosted. The console's assets are bundled rather than loaded from external content delivery networks. Optional observability export sends the engine's operational signals to destinations the operator configures; it is not vendor telemetry.

Self-hosting is not a guarantee that every container is isolated from every possible threat. Lab services currently have outbound network access, same-user processes are inside the trust boundary, and other residual risks remain. Read the trust boundaries in [Architecture](public-docs/ARCHITECTURE.md) and the manual's security model (§13) before exposing a lab beyond your test environment.

## Contribute and get help

[Contributing](CONTRIBUTING.md) explains the development workflow and DCO sign-off. [Support](SUPPORT.md) explains how to ask questions and file useful reports. Suspected security problems belong in the private channel described in [Security policy](SECURITY.md), not public issues. The maintainer and project contact is Jeremiah Ross, `dev@podaro.dev`. The project's repository is [`https://github.com/JeremiahJRRoss/podaro`](https://github.com/JeremiahJRRoss/podaro) — the location the root `SOURCE` file names and every build's `podaro legal` prints — with its [issues](https://github.com/JeremiahJRRoss/podaro/issues) and its [releases](https://github.com/JeremiahJRRoss/podaro/releases).

## Open-source scope

Podaro Community focuses on a single host and a human-scale team; the [User Manual](public-docs/USERMANUAL.md), §16, says what this release is and what comes next.

Podaro's first-party material — the engine, CLI, console and gateway, the schemas and specifications, the starter template and its modules, the scripts and the documentation — is licensed `AGPL-3.0-only`: strong copyleft, with no restriction added to it. Every first-party file carries `SPDX-License-Identifier: AGPL-3.0-only` and no copyright line; `REUSE.toml` covers the files that cannot carry that header, and `hack/spdx_check.py` holds the tree to it in CI. Current first-party releases use AGPL-3.0-only, subject to disclosed upstream and historical rights. Third-party material keeps its own licence and notices — the vendored console scripts and fonts, the common-password list, the Code of Conduct, the Go modules compiled into the binary — as [`NOTICE`](NOTICE) records and [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) gathers in full; `LICENSE` is the AGPL text, and `LICENSES/Apache-2.0.txt` the Apache-2.0 text some of those modules carry. Every release carries those files, and every running copy shows them: `podaro legal` prints the licence, the notices and the offer of the exact source of the binary you are running (`--licenses` every licence text), and the console's `/legal` page shows the same to anyone who can reach the console, signed in or not. The Podaro name is covered separately by [`TRADEMARKS.md`](TRADEMARKS.md), a proposed policy: the licence grants no trademark rights beyond what applicable law permits. Lab content you write yourself does not become AGPL merely because Podaro reads, stores, renders or executes it; copying protected expression from a Podaro example is assessed under the AGPL. Proprietary lab products have separate terms and are not redistributed by Podaro.

## The documents

The manuals are written as the specification the software is built to: any divergence between a document and the product is a bug in one of them, and the fix updates both in the same change. What remains before `v0.1.0` is the acceptance run on a clean host and the release itself.

| Document | Role |
|---|---|
| [`public-docs/INSTALL.md`](public-docs/INSTALL.md) | The installation manual: the install step by step, what lands on the host, offline installation, upgrading, uninstalling |
| [`public-docs/USERMANUAL.md`](public-docs/USERMANUAL.md) | The user manual: MVP behavior in product voice — the acceptance spec |
| [`public-docs/ARCHITECTURE.md`](public-docs/ARCHITECTURE.md) | The architecture on one page: the parts, the path from a definition to a running lab, the trust boundaries and what remains |
| [`schemas/`](schemas/) | The frozen interface contracts an author's YAML is validated against — `lab.podaro.dev/v1alpha2` is the current one — with the normative examples in [`scenarios/`](scenarios/): the starter template `grafana-prometheus-intro` and its playbook `first-dashboard`; [`modules/`](modules/) holds the installed module library |
| [`CHANGELOG.md`](CHANGELOG.md) | What each release does, and what it deliberately does not |
| [`LICENSE`](LICENSE) · [`NOTICE`](NOTICE) · [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) · [`TRADEMARKS.md`](TRADEMARKS.md) · [`SOURCE-AND-BUILD.md`](SOURCE-AND-BUILD.md) | The licence, the notices, the trademark policy and the source offer — what every release carries and `podaro legal` prints |

## Working in this repository

[Contributing](CONTRIBUTING.md) has the development workflow. CI runs on every pull request: `go build`, `go vet` and `go test`; the dependency-licence allowlist (`hack/allowed-licenses.txt`) and every tracked file's licence (`hack/spdx_check.py`: first-party files `AGPL-3.0-only` with no copyright line, by their own SPDX header or `REUSE.toml`; third-party files their own identifiers; `hack/spdx_check_test.sh` proves it fails where it must); `THIRD-PARTY-NOTICES.md` held to its sources (`hack/third_party_notices.sh --check`); schema self-validation and scenario YAML parsing; the lab gate (`hack/lab_gate.sh`: `podaro lab validate` and `lab plan` green and deterministic on the catalog's template); the scripted acceptance runs against the fake runtime (`hack/interrupt_test.sh`, `hack/gateway_test.sh`, `hack/ready_test.sh` with `hack/secret_leak_scan.sh`, `hack/attendee_matrix.sh`, `hack/observe_export.sh`, `hack/upgrade_test.sh`, `hack/retirement_migration_test.sh`); the exec conformance fixture under rootless Podman (`hack/exec_conformance.sh`); the console walked in a real browser (`hack/console_walk.sh`, which drives Chromium over the DevTools protocol and skips honestly without one); the licence gate and `PDR-W101` on first-party fixtures (`hack/license_gate_test.sh` on `hack/fixtures/eula-lab/`, `hack/w101_test.sh` on `hack/fixtures/w101-lab/`) and every built-in adapter and generator run once on vendor-neutral services (`hack/conformance_lab.sh`); the licence, the notices and the source offer on every path a binary reaches someone by (`hack/legal_surfaces_test.sh`) and a neutral-name build that moves the display name and nothing else (`hack/rebrand_test.sh`); the installer's static checks, answers and refusals (`hack/install_sh_test.sh`), the build script (`hack/build_sh_test.sh`) and the account wrapper (`hack/podaroctl_test.sh`); the release artifacts, built twice and compared (`hack/release_package.sh`, which tags and publishes nothing); every link in the documents resolving and the repository's coordinates spelled as `SOURCE` and `go.mod` spell them (`hack/link_check.py`, offline, with its probes `hack/link_check_test.sh`); and the two guards, a job each — nothing retired before the release back in the tree, in what the binary embeds, in the binary or in the release outside the role `hack/retirement_allow.txt` gives it (`hack/retirement_guard.sh`), and no former project identity in the tree, the binary, the release, the CLI's output or the console as the walk renders it, searched for by the hashes in `hack/identity_detectors.txt` (`hack/identity_guard.sh`) — each proven by its probes to fail where it must (`hack/retirement_guard_test.sh`, `hack/identity_guard_test.sh`).

To the extent copyright subsists, copyrightable first-party material owned by Jeremiah Ross is licensed under AGPL-3.0-only. [`NOTICE`](NOTICE) carries the project's copyright statement.
