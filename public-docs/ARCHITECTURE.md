<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Podaro — Architecture

*Podaro Community, Developer Preview · one page on how the parts fit. The [Installation Manual](INSTALL.md) says what lands on the host; the [User Manual](USERMANUAL.md) says how it behaves.*

Podaro is an application for designing and distributing multi-application training labs, product demonstrations, and bug reproduction demonstrations. It combines guided walkthroughs and multimedia instructional content with a single interface for interacting with applications and is designed for interoperability with Learning Management Systems. It uses Podman to orchestrate containers within a Linux virtual machine and includes checkpoints for verifying lab readiness and learner objectives.

Podaro is one Go binary, `podaro`, that is both the engine and the command line. The engine runs on a Linux host as a systemd user service of the dedicated `podaro` account, owns one API, and serves one web console per lab. The command line, the console and any automation are clients of that API. Podman runs the labs as rootless containers. Nothing else is required: no cloud service, no account beyond the operator's, no model or AI service, and no network call Podaro makes on its own.

## The parts

| Part | What it is | Where |
|---|---|---|
| **Engine** | The lifecycle (create, verify, reset, destroy), the checkpoints, the evidence journal, the catalog and the secrets, behind one API: on a local socket for the CLI, and through the gateway for browsers | `~/.local/bin/podaro`, the user service `podaro` |
| **Gateway** | The only listener on the host: one TLS port, 7777 by default. It routes by hostname — the console at `<instance>.<domain>`, each product at `<service>-<instance>.<domain>` — drops unknown hostnames, and admits nothing unauthenticated except the licence page | inside the engine |
| **Console** | One server-rendered page per instance: the status bar with the readiness ladder, one tab per product served through the gateway, the playbook rail, the Evidence tab. Its scripts and fonts are bundled in the binary; it loads nothing from anywhere else | inside the engine, served by the gateway |
| **CLI** | `podaro up`, `status`, `logs`, `seed`, `verify`, `reset`, `destroy`, `access`, and the rest the manual's §15 lists: a client of the API over the local socket | the same binary |
| **Podman** | Rootless containers, one isolated network per instance, images pinned by digest, no host bind mounts by default | the host's Podman, 4.4 or later |
| **Catalog** | The templates and modules installed on the host — the starter lab `grafana-prometheus-intro` and the modules it composes — extracted from the binary by `podaro system install` | `~/.local/state/podaro/catalog/` |
| **State** | Instances, their generated secrets (`0600`), their rendered environment files, their evidence journals, the local certificate authority and the engine's SQLite database | `~/.local/state/podaro/` |
| **Configuration** | The domain, the gateway port, TLS, and the optional observability export | `~/.config/podaro/config.yaml` |

## From a definition to a running lab

```text
  template  (lab.yaml, playbooks)            modules  (image digest, config,
  what to create ───────────────┐            init job, readiness) ───┐
                                ▼                                    ▼
                   podaro up grafana-prometheus-intro --name intro
                                │
                                ▼
                        instance "intro" ─ its own network, secrets, hostnames, evidence
                                ├─ service  grafana      (a container)
                                ├─ service  prometheus   (a container)
                                └─ one-shot init jobs, then the seeds
                                                    ▲
   browser ──TLS :7777──► gateway ──by hostname─────┤
                             │                      │
        console   intro.lab.example.com             │
        product   grafana-intro.lab.example.com ────┘  proxied into its tab
```

A **template** is a directory whose `lab.yaml` names the services, seeds, checkpoints, playbooks and profiles of a lab; a **module** is a reusable product building block a template composes. Templates are immutable once installed. An **instance** is one running copy of a template: `podaro up` creates it with its own network, generated credentials, hostnames and evidence, and `podaro destroy` removes all of it. Two instances on one host cannot see each other. An instance created from a template directory is an **authoring** instance, which tracks that directory; one created from the catalog is a **delivery** instance, pinned to a snapshot. The mode is fixed at create and enforced by the engine.

Every instance climbs the same seven stages, drawn identically by the console and the CLI:

`alive → healthy → initialized → connected → seeded → verified → ready`

**Ready means verified.** An instance is ready only when its baseline checkpoints pass, never merely when its containers are up. After a host reboot the engine reconciles on start: containers return to their stage and the baselines are judged again.

## Checkpoints and evidence

A **checkpoint** is a machine-verifiable assertion about live lab state. It has a class. **Baseline** checkpoints gate readiness. **Objective** checkpoints are the learner's work: expected red when the instance is created, and turned green by doing the exercise in the product and pressing **Verify**. The built-in checks query a product through its own interface; a **container-based exec adapter** extends verification to anything else, and runs behind five walls: a fresh container per run, no network egress, a read-only filesystem, no capabilities, and limits on processes, CPU and memory.

Every checkpoint run and every lifecycle and audit event is appended to the instance's **evidence**, which the engine alone writes: the console cannot record a pass, a human attestation stays an attestation, and a secret value never appears, because a redaction filter built from the instance's own secrets runs on every log line, evidence message and adapter output. Evidence exports as JSON, as JUnit (`report.junit.xml`, the format learning management systems and pipelines ingest) and as a self-contained HTML report. **Reset** returns the lab to a freshly verified baseline and keeps the history. **Destroy** removes the instance and its evidence, so export first.

## People and access

One **operator** account exists, created by `podaro auth setup`; the operator runs the host and the labs. An **attendee** gets an access link (`podaro access create intro --name alice --expires 8h`) that signs a browser into that one instance. The grant is fixed by the engine and the gateway alike: the status, the playbooks, Verify and the evidence of that instance, with no destroy, no reset, no logs and no other instance. A **presenter** runs the same playbook in Presenter mode. An **author** writes templates and works in an authoring instance.

## Trust boundaries

The labs are the permissive part by design; the platform around them is the hardened part, and containment is structural. The ten trust boundaries, what holds each, and what honestly remains:

| Boundary | What holds it | What remains |
|---|---|---|
| **B1** Internet ↔ gateway | One TLS port; unknown hostnames dropped; the operator login hashed with Argon2id and throttled per source; no banners | Request-rate limiting is future work: front a hostile exposure with your own reverse proxy |
| **B2** Browser sessions ↔ API | Cookie sessions with a CSRF double-submit token; attendee sessions bound to their instance in the engine, at the gateway and in every handler; tokens hashed at rest, expiring, revocable | A shared access link is bounded by its instance, its expiry and revocation |
| **B3** Console ↔ product tabs | The console is never frameable; products run on their own hostnames and never receive Podaro's credentials; authored narrative is escaped before it is rendered | Product interfaces are frameable inside the authenticated, instance-bound console, by design |
| **B4** Engine ↔ containers | Rootless Podman: root inside a container is not root on the host; unprivileged, capabilities dropped, no host bind mounts by default | Kernel and runtime vulnerabilities: the host's patch cadence is the operator's |
| **B5** Instance network ↔ host, other instances, the internet | One isolated network per instance; declared ports published on `127.0.0.1` only; the engine is never on an instance network | **Lab containers can reach the internet** (default NAT egress). The largest accepted residual of this release; add host firewall egress rules where it matters |
| **B6** Exec adapters ↔ the lab | The five walls above; secrets only by declared grant; root-UID images refused | — |
| **B7** Templates and bundles ↔ the platform | Images pinned by digest; validate and plan before create; licence acceptance typed per licence, never defaulted; the first use of a bundle digest forces a full plan review (portable bundles themselves are future work) | Nothing is signed in this release: review makes trust informed, not automatic |
| **B8** The host account | Never root; state, secrets and the socket `0700` and `0600`; generated values live only in the secrets store | Another process running as the `podaro` account is inside the boundary, and so is your backup hygiene |
| **B9** Evidence and exports | Only engine-run checkpoints produce results; evidence is append-only; secrets are filtered out of every artifact | An operator editing files on their own host is inside B8 by definition |
| **B10** Observability export | Off by default; the same redaction filter on the export path; destination credentials in `0600` token files; TLS verified unless explicitly disabled | A redaction miss would export at wire speed: the same reportable bug as a local leak |

Vendor telemetry is zero, ever: the only network call Podaro initiates is one the operator configured. Suspected vulnerabilities go through [`SECURITY.md`](../SECURITY.md), never a public issue.

## On the host

Everything of Podaro's lives under the `podaro` account, rootless: the package in `/opt/podaro/`, the binary in `~/.local/bin/`, the configuration in `~/.config/podaro/`, everything generated in `~/.local/state/podaro/`. The [Installation Manual](INSTALL.md), §3, lists every path with its mode, and §4 says what installation deliberately did not do. One port is exposed. At rest the engine makes no outbound connection.

## What this release is not

One host, one certified instance at a time. No fleet, no instructor console, no visual authoring, no portable bundles or repro mode yet, and no model or AI service in the runtime. The [User Manual](USERMANUAL.md), §16, says what this release is and what comes next.

## Where to look next

- The [Installation Manual](INSTALL.md): the install step by step, offline installation, upgrading, uninstalling.
- The [User Manual](USERMANUAL.md): concepts, the quickstart, the console, the lifecycle, authoring basics, the security model, troubleshooting, the CLI.
- The schemas in [`schemas/`](../schemas/), where `lab.podaro.dev/v1alpha2` is the current contract, and the starter template in [`scenarios/grafana-prometheus-intro/`](../scenarios/grafana-prometheus-intro/), the normative example of a template and a playbook.
- `podaro explain PDR-…` for any error code, and `podaro legal` for the licence, the notices and the source offer.
