<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Podaro Community — User Manual

**Applies to:** Podaro v0.1.x (MVP) · **Manual version:** 0.1 draft · **License:** AGPL-3.0-only

> **How to read this manual.** This manual is the specification the software is built to: any difference between product and manual is a bug — in one of them. File it either way.

---

## 1. What Podaro is

Podaro Community turns a YAML definition into a running, **verified** lab environment — a product demo, a guided training lab, or a bug reproduction — served to any browser from a single Linux VM. You define a lab once; Podaro creates disposable instances of it, proves they actually work by running checkpoints against live system state, and gives everyone — presenter, trainee, or engineer — one web console with the products, the instructions, and the verification in a single browser tab.

Physically, a lab is a set of applications — *products*, in this manual's words — each running as one or more containers on a private network that exists only for that instance. Nothing inside is reachable from outside the host except through Podaro's gateway, one TLS port, which serves the console and proxies each product's own interface into its tab; switching tabs is how you move between them, and the playbook rail beside the tabs says what to do in each.

Podaro is stack-agnostic. It ships with one starter lab — `grafana-prometheus-intro`, Prometheus and Grafana observing each other in 4 GB, all open source (§12) — but any stack that runs in containers is a valid lab: your product, an open source data platform, a customer's app and its dependencies.

Podaro is open source (AGPL-3.0-only) and runs entirely on hardware you control. There is no cloud service, no account, and zero telemetry to us — while pointing Podaro's *own* logs, metrics, and traces at *your* observability stack is one config block away (§4).

## 2. Concepts

| Term | Meaning |
|---|---|
| **Template** | A complete lab definition: services, networks, secrets spec, seeds, checkpoints, playbooks. Lives in a versioned directory; the file is `lab.yaml`. |
| **Module** | A reusable product building block a template composes (`use: modules/prometheus@3.13`): pinned image, config, init job, readiness logic. |
| **Instance** | A running, isolated, disposable copy of a template, with its own network, volumes, secrets, and URLs. |
| **Console** | The per-instance web page: status, product tabs, playbook rail, evidence. The only interface most lab users ever see. |
| **Playbook** | An ordered set of steps that renders as a guided lab, a live demo script, or (later) a repro procedure. |
| **Step** | One playbook unit: narrative, a console context, optional actions (like seeding data), an optional checkpoint. |
| **Checkpoint** | A machine-verifiable assertion about live lab state ("Prometheus is scraping Grafana"). The atom of trust. |
| **Seed** | A named, deterministic data injection ("send 200 query requests to the Prometheus API"). |
| **Evidence** | The recorded results of checkpoints and lifecycle events: JSON, JUnit, and a human-readable HTML report. |
| **Profile** | A named resource sizing for a template (`standard` in this release). |
| **Catalog** | The set of templates and modules installed on your host: `podaro system install` extracts the starter catalog, and `up`, `lab init` and `lab plan` read it. |

**The ready ladder.** Instances climb seven observable stages, and Podaro reports exactly where each service is:

`alive → healthy → initialized → connected → seeded → verified → ready`

**Ready means verified.** An instance is *ready* only when its **baseline** checkpoints pass — the infrastructure truths (data arrived, services connected), not when containers start. **Objective** checkpoints — the ones your playbook work turns green — are *expected red* at the start: they are the lab, and they never block ready. This is the difference between "the demo is probably fine" and "the demo is proven fine."

**Playbook modes.** The same playbook renders three ways in this release: **Guided** (you advance, each step can be verified, progress is saved), **Presenter** (you advance, speaker notes visible, checkpoints run silently as confidence lights), and **Author preview** (free navigation while building). Repro mode ships in a later release.

## 3. Requirements

- **A Linux host or VM you control.** Podaro is Linux-server software; every other OS participates through the browser. Tested first on RHEL-family distributions; any modern systemd distribution with Podman works.
- **Podman ≥ 4.4, rootless**, with subuid/subgid ranges and session lingering for the dedicated **`podaro` account** the installer creates (home `/opt/podaro`; `sudo -iu podaro` to operate). `install.sh` prepares all of this in its root stage; by hand, `podaro doctor` checks and prints the exact commands for anything missing.
- **Resources** depend on the template. The starter lab, `grafana-prometheus-intro`, runs in **4 GB RAM** — its `standard` profile reads *4 GB host · all open source* — and that is the sizing this release is tested at. A template of your own needs what its services need.
- **Network:** one free port for the gateway (default **7777**); outbound access to your image registries during create.
- **A browser** on any OS, current Chrome/Firefox/Edge/Safari.
- **DNS you can point at the VM** — real records for shared use, or your workstation's hosts file for private labs (§5).

## 4. Installation

```
sudo mkdir -p /opt/podaro && sudo tar -xzf podaro_v0.1.0_linux_amd64.tar.gz -C /opt/podaro
cd /opt/podaro && chmod +x install.sh && sudo ./install.sh     # prompts, with defaults; then: sudo -iu podaro
```

The installer creates the `podaro` account, prepares the host as root — subordinate ID ranges and session lingering for the account, Podman from your distribution if it is missing and you say yes, and a root-owned `podaroctl` in `/usr/local/bin` only if you ask for one; it writes no kernel value; each act printed — and then installs as that account, running `podaro doctor` for you ([`INSTALL.md`](INSTALL.md) is the full account). `sudo -iu podaro` gives a login shell; the installer's block in the account's profile supplies the runtime directory and session bus that `systemctl --user`, `journalctl --user` and `podman` need there, and the engine sets them for its own `systemctl` calls regardless of the shell. From your own shell, `podaroctl` beside the installer runs any `podaro` command as the account — `sudo /opt/podaro/podaroctl status`, or `sudo podaroctl status` once you let the installer put a root-owned copy on PATH — and `podaroctl shell` is the account's login shell. `podaro system status|start|stop|restart` are the service itself (§15). `doctor` stays the front door afterwards. It verifies Podman and rootless configuration, user lingering, free ports, disk space, and DNS resolution for your configured domain — and for every failure prints the exact remediation command; one kernel row is advisory, never a failure, because nothing in Podaro needs the value it reports. Run it whenever anything seems off; error messages will point you back to it.

**First-run setup** (the installer walks you through this; rerun any part later):

```
podaro setup --domain lab.example.com     # the parent domain your instances live under
podaro auth setup                          # create the operator login for the console
```

**TLS is on from the start.** Setup generates a local certificate authority and a wildcard certificate for `*.lab.example.com`, stored under your state directory. Trust `ca.crt` in your browser or OS trust store (setup prints per-OS instructions), and certificate warnings disappear for every lab you ever create. Bringing your own certificate instead:

```yaml
# ~/.config/podaro/config.yaml
domain: lab.example.com
gateway: { port: 7777 }
tls:
  cert_file: /path/fullchain.pem   # must cover *.lab.example.com
  key_file:  /path/privkey.pem
```

Automatic ACME/Let's Encrypt issuance arrives in a later release; bring-your-own works today.

**Observability export (optional, off by default).** Podaro can ship its *own* operational logs, metrics, and traces — never your labs' data, never anything to the project — to the backend you already run:

```yaml
# ~/.config/podaro/config.yaml
observability:
  logs:    { exporter: hec,  endpoint: https://collector.example.com:8088, token_file: /home/me/.config/podaro/hec.token }
  metrics: { exporter: otlp, endpoint: https://otel.corp:4318 }
  traces:  { exporter: otlp, endpoint: https://otel.corp:4318 }   # traces: OTLP only in this release
  attributes: { host: lab-01 }
```

Per-signal exporters: `otlp` (OTLP/HTTP, posted to that signal's own path when the endpoint is a base URL), `http` (JSON lines to any endpoint), `hec` (the HTTP Event Collector protocol — logs and metrics, with the `Authorization: Splunk <token>` scheme that protocol defines and the `hec` exporter sends). Everything exported passes the same redaction filter as local logs; a secret value leaving via export is the same reportable bug. `podaro observe test` sends a probe through each configured signal and reports what landed; `doctor` shows the posture — a row that appears only when export is on, since off is the default. Destination credentials (like the HEC token) are secrets — keep them in `0600` files referenced by `token_file`, never inline and never in the endpoint itself: an endpoint written `https://user:…@collector.internal` is refused, because that credential would sit in `config.yaml`, in the posture `GET /system/observe` returns, and in the line printed at every engine start.

The installer asks "export Podaro's logs over the HTTP Event Collector protocol?" — any collector that speaks it — and, if you say yes, writes exactly this block for `logs` with the endpoint and `host` attribute you give, keeps the token it read with echo off in `~/.config/podaro/hec.token` (`0600`), restarts the engine, and runs `observe test` before it finishes (INSTALL §2). The default is no.

**As built.** Export is off unless `observability:` names a destination: with no block the engine holds no client and opens no connection. What is exported is the engine's own operational signal — the journal lines the operator's own `journalctl` shows, one span per job (`podaro.create`, `podaro.destroy`, …) carrying the instance, the outcome and the duration, and the counts a job changes — never a lab's data. Records queue and never hold the engine: a full queue drops its oldest and counts the drop; a redaction filter that cannot be built (an unreadable secret store, `PDR-E412`) *withholds* the record rather than exporting text no filter saw, and counts that too. `podaro observe status` reports both counts and the last failure; `podaro observe test` exits non-zero when any probe did not land, and prints what the destination answered rather than a summary. Neither command can turn export on or move it: that is `config.yaml`, which the operator owns and the engine reads at start. A destination whose certificate you cannot verify yet takes `insecure: true` on that signal — explicit, per signal, named at every engine start and marked in `observe status` and `doctor`. It is the same connection minus verification: whatever the host's environment configures, `HTTPS_PROXY` above all, still applies to it.

**The source of the build you run (optional).** Every copy of Podaro offers its own source: `podaro legal`, and the console's `/legal` page for anyone who can reach the console, name the licence, the project's statements and where the exact source of the running binary is — the release's tag in the repository the binary names, or, for a build from the development line, that no tag holds it. An operator who runs a modified or downstream build publishes its source (`SOURCE-AND-BUILD.md`) and says where:

```yaml
# ~/.config/podaro/config.yaml
legal:
  source_url: https://git.example.com/our-fork/podaro   # printed beside the build's own offer, never in place of it
```

The value is printed on a page anyone who can reach the gateway reads, so it is an `http(s)` location and nothing else — one carrying a credential, a query or a fragment is refused. The engine reads it at start and when `podaro setup` reloads the configuration.

**Where things live** (XDG paths, rootless): configuration in `~/.config/podaro/`, everything generated in `~/.local/state/podaro/` — instances, secrets (0600, per instance), evidence, the CA. Templates you author live wherever you keep code. The engine runs as a systemd *user* service (`systemctl --user status podaro`), installed with lingering so labs survive logout.

## 5. Networking and DNS

Every instance gets browser-reachable hostnames under your domain, flattened to a single level so **one wildcard record and one wildcard certificate cover everything**:

| What | Hostname pattern | Example |
|---|---|---|
| Console | `<instance>.<domain>` | `intro.lab.example.com` |
| Each product UI | `<service>-<instance>.<domain>` | `grafana-intro.lab.example.com` |

Only the gateway port (default 7777) is ever exposed on the host. Product ports stay internal to the instance's isolated network. Unknown hostnames are dropped, and nothing answers unauthenticated.

**Option A — real DNS (shared/cloud use):** one record does it all: `*.lab.example.com  A  <VM-IP>`.

**Option B — workstation hosts file (private labs):** on the machine running the *browser*, add lines per hostname the console shows you (hosts files don't support wildcards):

```
203.0.113.10  intro.lab.example.com grafana-intro.lab.example.com prometheus-intro.lab.example.com
```

> **Never add these hostnames to the VM's own `/etc/hosts`.** The gateway resolves services internally; overriding names on the server itself can loop traffic. This rule has scars behind it.

## 6. Quickstart — the starter lab in ten minutes

One lab ships: `grafana-prometheus-intro` — Prometheus and Grafana, all open source, 4 GB (§12). It is the MVP's scripted experience, and it asks for no licence: every image in it is open source.

```
sudo -iu podaro                            # every podaro command runs as the account
podaro doctor                              # everything green?
podaro up grafana-prometheus-intro --name intro
```

`up` validates the template, shows you the plan, creates the instance, seeds it, and verifies it — streaming progress the whole way:

```
intro · grafana-prometheus-intro@1.0.0 · ●◐○○○○○ initializing
  grafana       ◐ initializing   typically 20s · elapsed 0:09
  prometheus    ● initialized    healthy in 13s
  checkpoints   baseline 0/4 · objectives 0/2
```

Each service's line says what it is waiting on and how long that typically takes, so the ladder tells you it's working, not stuck. When every service reaches *ready*:

```
✓ intro is ready — baseline 4/4 verified · objectives 0/2 (those are yours to earn)

https://intro.lab.example.com:7777
```

Four baselines passed — Prometheus is ready, Grafana is healthy, and Prometheus is scraping both itself and Grafana — so the lab proved itself before you touched it. The two objectives are red, as they should be: they are the checkpoints the lab exists to *earn*, `podaro verify` reports them by class, and neither gates `ready`.

Open the console, log in with your operator account, and follow the **Start here** card: the *Your First Verified Dashboard* playbook in Guided mode. Press **Run this step** on *Drive real traffic* — 200 query requests hit the Prometheus API and the checkpoint proves Prometheus counted them — then, in the Grafana tab, build a dashboard titled exactly **Lab Overview**, save it, hit **Verify**, and watch the checkpoint ask Grafana's own API whether that dashboard exists. Flip the rail to **Presenter** to see the same lab as a demo script with confidence lights. Open **Evidence** for the report. Then:

```
podaro reset intro      # back to freshly-verified baseline (shows impact first, asks)
podaro destroy intro    # gone completely: containers, volumes, network, secrets, routes
```

That loop — up, prove, use, reset, destroy — is the whole product. Everything else is detail.

## 7. The console

One page per instance; no navigation between pages. Three regions, in reading order:

**Status bar (top).** Instance name and template, the condensed ready ladder, and global actions (reset, evidence, logout). If anything regresses below *ready*, this bar tells you before your audience notices: the condensed ladder turns amber, and a screen reader is told once, in words. It says it only for a real fall — a lab that was ready and is not now — and never while a job is running, so a reset in progress raises no alarm (UX §5).

**Playbook rail (left, collapsible).** The active playbook in the active mode: current step narrative, its action buttons (e.g. **Send query-load · 200**, or one **Run this step** on a step that runs itself), its **Verify** button and result, and your position (`Step 2 of 4`). Selecting a step focuses the product tab it belongs to; switching tabs highlights which steps apply there.

**Tab strip and workspace (right).** `Overview` first: the full ladder per service with elapsed and typical times, the start-here card, and instance facts (URLs, profile, created-at). Then one tab per product UI — Grafana and Prometheus in the starter lab — embedded live through the gateway. Tabs load lazily (a heavy product UI costs nothing until you open it) and stay warm once opened. A product that can't be embedded shows a styled **Open ↗** card instead and opens in its own browser tab; the playbook rail stays in sync either way. `Evidence` last: every checkpoint run, filterable, with the downloadable HTML report.

**Credentials.** Nothing in Podaro has default passwords — every credential is generated per instance. Reveal them only in the console (Overview → Credentials → click to reveal; each reveal is recorded in evidence). The CLI deliberately never prints secret values.

## 8. Running labs — the instance lifecycle

```
podaro up <template|path> [--name X] [--profile standard] [--mode authoring|delivery]
podaro status [X] [--watch]                            # the ladder, live
podaro logs X [service] [--since 10m]                  # redacted service logs
podaro seed X <seed-name>                              # run a named data injection again
podaro verify X [--playbook <name>]                    # run all (or one playbook's) checkpoints now
podaro reset X                                         # return to freshly-verified baseline
podaro destroy X                                       # remove everything, confirm by name
```

Notes that save time: `up` is safe to interrupt — rerunning continues or cleans up, never half-duplicates. Instances survive host reboots: on start, the engine reconciles — containers return to their prior stage and baselines re-verify, all reported on the ladder; init and standing seeds are not run again against containers that kept their data. The reconcile says what it re-verified, in the journal and in evidence: the baselines were judged again and the objectives keep their verdicts (they are your work, and the containers kept what they held) — unless a container had to be recreated, in which case both classes are judged again, because the data a verdict was earned in went with it. The `ready` line after a reconcile reads `reconciled · …`, so a board you come back to says which run proved it. Instances have a fixed **mode**: `up` on a directory defaults to *authoring* (tracks your working files; evidence flagged as authoring work); `up` on a catalog template or a bundle defaults to *delivery* — snapshot-pinned and immutable, which is what audiences and attendees get. Modes never switch in place; to deliver what you authored, create a delivery instance from it. `reset` always shows its impact (what is destroyed, what survives) before asking; in this release reset is full-to-baseline, with finer scopes (data-only) on the roadmap. Reset also clears *objective* progress — the system and the record stay in agreement — while completed-run history remains in immutable evidence; the impact preview says so. `verify` is your pre-flight: run it before an audience ever sees the instance. This release certifies one instance at a time; you *can* start more, but concurrent-isolation guarantees land in the next release.

## 9. Taking a guided lab (trainees, sandbox users)

You need: an access link and a browser — the link signs you into *this lab only* (§2.1); there is nothing to install and no account to make. The console shows you what that link covers and nothing else: no Reset, no other labs — there is no control here whose answer would be “not allowed”. Open it, press **Start** on the offered playbook, and work through the steps — each tells you which tab to work in and focuses it for you. When a step has a checkpoint, do the work in the product, then press **Verify**. Green means the *system state* proves you did it; you can't green-light a step by clicking around. Red comes with the author's hint ("Nothing found? Check the title is exactly “Lab Overview” and that you pressed Save…") — fix and verify again. Gating in this release is *soft*: you may continue past a red step, but it stays visibly red. Steps that can't be machine-checked ask for self-confirmation and are recorded as such. Your progress is saved on the instance — close the browser, come back, resume. Finishing produces your completion evidence in the Evidence tab: every checkpoint, timestamped, downloadable.

## 10. Presenting a demo (solutions engineers)

**Before the audience:** `podaro verify intro` — every checkpoint runs; walk on stage only on green. **During:** switch the rail to Presenter. You advance steps; speaker notes and per-step confidence lights are in the rail (arrange windows so the audience sees the product tabs, not your notes — a dedicated clean-screen toggle is on the roadmap). The lights are checkpoints running silently: when you say "and Grafana now has that dashboard," the green dot means it's *true*. Seed buttons are your set pieces — **Send query-load · 200** (or **Run this step**) on cue. **When something goes sideways:** re-run the seed; if the instance is disturbed beyond a step, `podaro reset` returns you to verified baseline in about a minute on the starter lab — occasionally worth doing *during* the coffee-break story. **After:** the Evidence HTML report is your follow-up artifact — "here's the traffic Prometheus counted and the dashboard Grafana confirmed," with the timestamped queries that proved each.

## 11. Authoring basics

The authoring reference is the starter template, `scenarios/grafana-prometheus-intro/`, with the schemas in `schemas/`; here is the shape of it.

```
podaro lab init --from grafana-prometheus-intro ./my-lab   # scaffold from any installed template
podaro lab validate ./my-lab                               # schema + policy, with file:line errors
podaro lab plan ./my-lab                                   # human-readable diff of what create would do
podaro up ./my-lab --name dev                              # the inner loop; edit → up → look
```

An instance created from a path is an **authoring** instance: it tracks your directory, offers Author preview, wears a quiet `authoring` chip, and marks its evidence as authoring work — never confusable with a delivery run. The **workbench**, planned for a later release, adds an in-network inspector and toolbox tab to authoring instances only. And when the built-in adapters don't know your product, `adapter: exec` runs *your* digest-pinned container on the lab network as the judge — the community extension point. A minimal lab is genuinely minimal — modules carry the defaults:

```yaml
# yaml-language-server: $schema=https://schemas.podaro.dev/lab/v1alpha2.json
apiVersion: lab.podaro.dev/v1alpha2
kind: Template
metadata: { name: metrics-intro }
services:
  prometheus: { use: modules/prometheus@3.13 }
  grafana:    { use: modules/grafana@12.4 }
seeds:
  query-load: { generator: http-requests, count: 200, params: { service: prometheus, path: "/api/v1/query?query=up" } }
checkpoints:
  - id: grafana-scraped
    adapter: http
    params: { url: "http://prometheus:9090/api/v1/query?query=up{job=\"grafana\"}" }
    expect: { json_path: { path: "$.data.result[0].value[1]", op: eq, value: "1" } }
```

That schema header line gives you autocomplete, inline validation, and hover docs in VS Code with no extra tooling. Playbooks are YAML too — steps with markdown narrative, a `context` naming the tab, optional `actions` (seeds), an optional `checkpoint` with an authored `hint`. In the console, Author preview renders any playbook in any mode against your live dev instance, with a **test this checkpoint now** button per step.

## 12. The starter lab: grafana-prometheus-intro

The catalog's one template, *Grafana & Prometheus Intro* (`grafana-prometheus-intro@1.0.0`): a small, all-open-source lab that proves none of this is stack-specific — Prometheus scraping itself and Grafana, Grafana visualizing it, in 4 GB. It is also the reference the frozen interfaces — the schemas under `schemas/` — are written against.

**Services.** `prometheus` (`modules/prometheus@3.13`, Apache-2.0), scraping itself and the sibling `grafana` service every five seconds; and `grafana` (`modules/grafana@12.4`, AGPL-3.0-only), shipped with its Prometheus datasource already provisioned, embedding allowed and anonymous viewer access — labs are permissive; the platform contains them. Both images are open source and digest-pinned, so the lab declares no EULA and `up` asks for no licence. The one credential, Grafana's admin login, is generated per instance and revealed only in the console. Profile `standard` — *4 GB host · all open source* — gives each service 500m CPU and 512 MiB.

**Seed.** `query-load`: the `http-requests` generator sends 200 requests to the Prometheus query API (`/api/v1/query?query=up`) — deterministic, and safe to repeat.

**Baselines** (all `http`, all gating *ready*): `prometheus-ready` (Prometheus answers `/-/ready`), `grafana-healthy` (Grafana answers `/api/health`), `self-scrape-up` (`up{job="prometheus"}` is 1) and `grafana-scraped` (`up{job="grafana"}` is 1). Four green lights mean both services are up and Prometheus really is observing both — the lab proved itself before anyone touched it.

**Playbook.** *Your First Verified Dashboard* (`first-dashboard`, Guided and Presenter, soft gating), four steps:

| Step | Tab | What you do | Objective |
|---|---|---|---|
| `meet-the-stack` · Meet the stack | Overview | read the baseline board: the lab already proved itself | — |
| `drive-real-traffic` · Drive real traffic | Prometheus | run the step (seed `query-load`), then graph `prometheus_http_requests_total` | `traffic-observed` — Prometheus counts at least 200 requests to its query API |
| `build-a-dashboard` · Build a dashboard the system can find | Grafana | reveal the credential; build and save a dashboard titled exactly **Lab Overview** | `dashboard-exists` — Grafana's own search API returns a dashboard titled *Lab Overview* |
| `leave-with-receipts` · Leave with the receipts | Overview | download the Evidence report; break something and **Reset** | — |

Both objectives are red at create, as objectives should be: the traffic and the dashboard are the learner's work (so the lab never raises `PDR-W101`). Reset clears them; evidence keeps every run.

The lab retired on 2026-09-23 is not in the catalog and never shipped in a release; `podaro up` of its name is refused with `PDR-E107` before anything is validated.

## 13. Security model

**What the platform guarantees:** every container rootless and unprivileged; no host bind mounts by default; each instance on its own isolated network — instances cannot see each other or the host's services; the gateway is the only listener, TLS-fronted, deny-until-authenticated, dropping unknown hostnames; secrets generated per instance, stored 0600, revealed only through the audited console action, absent from logs, CLI output, and evidence; images digest-pinned. Attendee sessions are instance-confined by the engine and the gateway alike — no destroy, no reset, nothing beyond their lab. The trust boundaries and the residual risks, named rather than hidden, are in [`ARCHITECTURE.md`](ARCHITECTURE.md).

**What remains yours:** the VM itself — patching, firewalling (expose only the gateway port), snapshots; the safety of your DNS zone; protecting the operator login; trusting the local CA only on machines you control; and remembering that *labs are not production* — templates may deliberately run permissive product configurations, which is exactly why the platform contains them. Found a vulnerability? `SECURITY.md` in the repository has the disclosure process.

## 14. Troubleshooting

**Start with `podaro doctor`** — most issues are environmental and doctor names the fix. Every Podaro error follows one anatomy:

```
✗ PDR-E404  seed query-load cannot reach prometheus:9090
  cause     dial tcp: connect: connection refused
  evidence  /api/v1alpha1/instances/intro/evidence/ev_01J9…
  next      podaro status intro · the service must be running and the port a declared endpoint
```

Stable code, cause, evidence pointer, next action. If a message ever leaves you guessing, that's a documentation bug — please file it.

| Symptom | What's happening | Do |
|---|---|---|
| A service stuck at *initializing* | Its line shows elapsed against the module's typical time; some products are slow on first boot | Wait while elapsed is near typical; past it, `podaro logs X <service>` |
| Browser certificate warning | Local CA not trusted on this machine | Import `ca.crt` per §4, or bring your own cert |
| Console URL doesn't resolve | DNS/hosts not pointed at the VM | §5; and never on the VM's own `/etc/hosts` |
| `lab validate` or `up` fails with `PDR-E106` | The manifest names an adapter, generator or module retired with the lab retired on 2026-09-23 | Remove it, or judge with `http`, `container` or an `exec` adapter, generate with `http-requests`, `web-logs` or an `exec` generator, bring an inline service pinned by digest — `podaro explain PDR-E106` |
| `PDR-W103` on the install board, under `podaro status`, in the upgrade report or in the engine's log | An earlier build left something of the template retired on 2026-09-23 on this host: a catalog entry, or an instance created from it. Nothing deletes it; this release never offers the entry (`up` or `lab init --from` it is `PDR-E107`) and never reconciles, repairs, restarts or stops the instance — its containers stay as they are, and `status` reads `unsupported · retired template` | Save what you need from its evidence and reports, then `podaro destroy <instance>` — the one act that removes it; the catalog entry is yours to delete from the state directory — `podaro explain PDR-W103` |
| `verify`, `seed`, `reset`, a checkpoint run or a playbook action fails with `PDR-E215` | The instance is one an earlier build created from a retired template: this release carries none of what its lab used and does not run it | `podaro status X`, its evidence and its HTML and JUnit reports still read; `podaro destroy X` removes it — `podaro explain PDR-E215` |
| Services OOM-killed / very slow | Host under-provisioned for the template | §3 sizing; try a smaller template |
| A product tab is a card, not embedded | That product can't be safely iframed | Use **Open ↗**; the rail stays in sync |
| Checkpoint red but the product "looks right" | Checkpoints test state, not screens — something really is missing (often an un-deployed config) | Read the hint; hints are written for exactly this moment |
| `podman` permission errors | Rootless setup incomplete | `podaro doctor` — subuid/subgid and lingering checks |
| Console and product hostnames unreachable, DNS fine | The engine service is stopped or restarting | `podaro system status`, then `podaro system start`; `journalctl --user -u podaro` says why it stopped |

## 15. CLI reference

| Command | Purpose |
|---|---|
| `podaro doctor` | Environment diagnostics with remediations — a read of the host, never a fix. Per-instance diagnostics (`doctor <instance> --check <x>` and a `POST /system/doctor` route) are not built in this release; a lab's own account is `podaro logs` and its Evidence tab |
| `podaro setup` / `podaro auth …` | Domain, TLS, operator login (`auth reset` works only at the local socket, by design) |
| `podaro system install/upgrade/uninstall/status/start/stop/restart` | Service lifecycle. `status` reads `podaro.service` from systemd and probes the engine behind it, exit 0 only when both are up (`--json` for the facts); `start`, `stop` and `restart` drive the unit through `systemctl --user` with the account's session filled in, from any shell the account gets, and a stopped engine leaves the labs' containers running and the console unreachable. `upgrade` verifies a release's checksum before replacing anything and backs up the state first, and before it fetches anything lists what an earlier build left of a retired template (INSTALL §6); `--from` points at your own mirror on a host with no route out |
| `podaro access create/list/revoke <X>` | Attendee access links — instance-scoped, expiring (8h by default, 24h at most), revocable, audited. The link is printed once: Podaro keeps only its hash |
| `podaro observe status/test` | Observability-export posture; send a verification probe through each configured signal |
| `podaro up <template\|dir\|bundle> [--name] [--profile] [--mode] [--accept-license <id>]…` | Create + seed + verify, streaming progress; a template with vendor terms is created only after each licence id is typed at the prompt or passed by flag |
| `podaro status [X] [--watch]` | Ready ladder. `--watch` re-renders it as it moves — in place on a terminal, change by change when piped — until Ctrl-C, or until the lab is gone; with `--json`, one object per change. An instance an earlier build created from a retired template reads `unsupported · retired template` (§14) |
| `podaro logs X [service]` | Redacted logs (`--since 10m`, `--tail 200`, `-f` to follow). Naming no service lists the instance's own. A read capped at 4 MiB says so on stderr, so the log on stdout stays the product's own words |
| `podaro seed X <seed>` | Re-run a data injection |
| `podaro verify X [--playbook]` | Run checkpoints now (pre-flight) |
| `podaro reset X` | Baseline reset, impact shown first |
| `podaro destroy X` | Remove the instance entirely |
| `podaro lab init/validate/plan` | Authoring loop. `lab init --from <template> <dir>` copies an installed template (or the starter catalog inside the binary, before `system install` has run) and renames it after the directory — the one edit every copy needs; it refuses a directory that already holds files |
| `podaro catalog` | **Not in this release.** Browsing and searching the installed catalog is planned for a later release. What lists it today: `podaro status` on a host with no instances offers every installed template, `lab init --from` and `up` refuse an unknown name with the installed ones on the cause line, and `podaro system install` prints what it extracted. None of them offers a retired template, even where an earlier build left one in the catalog; the board and `status` say once that it is there (`PDR-W103`). |
| `podaro explain <PDR-Exxx>` | Expand any error code: cause, background, fixes. Offline — it reads the registry inside the binary, so it works when the engine does not. `--list` prints every code this release can emit; the code may be typed as you read it (`pdr-e503`, `E503`, `503`). |
| `podaro legal [--licenses]` | The licence (`AGPL-3.0-only`), the project's copyright and licensing statements, the offer of this binary's exact source, where releases are published and how to verify one against `SHA256SUMS`, the policy for the name (`TRADEMARKS.md`) and the third-party components — offline, from the files inside the binary. `--licenses` prints every licence and notice text the binary carries. The console's `/legal` page, linked from every page's footer, shows the same to anyone who can reach the console, signed in or not |

Machine-readable output: add `--json` to any read command.

## 16. Limits of this release, and what's next

This release: one host, one certified instance at a time, instance modes (authoring vs. delivery), soft gating, full-baseline reset, bring-your-own or generated TLS, guided + presenter modes. On the roadmap (in order): portable lab bundles (export any lab, re-use it on another VM) with repro mode built on them, proven concurrent instances, scoped resets, strict gating, polished evidence reports, LLM integration (authoring assistance and a read-only MCP server), then the bootable appliance image, ACME automation, TTL-bound share links, and small-footprint profiles. The **Podaro Community** product you're holding is complete, not a teaser.

## 17. Help, contributing, licenses

Questions and ideas: GitHub Discussions. Bugs: issues, with the error code and the evidence file when you have them. Contributions: start with `CONTRIBUTING.md` — lab content (templates, modules, playbooks) is the easiest and most valuable place to begin, and a lab you write for your own products is yours: it does not become AGPL merely because Podaro reads, stores, renders or executes it, while copying protected expression from a Podaro example is assessed under the AGPL. Podaro's first-party material, this manual included, is AGPL-3.0-only; `NOTICE` carries the project's copyright statement, `THIRD-PARTY-NOTICES.md` every third-party notice, and `TRADEMARKS.md` the separate policy for the name. Every release carries them, and every copy shows them: `podaro legal`, and the console's `/legal` page.

## Appendix — uninstall

```
podaro destroy <name>           # once per lab, confirmed by typing its name
podaro system uninstall         # removes the service, binary, CA, config; prints what it deletes first
sudo /opt/podaro/podaroctl system uninstall         # the same from your own shell (sudo podaroctl … once it is on PATH)
sudo /opt/podaro/install.sh --uninstall [--purge]   # the same from outside the account; --purge also removes it and /opt/podaro
```

State directories are listed before removal; nothing outside `~/.config/podaro` and `~/.local/state/podaro` is touched.

---

*Podaro Community User Manual v0.1 draft · this manual is the specification the software is built to*
