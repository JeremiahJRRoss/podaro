<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Podaro Quick Start — Ubuntu/Debian

You’ll need an Ubuntu or Debian server with systemd, at least **4 GB RAM**, sudo access, and network access for downloads. Podaro requires **Podman 4.4 or newer**. Allow **TCP port 7777** from the computer running your browser.

> **DNS requirement:** Your Podaro domain and lab subdomains must resolve to your server’s IP address. Configure a base-domain record and a wildcard DNS record as shown below. For private testing, you can use individual hosts-file entries on your workstation instead.

These instructions build from the source ZIP. The [build script](https://github.com/JeremiahJRRoss/podaro/blob/main/build.sh) supports `--install`, which handles package extraction and launches the installer.

## 1. Download, build, and install

Run these commands on the server as your normal sudo-enabled user, starting in a fresh working directory:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl unzip tar gzip coreutils python3

curl -fL https://github.com/JeremiahJRRoss/podaro/archive/refs/heads/main.zip -o podaro-main.zip
unzip podaro-main.zip
cd podaro-main

chmod +x build.sh install.sh hack/release_package.sh
./build.sh --yes --install
```

`--yes` lets the build script install a missing or outdated Go toolchain. `--install` creates `/opt/podaro`, extracts the built package, copies `SHA256SUMS`, and runs the installer through sudo.

The installer can install Podman and its rootless helpers through apt when needed.

**Build before installing:** running `install.sh` directly from the source ZIP fails because the compiled binary isn’t there yet.

## 2. Answer the installer prompts

For a private test setup, use:

| Prompt | Answer |
|---|---|
| Domain | `lab.example.test` |
| Gateway port | `7777` |
| Address for DNS | Your server’s IP address, reachable from your browser |
| TLS | `local-ca` |
| Operator username | `podaro-admin`, or your preferred login |
| Export logs | `no` |
| Create the starter lab | `yes` |
| Put `podaroctl` on PATH | `yes` |
| Install Podman, if asked | `yes` |

Confirm the plan and set your console password when prompted.

The installer creates the dedicated `podaro` Linux account and starts its service. Creating the starter lab also downloads the Grafana and Prometheus images.

## 3. Configure DNS or workstation hosts entries

The domain you entered during installation must resolve to your server from the computer running your browser. The installer prints the required DNS information, but you must configure the records yourself.

### Option A: DNS with a wildcard

For example, if your server is `192.168.1.50`, configure these records in the DNS server your workstation uses:

```text
lab.example.test      A    192.168.1.50
*.lab.example.test    A    192.168.1.50
```

Replace the domain and IP with your own. Use the same domain you entered during installation.

The wildcard covers lab and product hostnames such as:

- `intro.lab.example.test`
- `grafana-intro.lab.example.test`
- `prometheus-intro.lab.example.test`

The separate base-domain record covers `lab.example.test`, which the wildcard does not cover.

`lab.example.test` is an example for private testing. For public DNS, use a domain you control and an address reachable by your users.

### Option B: Workstation hosts file

For private testing without configuring DNS, add this line to the hosts file on the computer running your browser. Replace `192.168.1.50` with your server’s actual IP:

```text
192.168.1.50 lab.example.test intro.lab.example.test grafana-intro.lab.example.test prometheus-intro.lab.example.test
```

| Operating system | Hosts file |
|---|---|
| Linux/macOS | `/etc/hosts` |
| Windows | `C:\Windows\System32\drivers\etc\hosts` |

Edit the file with administrator privileges.

**Hosts files do not support wildcards.** Include all four names so the console and application tabs work, and add entries for any additional labs you create.

For a separate server, make these changes on your workstation. The [Podaro manual](https://github.com/JeremiahJRRoss/podaro/blob/main/public-docs/USERMANUAL.md#5-networking-and-dns) warns against adding the lab names to the server’s own hosts file.

## 4. Download and trust the CA certificate

On the server, make the public CA certificate available to copy:

```bash
sudo install -m 0644 \
  /opt/podaro/.local/state/podaro/ca/ca.crt \
  /tmp/podaro-ca.crt
```

On your browser’s computer, download it using your normal SSH account. Replace `youruser` and `SERVER_IP`:

```bash
scp youruser@SERVER_IP:/tmp/podaro-ca.crt .
```

Import `podaro-ca.crt` into the browser you’ll use:

| Browser | How to trust the CA |
|---|---|
| Chrome | Open `chrome://certificate-manager` and add the file as a trusted certificate. |
| Firefox | Open Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import. Select the file and enable trust for identifying websites. |

Restart your browser after importing.

**Copy only the public `.crt` file; keep `ca.key` on the server.**

Browser documentation: [Chrome certificate management](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md) · [Firefox certificate trust](https://wiki.mozilla.org/CA/Changing_Trust_Settings)

## 5. Open your first lab

Check the lab from your normal server shell:

```bash
sudo podaroctl status intro
```

If you chose **no** when asked to create the starter lab, create it now:

```bash
sudo podaroctl up grafana-prometheus-intro --name intro
```

Once ready, open:

**[https://intro.lab.example.test:7777](https://intro.lab.example.test:7777)**

If you used a different domain or port, use the console URL printed by Podaro.

Sign in with the operator username and password you created, then follow **Start here**.

Baseline checks should pass. Incomplete objective checks are expected until you do the exercises.

## Troubleshooting

Run:

```bash
sudo podaroctl doctor
```

| Symptom | Check |
|---|---|
| Hostname error | Confirm DNS or workstation hosts entries resolve the requested hostname to your server’s IP. |
| Base domain works but lab hostnames fail | Check the wildcard DNS record, or add each lab hostname to your workstation’s hosts file. |
| Certificate warning | Confirm you imported and trusted the Podaro CA in the browser you’re using. |
| Connection timeout | Check the server address, service, and firewall access to TCP port 7777. |
| Console opens but application tabs fail | Confirm the Grafana and Prometheus hostnames also resolve to the server. |
| `sudo: podaroctl: command not found` | Use `sudo /opt/podaro/podaroctl doctor` and the same full path for other commands. |

---

# Podaro Quick Start — CentOS Stream 10

You’ll need a CentOS Stream 10 server with systemd, at least **4 GB RAM**, sudo access, and network access for downloads. Podaro requires **Podman 4.4 or newer**. Allow **TCP port 7777** from the computer running your browser.

> **DNS requirement:** Your Podaro domain and lab subdomains must resolve to your server’s IP address. Configure a base-domain record and a wildcard DNS record as shown below. For private testing, you can use individual hosts-file entries on your workstation instead.

These instructions build from the source ZIP. The [build script](https://github.com/JeremiahJRRoss/podaro/blob/main/build.sh) supports `--install`, which handles package extraction and launches the installer.

**CentOS prerequisite:** Install Podman before running the installer. The installer’s automatic Podman installation currently uses apt, so it cannot perform that step on CentOS.

## 1. Install prerequisites, then download and build

Run these commands on the server as your normal sudo-enabled user:

```bash
sudo dnf install -y \
  ca-certificates unzip tar gzip coreutils python3 \
  podman shadow-utils passt fuse-overlayfs \
  dbus-broker iproute hostname procps-ng util-linux firewalld

command -v curl >/dev/null || sudo dnf install -y curl
```

The conditional command keeps an existing `curl` installation, including `curl-minimal`, and installs curl if it is missing.

Check that Podman and the user-namespace helpers are available:

```bash
podman --version
command -v newuidmap newgidmap
```

Podman must be version **4.4 or newer**, and both helper commands must be found before continuing.

From a fresh working directory, download and build Podaro:

```bash
curl -fL https://github.com/JeremiahJRRoss/podaro/archive/refs/heads/main.zip -o podaro-main.zip
unzip podaro-main.zip
cd podaro-main

chmod +x build.sh install.sh hack/release_package.sh
./build.sh --yes --install
```

`--yes` lets the build script install a missing or outdated Go toolchain. On CentOS, its fallback downloads and checksum-verifies the official Go archive and installs it under `/usr/local/go`.

`--install` creates `/opt/podaro`, extracts the built package, copies `SHA256SUMS`, and runs the installer through sudo.

**Build before installing:** running `install.sh` directly from the source ZIP fails because the compiled binary isn’t there yet.

## 2. Answer the installer prompts

For a private test setup, use:

| Prompt | Answer |
|---|---|
| Domain | `lab.example.test` |
| Gateway port | `7777` |
| Address for DNS | Your server’s IP address, reachable from your browser |
| TLS | `local-ca` |
| Operator username | `podaro-admin`, or your preferred login |
| Export logs | `no` |
| Create the starter lab | `yes` |
| Put `podaroctl` on PATH | `yes` |

Podman should already be detected from the prerequisite installation.

Confirm the plan and set your console password when prompted.

The installer creates the dedicated `podaro` Linux account, configures subordinate user/group IDs and lingering, and starts its user service. Creating the starter lab also downloads the Grafana and Prometheus images.

## 3. Allow the gateway through firewalld

On a standard test server using firewalld, start it and inspect the active zones:

```bash
sudo systemctl enable --now firewalld
sudo firewall-cmd --get-active-zones
```

Open TCP port 7777 in the zone used by the server’s network interface. The following example uses `public`; replace it if your interface uses another zone:

```bash
sudo firewall-cmd --zone=public --add-port=7777/tcp
sudo firewall-cmd --permanent --zone=public --add-port=7777/tcp
sudo firewall-cmd --zone=public --query-port=7777/tcp
```

The first command applies the rule immediately. The second preserves it across restarts. The final command should print `yes`.

If you selected another gateway port, use that port instead.

If the server is behind a cloud firewall, security group, or router, allow the same TCP port there from your browser’s network.

## 4. Configure DNS or workstation hosts entries

The domain you entered during installation must resolve to your server from the computer running your browser. The installer prints the required DNS information, but you must configure the records yourself.

### Option A: DNS with a wildcard

For example, if your server is `192.168.1.50`, configure these records in the DNS server your workstation uses:

```text
lab.example.test      A    192.168.1.50
*.lab.example.test    A    192.168.1.50
```

Replace the domain and IP with your own. Use the same domain you entered during installation.

The wildcard covers lab and product hostnames such as:

- `intro.lab.example.test`
- `grafana-intro.lab.example.test`
- `prometheus-intro.lab.example.test`

The separate base-domain record covers `lab.example.test`, which the wildcard does not cover.

`lab.example.test` is an example for private testing. For public DNS, use a domain you control and an address reachable by your users.

### Option B: Workstation hosts file

For private testing without configuring DNS, add this line to the hosts file on the computer running your browser. Replace `192.168.1.50` with your server’s actual IP:

```text
192.168.1.50 lab.example.test intro.lab.example.test grafana-intro.lab.example.test prometheus-intro.lab.example.test
```

| Operating system | Hosts file |
|---|---|
| Linux/macOS | `/etc/hosts` |
| Windows | `C:\Windows\System32\drivers\etc\hosts` |

Edit the file with administrator privileges.

**Hosts files do not support wildcards.** Include all four names so the console and application tabs work, and add entries for any additional labs you create.

For a separate server, make these changes on your workstation. The [Podaro manual](https://github.com/JeremiahJRRoss/podaro/blob/main/public-docs/USERMANUAL.md#5-networking-and-dns) warns against adding the lab names to the server’s own hosts file.

## 5. Download and trust the CA certificate

On the server, make the public CA certificate available to copy:

```bash
sudo install -m 0644 \
  /opt/podaro/.local/state/podaro/ca/ca.crt \
  /tmp/podaro-ca.crt
```

On your browser’s computer, download it using your normal SSH account. Replace `youruser` and `SERVER_IP`:

```bash
scp youruser@SERVER_IP:/tmp/podaro-ca.crt .
```

Import `podaro-ca.crt` into the browser you’ll use:

| Browser | How to trust the CA |
|---|---|
| Chrome | Open `chrome://certificate-manager` and add the file as a trusted certificate. |
| Firefox | Open Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import. Select the file and enable trust for identifying websites. |

Restart your browser after importing.

Trust the certificate on the computer running your browser. Installing it only on the CentOS server does not establish trust in a browser on another computer.

**Copy only the public `.crt` file; keep `ca.key` on the server.**

Browser documentation: [Chrome certificate management](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md) · [Firefox certificate trust](https://wiki.mozilla.org/CA/Changing_Trust_Settings)

## 6. Open your first lab

Check the lab from your normal server shell:

```bash
sudo /opt/podaro/podaroctl status intro
```

These commands use the wrapper’s full path so they work even when sudo’s PATH excludes `/usr/local/bin`.

If you chose **no** when asked to create the starter lab, create it now:

```bash
sudo /opt/podaro/podaroctl up grafana-prometheus-intro --name intro
```

Once ready, open:

**[https://intro.lab.example.test:7777](https://intro.lab.example.test:7777)**

If you used a different domain or port, use the console URL printed by Podaro.

Sign in with the operator username and password you created, then follow **Start here**.

Baseline checks should pass. Incomplete objective checks are expected until you do the exercises.

## Troubleshooting

Run:

```bash
sudo /opt/podaro/podaroctl doctor
sudo /opt/podaro/podaroctl system status
```

| Symptom | Check |
|---|---|
| Installer says the host is not an apt system | Complete the DNF prerequisite step and confirm `podman` and `newuidmap` are available. |
| Hostname error | Confirm DNS or workstation hosts entries resolve the requested hostname to your server’s IP. |
| Base domain works but lab hostnames fail | Check the wildcard DNS record, or add each lab hostname to your workstation’s hosts file. |
| Certificate warning | Confirm you imported and trusted the Podaro CA in the browser you’re using. |
| Connection timeout | Check the server address, service, firewalld zone, and any external firewall rules for TCP port 7777. |
| Console opens but application tabs fail | Confirm the Grafana and Prometheus hostnames also resolve to the server. |
| `sudo: podaroctl: command not found` | Use the full path: `sudo /opt/podaro/podaroctl`. |


---
---
# Podaro Community — Installation Manual

**Applies to:** Podaro v0.1.x (MVP) · **Doc version:** 0.1 draft · **License:** AGPL-3.0-only


> **How to read this manual.** The terminal output shown is what the installer produces, and every "behind the surface" claim is meant to be true of the code: a difference between the manual and the machine is a bug, in one or the other, and worth a report. It expands User Manual §4; that chapter is the summary, this is the full account.


---

References: [Podaro installation manual](https://github.com/JeremiahJRRoss/podaro/blob/main/public-docs/INSTALL.md) · [Podman installation](https://podman.io/docs/installation) · [firewalld port configuration](https://firewalld.org/documentation/howto/open-a-port-or-service.html)
---

## 1. Before you begin

**What installing gets you:** the `podaro` binary — engine, CLI, console, and the starter catalog — one template, `grafana-prometheus-intro`, all open source — are all embedded in that one file. Installation is one script: host preparation as root, then self-extraction and a user service as the dedicated `podaro` account. **What it does not get you:** lab images (they download at your first `podaro up`; a template that declares a third-party licence is created only after you type its id, and the starter template declares none), and nothing runs as root at any point.

**The trust posture, up front:**

- **Host preparation runs as root, once, and says so line by line; the engine never does.** `install.sh`, run under `sudo`, creates the dedicated `podaro` account whose home is `/opt/podaro`, gives it subordinate ID ranges and session lingering, and installs Podman from your distribution if you say yes — each act printed as its own row before the next — and then drops to that account for everything else. Nothing Podaro-specific runs as root: the binary, the service, the engine and every lab belong to `podaro`. Run as that account instead, the script performs no privileged act at all and *prints* (never runs) any command `doctor` still asks root for, exactly as the by-hand installation does. Root's work is three named lines — the account, its subordinate IDs, its lingering — plus Podman and a `podaroctl` copy only when you say yes, each one you can read before you run it, and it stops there. It changes no kernel value.
- Everything lands under the **`podaro` account's** home, `/opt/podaro`: `~/.local/bin/podaro`, `~/.config/podaro/`, `~/.local/state/podaro/`, one systemd *user* unit, and a three-line block in the account's `~/.profile` that gives a `sudo -iu podaro` shell the runtime directory, session bus and PATH a login without a logind session lacks — `~` is `/opt/podaro` throughout this manual. Outside it: the account's line in each of `/etc/subuid` and `/etc/subgid`, and its lingering flag. Nothing in `/usr` — unless you answer yes to the one question that offers it, a root-owned copy of `podaroctl` in `/usr/local/bin` so that `sudo podaroctl …` works from any shell (step 1) — and nothing in anyone else's account. You operate it with `sudo -iu podaro`, or from your own shell through `podaroctl` (step 6).
- The installer **never edits your shell files.** The new account starts from your distribution's default profile, which already puts `~/.local/bin` on its PATH; if a host's does not, the script prints the line to add and where — rc files are their owner's.
- The only network access during installation is downloading the release itself. Zero telemetry, to the project or to anyone — no phone-home, no analytics, no background version checks, ever. The engine inherits those manners with one operator-owned exception: **observability export** (User Manual §4) can ship Podaro's *own* logs, metrics, and traces to destinations *you* configure — off until you turn it on, redaction-filtered like everything else.
- Before running anything, you're welcome to read it: `tar -tzf` lists the package as `podaro`, `install.sh`, `install.test.yaml` and `podaroctl`, and beside them what you are owed with the binary — `LICENSE` (the GNU AGPL, version 3), `NOTICE`, `TRADEMARKS.md`, `THIRD-PARTY-NOTICES.md`, `LICENSES/`, `SOURCE-AND-BUILD.md` and `RELEASE-MANIFEST.json` — and both scripts are deliberately readable, because the binary does the real work. A bootstrap script at `get.podaro.dev` that downloads and verifies the package and then runs `install.sh` is planned; until it exists, the tarball is the install.

**Requirements** (details in User Manual §3): a Linux host with systemd, Podman ≥ 4.4 configured rootless, 4 GB RAM (the starter template's declared host envelope), a free port (7777 by default), and DNS you can point at the machine.

---

## 2. The install, step by step

### Step 1 — Get the package and run the installer

**You see:**

```
$ sudo mkdir -p /opt/podaro && sudo tar -xzf podaro_v0.1.0_linux_amd64.tar.gz -C /opt/podaro
$ cd /opt/podaro && chmod +x install.sh && sudo ./install.sh
◐ package                podaro v0.1.0 · linux/x86_64 · digest listed in SHA256SUMS
? domain instances live under [lab.example.com]:
? gateway port [7777]:
? address for the DNS block [203.0.113.10]:
? TLS: local-ca or own [local-ca]:
? operator username [podaro-admin]:
? export Podaro's logs over the HTTP Event Collector protocol? yes/no [no]:
? create the open-source lab now (grafana-prometheus-intro as 'intro'; two image pulls)? yes/no [no]:
? put podaroctl on PATH (a root-owned copy in /usr/local/bin, so sudo podaroctl works from any shell)? yes/no [no]:

domain          lab.example.com
gateway port    7777
dns address     203.0.113.10
tls             local-ca
operator        podaro-admin
password        prompted by podaro auth setup
log export      no
first lab       no
podaroctl       not on PATH · sudo /opt/podaro/podaroctl <command>
account         podaro · home /opt/podaro
install podman  asked if missing · not needed: 5.7.1 already installed

proceed? [Y/n]:
✓ podman                 5.7.1 · already installed
✓ account podaro         created · home /opt/podaro · no password (use sudo -iu podaro)
✓ subuid / subgid        100000-165535 mapped for podaro
✓ lingering              enabled for podaro · service manager running
○ podaroctl              not on PATH · sudo /opt/podaro/podaroctl <command> works as is
→ continuing as podaro
✓ user session           podaro · /run/user/1001
✓ binary                 /opt/podaro/.local/bin/podaro (0755)
✓ notices                LICENSE · NOTICE · TRADEMARKS.md · THIRD-PARTY-NOTICES.md beside the binary
✓ profile                /opt/podaro/.profile · session variables and PATH for sudo -iu podaro shells
```

**Behind the surface:** the tarball is the release, downloaded from the project's releases, `https://github.com/JeremiahJRRoss/podaro/releases` — each release's artifacts under `…/download/v<version>/`, where `system upgrade` finds them too (§6), and the location `podaro legal` names as where official releases are published; `tar -tzf` shows its eleven entries, and `SHA256SUMS` beside it (download it too) lets the script check the binary's digest before anything else — a mismatch is never installed. Every prompt carries a default: the domain from the host's own name, the port, the address the DNS block will print, the local CA, `podaro-admin` as the operator login — the console's login, never the same thing as the `podaro` Linux account that owns the service; `--yes` with `--answers <file>` (or `PODARO_*` variables) answers them all for an unattended install, and `install.test.yaml` in the package is such a file for a test host. The root stage then does exactly the rows it prints and nothing else — `useradd` for the `podaro` account with `/opt/podaro` as its home (no password; `sudo -iu podaro` is the way in), `usermod` for a free subordinate ID range if the distribution did not allocate one, `loginctl enable-linger` so the account's service manager runs without a login, `apt-get install podman` only if Podman is missing and you said yes, and a root-owned copy of `podaroctl` into `/usr/local/bin` only if you asked for one — and hands over with `runuser` to the account, carrying the answers in its environment. From there on it is the account's script: the binary copied to `~/.local/bin/podaro` with mode `0755` and the four notices a recipient reads first — `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `THIRD-PARTY-NOTICES.md` — copied beside it (`0644`), then steps 2 to 6 below, each the same command you could type. The transcript is `/opt/podaro/install-<UTC>.log`. (Cryptographic release *signing* — sigstore — is on the roadmap; until then, the checksum file and the reproducible-build instructions in the repository are the verification path.) `sudo ./install.sh --check` reports which of these rows are already done on a host and changes nothing; `--uninstall` is §7. Run from a checkout of the repository rather than the package, the script stops at its first row — there is no binary beside it — and names `./build.sh --install`, which builds the release from the checkout and then runs it (§5).

**Exporting logs from the start.** Answer `yes` to the export question and the script asks three more things — the endpoint of a collector that speaks the HTTP Event Collector protocol (`https://host:8088`; the collector path is added), the token, read with echo off and never printed, and the `host` attribute stamped on every record (default: this host's name) — and the answers summary shows `log export      hec · https://… · host lab-01 · token provided (never shown)`. As the account it then writes the Manual §4 `observability:` block for `logs` into `config.yaml` before `setup` runs, keeps the token in `~/.config/podaro/hec.token` (`0600`), restarts the engine once the operator account exists — the exporter is built at engine start — and runs `podaro observe status` and `podaro observe test`, so the transcript ends with whether the probe landed:

```
✓ log export             hec · https://collector.example.com:8088 · host lab-01 · token in ~/.config/podaro/hec.token (0600)
✓ service                restarted to start the export
✓ export probe           landed at https://collector.example.com:8088
```

A probe that does not land is a `!` row and the install still completes: fix the destination or the token, then `podaro observe test`. Unattended, `export_logs: yes` needs `hec_token_file`, a `0600` file holding the token — never the token itself in the answers file. The default is `no`, and nothing leaves the host unless you asked.

**Creating the first lab from the installer.** Answer `yes` to the last question and, once the operator account exists, the script runs the same `podaro up grafana-prometheus-intro --name intro` the summary would otherwise offer — the starter catalog's one template — streaming the ladder as `up` does, two image pulls included. The summary then prints what the engine says the lab's hostnames are, so the DNS or hosts-file work is spelled out rather than discovered tab by tab:

```
✓ lab intro              grafana-prometheus-intro · created

point dns at this host (one wildcard record covers every lab):
  *.lab.example.com    A    203.0.113.10
  or, on the browsing machine's hosts file, one line with every name this lab uses:
    203.0.113.10  lab.example.com intro.lab.example.com grafana-intro.lab.example.com prometheus-intro.lab.example.com

lab intro (grafana-prometheus-intro):
  console      https://intro.lab.example.com:7777
  grafana      https://grafana-intro.lab.example.com:7777
  prometheus   https://prometheus-intro.lab.example.com:7777
  the product names are loaded by the console's tabs and answer only to a signed-in session

operate as the account:  sudo -iu podaro   ·   from any shell: sudo /opt/podaro/podaroctl <podaro command>   ·   console login: podaro-admin
→ next: open the lab: https://intro.lab.example.com:7777
```

A create that does not finish is a `✗` row naming `podaro status intro` and the `up` to re-run; the install itself still completes. An `intro` that already exists is kept. Unattended, the key is `create_lab`; the default is `no`, because image pulls and lab creation are `podaro up`'s work (§4), not installation's, unless you ask.

**As built.** A release carries two artifacts per architecture and one manifest for all of them, and `hack/release_package.sh <version>` in the repository builds them: the bare binary `podaro-<version>-linux-<arch>`, which the planned bootstrap script and `system upgrade` download; the tarball `podaro_v<version>_linux_<arch>.tar.gz` holding `podaro`, `install.sh`, `install.test.yaml` and `podaroctl` with the legal files a recipient of the binary is owed — `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `THIRD-PARTY-NOTICES.md` (every third-party notice and licence text the binary carries), `LICENSES/` (the Apache-2.0 text compiled dependencies carry) and `SOURCE-AND-BUILD.md` (where the source is and how this build is reproduced) — and `RELEASE-MANIFEST.json`, which names the version, the Go release that built it, the architectures and every binary's digest and carries no commit; step 1 extracts it whole and §5's by-hand path extracts `podaro` and the four notices from it; and `SHA256SUMS`, covering every artifact in the format `sha256sum -c` reads. The binary carries the same legal files inside it: `podaro legal` prints the licence, the notices and the offer of its own source, `podaro legal --licenses` every licence text, and the console's `/legal` page the same to anyone who can reach the console. The architectures are `amd64` and `arm64`, because the asset name is resolved from *your* machine's architecture and not the builder's; one Linux host builds them all, since the binary needs no cgo. They sit at `…/download/v<version>/`, the path `system upgrade` and a filled mirror both expect (§6). The reproducible-build instruction is that script: for each architecture it builds the binary twice and packs the tarball twice, refuses to finish if either pair differs, and refuses a version the repository's `VERSION` file does not carry — so anyone can rebuild a release from its commit with the same Go version and compare digests against `SHA256SUMS` — the script pins the target feature levels (`GOAMD64=v1`, `GOARM64=v8.0`), refuses a builder whose toolchain reports a non-default `GOEXPERIMENT`, `GOFLAGS` or `GOFIPS140` — those three change what the compiler puts in the binary, and no printed value would explain it, because both builds of a pair inherit the same one; the default each is compared against is the one that toolchain itself reports, so nothing here goes stale — and prints the toolchain it used, so a builder's own `go env` settings cannot change what the release is. It tags nothing and publishes nothing.

### Step 2 — Install the service

From here on `install.sh` runs each step as the `podaro` account, and the output is the same whether it or you typed the command — the by-hand installation (§5) reads the same blocks.

**You see:**

```
$ podaro system install
✓ directories        ~/.config/podaro · ~/.local/state/podaro (0700)
✓ console assets     extracted from binary (no downloads)
✓ starter catalog    grafana-prometheus-intro
✓ legal notices      ~/.local/state/podaro/legal/ · licence and notices, from the binary
✓ user service       podaro.service enabled and running
✓ api socket         /run/user/1000/podaro/api.sock (0600)

engine is running · listening on the local socket only
→ next: podaro doctor
```

**Behind the surface:** the binary self-extracts its embedded assets — the console's static bundle (fonts included; the console never fetches anything external) and the starter templates/modules — into the state directory. It writes `~/.config/systemd/user/podaro.service`, runs `systemctl --user daemon-reload` and `enable --now`, and the engine opens its Unix socket in `$XDG_RUNTIME_DIR/podaro/`. The `api socket` row means the engine *answered* on that socket, not that the path exists: the socket is bound before reconcile-on-start, which is the part of start-up that can fail, and a socket left behind by a killed process outlives it — so the row is a read the engine served, and the mode shown is the socket's own `0600`. **Nothing is listening on the network yet** — the posture is progressive: socket-only after install, and the TLS gateway on 7777 only after `setup` gives it a domain and certificates. Engine logs go to your user journal: `journalctl --user -u podaro`.

Extraction adds and never deletes. On a host where an earlier build ran, the catalog may still hold the template retired on 2026-09-23; it stays where it is, it is never on the `starter catalog` row, and one row after that one says it is there — `! retired template   <retired-template> present, unsupported by this release · not offered · PDR-W103` (`podaro explain PDR-W103`). A host that never held it gets exactly the board above.

### Step 3 — Doctor

**You see:**

```
$ podaro doctor
✓ podman 4.9.4          rootless · cgroups v2
✓ subuid / subgid       165536-231071 mapped for jross
✗ lingering             disabled — labs would stop when you log out
  → run once:           sudo loginctl enable-linger jross
✓ vm.max_map_count      65530 — some search products require 262144; advisory
✓ port 7777             free
✓ disk                  118 GB free on ~/.local/state
○ dns                   no domain configured yet (podaro setup)

1 item needs root — run the printed command, then: podaro doctor
```

**Behind the surface:** every check is a read: `podman info` for version/rootless/cgroups, `/etc/subuid` and `/etc/subgid` for your ranges, `loginctl show-user` for lingering, `/proc/sys/vm/max_map_count` for the kernel value — an advisory row that never fails, because some search products require 262144 and nothing in Podaro does — a momentary bind test on 7777, `statfs` on the state directory. One further row appears only when you have configured the observability export (User Manual §4) — `✓ observability   export on · logs→hec · metrics→otlp`, or a warning naming any signal whose destination certificate you told it not to verify; with export off, which is the default, the board is exactly the one above. Doctor **diagnoses and prescribes but never operates** — by hand, the one `sudo` command above is the only privileged action in the entire installation, it is yours to run, and it is idempotent; `install.sh`'s root stage has already run it, and created the account, so under it the board is green at the first look. Re-running doctor after it turns the board green.

### Step 4 — Domain and TLS

**You see:**

```
$ podaro setup --domain lab.example.com
✓ config                  ~/.config/podaro/config.yaml
✓ certificate authority   Podaro Local CA · valid 10 years
✓ wildcard certificate    *.lab.example.com · valid 1 year · auto-renews
✓ gateway                 listening on :7777 (TLS)

trust the CA on machines that will browse labs:
  Linux    sudo trust anchor ~/.local/state/podaro/ca/ca.crt
  macOS    open ca.crt → Keychain → always trust
  Windows  certutil -addstore -user Root ca.crt

point dns at this host (one wildcard record covers every lab):
  *.lab.example.com    A    203.0.113.10

→ next: podaro auth setup
```

**Behind the surface:** setup validates the domain and port (a port you give must be inside 1–65535 — only omitting the flag keeps the configured one — and a changed port must be free) — and, when you bring your own certificate, that it loads and covers both `lab.example.com` and `*.lab.example.com` — before it touches anything, so a typo never replaces a working configuration; then it prepares the certificates before it replaces anything — staged beside the live set and swapped into place as one unit only after `config.yaml` is written (one atomic exchange on Linux filesystems that offer it, two renames the next engine start completes otherwise), so a write that fails, or a crash at any point, leaves the configuration and the live certificates consistent — and every write on the way is durable, not merely atomic: the temporary file is synced before the rename that puts it in place, the directory after it, and the swap itself is flushed as its own step before the engine is asked to open the door, so a power loss cannot take back what setup reported done; a `config.yaml` the rollback's snapshot cannot be read from stops setup before anything is replaced, since a rollback with nothing to put back is worse than not starting; the set that served before waits beside the new one until the engine has opened the gateway, and a reload that fails — the port taken meanwhile, the engine not running — puts `config.yaml` (byte for byte) and that set back, so nothing changes unless the door opens (a reload whose answer was lost on the socket is settled by what the engine serves — the candidate's door open *with the candidate's leaf itself* — its fingerprint, since a re-issue changes only the certificate and an expiry can be shared — means it happened; otherwise the disk is restored and the engine asked to re-read it; each of these calls has a time limit of its own, so an answer that never arrives spends only the reload's; and the engine applies reloads one at a time, in the order they read the configuration, so a reload whose answer was lost can never apply, late, a configuration a later reload has replaced) — generating an ECDSA P-256 certificate authority (10-year, key `0600`, never leaves the machine; a leaf never outlives it, and a setup re-run with less than a year of CA life left — or after it expired — creates a new CA and prints the trust block again) and a wildcard leaf for `*.lab.example.com` + the apex — the leaf is kept ≤ 825 days for Apple-platform trust rules and the engine re-issues it automatically before expiry, so trusting the CA once is a one-time act per browsing machine — and only then writes `config.yaml` (domain and gateway port; TLS paths appear there only when you bring your own certificate — the local CA lives at a fixed place in the state directory): a certificate that cannot be prepared never leaves a configuration naming a domain no leaf serves. Setup then asks the running engine, over the local socket, to re-read its configuration (a reload whose new port turns out to be taken keeps the working gateway serving on the old port and reports `PDR-E024`); only now does the engine bind `:7777` (or the port you chose) on every interface, TLS-only, HTTP/1.1, deny-until-authenticated: an unauthenticated request to any hostname gets the login page or `401`, and unknown hostnames are dropped — a server name outside the domain fails the TLS handshake, a wrong `Host` gets its connection closed without a reply. Bringing your own certificate instead skips CA generation entirely (User Manual §4 shows the config keys; setup checks that it covers `*.lab.example.com` *and* `lab.example.com` — a wildcard alone leaves the console's own hostname uncovered — and that it is inside its validity window and allows server authentication: an expired, not-yet-valid or client-only certificate is refused, never served). The printed DNS block uses your host's detected address (`--ip` overrides it); hosts-file users get the per-hostname variant after their first instance exists. Re-running setup is safe: the CA is reused, the leaf re-issued, the gateway re-read. Two setups never overlap: one started while another runs is refused (`PDR-E023`) rather than queued — the staged set, the previous set and the configuration's temporary file are one run's at a time, and each run's candidate is derived from the configuration the run before it committed (the lock precedes the read). The engine's own certificate renewal takes that same lock: a renewal that finds a setup holding it leaves the leaf in place and comes back at its next check, so no one ever issues into a set another holder is exchanging, and the running gateway never picks up a half-published generation. The engine completes an interrupted swap at its next start but removes nothing beside the live set — a previous set there is a running setup's way back — and setup drops such leftovers at its own start, under its lock.

### Step 5 — The operator account

**You see:**

```
$ podaro auth setup
username [jross]:
password (12+ characters, not displayed):
confirm:
✓ operator account created
✓ audit               recorded to system evidence

console: https://lab.example.com:7777
```

**Behind the surface:** the password is read with echo off, checked for length and against an embedded common-password list, handed to the engine over the local socket (the one door that needs no credential — possession of your user account is the credential), hashed by it with Argon2id (64 MiB, 3 iterations) into `~/.local/state/podaro/auth.json` (`0600`), and never written or logged anywhere else — there is no recovery, only `podaro auth reset` at the socket, which replaces the account and rotates the session-signing key so every console session is signed out — a login in flight when the reset begins completes first and is signed out by it, and none that begins after it sees the old password. Scripts pass `--username` and `--password-file <0600 file>` instead of the prompts; the password is never a flag value, and a file anyone else could read — or one that is not a regular file — is refused before it is read. A random session-signing key is generated alongside for the console's cookies. The creation event is the first entry in the system audit stream. Note the UX-guide convention already at work: the console URL is the last line, alone, where eyes and copy-paste land.
### Step 6 — Confirm

**You see:**

```
$ podaro status
no instances yet
→ podaro up grafana-prometheus-intro    4 GB host · all open source
```

```
$ podaro system status
✓ service            podaro.service · active (running) since Sat 2026-09-20 18:02:11 UTC · pid 4242 · 0 restarts
✓ engine             answers on /run/user/1001/podaro/api.sock
→ next: podaro status
```

Each offer is one installed template with the description its own standard profile declares — the catalog's words, read from the state directory, not a list this command keeps. A retired template an earlier build left in the catalog is never offered; one `PDR-W103` line under the offers says it is there. `podaro system status` reads the unit from systemd and probes the engine behind it — a unit that is active is not yet an engine that answers — and exits 0 only when both are up (`--json` for the same facts as one object; `systemctl --user status podaro` says the same in systemd's words). `podaro system start`, `stop` and `restart` drive the same unit through `systemctl --user` with the account's session filled in, so they work from any shell the account gets; `start` and `restart` wait until the engine answers, `restart` names the instances it reattached to, and a stopped engine leaves the labs' containers running under Podman and the console unreachable until `start`. From your own shell, `podaroctl` beside the installer runs any of these as the account: `sudo /opt/podaro/podaroctl system status`, or `sudo podaroctl system status` once you let the installer put it on PATH; `podaroctl shell` is the account's login shell, and `podaroctl --print …` shows the exact command it would run and runs nothing. A refusal — a unit systemd does not know, a bus the shell cannot reach, an engine that starts but does not answer — is `PDR-E027`, with the remedy the state calls for. Installation is complete. Everything past this point — image pulls, license acceptance, per-instance secrets — belongs to `podaro up` and is deliberately *not* part of installation (§4).

---

## 3. What is on your system now

| Path | What | Mode |
|---|---|---|
| `/opt/podaro/` | the `podaro` account's home — `~` in every row below — holding the extracted package (`podaro`, `install.sh`, `install.test.yaml`, `podaroctl`, and the legal files beside them) and the installer's transcript `install-<UTC>.log` | `0750` |
| `~/.local/bin/podaro` | the one binary: engine + CLI + embedded console and starter catalog, and the licence and notices it carries (`podaro legal`) | `0755` |
| `~/.local/bin/{LICENSE,NOTICE,TRADEMARKS.md,THIRD-PARTY-NOTICES.md}` | the release's notices, beside the binary they cover; `system uninstall` removes them with it, and an upgraded engine rewrites them to its own | `0644` |
| `~/.config/podaro/config.yaml` | domain, gateway port, TLS paths, the log export if you asked the installer for one | `0600` |
| `~/.config/podaro/hec.token` | the HEC token, only when you asked the installer to export logs (Manual §4) | `0600` |
| `~/.config/systemd/user/podaro.service` | the user service unit | `0644` |
| `~/.profile` | the account's login profile, with the installer's block appended: `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS` and `~/.local/bin` on PATH, so `sudo -iu podaro` shells reach the account's session | `0644` |
| `~/.local/state/podaro/` | everything generated (state dir) | `0700` |
| ├ `ca/` | local CA (`ca.crt`, `ca.key`) + wildcard leaf (`wildcard.pem`: one file, key and certificate, replaced by one rename; auto-renewing) | keys `0600` |
| ├ `auth.json` | operator hash + session signing key | `0600` |
| ├ `tokens/` | API tokens you create with `podaro auth token create` — present only then | dir `0700`, files `0600` |
| ├ `catalog/` | extracted templates and modules | — |
| ├ `legal/` | the licence and the notices, written from the binary by `podaro system install` — the tarball's legal files, for a host that never saw the tarball — and rewritten to its own by an upgraded engine at its start | files `0644` |
| ├ `state.db` | engine state (SQLite) | `0600` |
| ├ `staging/` | a delivery snapshot while its create is admitted — empty between creates, swept on start | `0700` |
| └ `instances/` | one directory per instance — `secrets/` (generated values), `env/` (the rendered env files its containers read), `evidence/` (the append-only journal), `modules/` (a delivery instance's pinned module library) — empty until first `up` | dir `0700`; secret values, env files and evidence entries `0600` |
| `$XDG_RUNTIME_DIR/podaro/api.sock` | local API socket (`/run/user/<uid>/podaro/`) | `0700` dir |
| `/etc/subuid`, `/etc/subgid` | one line each: the account's subordinate ID range (root stage) | — |
| `/var/lib/systemd/linger/podaro` | the account's lingering flag (root stage) | — |
| `/usr/local/bin/podaroctl` | only if you asked the installer for it: a root-owned copy of the wrapper, so `sudo podaroctl …` works from any shell (root stage) | `0755` |

**Network posture:** exactly one listener, `:7777` TLS (and none at all if you haven't run `setup`). No outbound connections at rest — and if you configure observability export, exactly those destinations join the outbound story, nothing else. Firewall guidance: allow 7777 in; that's the whole story.

**Logs:** as the account, `journalctl --user -u podaro` (`sudo -iu podaro` first); the installer's own transcript is `/opt/podaro/install-<UTC>.log`. Log lines are redaction-filtered like everything else the engine emits — a secret value appearing in the journal is a reportable bug, full stop.

## 4. What installation deliberately did not do

No container images were pulled (the starter template's two, Prometheus and Grafana, are fetched at first `up` with progress). No licenses were accepted — a template that declares a EULA has each licence id typed per create, recorded in evidence, never defaulted, and the starter catalog declares none. No lab secrets exist — credentials are generated per instance at create, not at install. No shell files were edited, no root was used, nothing phoned home. The gap between "installed" and "running a lab" is exactly one command, and the manual's quickstart (§6) takes it from here.

## 5. Offline and air-gapped installation

On a connected machine: download the release tarball for the target's architecture (`podaro_v0.1.0_linux_amd64.tar.gz` or `podaro_v0.1.0_linux_arm64.tar.gz`, plus `SHA256SUMS`) from the release page, `https://github.com/JeremiahJRRoss/podaro/releases`, verify it with `sha256sum --ignore-missing -c SHA256SUMS`, and carry it over. The manifest covers every artifact of the release, and this path needs only the tarball — `--ignore-missing` is what lets you check the one file you took without the bare `podaro-0.1.0-linux-amd64` binary beside it. Then:

```
$ tar -xzf podaro_v0.1.0_linux_amd64.tar.gz -C ~/.local/bin podaro LICENSE NOTICE TRADEMARKS.md THIRD-PARTY-NOTICES.md
$ podaro system install
```

Identical from Step 2 onward — the binary is self-contained, so installation needs no network at all. The tarball holds `podaro`, `install.sh`, `install.test.yaml`, `podaroctl`, `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `THIRD-PARTY-NOTICES.md`, `LICENSES/`, `SOURCE-AND-BUILD.md` and `RELEASE-MANIFEST.json`; this by-hand path extracts the binary and the four notices beside it, where `install.sh` puts them too, while extracting everything into `/opt/podaro` and running `install.sh` (step 1) needs no network either. A binary that arrives without the tarball — the bare `podaro-<version>-linux-<arch>` a release also publishes — still carries every one of those files inside it: `podaro legal` prints the licence, the notices and the offer of its exact source, `podaro legal --licenses` every licence text, and `podaro system install` writes the set to `~/.local/state/podaro/legal/` (step 2's `legal notices` row). Lab images travel the same way: `podman save` on a connected host, `podman load` on the target (or point modules at an internal registry mirror in `config.yaml`); `podaro doctor` treats unreachable public registries as `○ skipped` when a mirror is configured. The console was built for this: it makes zero external requests, so an air-gapped lab is a first-class citizen, not a degraded mode.

### From source

A checkout of the repository — `git clone`, or the zip GitHub offers — is not the package: there is no `podaro` binary in it, and `install.sh` run there stops at its first row and says so. `./build.sh` at the root of the checkout builds the release from it:

```
$ ./build.sh --check        # the tools and versions this checkout needs; builds nothing
$ ./build.sh                # the release into dist/download/v<version>/, then the install commands
$ ./build.sh --install      # the same build, then the package into /opt/podaro and install.sh under sudo
```

Every missing dependency is a row with its remedy — the packager's tools, Go at least the version `go.mod` declares — and nothing is installed on the machine unless `--yes` says so: then a missing or too-old Go comes from the distribution's package when that is new enough, else from the official tarball at `go.dev`, checksum verified, into `/usr/local/go`. The build is `hack/release_package.sh` (step 1, "As built"), so what a checkout produces is what a release is — the tarball and its `SHA256SUMS`, each artifact built twice and compared — for this machine's architecture unless `PODARO_RELEASE_ARCHES` names others. A tree without `.git` builds unstamped; a git tree with uncommitted changes is refused, because an artifact names a commit. `--quick` is the exception for iterating: one `go build` of the tree as it is into `dist/quick/`, unverified and never a release. `--install` runs the build as you and asks `sudo` for the install alone; from there the prompts are step 1's.

## 6. Upgrading

**You see:**

```
$ podaro system upgrade
◐ downloading podaro v0.1.1     18 MB
✓ checksum verified
✓ state backed up               state.db → state.db.bak-v0.1.0
✓ binary replaced · service restarted
✓ migrations                    2 applied, forward-only
✓ instances                     intro reattached · unaffected

engine v0.1.1 · api v1alpha1
```

**Behind the surface:** upgrade is the one command in Podaro that reaches the network on its own behalf, and only when you run it. It asks the release location — `https://github.com/JeremiahJRRoss/podaro/releases`, the project's releases, unless `--from` names another — what it calls latest (`--to` pins a version instead), downloads that release's binary for your platform and its `SHA256SUMS`, and **verifies the digest locally before anything is replaced** — a download that does not match the manifest is discarded and refused (`PDR-E025`), and the running install is untouched. The order is chosen so every failure leaves a working engine: download, verify, back up the state (`state.db.bak-v<current>`, taken through SQLite itself so it holds every committed row including those still in the write-ahead log — the engine keeps the original and goes on writing to it), replace the binary by one rename — flushed to the disk before anything else happens, because the restart that follows hands the new engine the state and it migrates that forward: a rename a power cut can undo would leave the old binary against a schema it refuses (`PDR-E211`), which is the downgrade this command will not perform, arrived at by accident — and only then restart the service. A flush that fails after the rename says so: the new binary is in place but not yet durable and the service was not restarted, which is not the same refusal as one where nothing was replaced. A downgrade is refused rather than half-performed, because migrations are forward-only; the refusal names the pair to restore together. One upgrade runs at a time, on an advisory lock held from the version check to the restart: two invocations of the old binary can overlap, and the slower one would take its backup *after* the first had already migrated the state — writing the migrated database over `state.db.bak-v<old>` and leaving that rollback pair with no backup the old binary can open. The second one is refused, naming the first (`PDR-E025`). On a host with no route out, `--from` points at a mirror you filled yourself — an air-gapped lab is a first-class citizen (§5), and an upgrade that could only reach the internet would make it a second-class one. A mirror's `latest` is one line: the version, or the `/tag/v<version>` line a release host would redirect to. A page is not an answer, and is refused as one. A development build made before 2026-09-27 asks an earlier release location, where nothing was ever published: point it at this one once, `podaro system upgrade --from https://github.com/JeremiahJRRoss/podaro/releases`, and the build it installs asks here by itself.

The restart is not called done until the restarted engine answers a read on its socket — a bound socket is not an answer, since it is created before reconcile-on-start and survives a killed process — and the instances row is a warning naming the cause when that read fails or the engine answers anything but `200`, rather than a row that quietly disappears — the API's own error envelope decodes into an empty instance list, so a status that is not checked reads as a healthy engine holding nothing. The running containers belong to Podman, not to the engine process — an engine restart reattaches to live instances and their persistent jobs rather than disturbing them. State migrations run forward-only after an automatic timestamped backup of `state.db` — a column a release adds is filled in at the next start where only the engine can derive it (this release's `ui` facts come from each instance's plan, so labs created before it get their product hostnames without being re-run; the migration records which instances predate the column, so the derivation happens once per instance and an instance that already carries its facts — or a service that simply has no `ui` endpoint — is never re-derived from a source that may have changed since); if a migration fails, the engine refuses to start half-migrated, prints the restore command, and the backup makes rollback a copy. An older binary refuses a newer `state.db` (`PDR-E211`) rather than guess at a schema it does not know: roll back the binary and the state together, from that backup. Release notes call out any upgrade that can't keep instances running; absent that note, upgrading mid-demo is safe, if not recommended for the nerves. The legal files follow the binary: the restarted engine rewrites `~/.local/state/podaro/legal/` and the notices beside `~/.local/bin/podaro` from the copies the new binary carries, so the files on disk say what `podaro legal` says — it creates neither where the install did not.

**What an earlier build left.** Before it asks the release location anything, the upgrade reads the state database's instance rows and the catalog directory — read-only — and lists what this release does not operate: the template retired on 2026-09-23, if an earlier build left it in the catalog, and any instance created from it, with how many of the containers carrying its label are running. On a host that holds neither there are no such rows, and the board is the one above.

```
$ podaro system upgrade
! retired template              <retired-template> in the catalog · not offered, never recreated · PDR-W103
! unsupported instance          old-lab · retired template · 1 of 2 containers running, left as they are · not reconciled · PDR-W103
◐ downloading podaro v0.1.1     18 MB
…
✓ instances                     intro reattached · unaffected · old-lab unsupported · left as they are
```

It reports and proceeds, because no release operates such an instance: the engine never reconciles, repairs, restarts or stops it, and every operation that would run its lab is refused (`PDR-E215`); its status, evidence and reports still read, and `podaro destroy` is the one act that removes it (`podaro explain PDR-W103`). What refuses the upgrade is a state database whose instance rows cannot be read — then nothing can say which instances are isolated — with `PDR-E025` naming why, before anything is fetched, and nothing replaced. A runtime the preflight cannot ask about containers is said on the instance's row, and the upgrade goes on.

## 7. Uninstalling

**You see:**

```
$ podaro system uninstall
✗ 1 instance still exists: pii-lab
  → podaro destroy pii-lab        (uninstall will not destroy labs for you)

$ podaro destroy pii-lab
…
$ podaro system uninstall
this removes: the service, the binary, ~/.config/podaro, ~/.local/state/podaro
it does not touch: podman itself, images already pulled, your shell files
confirm [y/N]: y
✓ service stopped and removed
✓ state and configuration removed
✓ binary and the notices beside it removed

podman images remain · remove with: podman rmi --all
```

Either works from a `sudo -iu podaro` shell — the engine sets the session variables its `systemctl --user` needs itself, whatever the shell has — or from your own shell as `sudo /opt/podaro/podaroctl system uninstall`. `sudo /opt/podaro/install.sh --uninstall` runs the same command as the account, from outside it; `--purge` then removes the account and `/opt/podaro` — the package included — and the `podaroctl` copy in `/usr/local/bin` if you had asked for one, after you type the account's name, and leaves the pulled images in place, saying how to remove them. It changes no kernel value, so it has none to revert; should a pre-release build of the installer have left `/etc/sysctl.d/99-podaro.conf` on the host, `--purge` names that inert file and how to remove it.

**Behind the surface:** uninstall **refuses while instances exist** — destroying labs is a decision you make per lab, by name, never a side effect of removing software. It refuses just as firmly when it cannot tell: an instance directory it fails to read is not an empty one, so the run aborts with `PDR-E026` and removes nothing — the same rule the stop check applies to engine liveness (`PDR-E022`). Each removal that follows reports what it actually did: a unit file, state directory, configuration, or binary that could not be removed fails the run and names which, rather than printing a row that claims otherwise, and whatever is still there stays there for a re-run. The notices `install.sh` put beside the binary go with it, first — and only Podaro's own: a directory whose `NOTICE` is not Podaro's is never touched. What remains afterward is only what Podman owns (pulled images, which you may want for reinstall) and anything you exported yourself (evidence reports). The one `sudo` change from doctor, lingering, is left in place by `podaro system uninstall` — it's inert, harmless, and yours (`sudo loginctl disable-linger <account>` reverts it); `install.sh --uninstall --purge` turns it off with the account.

## 8. Verifying what you just read

Every claim in this manual is checkable: read the bootstrap script (`curl … | less` — it only downloads and verifies), diff the file inventory (§3) against `find ~/.config/podaro ~/.local/state/podaro`, watch the network posture (`ss -tlnp | grep podaro` shows 7777 and nothing else), and read the journal for the absence of anything secret. An installation manual for a trust-sensitive tool should be an audit script in prose — treat it as one, and file a bug for any divergence you find.

---

*Podaro Community Installation Manual v0.1 draft · never root, one binary, nothing leaves the room*
