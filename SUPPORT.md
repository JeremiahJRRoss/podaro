<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Getting help with Podaro

Podaro Community is a Developer Preview. Help is community-based; there is no guaranteed response time or support service-level agreement in this preview.

**We need testers.** A careful report is often the fastest way to help both yourself and the next user. The [User Manual](public-docs/USERMANUAL.md) explains what to run; the test-report issue template is how to record what happened.

## Find the right route

| Situation | What to do |
|---|---|
| You are installing for the first time | Follow the [Installation Manual](public-docs/INSTALL.md), then the [User Manual](public-docs/USERMANUAL.md)'s quickstart (§6). |
| You see a `PDR-*` error | Run `podaro explain` with the actual code and read the [User Manual](public-docs/USERMANUAL.md)'s troubleshooting section (§14). |
| You need help using an implemented feature | Open a usage question in this repository's Discussions when enabled; otherwise use an issue clearly titled as a question. |
| You can reproduce a defect | Use the bug-report template; the sections below say what to include. |
| A documentation step is missing or misleading | Use the documentation-issue template; quote the page and section, not an entire private log. |
| You completed or attempted a test run | Submit the test-report template, including failures and skipped checks. |
| You suspect credential exposure, unauthorized access, or another security defect | Use [Security policy](SECURITY.md). Do not open a public reproduction. |

## Before asking

Read the [User Manual](public-docs/USERMANUAL.md)'s limits of this release (§16). Confirm your installed version with `podaro version`; for a source checkout, record the commit with `git rev-parse HEAD`. Check that the guide you followed applies to that version.

Use `podaro doctor` for host diagnostics and `podaro status` for instance state. Doctor diagnoses the host; it is not a per-instance repair command. A failure of a checkpoint may be the exercise working as intended, an incorrect checkpoint, or a problem in the environment. Tell us which condition you expected to change.

## Make a request answerable

Give a short description of your goal, your environment, the smallest sequence that reaches the problem, and the exact expected and actual outcomes. Include the relevant error code and a short sanitized output excerpt. State whether this was a fake-runtime test or a real Podman run.

For browser problems, record the browser and version, the page or playbook step, whether the product was embedded or opened in a separate tab, and the input method that failed. A screenshot with the address bar and credentials removed can help; do not attach raw browser profiles or HAR captures without reviewing their contents.

## Keep secrets out of support requests

Do not attach the Podaro state directory, authentication file, token files, private keys, rendered environment files, cookies, Authorization headers, or attendee join links. Do not paste the output of a credential reveal.

Redaction in the product is a safeguard, not permission to upload every log. Review diagnostic files yourself. Attach the smallest sanitized excerpt that shows the problem, and nothing from the paths listed above.

## Follow through

When new information arrives, add it to the original issue instead of opening duplicates. When you retest a proposed fix, report the exact new commit or artifact, the commands run, and the outcome. A clear confirmation that the fix worked is valuable.

Do not work around an uncertain destructive operation by deleting random state files. Preserve a minimal report and ask for guidance. Tests belong on disposable hosts, not production systems.
