---
name: Bug report
about: Report a reproducible functional defect in the Developer Preview.
title: "[Bug] "
---
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Security problem? Read SECURITY.md and report privately. Do not put credentials, join links, private keys, raw state, or an unreviewed capture in this issue. -->

# Problem

Describe the user-visible problem and what you were trying to accomplish.

## Before submitting

- [ ] I searched existing issues and read the [User Manual](https://github.com/JeremiahJRRoss/podaro/blob/main/public-docs/USERMANUAL.md)'s limits of this release (§16).
- [ ] I read [Support](https://github.com/JeremiahJRRoss/podaro/blob/main/SUPPORT.md) on what a report needs and what to keep out of it.
- [ ] This is appropriate for a public report, not a security-sensitive disclosure.
- [ ] I reviewed all excerpts and attachments for secrets and identifying information.

## Exact version and environment

| Field | Value |
|---|---|
| Podaro version | |
| Full commit or published artifact and SHA-256 | |
| Clean checkout or local changes | |
| Documentation revision | |
| OS / kernel / architecture | |
| Podman version / rootless status / delegated controllers | |
| CPU / RAM / free disk | |
| Browser and version, when relevant | |
| Real Podman or fake runtime | |
| Template / playbook / step, when relevant | |
| Cold or cached images | |

## Minimal reproduction

State the starting state, then list the smallest sequence of commands or UI actions that reproduces the problem. Identify whether the command ran on the host or the browser machine. Use synthetic data and sanitized names.

1. Starting state:
2. Action:
3. Observation:

## Expected result

What should have happened? For checkpoint issues, name the condition being tested rather than only saying “green.”

## Actual result

What happened instead? Include the command exit code or HTTP status, the actual `PDR-*` code, and the assertion result when applicable. Distinguish a failed operation from a successful operation returning a failed assertion.

## Sanitized evidence

Paste the smallest useful excerpt. Do not attach the entire state or diagnostic directory. Label screenshots and fake-runtime results accurately.

## Frequency and scope

Does this happen every time? On a fresh instance? On another revision or environment? What was not tested?

## Related testing

Link the associated test report, if there is one. Identify explicit skips or missing prerequisites.

## Workaround and cleanup

Describe any workaround attempted and its effects. Record leftover test objects before removing them; do not use global pruning to make cleanup appear successful.
