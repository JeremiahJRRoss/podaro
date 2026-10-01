<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Security Policy — Podaro Community

Podaro runs lab software that is deliberately permissive; the platform around it is not. Report failures in the platform's containment, authentication, authorization, credential handling, or evidence integrity privately.

> **Before the first release** the maintainer enables and verifies GitHub private vulnerability reporting on this repository, and verifies that the maintainer's address, `dev@podaro.dev`, receives mail. This policy promises no response window: an unstaffed promise is worse than none.

## Report privately

On the repository's GitHub page, `https://github.com/JeremiahJRRoss/podaro`, open **Security → Advisories → Report a vulnerability** ([directly](https://github.com/JeremiahJRRoss/podaro/security/advisories/new)) — or write to the maintainer, Jeremiah Ross, at `dev@podaro.dev`. Describe the affected component (engine, CLI, console, gateway, the exec contract, docs), the source revision or released artifact, prerequisites, a reproduction using synthetic data, expected and actual behavior, the impact you observed, and the `PDR-E` code if one appeared.

If the private-report option is missing, do not post exploit details, credentials, or sensitive artifacts publicly. Write to `dev@podaro.dev` instead; a public issue may say only that the private reporting channel is unavailable and ask the maintainers to restore it.

Do not include live passwords, tokens, private keys, customer records, or unrelated personal information in the initial report. Coordinate a safe transfer method if more sensitive evidence is needed.

## Scope

**In:** the engine, CLI, console, gateway configuration, the exec extension runtime and its five walls, instance/attendee session enforcement, secrets handling, and any way to make evidence lie. Reports are especially useful for cross-instance access, operator or attendee authorization bypass, credentials reaching unintended recipients, unsafe template or exec-container behavior, host access beyond documented boundaries, and evidence that can falsely appear machine-verified.

**Out:** vulnerabilities *in the third-party software a lab runs* (a database, a dashboard tool, a metrics store — report those upstream; Podaro's job is containing them, so a **containment failure is in scope** even when the payload is a product bug), templates and bundles you authored or imported, and the host OS.

A known limitation does not make a new report unimportant. The trust boundaries in [Architecture](public-docs/ARCHITECTURE.md) document accepted residuals: a report that matches a *named residual* is welcome as an issue rather than as a vulnerability, and a report that shows greater impact, a failed mitigation, or an incorrect threat-model assumption is a vulnerability report.

## Safe research

Test only systems and data you own or have permission to examine. Use dedicated test VMs and synthetic data. Do not target another person's lab, public demo, registries, or infrastructure without authorization. Avoid denial-of-service or destructive testing outside a specifically agreed environment.

See the trust boundaries in [Architecture](public-docs/ARCHITECTURE.md) and the [User Manual](public-docs/USERMANUAL.md)'s security model (§13) and limits (§16) for the documented boundaries. This policy is not a promise of vulnerability-free software or blanket permission to test third-party systems.

## Supported versions and response

Pre-1.0: the latest release and `main` only. Report the exact source revision or released artifact. There is no long-term-support branch, and no remediation schedule is promised.

Maintainers acknowledge and coordinate reports privately and say where the investigation stands as it moves. Do not assume a fix exists until an advisory or release note names the affected and corrected versions. No bounty program yet; reporters are credited in release notes with consent.

## Accidental public exposure

If you publish a live credential by accident, revoke or rotate it immediately and tell the maintainer privately. Editing a comment does not invalidate a copied credential. Remove the unnecessary exposure from public artifacts after preserving the private evidence that matters.

## Non-security testing

For ordinary functional defects, use the bug-report issue template as [Support](SUPPORT.md) describes. The project needs testers, but public test reports must exclude security-sensitive details.

Reference: [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository). Thank you for helping a lab platform deserve the trust it asks for.
