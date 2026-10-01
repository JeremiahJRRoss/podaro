---
name: Test report
about: Share a successful, failed, blocked, or partial Podaro evaluation.
title: "[Test] "
---
<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- We need testers. A precise blocked run is useful. Read public-docs/USERMANUAL.md and SUPPORT.md before posting. Never publish credentials, join links, private keys, raw state, or unreviewed captures. -->

# Test summary

**Goal and declared scope:**

**Manual sections followed (Installation Manual, User Manual):**

**Overall result:** PASS / FAIL / BLOCKED / PARTIAL — explain.

**Actual UTC date/time range:**

**Independent documentation-only run?** Describe assistance, undocumented steps, and changes during the run.

## Software and environment

| Field | Value |
|---|---|
| Podaro version | |
| Full commit / artifact name / binary SHA-256 | |
| Local modifications and documentation revision | |
| Source-built or downloaded artifact | |
| Exact Go version when built | |
| OS / kernel / architecture | |
| Podman version / rootless status / cgroup delegation | |
| CPU / RAM / free disk | |
| Browser/version and client OS | |
| Runtime: fake or real Podman | |
| Template / module/image versions | |
| Image cache state | |
| DNS method and TLS trust method, without private names | |
| Dedicated host and synthetic data confirmed | |

## Results

Use PASS / FAIL / BLOCKED / SKIPPED / NOT RUN for each check. A known failure is not a pass for the intended product criterion.

| Check ID or command | Status | UTC time | Actual observation | Evidence / issue |
|---|---|---|---|---|
| | NOT RUN | | | |

**Explicit skips or omitted resource controls:**

**Known limitations reproduced:**

**Untested scope:**

## Timings

Record installation, create-to-ready, ready-to-first-earned-objective, reset, and teardown separately. Include cache state and retries; do not paste design targets as observed times.

## Defects and documentation gaps

Link each independent issue. Include confusing instructions and missing prerequisites, not only crashes.

## Cleanup

What was created, what was removed, and what remained? Were unrelated objects affected? Account separately for images, authored source, reports, DNS/client trust, and host configuration.

## Privacy and accuracy

- [ ] I reviewed every public excerpt and attachment.
- [ ] I excluded credentials, join URLs, auth/token files, private keys, raw state, and browser credentials.
- [ ] I identified fake-runtime results and skipped checks explicitly.
- [ ] I recorded actual observations, not copied expected outcomes.
- [ ] I preserved earlier failures and identified any retest revision.

Keep credentials, join links and raw state out of the report; a sanitized excerpt is enough.
