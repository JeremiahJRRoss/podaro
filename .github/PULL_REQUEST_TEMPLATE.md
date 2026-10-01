<!-- SPDX-License-Identifier: AGPL-3.0-only -->
## Problem and intended outcome

Explain the user or maintainer problem this change addresses. Link the related issue and test report.

## What changed

Describe the change and any user-visible effects. Identify changes to public interfaces, configuration, security boundaries, lifecycle behavior, or lab checkpoint semantics.

## Verification

Say what you ran, where, and what it showed. For user-journey changes, name the manual section whose expected result you checked. Do not describe a fake-runtime check as a real-product test.

| Command / check | Environment and runtime | Outcome | Evidence / skip reason |
|---|---|---|---|
| | | NOT RUN | |

**Regression proof:** Does the new test fail on the old behavior? Explain when applicable.

**What remains untested:**

## Documentation and compatibility

Identify updated guides, examples, limitations, and error explanations. For breaking interfaces, describe the version/migration decision rather than silently changing the existing contract.

## Safety and licensing

- [ ] No credentials, join links, private keys, raw state, or unrelated personal data are included.
- [ ] Existing notices and appropriate SPDX identifiers are retained.
- [ ] Commits have accurate DCO sign-off as described in CONTRIBUTING.md.
- [ ] The relevant threat model was updated if a trust boundary changed.
- [ ] Generated artifacts are excluded unless deliberately required and reviewed.
- [ ] Tests did not run against production or unrelated valuable state.
- [ ] No test skip or known acceptance failure is represented as a pass.

## Maintainer notes

Record follow-up decisions or release implications. This pull request does not by itself authorize publication, a version bump, a release tag, or production deployment.
