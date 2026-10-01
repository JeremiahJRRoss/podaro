<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Podaro trademark policy

**Status:** proposed for the owner's and counsel's review; not a registration, not a clearance; ™ only where the owner has asserted the mark; `Podaro` is never described as a registered trademark unless and until it is (the owner, 2026-09-23).

This policy is about the name. The software's licence is a separate matter: [`LICENSE`](LICENSE) is the GNU Affero General Public License, version 3, unmodified (`AGPL-3.0-only`), and [`NOTICE`](NOTICE) carries the project's copyright and licensing statement. Nothing in this file adds a term to that licence or takes a right away from it.

## The policy

The Podaro name and associated project marks identify releases and services authorized by **Jeremiah Ross**. Copyright permissions for the software and other materials are stated separately. Those permissions do not include a general license to use the project's marks as the brand of another product or service.

This policy does not restrict truthful, non-misleading reference to the project, legally permitted identification or resale of genuine copies, required legal attribution, compatibility descriptions, commentary, criticism, or other uses permitted by applicable law.

Do not present a modified or independently operated offering as an official Podaro offering, or use the marks in a way likely to cause confusion about origin, sponsorship, certification, or endorsement. An independent fork or service should use its own prominent brand. Any branding permission beyond applicable law or an express published permission requires written authorization from the trademark owner.

Preserve required copyright, license, and attribution notices. Rebranding is not a reason to remove legal provenance. This policy does not withdraw rights to use, modify, distribute, or operate the software that are granted by its copyright license.

Requests for branding permission should be directed to **Jeremiah Ross through the contact method published by the official project**: `dev@podaro.dev`.

## What the policy means, point by point

- **Use, modification and redistribution are free under the AGPL.** Podaro software may be used, modified and redistributed under the GNU Affero General Public License, version 3. This policy withdraws none of those rights; it is about how a name is used, never about what anyone may do with the software.
- **No false endorsement, sponsorship or official status.** A fork, a modified build, a hosted service or a derivative distribution may not falsely imply that it is endorsed or sponsored by the project, or that it is an official Podaro release.
- **Distinct branding where confusion would result.** A materially modified distribution should use sufficiently distinct branding when continuing to call it Podaro would create confusion about its source or endorsement. An unmodified copy, truthfully identified, needs no new name.
- **Truthful references stay permitted.** Naming Podaro in a tutorial, a review, a comparison or a criticism is not something this policy restricts, and nothing here claims that nobody may say or write the word.
- **Compatibility statements are not prohibited.** A statement such as "compatible with Podaro" is not categorically prohibited, as long as it does not imply endorsement.
- **Nominative and other lawful uses are not prohibited.** Nominative use, and any other use applicable law permits, is outside what this policy restricts.
- **The software licence grants no trademark rights beyond what the law permits.** The AGPL's permissions cover the software; they are not a licence to use the project's marks as the brand of another product or service. The trademark reservation lives here, not in the licence text, and no additional term under section 7 of the AGPL has been added — whether one should be is counsel's call, and that question is open.
- **No registered-mark claim.** No registration has issued. Nothing in the software or its documentation uses the registered-mark symbol for Podaro or calls it a registered trademark, and nothing may until a registration issues and then only for the goods, services and territories it covers.

## Practical examples

| Use | Treatment under this policy |
|---|---|
| An operator runs the official unmodified software. | No requirement to rename a private installation merely because the operator is not the owner. |
| A distributor truthfully identifies an unmodified upstream release. | Legally permitted identification and resale are respected; the distributor is distinguished from the upstream project. |
| A fork markets itself as "Podaro Official" or implies the owner's approval. | Not authorized by this policy. |
| An independent hosted service uses its own name and accurately states that it uses or derives from Podaro. | Permitted as a truthful reference; the software licence and the reference stay separate from any claim of official endorsement. |
| A tutorial names Podaro, or a compatible tool describes its compatibility. | Lawful, non-misleading reference; no permission is needed to mention the name. |
| A fork keeps upstream notices, schema identifiers, import paths or compatibility strings. | Required provenance and technical identifiers are not public-facing branding, and keeping them is not a use of the marks as a brand. |

## Rebranding a build

A modified build can carry its own name without touching provenance or identifiers. The display name is one package, `internal/brand`, set at build time — `go build -ldflags "-X $(go list -m)/internal/brand.Name=<name> -X $(go list -m)/internal/brand.Title=<title>" ./cmd/podaro` — and never from a request; the licence, `NOTICE`, the third-party notices and the source offer that `podaro legal` prints are unchanged by it. The identifiers a fork keeps are compatibility, not branding: the `podaro` command, the `podaro_session` cookie, the `pdr-` container labels, the API path `/api/v1alpha1`, the schema `$id`s under `schemas.podaro.dev`, the state paths, and the Go import path. [`SOURCE-AND-BUILD.md`](SOURCE-AND-BUILD.md) says how a modified build publishes its own source, which the AGPL requires whatever the build is called.

No page or command of Podaro calls itself "official". What makes a release the project's is where it is published — the releases of the repository named in the `SOURCE` file — and that its artifacts match the `SHA256SUMS` published beside them; `podaro legal` prints both.

## What this policy is not

It is not the software licence, and it changes nothing in `LICENSE`. It is not a trademark registration, a clearance search, a filing or a claim of global exclusivity: none of those has been made, and the owner decides whether and where to seek them. It is not a ban on the word "Podaro". And it is a proposal: the owner and counsel review it before anyone relies on it.
